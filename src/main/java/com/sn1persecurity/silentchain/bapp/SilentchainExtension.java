package com.sn1persecurity.silentchain.bapp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Registration;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.scan.AiPassiveScanCheck;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.scan.ScanGate;
import com.sn1persecurity.silentchain.bapp.scan.ScannerStatus;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.ContextMenuProvider;
import com.sn1persecurity.silentchain.bapp.ui.main.MainTab;
import com.sn1persecurity.silentchain.bapp.ui.settings.SilentchainSettingsPanel;
import com.sn1persecurity.silentchain.bapp.util.Banner;
import com.sn1persecurity.silentchain.bapp.util.Lifecycle;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.SwingUtilities;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class SilentchainExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "SILENTCHAIN Community Edition";
    public static final String EXTENSION_VERSION = "1.3.1";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        Banner.print(api);

        Settings settings = new Settings();
        SettingsPersistence persistence = new SettingsPersistence(api);
        persistence.load(settings);

        // ---- Live state ----------------------------------------------------
        Lifecycle lifecycle = new Lifecycle();
        Counters counters = new Counters();
        TaskRegistry taskRegistry = new TaskRegistry();
        FindingsRegistry findingsRegistry = new FindingsRegistry();
        ScanState scanState = new ScanState(api, settings);

        // ---- AI + pipeline -------------------------------------------------
        ThreadPool threadPool = new ThreadPool(api.logging(), lifecycle);
        AiGate aiGate = AiGate.forApi(api);
        MontoyaHttpClient http = new MontoyaHttpClient(api, aiGate, settings);
        AiDispatcher dispatcher = new AiDispatcher(api, http, settings, aiGate);
        AiService aiService = new AiService(dispatcher);
        AnalysisOrchestrator orchestrator = new AnalysisOrchestrator(api, aiService, aiGate, settings,
                scanState, counters, taskRegistry, findingsRegistry, threadPool, lifecycle);
        scanState.setOnResume(orchestrator::resumeParked);

        api.userInterface().registerContextMenuItemsProvider(
                new ContextMenuProvider(api, aiService, aiGate, orchestrator, scanState, persistence)
        );

        ScanGate gate = new ScanGate(api, settings);
        AiPassiveScanCheck passiveCheck = new AiPassiveScanCheck(api, gate, aiGate, aiService,
                orchestrator, settings, scanState, counters, lifecycle);
        ScannerStatus scannerStatus = registerPassiveScanCheck(api, passiveCheck);

        // ---- UI ------------------------------------------------------------
        AtomicReference<MainTab> mainTabRef = new AtomicReference<>();
        SwingUtilities.invokeLater(() -> {
            if (lifecycle.isUnloading()) {
                return;
            }
            MainTab mainTab = null;
            Registration settingsReg = null;
            Registration tabReg = null;
            boolean ready = false;
            try {
                mainTab = new MainTab(api, settings, persistence, scanState, counters, taskRegistry,
                        findingsRegistry, orchestrator, threadPool, aiGate, passiveCheck::lastCallbackMillis,
                        scannerStatus);
                mainTabRef.set(mainTab);
                SilentchainSettingsPanel settingsPanel = new SilentchainSettingsPanel(api, settings, persistence,
                        dispatcher, aiGate, scanState, taskRegistry, threadPool, mainTab::onSettingsChanged);
                mainTab.setOnPassiveChanged(settingsPanel::syncPassive);

                settingsReg = api.userInterface().registerSettingsPanel(settingsPanel);
                tabReg = api.userInterface().registerSuiteTab("SILENTCHAIN Community", mainTab);

                ready = !lifecycle.isUnloading();   // false: unloaded while the UI was being built
                if (ready) {
                    scanState.info(EXTENSION_NAME + " v" + EXTENSION_VERSION + " ready. Passive scanning is "
                            + (settings.passiveEnabled() ? "ENABLED" : "DISABLED")
                            + " | Provider: " + settings.provider().displayName() + ".");
                }
            } catch (Throwable t) {
                api.logging().logToError(EXTENSION_NAME + ": could not build the user interface", t);
            } finally {
                if (!ready) {
                    if (mainTab != null) {
                        mainTab.dispose();
                    }
                    deregisterQuietly(settingsReg);
                    deregisterQuietly(tabReg);
                }
            }
        });

        api.extension().registerUnloadingHandler(() -> {
            try {
                lifecycle.markUnloading();
                api.logging().logToOutput(EXTENSION_NAME + " unloading...");
                orchestrator.cancelAll();
                MainTab mainTab = mainTabRef.get();
                if (mainTab != null) {
                    mainTab.dispose();
                }
                scanState.setConsoleSink(null);
                scanState.setOnResume(null);
            } catch (Throwable t) {
                api.logging().logToError("SILENTCHAIN: error during unload", t);
            } finally {
                threadPool.shutdownNow();
            }
        });
    }

    /**
     * Automatic analysis runs as a Burp Scanner passive check, which needs Burp
     * Suite Professional. On Community Edition there is no scanner (and Burp's AI
     * permission, which gates every provider, is never granted), so the
     * extension stays idle and says why.
     */
    private static ScannerStatus registerPassiveScanCheck(MontoyaApi api, AiPassiveScanCheck check) {
        BurpSuiteEdition edition;
        try {
            edition = api.burpSuite().version().edition();
        } catch (Throwable t) {
            edition = null;
        }
        if (edition == BurpSuiteEdition.COMMUNITY_EDITION) {
            api.logging().logToOutput(EXTENSION_NAME + " requires Burp Suite Professional: automatic analysis "
                    + "runs in Burp Scanner and AI features need Burp's 'Use AI' permission, neither of which "
                    + "is available in Burp Suite Community Edition. The extension is loaded but idle.");
            return ScannerStatus.COMMUNITY_EDITION;
        }
        try {
            api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST);
            return ScannerStatus.REGISTERED;
        } catch (Throwable t) {
            api.logging().logToError(EXTENSION_NAME + ": could not register the passive scan check; "
                    + "automatic analysis is unavailable (right-click analysis still works).", t);
            return ScannerStatus.FAILED;
        }
    }

    private static void deregisterQuietly(Registration registration) {
        if (registration != null) {
            try {
                registration.deregister();
            } catch (Throwable ignored) {
                // best effort while tearing down a half-built UI
            }
        }
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }
}
