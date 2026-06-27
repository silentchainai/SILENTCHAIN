package com.sn1persecurity.silentchain.bapp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.scan.PassiveHttpHandler;
import com.sn1persecurity.silentchain.bapp.scan.ScanGate;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.ContextMenuProvider;
import com.sn1persecurity.silentchain.bapp.ui.main.MainTab;
import com.sn1persecurity.silentchain.bapp.ui.settings.SettingsDialog;
import com.sn1persecurity.silentchain.bapp.util.Banner;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.SwingUtilities;
import java.awt.Window;
import java.util.Set;

public class SilentchainExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "SILENTCHAIN Community Edition";
    public static final String EXTENSION_VERSION = "1.3.0";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        Banner.print(api);

        Settings settings = new Settings();
        SettingsPersistence persistence = new SettingsPersistence(api);
        persistence.load(settings);

        // ---- Live state ----------------------------------------------------
        Counters counters = new Counters();
        TaskRegistry taskRegistry = new TaskRegistry();
        FindingsRegistry findingsRegistry = new FindingsRegistry();
        ScanState scanState = new ScanState(api, settings);

        // ---- AI + pipeline -------------------------------------------------
        ThreadPool threadPool = new ThreadPool();
        MontoyaHttpClient http = new MontoyaHttpClient(api);
        AiDispatcher dispatcher = new AiDispatcher(api, http, settings, threadPool);
        AiService aiService = new AiService(api, threadPool, dispatcher);
        AnalysisOrchestrator orchestrator = new AnalysisOrchestrator(
                api, aiService, settings, scanState, counters, taskRegistry, findingsRegistry);

        api.userInterface().registerContextMenuItemsProvider(
                new ContextMenuProvider(api, aiService, orchestrator, scanState)
        );

        ScanGate gate = new ScanGate(api, settings);
        api.http().registerHttpHandler(
                new PassiveHttpHandler(api, gate, aiService, orchestrator, settings, scanState, counters)
        );

        // ---- UI ------------------------------------------------------------
        SwingUtilities.invokeLater(() -> {
            Window parent = api.userInterface().swingUtils().suiteFrame();

            MainTab mainTab = new MainTab(api, settings, persistence, scanState,
                    counters, taskRegistry, findingsRegistry);

            SettingsDialog settingsDialog = new SettingsDialog(parent, api, settings, persistence,
                    dispatcher, scanState, taskRegistry, mainTab::onSettingsSaved);
            mainTab.setSettingsOpener(settingsDialog::showDialog);

            api.userInterface().registerSuiteTab("SILENTCHAIN Community", mainTab);

            scanState.info(EXTENSION_NAME + " v" + EXTENSION_VERSION + " ready. Passive scanning is "
                    + (settings.passiveEnabled() ? "ENABLED" : "DISABLED")
                    + " | Provider: " + settings.provider().displayName() + ".");
        });

        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput(EXTENSION_NAME + " unloading...");
            threadPool.shutdown();
        });
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }
}
