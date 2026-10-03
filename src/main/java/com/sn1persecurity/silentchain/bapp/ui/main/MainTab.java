package com.sn1persecurity.silentchain.bapp.ui.main;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.export.CsvExporter;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.scan.ScannerStatus;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingRow;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * Root SILENTCHAIN tab: assembles the Community-style single-tab layout and
 * drives a 1.5s refresh timer over the live state. The timer is stopped by
 * {@link #dispose()} from the extension's unloading handler.
 *
 * Layout:
 *   NORTH  : header + statistics + runtime status + control bar
 *   CENTER : vertical split: active tasks (top) / findings (bottom)
 *   SOUTH  : console pane
 */
public class MainTab extends JPanel implements ControlBar.Actions {

    private static final String UPGRADE_URL = "https://silentchain.ai/?referral=silentchain_bapp";
    private static final int REFRESH_MILLIS = 1500;

    private final MontoyaApi api;
    private final Settings settings;
    private final SettingsPersistence persistence;
    private final ScanState scanState;
    private final TaskRegistry taskRegistry;
    private final FindingsRegistry findingsRegistry;
    private final AnalysisOrchestrator orchestrator;
    private final ThreadPool threadPool;

    private final StatisticsPanel statisticsPanel;
    private final RuntimeStatusLine runtimeStatusLine;
    private final ControlBar controlBar;
    private final TaskTablePanel taskTablePanel;
    private final FindingsTablePanel findingsTablePanel;
    private final ConsolePane consolePane;
    private final Timer refreshTimer;

    private boolean refreshFailureLogged;
    private volatile Runnable onPassiveChanged = () -> { };

    public MainTab(MontoyaApi api,
                   Settings settings,
                   SettingsPersistence persistence,
                   ScanState scanState,
                   Counters counters,
                   TaskRegistry taskRegistry,
                   FindingsRegistry findingsRegistry,
                   AnalysisOrchestrator orchestrator,
                   ThreadPool threadPool,
                   AiGate aiGate,
                   LongSupplier lastPassiveCallbackMillis,
                   ScannerStatus scannerStatus) {
        super(new BorderLayout());
        this.api = api;
        this.settings = settings;
        this.persistence = persistence;
        this.scanState = scanState;
        this.taskRegistry = taskRegistry;
        this.findingsRegistry = findingsRegistry;
        this.orchestrator = orchestrator;
        this.threadPool = threadPool;

        this.statisticsPanel = new StatisticsPanel(counters);
        this.runtimeStatusLine = new RuntimeStatusLine(settings, scanState, aiGate, lastPassiveCallbackMillis,
                scannerStatus);
        this.controlBar = new ControlBar(settings, scanState, this);
        this.taskTablePanel = new TaskTablePanel(taskRegistry);
        this.findingsTablePanel = new FindingsTablePanel(findingsRegistry);
        this.consolePane = new ConsolePane(settings.theme());

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(new MainHeader());
        north.add(statisticsPanel);
        north.add(runtimeStatusLine);
        north.add(controlBar);

        JSplitPane center = new JSplitPane(JSplitPane.VERTICAL_SPLIT, taskTablePanel, findingsTablePanel);
        center.setResizeWeight(0.4);
        center.setDividerLocation(220);

        add(north, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(consolePane, BorderLayout.SOUTH);

        // Bridge the console log so ScanState.info/debug/error mirror into the pane.
        scanState.setConsoleSink(consolePane::append);

        refreshTimer = new Timer(REFRESH_MILLIS, e -> refreshSafely());
        refreshTimer.setInitialDelay(500);
        refreshTimer.start();
        refreshNow();
    }

    /** Stop the refresh timer (thread-safe; called from the unloading handler). */
    public void dispose() {
        refreshTimer.stop();
    }

    boolean refreshTimerRunning() {
        return refreshTimer.isRunning();
    }

    private void refreshSafely() {
        try {
            refreshNow();
        } catch (Throwable t) {
            // Log once: this fires every 1.5s, so repeating it would flood the error pane.
            if (!refreshFailureLogged) {
                refreshFailureLogged = true;
                api.logging().logToError("SILENTCHAIN: tab refresh failed", t);
            }
        }
    }

    private void refreshNow() {
        statisticsPanel.refresh();
        runtimeStatusLine.refresh();
        controlBar.refresh();
        taskTablePanel.refresh();
        findingsTablePanel.refresh();
    }

    /** Called after Start/Stop Scanning here, so other views (the settings panel) can follow. */
    public void setOnPassiveChanged(Runnable hook) {
        this.onPassiveChanged = hook != null ? hook : () -> { };
    }

    /** Re-apply the console theme. */
    public void applyTheme() {
        consolePane.applyTheme(settings.theme());
    }

    /** Called whenever a value changes in SILENTCHAIN's settings panel. */
    public void onSettingsChanged() {
        applyTheme();
        refreshNow();
    }

    // ---- ControlBar.Actions -------------------------------------------------

    @Override
    public void onSettings() {
        // Settings live in Burp's own Settings window (registerSettingsPanel).
        api.userInterface().openSettingsWindow();
    }

    @Override
    public void onToggleScanning() {
        boolean now = !settings.passiveEnabled();

        // Consent gate when enabling passive analysis.
        if (now && !DataConsentDialog.ensureConsent(api, persistence, this)) {
            controlBar.refresh();
            scanState.info("SILENTCHAIN: scanning not started (consent declined).");
            return;
        }

        settings.setPassiveEnabled(now);
        persistence.save(settings);
        onPassiveChanged.run();
        controlBar.refresh();
        runtimeStatusLine.refresh();
        scanState.info("SILENTCHAIN: passive scanning " + (now ? "STARTED" : "STOPPED") + ".");
    }

    @Override
    public void onClearCompleted() {
        int removed = taskRegistry.clearCompleted();
        taskTablePanel.refresh();
        scanState.info("SILENTCHAIN: cleared " + removed + " completed task(s).");
    }

    @Override
    public void onCancelAll() {
        int cancelled = orchestrator.cancelAll();
        taskTablePanel.refresh();
        scanState.info("SILENTCHAIN: cancelled " + cancelled + " task(s).");
    }

    @Override
    public void onTogglePause() {
        boolean paused = scanState.togglePaused();
        controlBar.refresh();
        runtimeStatusLine.refresh();
        scanState.info("SILENTCHAIN: tasks " + (paused ? "PAUSED" : "RESUMED") + ".");
    }

    @Override
    public void onExportCsv() {
        Path path = CsvExporter.chooseFile(this);
        if (path == null) {
            scanState.info("SILENTCHAIN: CSV export cancelled.");
            return;
        }
        List<FindingRow> rows = findingsRegistry.snapshot();
        boolean queued = threadPool.submitLocal("CSV export", () -> {
            try {
                CsvExporter.write(path, rows);
                scanState.info("SILENTCHAIN: exported " + rows.size() + " finding(s) to " + path);
            } catch (Exception e) {
                api.logging().logToError("SILENTCHAIN: CSV export to " + path + " failed", e);
                scanState.console("[ERROR] CSV export failed: " + e.getMessage());
            }
        });
        if (!queued) {
            scanState.info("SILENTCHAIN: CSV export not started (busy); try again.");
        }
    }

    @Override
    public void onUpgrade() {
        boolean queued = threadPool.submitLocal("open upgrade page", () -> {
            try {
                if (Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().browse(new URI(UPGRADE_URL));
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to open upgrade page: " + e.getMessage());
            }
        });
        if (!queued) {
            scanState.info("SILENTCHAIN: could not open the page (busy); try again.");
        }
    }
}
