package com.sn1persecurity.silentchain.bapp.ui.main;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.export.CsvExporter;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.net.URI;

/**
 * Root SILENTCHAIN tab — assembles the Community-style single-tab layout and
 * drives a 1.5s refresh timer over the live state.
 *
 * Layout:
 *   NORTH  : header + statistics + runtime status + control bar
 *   CENTER : vertical split — active tasks (top) / findings (bottom)
 *   SOUTH  : console pane
 */
public class MainTab extends JPanel implements ControlBar.Actions {

    private static final String UPGRADE_URL = "https://silentchain.ai/?referral=silentchain_bapp";

    private final MontoyaApi api;
    private final Settings settings;
    private final SettingsPersistence persistence;
    private final ScanState scanState;
    private final TaskRegistry taskRegistry;
    private final FindingsRegistry findingsRegistry;
    private Runnable settingsOpener;

    private final StatisticsPanel statisticsPanel;
    private final RuntimeStatusLine runtimeStatusLine;
    private final ControlBar controlBar;
    private final TaskTablePanel taskTablePanel;
    private final FindingsTablePanel findingsTablePanel;
    private final ConsolePane consolePane;

    public MainTab(MontoyaApi api,
                   Settings settings,
                   SettingsPersistence persistence,
                   ScanState scanState,
                   Counters counters,
                   TaskRegistry taskRegistry,
                   FindingsRegistry findingsRegistry) {
        super(new BorderLayout());
        this.api = api;
        this.settings = settings;
        this.persistence = persistence;
        this.scanState = scanState;
        this.taskRegistry = taskRegistry;
        this.findingsRegistry = findingsRegistry;

        this.statisticsPanel = new StatisticsPanel(counters);
        this.runtimeStatusLine = new RuntimeStatusLine(settings, scanState);
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

        startRefreshTimer();
        refreshNow();
    }

    private void startRefreshTimer() {
        Timer timer = new Timer(1500, e -> refreshNow());
        timer.setInitialDelay(500);
        timer.start();
    }

    private void refreshNow() {
        statisticsPanel.refresh();
        runtimeStatusLine.refresh();
        controlBar.refresh();
        taskTablePanel.refresh();
        findingsTablePanel.refresh();
    }

    /** Re-apply the console theme (called after a Settings save changes it). */
    public void applyTheme() {
        consolePane.applyTheme(settings.theme());
    }

    /** Wire the Settings button to open the modal dialog (set post-construction). */
    public void setSettingsOpener(Runnable opener) {
        this.settingsOpener = opener;
    }

    /** Called after the Settings dialog saves: re-theme + refresh immediately. */
    public void onSettingsSaved() {
        applyTheme();
        refreshNow();
    }

    // ---- ControlBar.Actions -------------------------------------------------

    @Override
    public void onSettings() {
        if (settingsOpener != null) {
            settingsOpener.run();
        }
    }

    @Override
    public void onToggleScanning() {
        boolean now = !settings.passiveEnabled();

        // Consent gate when enabling passive analysis.
        if (now && !DataConsentDialog.ensureConsent(api, persistence)) {
            controlBar.refresh();
            scanState.info("SILENTCHAIN: scanning not started (consent declined).");
            return;
        }

        settings.setPassiveEnabled(now);
        persistence.save(settings);
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
        int cancelled = taskRegistry.cancelAll();
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
        String path = CsvExporter.export(this, findingsRegistry);
        if (path != null) {
            scanState.info("SILENTCHAIN: exported findings to " + path);
        } else {
            scanState.info("SILENTCHAIN: CSV export cancelled or failed.");
        }
    }

    @Override
    public void onUpgrade() {
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(new URI(UPGRADE_URL));
            }
        } catch (Throwable t) {
            api.logging().logToError("Failed to open upgrade page: " + t.getMessage());
        }
    }

    /** Convenience for registration. */
    public JComponent component() {
        return this;
    }

    @SuppressWarnings("unused")
    private static Component noop() {
        return null;
    }
}
