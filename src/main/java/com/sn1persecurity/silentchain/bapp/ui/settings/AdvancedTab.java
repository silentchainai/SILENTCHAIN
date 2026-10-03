package com.sn1persecurity.silentchain.bapp.ui.settings;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.diag.TaskDiagnosticsReport;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Advanced settings tab, shown inside Burp's Settings window: Community items
 * (silentchain_ai_community.py:1507-1623) plus the safety rails. Values apply
 * as they are committed; there is no Save or Cancel.
 */
public class AdvancedTab extends JPanel {

    private final MontoyaApi api;
    private final Settings settings;
    private final SettingsPersistence persistence;
    private final ScanState scanState;
    private final Runnable onChanged;

    private final JCheckBox passiveScanning = new JCheckBox("Enable automatic passive scanning");
    private final JComboBox<String> consoleTheme = new JComboBox<>(new String[]{"Light", "Dark"});
    private final JCheckBox verboseLogging = new JCheckBox("Verbose logging");
    private final JTextField requestTimeout = new JTextField(8);

    private final JCheckBox sanitizer = new JCheckBox("Redact secrets / PII before sending to AI");
    private final JTextField maxResponseKb = new JTextField(8);
    private final JTextField hostRpm = new JTextField(8);
    private final JTextField dedupMinutes = new JTextField(8);

    /** True while fields are being filled programmatically, so listeners do not commit. */
    private boolean loading;

    public AdvancedTab(MontoyaApi api, Settings settings, SettingsPersistence persistence,
                       ScanState scanState, TaskRegistry taskRegistry, Runnable onChanged) {
        this.api = api;
        this.settings = settings;
        this.persistence = persistence;
        this.scanState = scanState;
        this.onChanged = onChanged;

        setLayout(new GridBagLayout());

        int row = 0;
        addRow(row++, "Passive Scanning:", passiveScanning);
        addRow(row++, "Console Theme:", consoleTheme);
        addRow(row++, "Verbose Logging:", verboseLogging);
        addRow(row++, "Third-party AI timeout (s):", requestTimeout);

        JButton diagBtn = new JButton("Run Task Diagnostics");
        diagBtn.addActionListener(e -> scanState.info(TaskDiagnosticsReport.generate(taskRegistry)));
        addRow(row++, "", diagBtn);

        addSection(row++, "Safety Rails (SILENTCHAIN Community Edition)");
        addRow(row++, "Sanitizer:", sanitizer);
        addRow(row++, "Scope:", new JLabel("Passive analysis covers in-scope targets only (Target > Scope)."));
        addRow(row++, "Max Response Size (KB):", maxResponseKb);
        addRow(row++, "Per-host Requests/Minute:", hostRpm);
        addRow(row++, "URL Dedup Window (min):", dedupMinutes);

        addUpgradeNotice(row++);

        passiveScanning.addItemListener(e -> onPassiveToggled());
        consoleTheme.addActionListener(e -> commitToggles());
        verboseLogging.addItemListener(e -> commitToggles());
        sanitizer.addItemListener(e -> commitToggles());
        CommitListeners.onCommit(requestTimeout, this::commitNumbers);
        CommitListeners.onCommit(maxResponseKb, this::commitNumbers);
        CommitListeners.onCommit(hostRpm, this::commitNumbers);
        CommitListeners.onCommit(dedupMinutes, this::commitNumbers);
    }

    // ---- Load / commit ------------------------------------------------------

    /** Fill every field from the live settings (called each time the panel is shown). */
    public void load() {
        loading = true;
        try {
            passiveScanning.setSelected(settings.passiveEnabled());
            consoleTheme.setSelectedItem(settings.theme() == Settings.ThemeChoice.DARK ? "Dark" : "Light");
            verboseLogging.setSelected(settings.verbose());
            sanitizer.setSelected(settings.sanitizerEnabled());
            showNumbers();
        } finally {
            loading = false;
        }
    }

    private void showNumbers() {
        requestTimeout.setText(Integer.toString(settings.requestTimeoutSeconds()));
        maxResponseKb.setText(Integer.toString(settings.maxResponseBytes() / 1024));
        hostRpm.setText(Integer.toString(settings.hostRequestsPerMinute()));
        dedupMinutes.setText(Long.toString(settings.urlDedupTtlMillis() / 60_000L));
    }

    private void onPassiveToggled() {
        if (loading) {
            return;
        }
        boolean wanted = passiveScanning.isSelected();
        if (wanted && !DataConsentDialog.ensureConsent(api, persistence, passiveScanning)) {
            loading = true;
            try {
                passiveScanning.setSelected(false);
            } finally {
                loading = false;
            }
            scanState.info("SILENTCHAIN: scanning not started (consent declined).");
            return;
        }
        if (wanted != settings.passiveEnabled()) {
            settings.setPassiveEnabled(wanted);
            save();
            scanState.info("SILENTCHAIN: passive scanning " + (wanted ? "STARTED" : "STOPPED") + ".");
        }
    }

    private void commitToggles() {
        if (loading) {
            return;
        }
        settings.setTheme("Dark".equals(consoleTheme.getSelectedItem())
                ? Settings.ThemeChoice.DARK : Settings.ThemeChoice.LIGHT);
        settings.setVerbose(verboseLogging.isSelected());
        settings.setSanitizerEnabled(sanitizer.isSelected());
        save();
    }

    private void commitNumbers() {
        if (loading) {
            return;
        }
        settings.setRequestTimeoutSeconds(
                CommitListeners.parseInt(requestTimeout.getText(), settings.requestTimeoutSeconds()));
        settings.setMaxResponseBytes(
                CommitListeners.parseInt(maxResponseKb.getText(), settings.maxResponseBytes() / 1024) * 1024);
        settings.setHostRequestsPerMinute(
                CommitListeners.parseInt(hostRpm.getText(), settings.hostRequestsPerMinute()));
        settings.setUrlDedupTtlMillis(CommitListeners.parseInt(dedupMinutes.getText(),
                (int) (settings.urlDedupTtlMillis() / 60_000L)) * 60_000L);
        loading = true;
        try {
            showNumbers();   // show the clamped values actually in effect
        } finally {
            loading = false;
        }
        save();
    }

    private void save() {
        persistence.save(settings);
        onChanged.run();
    }

    // ---- Layout helpers -----------------------------------------------------

    private void addRow(int row, String label, JComponent field) {
        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = row;
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(5, 8, 5, 8);
        add(new JLabel(label), lc);

        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1; fc.gridy = row;
        fc.anchor = GridBagConstraints.WEST;
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(5, 0, 5, 8);
        add(field, fc);
    }

    private void addSection(int row, String title) {
        JLabel label = new JLabel(title);
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, label.getForeground()),
                BorderFactory.createEmptyBorder(6, 0, 2, 0)));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        c.insets = new Insets(12, 8, 4, 8);
        add(label, c);
    }

    private void addUpgradeNotice(int row) {
        JTextArea notice = new JTextArea(
                "COMMUNITY-TIER (free) - Passive Analysis Only\n" +
                "SILENTCHAIN Pro adds: active verification, advanced payload libraries,\n" +
                "WAF detection & evasion, out-of-band (OOB) testing, and priority support.\n" +
                "Visit https://silentchain.ai for more information.");
        notice.setEditable(false);
        notice.setOpaque(false);
        notice.setBorder(BorderFactory.createTitledBorder("Upgrade"));

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0; c.weighty = 1.0;
        c.insets = new Insets(12, 8, 8, 8);
        add(notice, c);
    }
}
