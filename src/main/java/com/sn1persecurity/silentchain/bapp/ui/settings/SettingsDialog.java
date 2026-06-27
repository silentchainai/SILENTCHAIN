package com.sn1persecurity.silentchain.bapp.ui.settings;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.SilentchainExtension;
import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Window;

/**
 * Modal Settings dialog (Community silentchain_ai_community.py:1314-1698):
 * 750x650, JTabbedPane of "AI Provider" + "Advanced", Save / Cancel.
 */
public class SettingsDialog {

    private final MontoyaApi api;
    private final Settings settings;
    private final SettingsPersistence persistence;
    private final Runnable onSaved;

    private final JDialog dialog;
    private final AiProviderTab aiTab;
    private final AdvancedTab advancedTab;

    public SettingsDialog(Window parent,
                          MontoyaApi api,
                          Settings settings,
                          SettingsPersistence persistence,
                          AiDispatcher dispatcher,
                          ScanState scanState,
                          TaskRegistry taskRegistry,
                          Runnable onSaved) {
        this.api = api;
        this.settings = settings;
        this.persistence = persistence;
        this.onSaved = onSaved;

        this.aiTab = new AiProviderTab(settings, dispatcher);
        this.advancedTab = new AdvancedTab(settings, scanState, taskRegistry);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("AI Provider", aiTab);
        tabs.addTab("Advanced", advancedTab);

        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> onSave());
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> onCancel());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        buttons.add(saveBtn);
        buttons.add(cancelBtn);

        dialog = new JDialog(parent, SilentchainExtension.EXTENSION_NAME + " Settings");
        dialog.setModal(true);
        dialog.getContentPane().setLayout(new BorderLayout());
        dialog.getContentPane().add(tabs, BorderLayout.CENTER);
        dialog.getContentPane().add(buttons, BorderLayout.SOUTH);
        dialog.setSize(750, 650);
        dialog.setLocationRelativeTo(parent);
    }

    /** Reload both tabs from the live settings and show the modal. */
    public void showDialog() {
        aiTab.load();
        advancedTab.load();
        dialog.setVisible(true);
    }

    private void onSave() {
        aiTab.store();
        advancedTab.store();

        // Consent gate: if passive was just enabled and not yet acknowledged.
        if (settings.passiveEnabled() && !DataConsentDialog.ensureConsent(api, persistence)) {
            settings.setPassiveEnabled(false);
            advancedTab.setPassiveSelected(false);
        }

        persistence.save(settings);
        if (onSaved != null) {
            onSaved.run();
        }
        dialog.setVisible(false);
    }

    private void onCancel() {
        // Revert any in-memory mutations made by Test Connection / Refresh.
        persistence.load(settings);
        dialog.setVisible(false);
    }
}
