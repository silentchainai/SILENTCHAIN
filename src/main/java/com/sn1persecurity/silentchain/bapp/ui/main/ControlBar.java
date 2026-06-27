package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;

import javax.swing.JButton;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;

/**
 * Row of control buttons (Community silentchain_ai_community.py:508-545).
 */
public class ControlBar extends JPanel {

    /** Button action callbacks, implemented by {@link MainTab}. */
    public interface Actions {
        void onSettings();
        void onToggleScanning();
        void onClearCompleted();
        void onCancelAll();
        void onTogglePause();
        void onExportCsv();
        void onUpgrade();
    }

    private final Settings settings;
    private final ScanState scanState;

    private final JButton scanningBtn = new JButton("Start Scanning");
    private final JButton pauseBtn = new JButton("Pause All Tasks");

    public ControlBar(Settings settings, ScanState scanState, Actions actions) {
        this.settings = settings;
        this.scanState = scanState;

        setLayout(new FlowLayout(FlowLayout.CENTER, 6, 4));
        setAlignmentX(Component.CENTER_ALIGNMENT);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));

        JButton settingsBtn = colored(new JButton("Settings"), Theme.ACCENT_BLUE, Color.WHITE);
        settingsBtn.addActionListener(e -> actions.onSettings());

        scanningBtn.addActionListener(e -> actions.onToggleScanning());

        JButton clearBtn = new JButton("Clear Completed");
        clearBtn.addActionListener(e -> actions.onClearCompleted());

        JButton cancelBtn = new JButton("Cancel All Tasks");
        cancelBtn.addActionListener(e -> actions.onCancelAll());

        pauseBtn.addActionListener(e -> actions.onTogglePause());

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> actions.onExportCsv());

        JButton upgradeBtn = colored(new JButton("Upgrade to Professional"), Theme.ACCENT_ORANGE, Color.WHITE);
        upgradeBtn.addActionListener(e -> actions.onUpgrade());

        add(settingsBtn);
        add(scanningBtn);
        add(clearBtn);
        add(cancelBtn);
        add(pauseBtn);
        add(exportBtn);
        add(upgradeBtn);

        refresh();
    }

    public void refresh() {
        boolean scanning = settings.passiveEnabled();
        if (scanning) {
            scanningBtn.setText("Stop Scanning");
            style(scanningBtn, Theme.SCAN_GREEN, Color.WHITE);
        } else {
            scanningBtn.setText("Start Scanning");
            style(scanningBtn, Theme.SCAN_RED, Color.WHITE);
        }
        pauseBtn.setText(scanState.isPaused() ? "Resume All Tasks" : "Pause All Tasks");
    }

    private JButton colored(JButton b, Color bg, Color fg) {
        style(b, bg, fg);
        return b;
    }

    private void style(JButton b, Color bg, Color fg) {
        b.setBackground(bg);
        b.setForeground(fg);
        b.setOpaque(true);
        b.setBorderPainted(false);
    }
}
