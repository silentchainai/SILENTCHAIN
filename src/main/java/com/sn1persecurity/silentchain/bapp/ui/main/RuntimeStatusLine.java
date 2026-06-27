package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.ScanState;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;

/**
 * Single-line runtime status (Community silentchain_ai_community.py:500-505):
 * "Provider: X | Model: Y | Scanning: Active | ...".
 */
public class RuntimeStatusLine extends JPanel {

    private final Settings settings;
    private final ScanState scanState;
    private final JLabel label = new JLabel(" ");

    public RuntimeStatusLine(Settings settings, ScanState scanState) {
        this.settings = settings;
        this.scanState = scanState;
        setBorder(BorderFactory.createTitledBorder("Runtime Status"));
        setLayout(new FlowLayout(FlowLayout.CENTER, 4, 2));
        setAlignmentX(Component.CENTER_ALIGNMENT);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        add(label);
    }

    public void refresh() {
        String provider = settings.provider().displayName();
        String model = settings.model().isBlank() ? "(default)" : settings.model();
        String scanning;
        if (!settings.passiveEnabled()) {
            scanning = "Stopped";
        } else if (scanState.isPaused()) {
            scanning = "Paused";
        } else {
            scanning = "Active";
        }
        label.setText(String.format("Provider: %s | Model: %s | Scanning: %s", provider, model, scanning));
    }
}
