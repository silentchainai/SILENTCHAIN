package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.ScanState;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.function.LongSupplier;

/**
 * Single-line runtime status (Community silentchain_ai_community.py:500-505):
 * "Provider: X | Model: Y | Scanning: Active | AI: Enabled", plus a hint when
 * passive analysis is on but Burp has not called the passive scan check yet
 * (no live audit task, or nothing in scope).
 */
public class RuntimeStatusLine extends JPanel {

    private final Settings settings;
    private final ScanState scanState;
    private final AiGate aiGate;
    private final LongSupplier lastPassiveCallbackMillis;
    private final JLabel label = new JLabel(" ");

    public RuntimeStatusLine(Settings settings, ScanState scanState, AiGate aiGate,
                             LongSupplier lastPassiveCallbackMillis) {
        this.settings = settings;
        this.scanState = scanState;
        this.aiGate = aiGate;
        this.lastPassiveCallbackMillis = lastPassiveCallbackMillis;
        setBorder(BorderFactory.createTitledBorder("Runtime Status"));
        setLayout(new FlowLayout(FlowLayout.CENTER, 4, 2));
        setAlignmentX(Component.CENTER_ALIGNMENT);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        label.putClientProperty("html.disable", Boolean.TRUE);
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
        String ai = aiGate.isEnabled() ? "Enabled" : "Disabled (tick 'Use AI' in Extensions > Installed)";
        StringBuilder text = new StringBuilder(String.format(
                "Provider: %s | Model: %s | Scanning: %s | AI: %s", provider, model, scanning, ai));
        if (settings.passiveEnabled() && lastPassiveCallbackMillis.getAsLong() == 0L) {
            text.append(" | Waiting for Burp Scanner (needs a live audit task)");
        }
        label.setText(text.toString());
    }
}
