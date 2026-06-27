package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

/**
 * Theme-aware scrolling console (Community silentchain_ai_community.py:623-640,
 * 693-702). Fed by {@link com.sn1persecurity.silentchain.bapp.state.ScanState}
 * via {@link #append(String)} (which marshals to the EDT).
 */
public class ConsolePane extends JPanel {

    private static final int MAX_CHARS = 200_000;

    private final JTextArea area = new JTextArea(10, 80);

    public ConsolePane(Settings.ThemeChoice theme) {
        super(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Console"));

        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));

        JScrollPane scroll = new JScrollPane(area,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.setPreferredSize(new Dimension(100, 180));
        add(scroll, BorderLayout.CENTER);

        applyTheme(theme);
    }

    /** Thread-safe: may be called from any thread. */
    public void append(String line) {
        SwingUtilities.invokeLater(() -> {
            area.append(line + "\n");
            int len = area.getDocument().getLength();
            if (len > MAX_CHARS) {
                try {
                    area.getDocument().remove(0, len - MAX_CHARS);
                } catch (Exception ignored) {
                    // ignore truncation failures
                }
            }
            area.setCaretPosition(area.getDocument().getLength());
        });
    }

    public void applyTheme(Settings.ThemeChoice theme) {
        SwingUtilities.invokeLater(() -> {
            area.setBackground(Theme.consoleBackground(theme));
            area.setForeground(Theme.consoleForeground(theme));
            area.setCaretColor(Theme.consoleForeground(theme));
        });
    }
}
