package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.SilentchainExtension;
import com.sn1persecurity.silentchain.bapp.ui.theme.Theme;

import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;

/**
 * Title + tagline header (Community silentchain_ai_community.py:449,456).
 *
 * Fills the full tab width (see {@link #getMaximumSize()}) and centers both
 * labels horizontally so it aligns with the other top-bar sections.
 */
public class MainHeader extends JPanel {

    public MainHeader() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(new EmptyBorder(8, 10, 4, 10));
        setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel title = new JLabel(SilentchainExtension.EXTENSION_NAME
                + " v" + SilentchainExtension.EXTENSION_VERSION);
        title.setFont(new Font(Font.MONOSPACED, Font.BOLD, 16));
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setHorizontalAlignment(JLabel.CENTER);

        JLabel tagline = new JLabel("AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite");
        tagline.setFont(new Font(Font.DIALOG, Font.ITALIC, 12));
        tagline.setForeground(Theme.ACCENT_ORANGE);
        tagline.setAlignmentX(Component.CENTER_ALIGNMENT);
        tagline.setHorizontalAlignment(JLabel.CENTER);

        add(title);
        add(tagline);
    }

    @Override
    public Dimension getMaximumSize() {
        // Fill width so BoxLayout centers the labels across the whole tab,
        // but keep the natural height (don't stretch vertically).
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
