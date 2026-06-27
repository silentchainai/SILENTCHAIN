package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Color-background renderer for the Severity column of the Findings table.
 * Palette ported from Community (silentchain_ai_community.py:2864-2887).
 */
public class SeverityCellRenderer extends DefaultTableCellRenderer {

    private static final Color HIGH_BG   = new Color(0xC8, 0x00, 0x00);
    private static final Color MEDIUM_BG = new Color(0xFF, 0x8C, 0x00);
    private static final Color LOW_BG    = new Color(0xFF, 0xC8, 0x00);
    private static final Color INFO_BG   = new Color(0x00, 0x64, 0xC8);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        String severity = value != null ? value.toString() : "";
        c.setHorizontalAlignment(SwingConstants.CENTER);
        c.setFont(new Font(Font.MONOSPACED, Font.BOLD, c.getFont().getSize()));

        Color bg = backgroundFor(severity);
        if (bg != null) {
            c.setBackground(bg);
            c.setForeground(textColorFor(severity));
            c.setOpaque(true);
        } else {
            c.setOpaque(false);
        }
        return c;
    }

    private Color backgroundFor(String severity) {
        return switch (severity) {
            case "High" -> HIGH_BG;
            case "Medium" -> MEDIUM_BG;
            case "Low" -> LOW_BG;
            case "Information", "Info" -> INFO_BG;
            default -> null;
        };
    }

    private Color textColorFor(String severity) {
        // Low (yellow) uses black text for contrast; everything else white.
        return "Low".equals(severity) ? Color.BLACK : Color.WHITE;
    }
}
