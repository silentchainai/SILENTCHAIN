package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Color-text renderer for the Confidence column of the Findings table.
 * Palette ported from Community (silentchain_ai_community.py:2889-2905).
 */
public class ConfidenceCellRenderer extends DefaultTableCellRenderer {

    private static final Color CERTAIN   = new Color(0x00, 0x96, 0x00);
    private static final Color FIRM      = new Color(0x00, 0x64, 0xC8);
    private static final Color TENTATIVE = new Color(0xC8, 0x64, 0x00);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        String confidence = value != null ? value.toString() : "";
        c.setFont(new Font(Font.MONOSPACED, Font.BOLD, c.getFont().getSize()));
        if (!isSelected) {
            c.setForeground(colorFor(confidence));
        }
        return c;
    }

    private Color colorFor(String confidence) {
        return switch (confidence) {
            case "Certain" -> CERTAIN;
            case "Firm" -> FIRM;
            case "Tentative" -> TENTATIVE;
            default -> Color.GRAY;
        };
    }
}
