package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Color-codes the Status column of the Active Tasks table.
 * Palette ported from Community (silentchain_ai_community.py:2835-2862).
 */
public class StatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color CANCELLED = new Color(0x96, 0x00, 0x00);
    private static final Color PAUSED    = new Color(0x96, 0x96, 0x00);
    private static final Color ERROR     = new Color(0xC8, 0x00, 0x00);
    private static final Color SKIPPED   = new Color(0xC8, 0x64, 0x00);
    private static final Color COMPLETED = new Color(0x00, 0x96, 0x00);
    private static final Color RUNNING   = new Color(0x00, 0x64, 0xC8);
    private static final Color QUEUED    = new Color(0x64, 0x64, 0x64);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        String status = value != null ? value.toString() : "";
        c.setFont(c.getFont().deriveFont(Font.BOLD));
        if (!isSelected) {
            c.setForeground(colorFor(status));
        }
        return c;
    }

    private Color colorFor(String status) {
        return switch (status) {
            case "Cancelled" -> CANCELLED;
            case "Paused"    -> PAUSED;
            case "Error"     -> ERROR;
            case "Skipped"   -> SKIPPED;
            case "Completed" -> COMPLETED;
            case "Analyzing", "Waiting" -> RUNNING;
            default -> QUEUED;
        };
    }
}
