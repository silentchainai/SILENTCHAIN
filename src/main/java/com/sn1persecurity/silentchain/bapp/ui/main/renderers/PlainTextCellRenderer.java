package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import javax.swing.table.DefaultTableCellRenderer;

/**
 * Table cell renderer that never interprets cell text as HTML. Swing renders a
 * JLabel whose text starts with "&lt;html&gt;" as HTML (including remote images), and
 * finding titles come from the AI while URLs come from the target, so both are
 * untrusted. Every SILENTCHAIN table renderer extends this.
 */
public class PlainTextCellRenderer extends DefaultTableCellRenderer {

    public PlainTextCellRenderer() {
        putClientProperty("html.disable", Boolean.TRUE);
    }
}
