package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import javax.swing.DefaultListCellRenderer;

/**
 * List/combo renderer that never interprets item text as HTML. Model names come
 * from the AI provider's API; rendered as HTML, an image tag would make the JVM
 * fetch a URL outside Burp's networking.
 */
public class PlainTextListCellRenderer extends DefaultListCellRenderer {

    public PlainTextListCellRenderer() {
        putClientProperty("html.disable", Boolean.TRUE);
    }
}
