package com.sn1persecurity.silentchain.bapp.ui.main.renderers;

import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A cell whose text starts with "&lt;html&gt;" must render as plain text: Swing would
 * otherwise parse it as HTML (and fetch remote images) for AI- or target-supplied
 * values.
 */
class PlainTextCellRendererTest {

    private static final String HOSTILE = "<html><img src='http://127.0.0.1:1/x'>owned</html>";

    private static JComponent render(TableCellRenderer renderer) {
        JTable table = new JTable(1, 1);
        return (JComponent) renderer.getTableCellRendererComponent(table, HOSTILE, false, false, 0, 0);
    }

    @Test
    void htmlIsNotInterpreted() {
        for (TableCellRenderer r : new TableCellRenderer[]{
                new PlainTextCellRenderer(), new SeverityCellRenderer(),
                new StatusCellRenderer(), new ConfidenceCellRenderer()}) {
            assertNull(render(r).getClientProperty(BasicHTML.propertyKey), r.getClass().getSimpleName());
        }
    }

    /** Control: a stock renderer DOES build an HTML view for the same value. */
    @Test
    void stockRendererWouldInterpretIt() {
        assertNotNull(render(new DefaultTableCellRenderer()).getClientProperty(BasicHTML.propertyKey));
    }
}
