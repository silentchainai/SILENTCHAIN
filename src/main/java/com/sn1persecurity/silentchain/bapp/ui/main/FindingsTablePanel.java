package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.state.FindingRow;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.ui.main.renderers.ConfidenceCellRenderer;
import com.sn1persecurity.silentchain.bapp.ui.main.renderers.SeverityCellRenderer;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

/**
 * Findings stats line + Findings table
 * (Community silentchain_ai_community.py:582-615):
 * Discovered At, URL, Finding, Severity, Confidence.
 */
public class FindingsTablePanel extends JPanel {

    private final FindingsRegistry registry;
    private final FindingsTableModel model = new FindingsTableModel();
    private final JTable table = new JTable(model);
    private final JLabel statsLine = new JLabel("Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0");

    public FindingsTablePanel(FindingsRegistry registry) {
        super(new BorderLayout());
        this.registry = registry;
        setBorder(BorderFactory.createTitledBorder("Findings"));

        statsLine.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
        statsLine.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));

        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(3).setCellRenderer(new SeverityCellRenderer());
        table.getColumnModel().getColumn(4).setCellRenderer(new ConfidenceCellRenderer());
        setPreferredWidth(0, 150);
        setPreferredWidth(1, 300);
        setPreferredWidth(2, 250);
        setPreferredWidth(3, 80);
        setPreferredWidth(4, 90);

        add(statsLine, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    public void refresh() {
        model.setRows(registry.snapshot());
        statsLine.setText(String.format("Total: %d | High: %d | Medium: %d | Low: %d | Info: %d",
                registry.total(), registry.high(), registry.medium(), registry.low(), registry.info()));
    }

    private void setPreferredWidth(int col, int width) {
        TableColumn c = table.getColumnModel().getColumn(col);
        c.setPreferredWidth(width);
    }

    private static class FindingsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Discovered At", "URL", "Finding", "Severity", "Confidence"};
        private List<FindingRow> rows = new ArrayList<>();

        void setRows(List<FindingRow> newRows) {
            this.rows = newRows;
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            FindingRow f = rows.get(row);
            return switch (col) {
                case 0 -> f.discoveredAt();
                case 1 -> f.url();
                case 2 -> f.finding();
                case 3 -> f.severity();
                case 4 -> f.confidence();
                default -> "";
            };
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }
    }
}
