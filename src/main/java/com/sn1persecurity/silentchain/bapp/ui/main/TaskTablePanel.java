package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.ui.main.renderers.StatusCellRenderer;

import javax.swing.BorderFactory;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JPanel;

/**
 * Active Tasks table (Community silentchain_ai_community.py:554-579):
 * Timestamp, Type, URL, Status, Duration.
 */
public class TaskTablePanel extends JPanel {

    private final TaskRegistry registry;
    private final TaskTableModel model = new TaskTableModel();
    private final JTable table = new JTable(model);

    public TaskTablePanel(TaskRegistry registry) {
        super(new BorderLayout());
        this.registry = registry;
        setBorder(BorderFactory.createTitledBorder("Active Tasks"));

        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(3).setCellRenderer(new StatusCellRenderer());
        setPreferredWidth(0, 150);
        setPreferredWidth(1, 120);
        setPreferredWidth(2, 300);
        setPreferredWidth(3, 130);
        setPreferredWidth(4, 80);

        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    public void refresh() {
        model.setRows(registry.snapshot());
    }

    private void setPreferredWidth(int col, int width) {
        TableColumn c = table.getColumnModel().getColumn(col);
        c.setPreferredWidth(width);
    }

    private static class TaskTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Timestamp", "Type", "URL", "Status", "Duration"};
        private List<ScanTask> rows = new ArrayList<>();

        void setRows(List<ScanTask> newRows) {
            this.rows = newRows;
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            ScanTask t = rows.get(row);
            return switch (col) {
                case 0 -> t.timestamp();
                case 1 -> t.type();
                case 2 -> t.url();
                case 3 -> t.status().label();
                case 4 -> t.durationLabel();
                default -> "";
            };
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }
    }
}
