package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.state.Counters;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;

/**
 * Eight live counters in a 4x2 grid (Community silentchain_ai_community.py:466-497).
 *
 * The grid is held in an inner panel that is centered (FlowLayout.CENTER) inside
 * the full-width titled panel, so the statistics block lines up with the other
 * centered top-bar sections instead of stretching edge-to-edge.
 */
public class StatisticsPanel extends JPanel {

    private final Counters counters;

    private final JLabel totalRequests = valueLabel();
    private final JLabel analyzed = valueLabel();
    private final JLabel skippedDup = valueLabel();
    private final JLabel skippedRate = valueLabel();
    private final JLabel skippedLowConf = valueLabel();
    private final JLabel findingsCreated = valueLabel();
    private final JLabel cacheHits = valueLabel();
    private final JLabel errors = valueLabel();

    public StatisticsPanel(Counters counters) {
        this.counters = counters;
        setLayout(new FlowLayout(FlowLayout.CENTER, 0, 0));
        setBorder(BorderFactory.createTitledBorder("Statistics"));
        setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel grid = new JPanel(new GridLayout(2, 4, 28, 4));
        grid.add(cell("Total Requests:", totalRequests));
        grid.add(cell("Analyzed:", analyzed));
        grid.add(cell("Skipped (Duplicate):", skippedDup));
        grid.add(cell("Skipped (Rate Limit):", skippedRate));
        grid.add(cell("Skipped (Low Confidence):", skippedLowConf));
        grid.add(cell("Findings Created:", findingsCreated));
        grid.add(cell("Cache Hits:", cacheHits));
        grid.add(cell("Errors:", errors));
        add(grid);
    }

    @Override
    public Dimension getMaximumSize() {
        // Fill width (so it is centered relative to the whole tab) but keep
        // the natural height — never stretch vertically.
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }

    public void refresh() {
        totalRequests.setText(Long.toString(counters.totalRequests()));
        analyzed.setText(Long.toString(counters.analyzed()));
        skippedDup.setText(Long.toString(counters.skippedDuplicate()));
        skippedRate.setText(Long.toString(counters.skippedRateLimit()));
        skippedLowConf.setText(Long.toString(counters.skippedLowConfidence()));
        findingsCreated.setText(Long.toString(counters.findingsCreated()));
        cacheHits.setText(Long.toString(counters.cacheHits()));
        errors.setText(Long.toString(counters.errors()));
    }

    private JPanel cell(String name, JLabel value) {
        JPanel p = new JPanel();
        p.setLayout(new GridLayout(1, 2, 4, 0));
        JLabel n = new JLabel(name);
        n.setFont(n.getFont().deriveFont(Font.PLAIN));
        p.add(n);
        p.add(value);
        return p;
    }

    private static JLabel valueLabel() {
        JLabel l = new JLabel("0");
        l.setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));
        return l;
    }
}
