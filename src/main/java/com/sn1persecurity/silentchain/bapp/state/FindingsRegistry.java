package com.sn1persecurity.silentchain.bapp.state;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe registry of findings backing the Findings table and the
 * "Total: X | High: X | ..." stats line. Newest finding is shown first.
 *
 * This is SEPARATE from Burp's AuditIssue site map: findings appear in BOTH
 * places (our table for the Community-style UX + Burp Scanner Issues for the
 * standard Burp workflow).
 */
public class FindingsRegistry {

    private final CopyOnWriteArrayList<FindingRow> findings = new CopyOnWriteArrayList<>();

    public void add(FindingRow row) {
        findings.add(0, row);
    }

    public List<FindingRow> snapshot() {
        return new ArrayList<>(findings);
    }

    public int total() {
        return findings.size();
    }

    public int countBySeverity(String severity) {
        int n = 0;
        for (FindingRow f : findings) {
            if (f.severity() != null && f.severity().equalsIgnoreCase(severity)) {
                n++;
            }
        }
        return n;
    }

    public int high()   { return countBySeverity("High"); }
    public int medium() { return countBySeverity("Medium"); }
    public int low()    { return countBySeverity("Low"); }

    /** Information findings count (accepts "Information" or "Info"). */
    public int info() {
        int n = 0;
        for (FindingRow f : findings) {
            String s = f.severity();
            if (s != null && (s.equalsIgnoreCase("Information") || s.equalsIgnoreCase("Info"))) {
                n++;
            }
        }
        return n;
    }

    public void clear() {
        findings.clear();
    }
}
