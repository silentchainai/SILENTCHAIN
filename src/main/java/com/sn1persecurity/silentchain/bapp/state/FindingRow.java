package com.sn1persecurity.silentchain.bapp.state;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * A findings-table row (Community columns: Discovered At, URL, Finding,
 * Severity, Confidence).
 */
public class FindingRow {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String discoveredAt;
    private final String url;
    private final String finding;
    private final String severity;
    private final String confidence;

    public FindingRow(String url, String finding, String severity, String confidence) {
        this.discoveredAt = LocalDateTime.now().format(TS);
        this.url = url;
        this.finding = finding;
        this.severity = severity;
        this.confidence = confidence;
    }

    public String discoveredAt() { return discoveredAt; }
    public String url()          { return url; }
    public String finding()      { return finding; }
    public String severity()     { return severity; }
    public String confidence()   { return confidence; }
}
