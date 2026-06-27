package com.sn1persecurity.silentchain.bapp.state;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * A single analysis task shown in the Active Tasks table
 * (Community columns: Timestamp, Type, URL, Status, Duration).
 */
public class ScanTask {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String timestamp;
    private final String type;
    private final String url;
    private final long startMillis;

    private volatile TaskStatus status = TaskStatus.QUEUED;
    private volatile long endMillis = 0L;

    public ScanTask(String type, String url) {
        this.timestamp = LocalDateTime.now().format(TS);
        this.type = type;
        this.url = url;
        this.startMillis = System.currentTimeMillis();
    }

    public String timestamp() { return timestamp; }
    public String type()      { return type; }
    public String url()       { return url; }

    public TaskStatus status() { return status; }

    public void setStatus(TaskStatus newStatus) {
        this.status = newStatus;
        if (newStatus.isTerminal() && endMillis == 0L) {
            this.endMillis = System.currentTimeMillis();
        }
    }

    /** Human-readable duration, e.g. "1.8s" or "—" while still queued. */
    public String durationLabel() {
        long end = endMillis != 0L ? endMillis : System.currentTimeMillis();
        long ms = Math.max(0L, end - startMillis);
        if (status == TaskStatus.QUEUED) {
            return "—";
        }
        return String.format("%.1fs", ms / 1000.0);
    }
}
