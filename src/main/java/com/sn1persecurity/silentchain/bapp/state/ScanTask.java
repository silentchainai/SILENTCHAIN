package com.sn1persecurity.silentchain.bapp.state;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A single analysis task shown in the Active Tasks table
 * (Community columns: Timestamp, Type, URL, Status, Duration).
 *
 * Status transitions are compare-and-set, and a terminal status is final: a
 * user's Cancel can never be overwritten by a worker that later finishes, and
 * {@link #finish} is a safe "make sure this task ends" call from a finally block.
 */
public class ScanTask {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String timestamp;
    private final String type;
    private final String url;

    private final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.QUEUED);
    private volatile long startedMillis = 0L;
    private volatile long endMillis = 0L;

    public ScanTask(String type, String url) {
        this.timestamp = LocalDateTime.now().format(TS);
        this.type = type;
        this.url = url;
    }

    public String timestamp() { return timestamp; }
    public String type()      { return type; }
    public String url()       { return url; }

    public TaskStatus status() { return status.get(); }

    public boolean isCancelled() { return status.get() == TaskStatus.CANCELLED; }

    /** QUEUED or PAUSED -> ANALYZING. False if the task was cancelled (or already started). */
    public boolean tryStart() {
        if (status.compareAndSet(TaskStatus.QUEUED, TaskStatus.ANALYZING)
                || status.compareAndSet(TaskStatus.PAUSED, TaskStatus.ANALYZING)) {
            startedMillis = System.currentTimeMillis();
            return true;
        }
        return false;
    }

    /** QUEUED -> PAUSED (the worker found tasks paused before starting it). True if now PAUSED. */
    public boolean park() {
        return status.compareAndSet(TaskStatus.QUEUED, TaskStatus.PAUSED)
                || status.get() == TaskStatus.PAUSED;
    }

    /**
     * Move to a terminal status unless the task already has one. Returns true if
     * this call ended the task.
     */
    public boolean finish(TaskStatus terminal) {
        if (!terminal.isTerminal()) {
            throw new IllegalArgumentException("not a terminal status: " + terminal);
        }
        while (true) {
            TaskStatus current = status.get();
            if (current.isTerminal()) {
                return false;
            }
            if (status.compareAndSet(current, terminal)) {
                endMillis = System.currentTimeMillis();
                return true;
            }
        }
    }

    /** Human-readable analysis duration, e.g. "1.8s", or "-" until analysis starts. */
    public String durationLabel() {
        long started = startedMillis;
        if (started == 0L) {
            return "-";
        }
        long end = endMillis != 0L ? endMillis : System.currentTimeMillis();
        return String.format("%.1fs", Math.max(0L, end - started) / 1000.0);
    }
}
