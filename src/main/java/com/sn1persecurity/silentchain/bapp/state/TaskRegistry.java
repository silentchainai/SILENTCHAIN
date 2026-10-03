package com.sn1persecurity.silentchain.bapp.state;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe registry of analysis tasks backing the Active Tasks table.
 * Newest task is shown first. Capped so a long session cannot grow it without
 * bound: the oldest finished tasks are dropped first; active tasks never are.
 */
public class TaskRegistry {

    static final int MAX_TASKS = 1_000;

    private final CopyOnWriteArrayList<ScanTask> tasks = new CopyOnWriteArrayList<>();

    public ScanTask newTask(String type, String url) {
        ScanTask task = new ScanTask(type, url);
        tasks.add(0, task);
        evictFinishedOverCap();
        return task;
    }

    /** Remove all terminal (completed / skipped / error / cancelled) tasks. */
    public int clearCompleted() {
        List<ScanTask> done = new ArrayList<>();
        for (ScanTask t : tasks) {
            if (t.status().isTerminal()) {
                done.add(t);
            }
        }
        tasks.removeAll(done);
        return done.size();
    }

    /** Cancel every non-terminal task. Returns the number cancelled. */
    public int cancelAll() {
        int n = 0;
        for (ScanTask t : tasks) {
            if (t.finish(TaskStatus.CANCELLED)) {
                n++;
            }
        }
        return n;
    }

    public List<ScanTask> snapshot() {
        return new ArrayList<>(tasks);
    }

    public int size() {
        return tasks.size();
    }

    private void evictFinishedOverCap() {
        int excess = tasks.size() - MAX_TASKS;
        if (excess <= 0) {
            return;
        }
        List<ScanTask> evict = new ArrayList<>();
        List<ScanTask> snapshot = snapshot();
        for (int i = snapshot.size() - 1; i >= 0 && evict.size() < excess; i--) {
            ScanTask t = snapshot.get(i);
            if (t.status().isTerminal()) {
                evict.add(t);
            }
        }
        tasks.removeAll(evict);
    }
}
