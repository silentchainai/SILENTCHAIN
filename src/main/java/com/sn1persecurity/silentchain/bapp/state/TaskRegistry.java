package com.sn1persecurity.silentchain.bapp.state;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe registry of analysis tasks backing the Active Tasks table.
 * Newest task is shown first.
 */
public class TaskRegistry {

    private final CopyOnWriteArrayList<ScanTask> tasks = new CopyOnWriteArrayList<>();

    public ScanTask newTask(String type, String url) {
        ScanTask task = new ScanTask(type, url);
        tasks.add(0, task);
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
            if (!t.status().isTerminal()) {
                t.setStatus(TaskStatus.CANCELLED);
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
}
