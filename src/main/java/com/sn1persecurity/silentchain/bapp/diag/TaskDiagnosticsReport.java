package com.sn1persecurity.silentchain.bapp.diag;

import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.state.TaskStatus;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a human-readable diagnostics report of the task queue, bound to the
 * "Run Task Diagnostics" button (Community silentchain_ai_community.py:1587).
 */
public final class TaskDiagnosticsReport {

    private TaskDiagnosticsReport() {}

    public static String generate(TaskRegistry registry) {
        List<ScanTask> tasks = registry.snapshot();

        Map<TaskStatus, Integer> counts = new EnumMap<>(TaskStatus.class);
        for (TaskStatus s : TaskStatus.values()) {
            counts.put(s, 0);
        }
        for (ScanTask t : tasks) {
            counts.merge(t.status(), 1, Integer::sum);
        }

        int active = counts.get(TaskStatus.ANALYZING) + counts.get(TaskStatus.WAITING);
        int queued = counts.get(TaskStatus.QUEUED);

        StringBuilder sb = new StringBuilder();
        sb.append("===== SILENTCHAIN Task Diagnostics =====\n");
        sb.append("Total tasks tracked : ").append(tasks.size()).append('\n');
        for (TaskStatus s : TaskStatus.values()) {
            sb.append(String.format("  %-10s : %d%n", s.label(), counts.get(s)));
        }
        sb.append("Active (analyzing+waiting): ").append(active).append('\n');
        sb.append("Queued                    : ").append(queued).append('\n');

        if (queued > 0 && active == 0) {
            sb.append("NOTE: tasks are queued but none are active — the worker pool may be ")
              .append("saturated or the AI provider may be slow/unreachable. Check the ")
              .append("Settings -> AI Provider -> Test Connection result.\n");
        }
        if (counts.get(TaskStatus.ERROR) > 0) {
            sb.append("NOTE: ").append(counts.get(TaskStatus.ERROR))
              .append(" task(s) ended in ERROR — check provider credentials / credits / connectivity.\n");
        }
        sb.append("========================================");
        return sb.toString();
    }
}
