package com.sn1persecurity.silentchain.bapp.state;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaskRegistryTest {

    @Test
    void cancelAllCountsOnlyUnfinishedTasks() {
        TaskRegistry r = new TaskRegistry();
        r.newTask("passive", "a").finish(TaskStatus.COMPLETED);
        r.newTask("passive", "b");
        r.newTask("passive", "c").park();

        assertEquals(2, r.cancelAll());
        assertEquals(0, r.cancelAll());
    }

    @Test
    void capEvictsOldestFinishedTasksButNeverActiveOnes() {
        TaskRegistry r = new TaskRegistry();
        ScanTask oldestActive = r.newTask("passive", "active");
        for (int i = 0; i < TaskRegistry.MAX_TASKS + 50; i++) {
            r.newTask("passive", "done-" + i).finish(TaskStatus.COMPLETED);
        }

        assertEquals(TaskRegistry.MAX_TASKS, r.size());
        assertTrue(r.snapshot().contains(oldestActive));
        assertEquals("done-" + (TaskRegistry.MAX_TASKS + 49), r.snapshot().get(0).url(), "newest first");
    }
}
