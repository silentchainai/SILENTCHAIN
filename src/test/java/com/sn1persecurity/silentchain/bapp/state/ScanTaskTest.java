package com.sn1persecurity.silentchain.bapp.state;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanTaskTest {

    @Test
    void startsQueuedWithNoDuration() {
        ScanTask t = new ScanTask("passive", "https://a.example/");
        assertEquals(TaskStatus.QUEUED, t.status());
        assertEquals("-", t.durationLabel());
    }

    @Test
    void terminalStatusIsFinal() {
        ScanTask t = new ScanTask("passive", "u");
        assertTrue(t.finish(TaskStatus.CANCELLED));
        assertFalse(t.finish(TaskStatus.COMPLETED), "a user's cancel must not be overwritten");
        assertFalse(t.finish(TaskStatus.ERROR));
        assertFalse(t.tryStart());
        assertEquals(TaskStatus.CANCELLED, t.status());
    }

    @Test
    void startParkAndResume() {
        ScanTask t = new ScanTask("passive", "u");
        assertTrue(t.park());
        assertTrue(t.park(), "parking an already paused task is fine");
        assertEquals(TaskStatus.PAUSED, t.status());
        assertTrue(t.tryStart());
        assertEquals(TaskStatus.ANALYZING, t.status());
        assertFalse(t.tryStart(), "cannot start twice");
        assertFalse(t.park(), "a running task is not parked");
        assertTrue(t.finish(TaskStatus.COMPLETED));
        assertTrue(t.durationLabel().endsWith("s"));
    }

    @Test
    void finishRejectsNonTerminalStatus() {
        ScanTask t = new ScanTask("passive", "u");
        assertThrows(IllegalArgumentException.class, () -> t.finish(TaskStatus.ANALYZING));
    }
}
