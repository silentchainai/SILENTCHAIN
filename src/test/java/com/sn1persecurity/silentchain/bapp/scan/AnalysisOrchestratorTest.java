package com.sn1persecurity.silentchain.bapp.scan;

import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskStatus;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalysisOrchestratorTest {

    private final PipelineFixture f = new PipelineFixture();

    @AfterEach
    void tearDown() {
        f.close();
    }

    private ScanTask onlyTask() {
        assertEquals(1, f.tasks.size());
        return f.tasks.snapshot().get(0);
    }

    /**
     * Regression for the extension-portal #231 rejection: a passive scan check must
     * not cause ANY traffic to the scanned host, even indirectly via a queue. A
     * passive job without a response must never reach api.http().sendRequest.
     */
    @Test
    void passiveJobWithoutResponseNeverContactsTheTarget() {
        assertTrue(f.orchestrator.tryAdmitPassive());
        assertTrue(f.orchestrator.analyzePassive(PipelineFixture.exchange(false)));

        assertEquals(0, f.sendRequests.get());
        assertTrue(onlyTask().status().isTerminal());
        assertTrue(f.allPassiveSlotsFree());
    }

    /** Control: the user-initiated path does fetch a missing response, exactly once. */
    @Test
    void onDemandJobWithoutResponseFetchesItOnce() {
        assertTrue(f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(false)));

        assertEquals(1, f.sendRequests.get());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
    }

    @Test
    void findingsAreAddedToTheSiteMap() {
        f.analyzer = p -> Optional.of("{\"findings\":[{\"title\":\"Reflected XSS\",\"severity\":\"High\","
                + "\"confidence\":92,\"cwe\":\"CWE-79\",\"owasp\":\"A03:2021\"}]}");

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        assertEquals(1, f.siteMapAdds.size());
        assertEquals(1, f.findings.snapshot().size());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertEquals(0, f.sendRequests.get(), "the exchange already had a response");
    }

    /** Review point 5: an unexpected exception is logged and the task still ends. */
    @Test
    void unexpectedExceptionIsLoggedAndTheTaskEndsInError() {
        RuntimeException boom = new IllegalStateException("provider blew up");
        f.analyzer = p -> { throw boom; };

        assertTrue(f.orchestrator.tryAdmitPassive());
        f.orchestrator.analyzePassive(PipelineFixture.exchange(true));

        assertEquals(TaskStatus.ERROR, onlyTask().status());
        assertEquals(1, f.counters.errors());
        assertSame(boom, f.loggedErrors.get(0));
        assertTrue(f.allPassiveSlotsFree(), "the backlog slot must be released on failure");
    }

    @Test
    void cancelledWhileQueuedNeverRunsAndStaysCancelled() {
        f.defer = true;
        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));
        assertEquals(TaskStatus.QUEUED, onlyTask().status());

        assertEquals(1, f.orchestrator.cancelAll());
        f.runDeferred();

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertTrue(f.siteMapAdds.isEmpty());
    }

    @Test
    void cancelDuringAnalysisIsNotOverwrittenAndAddsNothing() {
        f.analyzer = p -> {
            f.orchestrator.cancelAll();
            return Optional.of("{\"findings\":[{\"title\":\"X\",\"severity\":\"High\",\"confidence\":95}]}");
        };

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertTrue(f.siteMapAdds.isEmpty());
    }

    @Test
    void stopScanningCancelsQueuedPassiveWork() {
        f.defer = true;
        assertTrue(f.orchestrator.tryAdmitPassive());
        f.orchestrator.analyzePassive(PipelineFixture.exchange(true));

        f.settings.setPassiveEnabled(false);
        f.runDeferred();

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void aiDisabledAfterQueueingSkipsTheJob() {
        f.defer = true;
        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        f.aiEnabled.set(false);
        f.runDeferred();

        assertEquals(TaskStatus.SKIPPED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
    }

    @Test
    void pausedWorkIsParkedThenResumed() {
        f.scanState.setPaused(true);
        assertTrue(f.orchestrator.tryAdmitPassive());
        f.orchestrator.analyzePassive(PipelineFixture.exchange(true));

        assertEquals(TaskStatus.PAUSED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertFalse(f.allPassiveSlotsFree(), "a parked job keeps its backlog slot");

        f.scanState.setPaused(false);

        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertEquals(1, f.analyzerCalls.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void cancelAllReleasesParkedWork() {
        f.scanState.setPaused(true);
        assertTrue(f.orchestrator.tryAdmitPassive());
        f.orchestrator.analyzePassive(PipelineFixture.exchange(true));

        f.orchestrator.cancelAll();
        f.scanState.setPaused(false);

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void fullQueueCancelsTheTaskAndReleasesTheSlot() {
        f.rejectAll = true;
        assertTrue(f.orchestrator.tryAdmitPassive());

        assertFalse(f.orchestrator.analyzePassive(PipelineFixture.exchange(true)));

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void unloadingCancelsQueuedWork() {
        f.defer = true;
        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        f.lifecycle.markUnloading();
        f.runDeferred();

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
    }
}
