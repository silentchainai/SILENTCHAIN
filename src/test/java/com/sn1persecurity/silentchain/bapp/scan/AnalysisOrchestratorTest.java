package com.sn1persecurity.silentchain.bapp.scan;

import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskStatus;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalysisOrchestratorTest {

    private static final String ONE_FINDING = "{\"findings\":[{\"title\":\"Reflected XSS\",\"severity\":\"High\","
            + "\"confidence\":92,\"cwe\":\"CWE-79\",\"owasp\":\"A03:2021\"}]}";

    private final PipelineFixture f = new PipelineFixture();
    private final AtomicInteger abandoned = new AtomicInteger();

    @AfterEach
    void tearDown() {
        f.close();
    }

    private ScanTask onlyTask() {
        assertEquals(1, f.tasks.size());
        return f.tasks.snapshot().get(0);
    }

    /** Admit and queue one passive job the way AiPassiveScanCheck does. */
    private boolean queuePassive(boolean withResponse) {
        assertTrue(f.orchestrator.tryAdmitPassive());
        return f.orchestrator.analyzePassive(PipelineFixture.exchange(withResponse), abandoned::incrementAndGet);
    }

    /**
     * Regression for the extension-portal #231 rejection: a passive scan check must
     * not cause ANY traffic to the scanned host, even indirectly via a queue. A
     * passive job without a response must never reach api.http().sendRequest.
     */
    @Test
    void passiveJobWithoutResponseNeverContactsTheTarget() {
        assertTrue(queuePassive(false));

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
    void outOfScopeOnDemandJobIsNeitherFetchedNorAnalyzed() {
        f.inScope.set(false);

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(false));

        assertEquals(0, f.sendRequests.get());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(TaskStatus.SKIPPED, onlyTask().status());
    }

    @Test
    void findingsAreAddedToTheSiteMapAndCounted() {
        f.analyzer = p -> Optional.of(ONE_FINDING);

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        assertEquals(1, f.siteMapAdds.size());
        assertEquals(1, f.findings.snapshot().size());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertEquals(1, f.counters.analyzed());
        assertEquals(0, f.sendRequests.get(), "the exchange already had a response");
    }

    /** Review point 5: an unexpected exception is logged and the task still ends. */
    @Test
    void unexpectedExceptionIsLoggedAndTheTaskEndsInError() {
        RuntimeException boom = new IllegalStateException("provider blew up");
        f.analyzer = p -> { throw boom; };

        queuePassive(true);

        assertEquals(TaskStatus.ERROR, onlyTask().status());
        assertEquals(1, f.counters.errors());
        assertSame(boom, f.loggedErrors.get(0));
        assertTrue(f.allPassiveSlotsFree(), "the backlog slot must be released on failure");
        assertEquals(0, abandoned.get(), "the provider was called: the URL counts as analyzed");
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
            return Optional.of(ONE_FINDING);
        };

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertTrue(f.siteMapAdds.isEmpty());
    }

    @Test
    void stopScanningCancelsQueuedPassiveWorkAndHandsBackTheReservation() {
        f.defer = true;
        queuePassive(true);

        f.settings.setPassiveEnabled(false);
        f.runDeferred();

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(0, f.counters.analyzed(), "never reached the AI");
        assertEquals(1, abandoned.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    /** A result the provider already returned (and charged for) is kept when scanning stops. */
    @Test
    void stopScanningDuringTheAiCallKeepsTheResult() {
        f.analyzer = p -> {
            f.settings.setPassiveEnabled(false);
            return Optional.of(ONE_FINDING);
        };

        queuePassive(true);

        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertEquals(1, f.siteMapAdds.size());
        assertEquals(0, abandoned.get());
    }

    @Test
    void aiDisabledAfterQueueingSkipsTheJob() {
        f.defer = true;
        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        f.aiEnabled.set(false);
        f.runDeferred();

        assertEquals(TaskStatus.SKIPPED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(0, f.counters.analyzed());
    }

    @Test
    void scopeIsRecheckedWhenAQueuedPassiveJobRuns() {
        f.defer = true;
        queuePassive(true);

        f.inScope.set(false);    // the user narrowed the scope while the job waited
        f.runDeferred();

        assertEquals(TaskStatus.SKIPPED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(1, abandoned.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void pausedWorkIsParkedThenResumed() {
        f.scanState.setPaused(true);
        queuePassive(true);

        assertEquals(TaskStatus.PAUSED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertFalse(f.allPassiveSlotsFree(), "a parked job keeps its backlog slot");

        f.scanState.setPaused(false);

        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertEquals(1, f.analyzerCalls.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void parkedOnDemandWorkIsMovedToDisk() {
        f.scanState.setPaused(true);
        PipelineFixture.tempFileCopies.set(0);

        f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true));

        assertEquals(TaskStatus.PAUSED, onlyTask().status());
        assertEquals(1, PipelineFixture.tempFileCopies.get());
    }

    /**
     * Pausing must not lift the queue bound: admission is refused up front (so the
     * user is told), and nothing admitted is silently cancelled on resume.
     */
    @Test
    void pausedBacklogIsBoundedAndResumeLosesNothing() {
        f.scanState.setPaused(true);
        int admitted = 0;
        for (int i = 0; i < ThreadPool.ANALYSIS_QUEUE + 50; i++) {
            if (f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true))) {
                admitted++;
            }
        }
        assertEquals(ThreadPool.ANALYSIS_QUEUE, admitted);

        f.scanState.setPaused(false);

        long cancelled = f.tasks.snapshot().stream().filter(t -> t.status() == TaskStatus.CANCELLED).count();
        assertEquals(0, cancelled);
        assertEquals(ThreadPool.ANALYSIS_QUEUE, f.analyzerCalls.get());
    }

    @Test
    void cancelAllReleasesParkedWork() {
        f.scanState.setPaused(true);
        queuePassive(true);

        f.orchestrator.cancelAll();
        f.scanState.setPaused(false);

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(1, abandoned.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void fullQueueCancelsTheTaskAndReleasesEverything() {
        f.rejectAll = true;

        assertFalse(queuePassive(true));

        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertEquals(1, abandoned.get());
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
