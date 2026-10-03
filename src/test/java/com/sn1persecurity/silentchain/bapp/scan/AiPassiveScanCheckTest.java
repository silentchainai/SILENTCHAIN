package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskStatus;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiPassiveScanCheckTest {

    private static final String ONE_FINDING = "{\"findings\":[{\"title\":\"Reflected XSS\",\"severity\":\"High\","
            + "\"confidence\":92,\"cwe\":\"CWE-79\",\"owasp\":\"A03:2021\"}]}";

    /** Long enough that returning within {@link #PROMPTLY} proves the wait was cut short. */
    private static final long LONG_WAIT_MILLIS = 10_000;
    private static final Duration PROMPTLY = Duration.ofSeconds(2);

    private final PipelineFixture f = new PipelineFixture();
    private final ScanGate gate = new ScanGate(f.api, f.settings);
    private final AiPassiveScanCheck check = checkWaiting(100);
    private final AiPassiveScanCheck longWait = checkWaiting(LONG_WAIT_MILLIS);

    @AfterEach
    void tearDown() {
        PipelineFixture.onCopyToTempFile = () -> { };
        f.close();
    }

    private AiPassiveScanCheck checkWaiting(long millis) {
        return new AiPassiveScanCheck(f.api, gate, f.aiGate, f.aiService, f.orchestrator, f.settings,
                f.scanState, f.counters, f.lifecycle, millis);
    }

    private ScanTask onlyTask() {
        assertEquals(1, f.tasks.size());
        return f.tasks.snapshot().get(0);
    }

    /** Run doCheck on another thread (a Burp scanner thread) once its job is queued. */
    private Future<AuditResult> doCheckInBackground(ExecutorService scanner) throws InterruptedException {
        Future<AuditResult> result = scanner.submit(() -> longWait.doCheck(PipelineFixture.exchange(true)));
        long deadline = System.currentTimeMillis() + 5_000;
        while (f.tasks.size() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(5);
        }
        assertEquals(1, f.tasks.size(), "the job was queued");
        return result;
    }

    /** Review #244 point 1: findings come back to Burp Scanner in the AuditResult. */
    @Test
    void returnsTheAiFindingsInTheAuditResult() {
        f.analyzer = p -> Optional.of(ONE_FINDING);

        AuditResult result = check.doCheck(PipelineFixture.exchange(true));

        assertEquals(1, result.auditIssues().size());
        assertTrue(f.siteMapAdds.isEmpty(), "returned to the scanner, not added to the site map");
        assertEquals(1, f.findings.snapshot().size());
        assertEquals(1, f.counters.findingsCreated());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertTrue(f.allPassiveSlotsFree());
        assertFalse(check.checkName().isBlank());
        assertTrue(check.lastCallbackMillis() > 0);
    }

    @Test
    void noFindingsReturnsAnEmptyResult() {
        AuditResult result = check.doCheck(PipelineFixture.exchange(true));

        assertTrue(result.auditIssues().isEmpty());
        assertTrue(f.siteMapAdds.isEmpty());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
    }

    /** A result that misses the wait is not lost, and is reported only once. */
    @Test
    void lateResultIsAddedToTheSiteMapOnceAndNotReturned() {
        f.defer = true;
        f.analyzer = p -> Optional.of(ONE_FINDING);

        AuditResult result = check.doCheck(PipelineFixture.exchange(true));   // gives up after 100 ms

        assertTrue(result.auditIssues().isEmpty());
        assertEquals(TaskStatus.QUEUED, onlyTask().status());

        f.runDeferred();

        assertEquals(1, f.siteMapAdds.size());
        assertEquals(1, f.findings.snapshot().size());
        assertEquals(1, f.counters.findingsCreated());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void parkedJobFreesTheScannerThreadAndReportsOnResume() {
        f.analyzer = p -> Optional.of(ONE_FINDING);
        PipelineFixture.onCopyToTempFile = () -> f.scanState.setPaused(true);   // paused once admitted

        AuditResult result = assertTimeout(PROMPTLY, () -> longWait.doCheck(PipelineFixture.exchange(true)));

        assertTrue(result.auditIssues().isEmpty());
        assertEquals(TaskStatus.PAUSED, onlyTask().status());

        PipelineFixture.onCopyToTempFile = () -> { };
        f.scanState.setPaused(false);

        assertEquals(1, f.siteMapAdds.size());
        assertEquals(TaskStatus.COMPLETED, onlyTask().status());
        assertTrue(f.allPassiveSlotsFree());
    }

    /** No more scanner threads wait than there are analysis threads. */
    @Test
    void busyPoolDoesNotHoldTheScannerThread() {
        f.defer = true;
        f.analyzer = p -> Optional.of(ONE_FINDING);
        assertTrue(f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true)));
        assertTrue(f.orchestrator.analyzeOnDemand(PipelineFixture.exchange(true)));

        AuditResult result = assertTimeout(PROMPTLY, () -> longWait.doCheck(PipelineFixture.exchange(true)));

        assertTrue(result.auditIssues().isEmpty());
        f.runDeferred();
        assertEquals(3, f.analyzerCalls.get());
        assertEquals(3, f.siteMapAdds.size(), "the queued passive result still reaches Burp");
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void queueFullReturnsAtOnce() {
        f.rejectAll = true;

        AuditResult result = assertTimeout(PROMPTLY, () -> longWait.doCheck(PipelineFixture.exchange(true)));

        assertTrue(result.auditIssues().isEmpty());
        assertEquals(1, f.counters.skippedBacklog());
        assertTrue(f.allPassiveSlotsFree());

        f.rejectAll = false;
        check.doCheck(PipelineFixture.exchange(true));
        assertEquals(1, f.analyzerCalls.get(), "the rejected URL is not treated as analyzed");
    }

    @Test
    void cancelDuringTheAiCallFreesTheThreadAndAddsNothing() {
        f.analyzer = p -> {
            f.orchestrator.cancelAll();
            return Optional.of(ONE_FINDING);
        };

        AuditResult result = assertTimeout(PROMPTLY, () -> longWait.doCheck(PipelineFixture.exchange(true)));

        assertTrue(result.auditIssues().isEmpty());
        assertTrue(f.siteMapAdds.isEmpty());
        assertEquals(TaskStatus.CANCELLED, onlyTask().status());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void cancelAllFreesAWaitingScannerThread() throws Exception {
        f.defer = true;
        ExecutorService scanner = Executors.newSingleThreadExecutor();
        try {
            Future<AuditResult> result = doCheckInBackground(scanner);

            f.orchestrator.cancelAll();

            assertTrue(result.get(2, TimeUnit.SECONDS).auditIssues().isEmpty());
        } finally {
            scanner.shutdownNow();
        }
        f.runDeferred();
        assertEquals(0, f.analyzerCalls.get());
        assertTrue(f.siteMapAdds.isEmpty());
        assertTrue(f.allPassiveSlotsFree());
    }

    /** Unload discards queued jobs without running them: the waiter must not depend on the job. */
    @Test
    void unloadFreesAWaitingScannerThreadEvenIfItsJobNeverRuns() throws Exception {
        f.defer = true;
        ExecutorService scanner = Executors.newSingleThreadExecutor();
        try {
            Future<AuditResult> result = doCheckInBackground(scanner);

            f.lifecycle.markUnloading();

            assertTrue(result.get(2, TimeUnit.SECONDS).auditIssues().isEmpty());
        } finally {
            scanner.shutdownNow();
        }
    }

    @Test
    void interruptedScannerThreadStopsWaitingAndKeepsTheFlag() {
        f.defer = true;
        f.analyzer = p -> Optional.of(ONE_FINDING);
        Thread.currentThread().interrupt();
        try {
            AuditResult result = assertTimeout(PROMPTLY, () -> longWait.doCheck(PipelineFixture.exchange(true)));

            assertTrue(result.auditIssues().isEmpty());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        f.runDeferred();
        assertEquals(1, f.siteMapAdds.size());
    }

    @Test
    void consolidatesTheSameIssueAtTheSameUrl() {
        AuditIssue existing = issue("SILENTCHAIN: Reflected XSS", "https://target.example/a");

        assertEquals(ConsolidationAction.KEEP_EXISTING,
                check.consolidateIssues(existing, issue("SILENTCHAIN: Reflected XSS", "https://target.example/a")));
        assertEquals(ConsolidationAction.KEEP_BOTH,
                check.consolidateIssues(existing, issue("SILENTCHAIN: SQL Injection", "https://target.example/a")));
        assertEquals(ConsolidationAction.KEEP_BOTH,
                check.consolidateIssues(existing, issue("SILENTCHAIN: Reflected XSS", "https://target.example/b")));
    }

    private static AuditIssue issue(String name, String baseUrl) {
        return DeepStub.of(AuditIssue.class, Map.of("name", a -> name, "baseUrl", a -> baseUrl));
    }

    @Test
    void eligibleInScopeExchangeIsAnalyzedOnceFromATempFileCopy() {
        check.doCheck(PipelineFixture.exchange(true));
        check.doCheck(PipelineFixture.exchange(true));   // same URL again

        assertEquals(1, f.analyzerCalls.get());
        assertEquals(1, f.counters.skippedDuplicate());
        assertEquals(1, PipelineFixture.tempFileCopies.get(), "the queued copy lives on disk");
        assertEquals(0, f.sendRequests.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void exchangeWithoutResponseIsSkippedWithoutContactingTheTarget() {
        check.doCheck(PipelineFixture.exchange(false));

        assertEquals(0, f.tasks.size());
        assertEquals(0, f.sendRequests.get());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void outOfScopeIsNeverAnalyzedAndNotCountedAsBacklog() {
        f.inScope.set(false);

        check.doCheck(PipelineFixture.exchange(true));

        assertEquals(0, f.tasks.size());
        assertEquals(0, f.analyzerCalls.get());
        assertEquals(0, f.counters.skippedBacklog());
        assertTrue(f.allPassiveSlotsFree());
    }

    @Test
    void nothingHappensWhenPassiveIsOffPausedOrAiDisabled() {
        f.settings.setPassiveEnabled(false);
        check.doCheck(PipelineFixture.exchange(true));

        f.settings.setPassiveEnabled(true);
        f.scanState.setPaused(true);
        check.doCheck(PipelineFixture.exchange(true));

        f.scanState.setPaused(false);
        f.aiEnabled.set(false);
        check.doCheck(PipelineFixture.exchange(true));

        assertEquals(0, f.tasks.size());
        assertEquals(0, f.analyzerCalls.get());
    }

    @Test
    void fullBacklogSkipsInsteadOfQueueing() {
        for (int i = 0; i < AnalysisOrchestrator.PASSIVE_BACKLOG; i++) {
            assertTrue(f.orchestrator.tryAdmitPassive());
        }

        check.doCheck(PipelineFixture.exchange(true));

        assertEquals(0, f.tasks.size());
        assertEquals(1, f.counters.skippedBacklog());
    }

    /** A URL whose job never reached the AI is not treated as already analyzed. */
    @Test
    void abandonedItemCanBeAnalyzedLater() {
        f.defer = true;
        check.doCheck(PipelineFixture.exchange(true));
        f.settings.setPassiveEnabled(false);   // Stop Scanning before the job runs
        f.runDeferred();
        assertEquals(0, f.analyzerCalls.get());

        f.defer = false;
        f.settings.setPassiveEnabled(true);
        check.doCheck(PipelineFixture.exchange(true));

        assertEquals(1, f.analyzerCalls.get());
        assertEquals(0, f.counters.skippedDuplicate());
    }

    @Test
    void failuresInsideTheCheckAreContained() {
        AiPassiveScanCheck broken = new AiPassiveScanCheck(f.api, null, f.aiGate, f.aiService, f.orchestrator,
                f.settings, f.scanState, f.counters, f.lifecycle);

        AuditResult result = broken.doCheck(PipelineFixture.exchange(true));   // NPE on the null gate

        assertTrue(result.auditIssues().isEmpty());
        assertEquals(1, f.loggedErrors.size());
        assertTrue(f.allPassiveSlotsFree(), "no slot may leak when evaluation throws");
    }
}
