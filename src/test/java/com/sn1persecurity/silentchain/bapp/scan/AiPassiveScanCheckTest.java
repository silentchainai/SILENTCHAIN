package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.scanner.AuditResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiPassiveScanCheckTest {

    private final PipelineFixture f = new PipelineFixture();
    private final ScanGate gate = new ScanGate(f.api, f.settings);
    private final AiPassiveScanCheck check = new AiPassiveScanCheck(f.api, gate, f.aiGate, f.aiService,
            f.orchestrator, f.settings, f.scanState, f.counters, f.lifecycle);

    @AfterEach
    void tearDown() {
        f.close();
    }

    @Test
    void returnsAnEmptyResultImmediately() {
        assertFalse(check.checkName().isBlank());
        AuditResult result = check.doCheck(PipelineFixture.exchange(true));
        assertTrue(result.auditIssues().isEmpty(), "AI findings are added asynchronously, never returned here");
        assertTrue(check.lastCallbackMillis() > 0);
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
