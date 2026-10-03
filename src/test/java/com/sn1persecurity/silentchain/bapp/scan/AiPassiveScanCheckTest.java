package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.scanner.AuditResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiPassiveScanCheckTest {

    private final PipelineFixture f = new PipelineFixture();
    private final AiPassiveScanCheck check = new AiPassiveScanCheck(f.api, new ScanGate(f.api, f.settings),
            f.aiGate, f.aiService, f.orchestrator, f.settings, f.scanState, f.counters, f.lifecycle);

    @AfterEach
    void tearDown() {
        f.close();
    }

    @Test
    void hasANameAndAlwaysReturnsAResult() {
        assertFalse(check.checkName().isBlank());
        AuditResult result = check.doCheck(PipelineFixture.exchange(true));
        assertNotNull(result);
        assertTrue(check.lastCallbackMillis() > 0);
    }

    @Test
    void eligibleInScopeExchangeIsAnalyzedOnce() {
        check.doCheck(PipelineFixture.exchange(true));
        check.doCheck(PipelineFixture.exchange(true));   // same URL again

        assertEquals(1, f.analyzerCalls.get());
        assertEquals(1, f.counters.skippedDuplicate());
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
    void outOfScopeIsNeverAnalyzed() {
        f.inScope.set(false);

        check.doCheck(PipelineFixture.exchange(true));

        assertEquals(0, f.tasks.size());
        assertEquals(0, f.analyzerCalls.get());
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

    @Test
    void failuresInsideTheCheckAreContained() {
        f.inScope.set(true);
        AiPassiveScanCheck broken = new AiPassiveScanCheck(f.api, null, f.aiGate, f.aiService, f.orchestrator,
                f.settings, f.scanState, f.counters, f.lifecycle);

        AuditResult result = broken.doCheck(PipelineFixture.exchange(true));   // NPE on the null gate

        assertNotNull(result);
        assertEquals(1, f.loggedErrors.size());
        assertTrue(f.allPassiveSlotsFree(), "the slot must be released when evaluation throws");
    }
}
