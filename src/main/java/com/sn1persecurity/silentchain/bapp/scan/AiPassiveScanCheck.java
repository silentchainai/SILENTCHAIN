package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.util.Lifecycle;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Burp Scanner passive check that feeds in-scope exchanges to the AI analysis
 * pipeline. Registered with {@code api.scanner().registerPassiveScanCheck(...,
 * ScanCheckType.PER_REQUEST)}, so Burp's live audit tasks and scans decide what
 * reaches it.
 *
 * Contract:
 *   - Returns immediately with an empty {@link AuditResult}. An LLM round trip
 *     takes seconds (and Burp AI prompts have no timeout), so blocking a
 *     scanner thread on it would stall Burp's audit; instead the exchange is
 *     handed to a bounded background queue and AI findings are added to the
 *     site map when the analysis completes.
 *   - NEVER causes traffic to the scanned host. Exchanges without a response
 *     are skipped, and the passive path through {@link AnalysisOrchestrator}
 *     cannot fetch one.
 *   - Analyzes only in-scope targets, de-duplicated by URL and rate-limited per
 *     host ({@link ScanGate}), and only while passive analysis is switched on,
 *     tasks are not paused, and AI is enabled for the extension in Burp.
 */
public class AiPassiveScanCheck implements PassiveScanCheck {

    static final String CHECK_NAME = "SILENTCHAIN AI passive analysis";

    private final MontoyaApi api;
    private final ScanGate gate;
    private final AiGate aiGate;
    private final AiService aiService;
    private final AnalysisOrchestrator orchestrator;
    private final Settings settings;
    private final ScanState scanState;
    private final Counters counters;
    private final Lifecycle lifecycle;

    private final AtomicLong lastCallbackMillis = new AtomicLong();

    public AiPassiveScanCheck(MontoyaApi api, ScanGate gate, AiGate aiGate, AiService aiService,
                              AnalysisOrchestrator orchestrator, Settings settings, ScanState scanState,
                              Counters counters, Lifecycle lifecycle) {
        this.api = api;
        this.gate = gate;
        this.aiGate = aiGate;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.settings = settings;
        this.scanState = scanState;
        this.counters = counters;
        this.lifecycle = lifecycle;
    }

    @Override
    public String checkName() {
        return CHECK_NAME;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        try {
            consider(requestResponse);
        } catch (Throwable t) {
            if (!lifecycle.isUnloading()) {
                api.logging().logToError("SILENTCHAIN passive check failed", t);
            }
        }
        return AuditResult.auditResult(List.of());
    }

    /** When Burp last invoked this check (0 if never this session). */
    public long lastCallbackMillis() {
        return lastCallbackMillis.get();
    }

    private void consider(HttpRequestResponse rr) {
        lastCallbackMillis.set(System.currentTimeMillis());

        if (lifecycle.isUnloading() || !settings.passiveEnabled() || scanState.isPaused()) {
            return;
        }
        if (rr == null || rr.request() == null || !rr.hasResponse()) {
            return;   // never fetch a missing response from a passive check
        }
        if (!aiGate.isEnabled() || !aiService.isConfigured()) {
            return;
        }

        counters.incTotalRequests();

        if (!orchestrator.tryAdmitPassive()) {
            counters.incSkippedBacklog();
            return;
        }
        boolean handedOff = false;
        try {
            GateDecision decision = gate.evaluate(rr.request(), rr.response());
            switch (decision) {
                case ANALYZE -> {
                    // Keep the queued copy on disk, not the heap (large projects).
                    HttpRequestResponse queued = rr.copyToTempFile();
                    handedOff = true;   // the job owns the slot from here, even if the queue rejects it
                    if (!orchestrator.analyzePassive(queued)) {
                        counters.incSkippedBacklog();
                    }
                }
                case SKIP_DUPLICATE -> counters.incSkippedDuplicate();
                case SKIP_RATE_LIMIT -> counters.incSkippedRateLimit();
                default -> { /* out of scope / content type / size: silently filtered */ }
            }
        } finally {
            if (!handedOff) {
                orchestrator.releasePassiveAdmission();
            }
        }
    }
}
