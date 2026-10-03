package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.util.Lifecycle;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Burp Scanner passive check that feeds in-scope exchanges to the AI analysis
 * pipeline. Registered with {@code api.scanner().registerPassiveScanCheck(...,
 * ScanCheckType.PER_REQUEST)}, so Burp's live audit tasks and scans decide what
 * reaches it.
 *
 * Contract:
 *   - Returns the AI findings in its {@link AuditResult}, so Burp Scanner
 *     reports and consolidates them. The exchange is analyzed on the
 *     extension's bounded analysis pool; the scanner thread waits for the
 *     result only when the analysis can start at once (so no more scanner
 *     threads wait than there are analysis threads) and for at most
 *     {@link #RESULT_WAIT_MILLIS}, because an LLM round trip takes seconds and
 *     Burp AI prompts have no timeout. It stops waiting at once if the job is
 *     cancelled, parked (tasks paused) or the extension unloads.
 *   - A result that arrives after the check stopped waiting (or for an item
 *     that had to queue) is added with {@code api.siteMap().add()} instead of
 *     being discarded, since the AI call has been paid for. Each result is
 *     reported exactly once ({@link ResultHandoff}).
 *   - NEVER causes traffic to the scanned host. Exchanges without a response
 *     are skipped, and the passive path through {@link AnalysisOrchestrator}
 *     cannot fetch one.
 *   - Analyzes only in-scope targets, de-duplicated by URL and rate-limited per
 *     host ({@link ScanGate}), and only while passive analysis is switched on,
 *     tasks are not paused, and AI is enabled for the extension in Burp.
 */
public class AiPassiveScanCheck implements PassiveScanCheck {

    static final String CHECK_NAME = "SILENTCHAIN AI passive analysis";

    /** Longest a scanner thread waits for an analysis that started at once. */
    static final long RESULT_WAIT_MILLIS = 60_000L;

    private final MontoyaApi api;
    private final ScanGate gate;
    private final AiGate aiGate;
    private final AiService aiService;
    private final AnalysisOrchestrator orchestrator;
    private final Settings settings;
    private final ScanState scanState;
    private final Counters counters;
    private final Lifecycle lifecycle;
    private final long resultWaitMillis;

    private final AtomicLong lastCallbackMillis = new AtomicLong();

    public AiPassiveScanCheck(MontoyaApi api, ScanGate gate, AiGate aiGate, AiService aiService,
                              AnalysisOrchestrator orchestrator, Settings settings, ScanState scanState,
                              Counters counters, Lifecycle lifecycle) {
        this(api, gate, aiGate, aiService, orchestrator, settings, scanState, counters, lifecycle,
                RESULT_WAIT_MILLIS);
    }

    /** As the public constructor, with a different wait budget (tests). */
    AiPassiveScanCheck(MontoyaApi api, ScanGate gate, AiGate aiGate, AiService aiService,
                       AnalysisOrchestrator orchestrator, Settings settings, ScanState scanState,
                       Counters counters, Lifecycle lifecycle, long resultWaitMillis) {
        this.api = api;
        this.gate = gate;
        this.aiGate = aiGate;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.settings = settings;
        this.scanState = scanState;
        this.counters = counters;
        this.lifecycle = lifecycle;
        this.resultWaitMillis = resultWaitMillis;
    }

    @Override
    public String checkName() {
        return CHECK_NAME;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        ResultHandoff handoff = null;
        try {
            handoff = consider(requestResponse);
        } catch (Throwable t) {
            if (!lifecycle.isUnloading()) {
                api.logging().logToError("SILENTCHAIN passive check failed", t);
            }
        }
        // Nothing in consider() can throw once a job is queued, so a handoff
        // the job may deliver to is always awaited (and so detached) here.
        List<AuditIssue> issues = handoff != null ? handoff.await(resultWaitMillis) : List.of();
        return AuditResult.auditResult(issues);
    }

    /**
     * Burp calls this when this check reports more than one issue for the same
     * URL path. The same AI finding (issue name) at the same URL is one issue.
     */
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue != null && newIssue != null
                && existingIssue.name() != null
                && existingIssue.name().equals(newIssue.name())
                && Objects.equals(existingIssue.baseUrl(), newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    /** When Burp last invoked this check (0 if never this session). */
    public long lastCallbackMillis() {
        return lastCallbackMillis.get();
    }

    /** Returns the queued job's handoff, or null if nothing was queued. */
    private ResultHandoff consider(HttpRequestResponse rr) {
        lastCallbackMillis.set(System.currentTimeMillis());

        if (lifecycle.isUnloading() || !settings.passiveEnabled() || scanState.isPaused()) {
            return null;
        }
        if (rr == null || rr.request() == null || !rr.hasResponse()) {
            return null;   // never fetch a missing response from a passive check
        }
        if (!aiGate.isEnabled() || !aiService.isConfigured()) {
            return null;
        }

        counters.incTotalRequests();

        // Side-effect-free filters first, so "Skipped (Backlog)" only counts
        // items that would otherwise have been analyzed.
        if (gate.prefilter(rr.request(), rr.response()) != GateDecision.ANALYZE) {
            return null;   // out of scope / content type / size: silently filtered
        }
        if (!orchestrator.tryAdmitPassive()) {
            counters.incSkippedBacklog();
            return null;
        }
        boolean handedOff = false;
        try {
            ScanGate.Reservation reservation = gate.reserve(rr.request());
            switch (reservation.decision()) {
                case ANALYZE -> {
                    HttpRequestResponse queued;
                    try {
                        // Keep the queued copy on disk, not the heap (large projects).
                        queued = rr.copyToTempFile();
                    } catch (RuntimeException e) {
                        gate.release(reservation);
                        throw e;
                    }
                    handedOff = true;   // the job owns the slot from here, even if the queue rejects it
                    boolean await = orchestrator.passiveCanStartNow();
                    ResultHandoff handoff = orchestrator.analyzePassive(queued, () -> gate.release(reservation), await);
                    if (handoff == null) {
                        counters.incSkippedBacklog();
                    }
                    return handoff;
                }
                case SKIP_DUPLICATE -> counters.incSkippedDuplicate();
                case SKIP_RATE_LIMIT -> counters.incSkippedRateLimit();
                default -> { /* not reachable after prefilter */ }
            }
            return null;
        } finally {
            if (!handedOff) {
                orchestrator.releasePassiveAdmission();
            }
        }
    }
}
