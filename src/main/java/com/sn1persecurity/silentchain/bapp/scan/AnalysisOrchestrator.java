package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.ai.ParsedFinding;
import com.sn1persecurity.silentchain.bapp.ai.PromptLibrary;
import com.sn1persecurity.silentchain.bapp.ai.ResponseParser;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.data.DataSanitizer;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingRow;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.ScanTask;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.state.TaskStatus;
import com.sn1persecurity.silentchain.bapp.util.Lifecycle;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;

/**
 * Single source of truth for the AI analysis pipeline:
 * sanitize -> prompt -> AI provider -> restore -> parse -> AuditIssue + table row.
 *
 * Two entry points:
 * <ul>
 *   <li>{@link #analyzePassive} - from {@link AiPassiveScanCheck}. NEVER sends
 *       anything to the scanned host: a passive scan check must not generate
 *       target traffic, even indirectly through this queue.</li>
 *   <li>{@link #analyzeOnDemand} - from the user's context-menu action. May send
 *       the request once to capture a missing response.</li>
 * </ul>
 *
 * Each job runs on the analysis pool inside try/catch/finally, so it always ends
 * in a terminal state and failures reach the extension error stream. Cancel,
 * pause, Stop Scanning, the AI permission and unloading are re-checked while the
 * job runs, not just when it is queued.
 */
public class AnalysisOrchestrator {

    /** Findings below this AI confidence are dropped (Community map_confidence). */
    private static final int MIN_CONFIDENCE = 50;

    /** Max passive jobs queued + running + parked at once; beyond this, passive items are skipped. */
    static final int PASSIVE_BACKLOG = 16;

    static final String TRIGGER_PASSIVE = "passive";
    static final String TRIGGER_ON_DEMAND = "context-menu";

    private record Job(HttpRequestResponse rr, String trigger, boolean passive, boolean allowFetch, ScanTask task) {}

    private final MontoyaApi api;
    private final AiService aiService;
    private final AiGate aiGate;
    private final Settings settings;
    private final ScanState scanState;
    private final Counters counters;
    private final TaskRegistry taskRegistry;
    private final FindingsRegistry findingsRegistry;
    private final ThreadPool threadPool;
    private final Lifecycle lifecycle;

    private final Semaphore passiveSlots = new Semaphore(PASSIVE_BACKLOG);
    private final Queue<Job> parkedJobs = new ConcurrentLinkedQueue<>();

    public AnalysisOrchestrator(MontoyaApi api,
                                AiService aiService,
                                AiGate aiGate,
                                Settings settings,
                                ScanState scanState,
                                Counters counters,
                                TaskRegistry taskRegistry,
                                FindingsRegistry findingsRegistry,
                                ThreadPool threadPool,
                                Lifecycle lifecycle) {
        this.api = api;
        this.aiService = aiService;
        this.aiGate = aiGate;
        this.settings = settings;
        this.scanState = scanState;
        this.counters = counters;
        this.taskRegistry = taskRegistry;
        this.findingsRegistry = findingsRegistry;
        this.threadPool = threadPool;
        this.lifecycle = lifecycle;
    }

    // ---- Admission ----------------------------------------------------------

    /** Reserve a passive backlog slot. Non-blocking; false means the backlog is full. */
    public boolean tryAdmitPassive() {
        return passiveSlots.tryAcquire();
    }

    /** Give back a slot from {@link #tryAdmitPassive} that was not handed to {@link #analyzePassive}. */
    public void releasePassiveAdmission() {
        passiveSlots.release();
    }

    /**
     * Queue a passive analysis. The caller must hold a slot from
     * {@link #tryAdmitPassive}; ownership of the slot passes to the job.
     * The exchange must already have its response: this path never fetches one.
     *
     * @return false if the analysis queue was full (the slot is released).
     */
    public boolean analyzePassive(HttpRequestResponse rr) {
        return submitOrDrop(new Job(rr, TRIGGER_PASSIVE, true, false,
                taskRegistry.newTask(TRIGGER_PASSIVE, safeUrl(rr))));
    }

    /**
     * Queue a user-initiated analysis. If the exchange has no response, the
     * request is sent once (from the worker, never the EDT) to capture one.
     *
     * @return false if the analysis queue was full.
     */
    public boolean analyzeOnDemand(HttpRequestResponse rr) {
        return submitOrDrop(new Job(rr, TRIGGER_ON_DEMAND, false, true,
                taskRegistry.newTask(TRIGGER_ON_DEMAND, safeUrl(rr))));
    }

    /** Cancel every task, including work parked while paused. Returns the number cancelled. */
    public int cancelAll() {
        int cancelled = taskRegistry.cancelAll();
        Job job;
        while ((job = parkedJobs.poll()) != null) {
            if (job.passive()) {
                passiveSlots.release();
            }
        }
        return cancelled;
    }

    /** Re-queue work parked while tasks were paused (wired to ScanState's resume hook). */
    public void resumeParked() {
        Job job;
        while ((job = parkedJobs.poll()) != null) {
            submitOrDrop(job);
        }
    }

    private boolean submitOrDrop(Job job) {
        if (threadPool.submitAnalysis("analysis (" + job.trigger() + ")", () -> runJob(job))) {
            return true;
        }
        job.task().finish(TaskStatus.CANCELLED);
        if (job.passive()) {
            passiveSlots.release();
        }
        return false;
    }

    // ---- Worker -------------------------------------------------------------

    private void runJob(Job job) {
        ScanTask task = job.task();
        boolean parked = false;
        try {
            if (scanState.isPaused() && task.park()) {
                parked = true;
                parkedJobs.add(job);
                if (!scanState.isPaused()) {
                    resumeParked();    // resumed while this job was being parked
                }
                return;
            }
            if (!task.tryStart()) {
                return;                // cancelled while queued
            }
            counters.incAnalyzed();

            if (stopRequested(job) || !aiEnabled(job)) {
                return;
            }
            HttpRequestResponse resolved = job.allowFetch() ? ensureResponse(job.rr(), job.trigger()) : job.rr();

            if (stopRequested(job) || !aiEnabled(job)) {
                return;
            }
            DataSanitizer sanitizer = new DataSanitizer(settings.sanitizerEnabled());
            String prompt = PromptLibrary.buildAnalysisPrompt(resolved, sanitizer);
            Optional<String> result = aiService.analyze(prompt);

            if (stopRequested(job)) {
                return;
            }
            handleResult(resolved, sanitizer, job, result);
        } catch (Throwable t) {
            counters.incErrors();
            if (!lifecycle.isUnloading()) {
                String message = "SILENTCHAIN [" + job.trigger() + "]: analysis failed for " + safeUrl(job.rr());
                api.logging().logToError(message, t);
                scanState.console("[ERROR] " + message + ": " + t);
            }
        } finally {
            if (!parked) {
                task.finish(TaskStatus.ERROR);   // no-op when a terminal status was already set
                if (job.passive()) {
                    passiveSlots.release();
                }
            }
        }
    }

    /** True (and the task is ended) if the job was cancelled or must not continue. */
    private boolean stopRequested(Job job) {
        ScanTask task = job.task();
        if (task.status().isTerminal()) {
            return true;                        // cancelled by the user
        }
        if (lifecycle.isUnloading()) {
            task.finish(TaskStatus.CANCELLED);
            return true;
        }
        if (job.passive() && !settings.passiveEnabled()) {
            task.finish(TaskStatus.CANCELLED);  // Stop Scanning cancels queued passive work
            return true;
        }
        return false;
    }

    /** False (and the task is skipped) if AI was disabled for the extension since the job was queued. */
    private boolean aiEnabled(Job job) {
        if (aiGate.isEnabled()) {
            return true;
        }
        job.task().finish(TaskStatus.SKIPPED);
        return false;
    }

    /**
     * Context-menu path only. Guarantees the exchange has a response so the AI
     * always sees the full request + response. When the target has none (e.g. an
     * "Analyze" on a site-map URL or a Repeater request tab) the request is sent
     * once via Burp's HTTP stack to capture a response. No-op when a response
     * already exists.
     */
    private HttpRequestResponse ensureResponse(HttpRequestResponse rr, String trigger) {
        if (rr.response() != null) {
            return rr;
        }
        HttpRequest req = rr.request();
        if (req == null) {
            return rr;
        }
        try {
            HttpRequestResponse sent = api.http().sendRequest(req,
                    RequestOptions.requestOptions().withResponseTimeout(settings.requestTimeoutSeconds() * 1000L));
            if (sent != null && sent.response() != null) {
                scanState.info("SILENTCHAIN [" + trigger + "]: no response on target; sent the request "
                        + "to capture one for analysis (" + safeUrl(rr) + ").");
                return sent;
            }
        } catch (Throwable t) {
            scanState.error("SILENTCHAIN [" + trigger + "]: could not fetch a response for "
                    + safeUrl(rr) + ": " + t.getMessage());
        }
        return rr;
    }

    private void handleResult(HttpRequestResponse rr, DataSanitizer sanitizer, Job job, Optional<String> result) {
        ScanTask task = job.task();
        String trigger = job.trigger();
        String url = safeUrl(rr);

        if (result.isEmpty()) {
            counters.incErrors();
            task.finish(TaskStatus.ERROR);
            scanState.debug("SILENTCHAIN [" + trigger + "]: no result for " + url);
            return;
        }

        String restored = sanitizer.restore(result.get());
        List<ParsedFinding> findings = ResponseParser.parse(restored);

        if (findings.isEmpty()) {
            task.finish(TaskStatus.COMPLETED);
            scanState.debug("SILENTCHAIN [" + trigger + "]: no findings for " + url);
            return;
        }

        int created = 0;
        for (ParsedFinding f : findings) {
            if (task.isCancelled() || lifecycle.isUnloading()) {
                break;
            }
            if (f.confidence() < MIN_CONFIDENCE) {
                counters.incSkippedLowConfidence();
                continue;
            }
            try {
                AuditIssue issue = FindingBuilder.build(f, rr);
                api.siteMap().add(issue);

                findingsRegistry.add(new FindingRow(
                        url,
                        f.title(),
                        normalizeSeverity(f.severityRaw()),
                        confidenceLabel(f.confidence())
                ));
                counters.incFindingsCreated();
                created++;

                scanState.info("SILENTCHAIN [" + trigger + "] finding: ["
                        + normalizeSeverity(f.severityRaw()) + " / " + f.confidence() + "%] "
                        + f.title() + " (" + f.owasp().code() + ") at " + url);
            } catch (Throwable t) {
                counters.incErrors();
                api.logging().logToError("SILENTCHAIN: failed to add finding for " + url, t);
                scanState.console("[ERROR] Failed to add SILENTCHAIN finding: " + t.getMessage());
            }
        }

        task.finish(TaskStatus.COMPLETED);

        if (sanitizer.injectionDetected()) {
            scanState.info("SILENTCHAIN [" + trigger + "]: prompt-injection neutralized for "
                    + url + " (" + sanitizer.injectionSummary() + ").");
        }

        scanState.debug("SILENTCHAIN [" + trigger + "]: " + created + " finding(s) created for " + url);
    }

    static String normalizeSeverity(String raw) {
        if (raw == null) {
            return "Information";
        }
        return switch (raw.trim().toLowerCase()) {
            case "high", "critical" -> "High";
            case "medium" -> "Medium";
            case "low" -> "Low";
            default -> "Information";
        };
    }

    static String confidenceLabel(int aiConfidence) {
        if (aiConfidence < 75) return "Tentative";
        if (aiConfidence < 90) return "Firm";
        return "Certain";
    }

    private static String safeUrl(HttpRequestResponse rr) {
        HttpRequest req = rr != null ? rr.request() : null;
        return req != null ? req.url() : "<no-url>";
    }
}
