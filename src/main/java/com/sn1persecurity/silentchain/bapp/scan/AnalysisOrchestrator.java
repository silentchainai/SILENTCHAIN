package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiNotSentException;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;

/**
 * Single source of truth for the AI analysis pipeline:
 * sanitize -> prompt -> AI provider -> restore -> parse -> AuditIssue + table row.
 * Each job's issues are handed to the passive scan check waiting for them (and
 * so returned to Burp Scanner in its {@code AuditResult}); when nobody is
 * waiting they are added with {@code api.siteMap().add()}. Exactly one of the
 * two happens ({@link ResultHandoff}).
 *
 * Two entry points:
 * <ul>
 *   <li>{@link #analyzePassive} - from {@link AiPassiveScanCheck}. NEVER sends
 *       anything to the scanned host: a passive scan check must not generate
 *       target traffic, even indirectly through this queue.</li>
 *   <li>{@link #analyzeOnDemand} - from the user's context-menu action. May send
 *       the request once to capture a missing response. Not a scan check, so its
 *       issues always go to the site map.</li>
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

    /**
     * One analysis. {@code onAbandoned} (passive jobs: hand back the ScanGate
     * reservation) runs if the job ends without reaching the AI provider.
     * {@code handoff} receives the issues if a scan check is still waiting.
     */
    private record Job(HttpRequestResponse rr, String trigger, boolean passive, boolean allowFetch,
                       ScanTask task, Runnable onAbandoned, ResultHandoff handoff) {
        Job withExchange(HttpRequestResponse other) {
            return new Job(other, trigger, passive, allowFetch, task, onAbandoned, handoff);
        }
    }

    /** An issue built from one AI finding, kept with its source for the table row. */
    private record BuiltIssue(ParsedFinding finding, AuditIssue issue) {}

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
    /**
     * Every job, queued + running + parked, holds one of these. Sized to the
     * analysis queue, so admission fails up front (and the user is told) instead
     * of the executor rejecting work later, e.g. when parked work is resumed.
     */
    private final Semaphore jobSlots = new Semaphore(ThreadPool.ANALYSIS_QUEUE);
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
        if (!passiveSlots.tryAcquire()) {
            return false;
        }
        if (!jobSlots.tryAcquire()) {
            passiveSlots.release();
            return false;
        }
        return true;
    }

    /** Give back a slot from {@link #tryAdmitPassive} that was not handed to {@link #analyzePassive}. */
    public void releasePassiveAdmission() {
        jobSlots.release();
        passiveSlots.release();
    }

    /**
     * True if every outstanding job, including one just admitted, fits on the
     * analysis threads, i.e. a newly queued job starts at once. Only then is it
     * worth holding a Burp scanner thread for the result: a job queued behind
     * others would mostly outlast the wait. Conservative (parked work counts).
     */
    boolean passiveCanStartNow() {
        return ThreadPool.ANALYSIS_QUEUE - jobSlots.availablePermits() <= ThreadPool.ANALYSIS_THREADS;
    }

    /**
     * Queue a passive analysis. The caller must hold a slot from
     * {@link #tryAdmitPassive}; ownership of the slot passes to the job.
     * The exchange must already have its response: this path never fetches one.
     *
     * @param onAbandoned run if the job ends without reaching the AI provider
     * @param awaitResult the caller will wait for the issues: it MUST then call
     *                    {@link ResultHandoff#await} on the returned handoff exactly once
     * @return the job's handoff ({@link ResultHandoff#none()} unless awaitResult),
     *         or null if the analysis queue was full (the slot is released).
     */
    ResultHandoff analyzePassive(HttpRequestResponse rr, Runnable onAbandoned, boolean awaitResult) {
        ScanTask task = taskRegistry.newTask(TRIGGER_PASSIVE, safeUrl(rr));
        ResultHandoff handoff = awaitResult
                ? new ResultHandoff(() -> lifecycle.isUnloading() || task.status().isTerminal())
                : ResultHandoff.none();
        boolean queued = submitOrDrop(new Job(rr, TRIGGER_PASSIVE, true, false, task, onAbandoned, handoff));
        return queued ? handoff : null;
    }

    /**
     * Queue a user-initiated analysis. If the exchange has no response, the
     * request is sent once (from the worker, never the EDT) to capture one.
     *
     * @return false if the analysis queue was full (nothing was queued).
     */
    public boolean analyzeOnDemand(HttpRequestResponse rr) {
        if (!jobSlots.tryAcquire()) {
            return false;
        }
        return submitOrDrop(new Job(rr, TRIGGER_ON_DEMAND, false, true,
                taskRegistry.newTask(TRIGGER_ON_DEMAND, safeUrl(rr)), null, ResultHandoff.none()));
    }

    /** Cancel every task, including work parked while paused. Returns the number cancelled. */
    public int cancelAll() {
        int cancelled = taskRegistry.cancelAll();
        Job job;
        while ((job = parkedJobs.poll()) != null) {
            drop(job);   // also a task created after the registry pass
        }
        return cancelled;
    }

    /** Free job slots (tests). */
    int availableJobSlots() {
        return jobSlots.availablePermits();
    }

    /** Re-queue work parked while tasks were paused (wired to ScanState's resume hook). */
    public void resumeParked() {
        int dropped = 0;
        Job job;
        while ((job = parkedJobs.poll()) != null) {
            if (!submitOrDrop(job)) {
                dropped++;
            }
        }
        if (dropped > 0) {
            scanState.info("SILENTCHAIN: " + dropped + " paused task(s) could not be re-queued and were cancelled.");
        }
    }

    private boolean submitOrDrop(Job job) {
        if (threadPool.submitAnalysis("analysis (" + job.trigger() + ")", () -> runJob(job))) {
            return true;
        }
        drop(job);
        return false;
    }

    /** End a job that will not run: cancel its task, free any waiter, hand back its slots. */
    private void drop(Job job) {
        job.task().finish(TaskStatus.CANCELLED);
        job.handoff().release();
        abandon(job);
        releaseSlots(job);
    }

    private void releaseSlots(Job job) {
        jobSlots.release();
        if (job.passive()) {
            passiveSlots.release();
        }
    }

    private void abandon(Job job) {
        Runnable hook = job.onAbandoned();
        if (hook != null) {
            try {
                hook.run();
            } catch (Throwable t) {
                api.logging().logToError("SILENTCHAIN: failed to release a passive reservation", t);
            }
        }
    }

    // ---- Worker -------------------------------------------------------------

    private void runJob(Job job) {
        ScanTask task = job.task();
        boolean parked = false;
        boolean reachedAi = false;
        try {
            if (scanState.isPaused() && !lifecycle.isUnloading() && task.park()) {
                // Parked work may wait indefinitely: keep the exchange on disk, not the heap.
                Job toPark = job.passive() ? job : job.withExchange(job.rr().copyToTempFile());
                parkedJobs.add(toPark);
                parked = true;
                // Cancel All or unload may have run between park() and add(): their drain did not
                // see this job, so take it back (remove() claims it at most once) and end it here.
                if ((task.status().isTerminal() || lifecycle.isUnloading()) && parkedJobs.remove(toPark)) {
                    drop(toPark);
                    return;
                }
                if (!scanState.isPaused()) {
                    resumeParked();    // resumed while this job was being parked
                }
                return;
            }
            if (!task.tryStart()) {
                return;                // cancelled while queued
            }
            if (stopRequested(job) || !aiReady(job) || !stillInScope(job)) {
                return;
            }
            HttpRequestResponse resolved = job.allowFetch() ? ensureResponse(job.rr(), job.trigger()) : job.rr();

            // The fetch can take up to the request timeout: re-check everything, scope included.
            if (stopRequested(job) || !aiReady(job) || !stillInScope(job)) {
                return;
            }
            DataSanitizer sanitizer = new DataSanitizer(settings.sanitizerEnabled());
            String prompt = PromptLibrary.buildAnalysisPrompt(resolved, sanitizer);
            Optional<String> result;
            reachedAi = true;
            try {
                result = aiService.analyze(prompt);
            } catch (AiNotSentException e) {
                // AI was disabled or the provider unconfigured while the prompt was built.
                reachedAi = false;
                task.finish(TaskStatus.SKIPPED);
                scanState.debug("SILENTCHAIN [" + job.trigger() + "]: skipped, " + e.getMessage());
                return;
            }
            counters.incAnalyzed();

            // The provider has been paid: only an explicit cancel or unload discards
            // the result (Stop Scanning only stops work that has not started).
            if (cancelledOrUnloading(job)) {
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
            // Whatever happened, nothing more is coming for a waiting scan check now. A parked
            // job runs later, after its waiter has gone, and so reports through the site map.
            job.handoff().release();
            if (!parked) {
                task.finish(TaskStatus.ERROR);   // no-op when a terminal status was already set
                if (!reachedAi) {
                    abandon(job);
                }
                releaseSlots(job);
            }
        }
    }

    /** True (and the task is ended) if the job was cancelled or the extension is unloading. */
    private boolean cancelledOrUnloading(Job job) {
        ScanTask task = job.task();
        if (task.status().isTerminal()) {
            return true;                        // cancelled by the user
        }
        if (lifecycle.isUnloading()) {
            task.finish(TaskStatus.CANCELLED);
            return true;
        }
        return false;
    }

    /** As {@link #cancelledOrUnloading}, and Stop Scanning cancels passive work that has not started. */
    private boolean stopRequested(Job job) {
        if (cancelledOrUnloading(job)) {
            return true;
        }
        if (job.passive() && !settings.passiveEnabled()) {
            job.task().finish(TaskStatus.CANCELLED);
            return true;
        }
        return false;
    }

    /**
     * Burp's scope can change while a job waits in the queue or parked; nothing
     * out of scope is sent to the AI or fetched from the target.
     */
    private boolean stillInScope(Job job) {
        HttpRequest req = job.rr().request();
        String url = req != null ? req.url() : null;
        if (url != null && !url.isBlank() && api.scope().isInScope(url)) {
            return true;
        }
        job.task().finish(TaskStatus.SKIPPED);
        scanState.debug("SILENTCHAIN [" + job.trigger() + "]: skipped, not in Burp's target scope: " + url);
        return false;
    }

    /**
     * False (and the task is skipped) if AI was disabled for the extension, or the
     * provider is no longer configured, since the job was queued: nothing would be
     * sent, so the job must not count as analyzed.
     */
    private boolean aiReady(Job job) {
        if (aiGate.isEnabled() && aiService.isConfigured()) {
            return true;
        }
        job.task().finish(TaskStatus.SKIPPED);
        scanState.debug("SILENTCHAIN [" + job.trigger() + "]: skipped, AI is disabled or the provider is not configured.");
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
        if (req == null || !api.scope().isInScope(req.url())) {
            return rr;                         // never replay an out-of-scope request
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

        List<BuiltIssue> built = new ArrayList<>();
        for (ParsedFinding f : findings) {
            if (task.isCancelled() || lifecycle.isUnloading()) {
                break;
            }
            if (f.confidence() < MIN_CONFIDENCE) {
                counters.incSkippedLowConfidence();
                continue;
            }
            try {
                built.add(new BuiltIssue(f, FindingBuilder.build(f, rr)));
            } catch (Throwable t) {
                reportAddFailure(url, t);
            }
        }
        if (cancelledOrUnloading(job)) {
            return;
        }

        // Hand the issues to the passive scan check still waiting for them (Burp Scanner
        // then reports and consolidates them); otherwise add them to the site map.
        List<BuiltIssue> reported = built;
        String via = "the scanner result";
        if (!built.isEmpty() && !job.handoff().deliver(issuesOf(built))) {
            if (cancelledOrUnloading(job)) {
                return;                        // the waiter may have left because of Cancel All
            }
            via = "the site map";
            reported = addToSiteMap(built, task, url);
        }

        for (BuiltIssue b : reported) {
            ParsedFinding f = b.finding();
            findingsRegistry.add(new FindingRow(
                    url,
                    f.title(),
                    normalizeSeverity(f.severityRaw()),
                    confidenceLabel(f.confidence())
            ));
            counters.incFindingsCreated();
            scanState.info("SILENTCHAIN [" + trigger + "] finding: ["
                    + normalizeSeverity(f.severityRaw()) + " / " + f.confidence() + "%] "
                    + f.title() + " (" + f.owasp().code() + ") at " + url);
        }

        // Only after the handoff: a waiting scan check reads a finished task as "nothing coming".
        task.finish(TaskStatus.COMPLETED);

        if (sanitizer.injectionDetected()) {
            scanState.info("SILENTCHAIN [" + trigger + "]: prompt-injection neutralized for "
                    + url + " (" + sanitizer.injectionSummary() + ").");
        }

        scanState.debug("SILENTCHAIN [" + trigger + "]: " + reported.size() + " finding(s) created for " + url
                + (reported.isEmpty() ? "" : " (reported via " + via + ")"));
    }

    private List<BuiltIssue> addToSiteMap(List<BuiltIssue> built, ScanTask task, String url) {
        List<BuiltIssue> added = new ArrayList<>();
        for (BuiltIssue b : built) {
            if (task.isCancelled() || lifecycle.isUnloading()) {
                break;
            }
            try {
                api.siteMap().add(b.issue());
                added.add(b);
            } catch (Throwable t) {
                reportAddFailure(url, t);
            }
        }
        return added;
    }

    private void reportAddFailure(String url, Throwable t) {
        counters.incErrors();
        api.logging().logToError("SILENTCHAIN: failed to add finding for " + url, t);
        scanState.console("[ERROR] Failed to add SILENTCHAIN finding: " + t.getMessage());
    }

    private static List<AuditIssue> issuesOf(List<BuiltIssue> built) {
        List<AuditIssue> issues = new ArrayList<>(built.size());
        for (BuiltIssue b : built) {
            issues.add(b.issue());
        }
        return issues;
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
