package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

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

import java.util.List;
import java.util.Optional;

/**
 * Single source of truth for the AI analysis pipeline:
 * sanitize -> prompt -> AI provider -> restore -> parse -> AuditIssue + table row.
 *
 * Shared by ContextMenuProvider (on-demand) and PassiveHttpHandler (auto).
 * Updates the live state (tasks, findings, counters, console) so the
 * SILENTCHAIN tab reflects activity in real time.
 */
public class AnalysisOrchestrator {

    /** Findings below this AI confidence are dropped (Community map_confidence). */
    private static final int MIN_CONFIDENCE = 50;

    private final MontoyaApi api;
    private final AiService aiService;
    private final Settings settings;
    private final ScanState scanState;
    private final Counters counters;
    private final TaskRegistry taskRegistry;
    private final FindingsRegistry findingsRegistry;

    public AnalysisOrchestrator(MontoyaApi api,
                                AiService aiService,
                                Settings settings,
                                ScanState scanState,
                                Counters counters,
                                TaskRegistry taskRegistry,
                                FindingsRegistry findingsRegistry) {
        this.api = api;
        this.aiService = aiService;
        this.settings = settings;
        this.scanState = scanState;
        this.counters = counters;
        this.taskRegistry = taskRegistry;
        this.findingsRegistry = findingsRegistry;
    }

    public void analyzeAsync(HttpRequestResponse rr, String trigger) {
        String url = safeUrl(rr);
        ScanTask task = taskRegistry.newTask(trigger, url);

        counters.incAnalyzed();
        task.setStatus(TaskStatus.ANALYZING);

        DataSanitizer sanitizer = new DataSanitizer(settings.sanitizerEnabled());

        // Whole chain runs on the AI worker pool: ensureResponse() may issue a
        // blocking HTTP send (when the exchange has no captured response, e.g. a
        // context-menu "Analyze" on a site-map URL), which must never run on the
        // EDT (context-menu action) or Burp's HTTP-handler thread (passive).
        aiService.submit(() -> {
            HttpRequestResponse resolved = ensureResponse(rr, trigger);
            String prompt = PromptLibrary.buildAnalysisPrompt(resolved, sanitizer);
            Optional<String> result = aiService.analyze(prompt);
            handleResult(resolved, sanitizer, trigger, task, result);
        });
    }

    /**
     * Guarantees the exchange has a response so the AI always sees the full
     * request + response. When the target has none — e.g. a context-menu
     * "Analyze" on a site-map URL or a Repeater request tab — the request is
     * sent once via Burp's HTTP stack to capture a response, then the req+resp
     * pair is analyzed. No-op when a response already exists, so the passive
     * path never issues an extra request.
     *
     * Ported from SILENTCHAIN Pro v2 (AnalysisOrchestrator.ensureResponse,
     * release v2.0.7) — without this, response-less site-map entries produced
     * "no result" for every analyzed URL.
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
            HttpRequestResponse sent = api.http().sendRequest(req);
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

    private void handleResult(HttpRequestResponse rr, DataSanitizer sanitizer, String trigger,
                              ScanTask task, Optional<String> result) {
        String url = safeUrl(rr);

        if (result.isEmpty()) {
            counters.incErrors();
            task.setStatus(TaskStatus.ERROR);
            scanState.debug("SILENTCHAIN [" + trigger + "]: no result for " + url);
            return;
        }

        String restored = sanitizer.restore(result.get());
        List<ParsedFinding> findings = ResponseParser.parse(restored);

        if (findings.isEmpty()) {
            task.setStatus(TaskStatus.COMPLETED);
            scanState.debug("SILENTCHAIN [" + trigger + "]: no findings for " + url);
            return;
        }

        int created = 0;
        for (ParsedFinding f : findings) {
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
                scanState.error("Failed to add SILENTCHAIN finding: " + t.getMessage());
            }
        }

        task.setStatus(TaskStatus.COMPLETED);

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
        HttpRequest req = rr.request();
        return req != null ? req.url() : "<no-url>";
    }
}
