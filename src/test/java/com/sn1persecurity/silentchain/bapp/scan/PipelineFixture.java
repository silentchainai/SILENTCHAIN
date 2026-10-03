package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.FindingsRegistry;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;
import com.sn1persecurity.silentchain.bapp.testutil.MontoyaFactoryStub;
import com.sn1persecurity.silentchain.bapp.util.Lifecycle;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/** Wires a real AnalysisOrchestrator to stubbed Burp + AI for pipeline tests. */
final class PipelineFixture implements AutoCloseable {

    static final String TARGET_URL = "https://target.example/item?id=1";

    final AtomicInteger sendRequests = new AtomicInteger();
    final AtomicInteger analyzerCalls = new AtomicInteger();
    final List<Object> siteMapAdds = new ArrayList<>();
    final List<Throwable> loggedErrors = new ArrayList<>();
    final AtomicBoolean aiEnabled = new AtomicBoolean(true);
    final AtomicBoolean inScope = new AtomicBoolean(true);
    /** Number of copyToTempFile() calls on exchanges built by {@link #exchange}. */
    static final AtomicInteger tempFileCopies = new AtomicInteger();

    /** When true, jobs are held in {@link #deferred} instead of running inline. */
    boolean defer;
    /** When true, the analysis queue rejects jobs (as if full). */
    boolean rejectAll;
    final Deque<Runnable> deferred = new ArrayDeque<>();

    Function<String, Optional<String>> analyzer = prompt -> Optional.of("{\"findings\":[]}");

    /** AuditResult.auditResult(...) returns a stub that reports exactly the issues passed in. */
    final MontoyaFactoryStub factory = MontoyaFactoryStub.install(Map.of("auditResult", a -> {
        List<?> issues = a[0] instanceof List<?> list ? list : Arrays.asList((AuditIssue[]) a[0]);
        return DeepStub.of(AuditResult.class, Map.of("auditIssues", x -> issues));
    }));
    final MontoyaApi api;
    final Settings settings = new Settings();
    final Lifecycle lifecycle = new Lifecycle();
    final Counters counters = new Counters();
    final TaskRegistry tasks = new TaskRegistry();
    final FindingsRegistry findings = new FindingsRegistry();
    final ScanState scanState;
    final ThreadPool pool;
    final AiGate aiGate = new AiGate(aiEnabled::get, m -> { });
    final AiService aiService;
    final AnalysisOrchestrator orchestrator;

    PipelineFixture() {
        tempFileCopies.set(0);
        Map<String, Function<Object[], Object>> overrides = new HashMap<>();
        overrides.put("sendRequest", a -> {
            sendRequests.incrementAndGet();
            return exchange(true);
        });
        overrides.put("add", a -> {
            siteMapAdds.add(a[0]);
            return null;
        });
        overrides.put("logToError", a -> {
            for (Object o : a) {
                if (o instanceof Throwable t) {
                    loggedErrors.add(t);
                }
            }
            return null;
        });
        overrides.put("isEnabled", a -> aiEnabled.get());
        overrides.put("isInScope", a -> inScope.get());
        api = DeepStub.of(MontoyaApi.class, overrides);

        settings.setPassiveEnabled(true);
        scanState = new ScanState(api, settings);
        pool = new ThreadPool(api.logging(), lifecycle) {
            @Override
            public boolean submitAnalysis(String what, Runnable task) {
                if (rejectAll) {
                    return false;
                }
                if (defer) {
                    deferred.add(task);
                } else {
                    task.run();
                }
                return true;
            }
        };
        aiService = new AiService(null) {
            @Override
            public Optional<String> analyze(String userPrompt) {
                analyzerCalls.incrementAndGet();
                return analyzer.apply(userPrompt);
            }

            @Override
            public boolean isConfigured() {
                return true;
            }
        };
        orchestrator = new AnalysisOrchestrator(api, aiService, aiGate, settings, scanState, counters,
                tasks, findings, pool, lifecycle);
        scanState.setOnResume(orchestrator::resumeParked);
    }

    void runDeferred() {
        Runnable r;
        while ((r = deferred.poll()) != null) {
            r.run();
        }
    }

    /** True if every passive backlog slot is free (none leaked). */
    boolean allPassiveSlotsFree() {
        int admitted = 0;
        while (admitted <= AnalysisOrchestrator.PASSIVE_BACKLOG && orchestrator.tryAdmitPassive()) {
            admitted++;
        }
        for (int i = 0; i < admitted; i++) {
            orchestrator.releasePassiveAdmission();
        }
        return admitted == AnalysisOrchestrator.PASSIVE_BACKLOG;
    }

    static HttpRequestResponse exchange(boolean withResponse) {
        HttpRequest request = DeepStub.of(HttpRequest.class, Map.of(
                "url", a -> TARGET_URL,
                "method", a -> "GET"));
        HttpResponse response = withResponse ? DeepStub.of(HttpResponse.class, Map.of(
                "headerValue", a -> "text/html; charset=utf-8",
                "body", a -> DeepStub.of(ByteArray.class, Map.of("length", x -> 512)),
                "bodyToString", a -> "<html>hello</html>")) : null;
        HttpRequestResponse[] self = new HttpRequestResponse[1];
        self[0] = DeepStub.of(HttpRequestResponse.class, Map.of(
                "request", a -> request,
                "response", a -> response,
                "hasResponse", a -> withResponse,
                "copyToTempFile", a -> {
                    tempFileCopies.incrementAndGet();
                    return self[0];
                }));
        return self[0];
    }

    @Override
    public void close() {
        pool.shutdownNow();
        factory.close();
    }
}
