package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.state.Counters;
import com.sn1persecurity.silentchain.bapp.state.ScanState;

/**
 * Passive observer that submits eligible responses to the configured AI
 * provider for analysis.
 *
 * Contract:
 *   - NEVER blocks the proxy thread. ScanGate.evaluate() returns quickly; all
 *     AI work happens on the ThreadPool via AnalysisOrchestrator.
 *   - NEVER modifies requests or responses. Returns continueWith() in both
 *     callbacks.
 *   - NEVER fires when the AI provider is unavailable, passive scanning is off,
 *     or tasks are paused.
 */
public class PassiveHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final ScanGate gate;
    private final AiService aiService;
    private final AnalysisOrchestrator orchestrator;
    private final Settings settings;
    private final ScanState scanState;
    private final Counters counters;

    public PassiveHttpHandler(MontoyaApi api, ScanGate gate, AiService aiService,
                              AnalysisOrchestrator orchestrator, Settings settings,
                              ScanState scanState, Counters counters) {
        this.api = api;
        this.gate = gate;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.settings = settings;
        this.scanState = scanState;
        this.counters = counters;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            if (!settings.passiveEnabled() || scanState.isPaused()) {
                return ResponseReceivedAction.continueWith(response);
            }
            if (!aiService.isAvailable()) {
                return ResponseReceivedAction.continueWith(response);
            }

            counters.incTotalRequests();

            GateDecision decision = gate.evaluate(response);
            switch (decision) {
                case ANALYZE -> {
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                            response.initiatingRequest(), response);
                    orchestrator.analyzeAsync(rr, "passive");
                }
                case SKIP_DUPLICATE -> counters.incSkippedDuplicate();
                case SKIP_RATE_LIMIT -> counters.incSkippedRateLimit();
                default -> { /* scope / content-type / size / tool — silently filtered */ }
            }
        } catch (Throwable t) {
            api.logging().logToError("PassiveHttpHandler error: " + t.getMessage());
        }
        return ResponseReceivedAction.continueWith(response);
    }
}
