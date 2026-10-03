package com.sn1persecurity.silentchain.bapp.net;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Thin wrapper around api.http().sendRequest(...) for all outbound third-party
 * LLM HTTP. Mandatory per PortSwigger BApp AI guideline #3: third-party calls
 * must use Montoya networking with upstream TLS verification.
 *
 * This is the single egress point for third-party AI traffic, so it also
 * enforces {@link AiGate} as a hard block: when AI is disabled for the
 * extension, no request leaves, whichever provider or code path asked.
 *
 * NEVER replace this with java.net.HttpURLConnection, OkHttp, Apache HttpClient,
 * or any other JVM-side HTTP stack. Doing so will fail BApp Store review.
 */
public class MontoyaHttpClient {

    /** Status reported when the request was not sent because AI is disabled. */
    public static final int STATUS_AI_DISABLED = -1;

    public record HttpReply(int status, String body, Map<String, String> headers) {
        public boolean ok() { return status >= 200 && status < 300; }
    }

    private final MontoyaApi api;
    private final AiGate aiGate;
    private final Settings settings;

    public MontoyaHttpClient(MontoyaApi api, AiGate aiGate, Settings settings) {
        this.api = api;
        this.aiGate = aiGate;
        this.settings = settings;
    }

    public HttpReply get(String url, Map<String, String> headers) {
        return send("GET", url, headers, null);
    }

    public HttpReply postJson(String url, Map<String, String> headers, String jsonBody) {
        Map<String, String> merged = new LinkedHashMap<>(headers != null ? headers : Collections.emptyMap());
        merged.putIfAbsent("Content-Type", "application/json");
        merged.putIfAbsent("Accept", "application/json");
        return send("POST", url, merged, jsonBody);
    }

    private HttpReply send(String method, String url, Map<String, String> headers, String body) {
        if (!aiGate.isEnabled()) {
            return new HttpReply(STATUS_AI_DISABLED, "", Collections.emptyMap());
        }
        try {
            // Built inside the try: the URL is user-configured and a malformed
            // one must surface as a failed reply, not an exception on the caller.
            HttpRequest request = buildRequest(method, url, headers, body);
            // BApp AI requirement: third-party LLM requests must use Montoya
            // networking WITH upstream TLS verification so a MITM cannot tamper
            // with prompts/responses. (Harmless for plain-HTTP localhost Ollama.)
            RequestOptions options = RequestOptions.requestOptions()
                    .withUpstreamTLSVerification()
                    .withResponseTimeout(settings.requestTimeoutSeconds() * 1000L);
            HttpRequestResponse rr = api.http().sendRequest(request, options);
            HttpResponse resp = rr.response();
            if (resp == null) {
                api.logging().logToError("SILENTCHAIN: no response from the AI provider within "
                        + settings.requestTimeoutSeconds() + " s (timed out or connection failed). "
                        + "For slow local models raise 'Third-party AI timeout (s)' in SILENTCHAIN's settings.");
                return new HttpReply(0, "", Collections.emptyMap());
            }
            String bodyStr = resp.bodyToString();
            Map<String, String> headerMap = new LinkedHashMap<>();
            resp.headers().forEach(h -> headerMap.put(h.name(), h.value()));
            return new HttpReply(resp.statusCode(), bodyStr, headerMap);
        } catch (Throwable t) {
            api.logging().logToError("MontoyaHttpClient: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            return new HttpReply(0, "", Collections.emptyMap());
        }
    }

    private static HttpRequest buildRequest(String method, String url, Map<String, String> headers, String body) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                req = req.withHeader(e.getKey(), e.getValue());
            }
        }
        if (body != null) {
            req = req.withBody(body);
        }
        return req;
    }

    /** Build a generic Authorization: Bearer header map. */
    public static Map<String, String> bearer(String apiKey) {
        return Map.of("Authorization", "Bearer " + apiKey);
    }
}
