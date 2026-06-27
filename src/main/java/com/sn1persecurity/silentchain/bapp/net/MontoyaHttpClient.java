package com.sn1persecurity.silentchain.bapp.net;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Thin wrapper around api.http().sendRequest(...) for all outbound third-party
 * LLM HTTP. Mandatory per PortSwigger BApp AI guideline #3: third-party calls
 * must use Montoya networking with upstream TLS verification.
 *
 * NEVER replace this with java.net.HttpURLConnection, OkHttp, Apache HttpClient,
 * or any other JVM-side HTTP stack. Doing so will fail BApp Store review.
 */
public class MontoyaHttpClient {

    public record HttpReply(int status, String body, Map<String, String> headers) {
        public boolean ok() { return status >= 200 && status < 300; }
    }

    private final MontoyaApi api;

    public MontoyaHttpClient(MontoyaApi api) {
        this.api = api;
    }

    public HttpReply get(String url, Map<String, String> headers) {
        return send(buildRequest("GET", url, headers, null));
    }

    public HttpReply postJson(String url, Map<String, String> headers, String jsonBody) {
        Map<String, String> merged = new LinkedHashMap<>(headers != null ? headers : Collections.emptyMap());
        merged.putIfAbsent("Content-Type", "application/json");
        merged.putIfAbsent("Accept", "application/json");
        return send(buildRequest("POST", url, merged, jsonBody));
    }

    private HttpRequest buildRequest(String method, String url, Map<String, String> headers, String body) {
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

    private HttpReply send(HttpRequest request) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(request);
            HttpResponse resp = rr.response();
            if (resp == null) {
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

    public static String hostOf(String url) {
        try {
            return new URI(url).getHost();
        } catch (Throwable t) {
            return null;
        }
    }

    public static boolean isHttps(String url) {
        try {
            return "https".equalsIgnoreCase(new URI(url).getScheme());
        } catch (Throwable t) {
            return false;
        }
    }

    @SuppressWarnings("unused")
    private static String utf8(String s) {
        return new String(s.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    /** Build a generic Authorization: Bearer header map. */
    public static Map<String, String> bearer(String apiKey) {
        return Map.of("Authorization", "Bearer " + apiKey);
    }

    /** Optional helper to convert {@link HttpReply} body to {@link Optional}. */
    public static Optional<String> bodyIfOk(HttpReply r) {
        return r.ok() ? Optional.of(r.body) : Optional.empty();
    }
}
