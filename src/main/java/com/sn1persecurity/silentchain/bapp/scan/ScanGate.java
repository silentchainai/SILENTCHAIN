package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Layered filter that decides whether an exchange seen by the passive scan
 * check is worth submitting to the configured AI provider. Order is
 * cheap-to-expensive: in-scope -> content type -> body size -> URL dedup ->
 * per-host rate limit.
 *
 * Passive analysis is always limited to Burp's target scope: PortSwigger's AI
 * guidance is to send only in-scope traffic, and Burp's live audit tasks and
 * scans can feed out-of-scope items.
 *
 * Thread-safe: the dedup check, the rate-limit check and recording both happen
 * under one lock, so concurrent scanner threads cannot both admit the same URL
 * or overshoot a host's budget.
 */
public class ScanGate {

    private static final long RATE_WINDOW_MILLIS = 60_000L;

    private final MontoyaApi api;
    private final Settings settings;

    private final Object lock = new Object();
    private final Map<String, Long> recentUrls;
    private final Map<String, Deque<Long>> hostWindows = new HashMap<>();

    public ScanGate(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
        this.recentUrls = new LinkedHashMap<>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return size() > settings.urlDedupCapacity();
            }
        };
    }

    /**
     * Full decision with skip-reason attribution. Has side effects ONLY when it
     * returns {@link GateDecision#ANALYZE}: it records the URL in the dedup map
     * and the host in the rate-limit window.
     */
    public GateDecision evaluate(HttpRequest request, HttpResponse response) {
        if (request == null || response == null) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        String url = request.url();
        if (url == null || url.isBlank()) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        int bodyLength = response.body() != null ? response.body().length() : 0;
        return evaluate(request.method(), url, api.scope().isInScope(url),
                response.headerValue("Content-Type"), bodyLength, System.currentTimeMillis());
    }

    /** Pure decision over already-extracted fields (unit-testable without Burp). */
    GateDecision evaluate(String method, String url, boolean inScope, String contentType,
                          int bodyLength, long nowMillis) {
        if (url == null || url.isBlank()) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        if (!inScope) {
            return GateDecision.SKIP_SCOPE;
        }
        if (!contentTypeAllowed(contentType)) {
            return GateDecision.SKIP_CONTENT_TYPE;
        }
        if (bodyLength <= 0 || bodyLength > settings.maxResponseBytes()) {
            return GateDecision.SKIP_SIZE;
        }

        String dedupKey = method + " " + normalizeUrl(url);
        String host = extractHost(url);
        synchronized (lock) {
            Long seenAt = recentUrls.get(dedupKey);
            if (seenAt != null && (nowMillis - seenAt) < settings.urlDedupTtlMillis()) {
                return GateDecision.SKIP_DUPLICATE;
            }
            Deque<Long> window = null;
            if (host != null) {
                pruneHostWindows(nowMillis);
                window = hostWindows.computeIfAbsent(host, h -> new ArrayDeque<>());
                if (window.size() >= settings.hostRequestsPerMinute()) {
                    return GateDecision.SKIP_RATE_LIMIT;
                }
            }
            recentUrls.put(dedupKey, nowMillis);
            if (window != null) {
                window.addLast(nowMillis);
            }
            return GateDecision.ANALYZE;
        }
    }

    /** Drop expired hits from every host window and forget hosts with none left. Caller holds the lock. */
    private void pruneHostWindows(long nowMillis) {
        long windowStart = nowMillis - RATE_WINDOW_MILLIS;
        Iterator<Map.Entry<String, Deque<Long>>> it = hostWindows.entrySet().iterator();
        while (it.hasNext()) {
            Deque<Long> window = it.next().getValue();
            while (!window.isEmpty() && window.peekFirst() < windowStart) {
                window.pollFirst();
            }
            if (window.isEmpty()) {
                it.remove();
            }
        }
    }

    private boolean contentTypeAllowed(String contentType) {
        if (contentType == null) {
            return false;
        }
        String normalized = contentType.split(";")[0].trim().toLowerCase();
        return settings.contentTypeAllowList().contains(normalized);
    }

    private static String normalizeUrl(String url) {
        int hash = url.indexOf('#');
        return hash >= 0 ? url.substring(0, hash) : url;
    }

    private static String extractHost(String url) {
        try {
            return new URI(url).getHost();
        } catch (URISyntaxException e) {
            return null;
        }
    }
}
