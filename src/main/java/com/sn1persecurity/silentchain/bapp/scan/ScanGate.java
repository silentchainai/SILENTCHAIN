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
 * Decides whether an exchange seen by the passive scan check is worth
 * submitting to the configured AI provider, in two steps:
 *
 * <ol>
 *   <li>{@link #prefilter} - side-effect free: in-scope, content type, body
 *       size. Passive analysis is always limited to Burp's target scope:
 *       PortSwigger's AI guidance is to send only in-scope traffic, and Burp's
 *       live audit tasks and scans can feed out-of-scope items.</li>
 *   <li>{@link #reserve} - URL de-duplication and the per-host rate limit,
 *       checked and recorded atomically under one lock. A reservation whose job
 *       never reaches the AI is handed back with {@link #release}, so a dropped
 *       item is not treated as already analyzed.</li>
 * </ol>
 */
public class ScanGate {

    private static final long RATE_WINDOW_MILLIS = 60_000L;

    /** Outcome of {@link #reserve}; {@code at} identifies the recorded entries for {@link #release}. */
    public record Reservation(GateDecision decision, String dedupKey, String host, long at) {}

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

    /** Scope, content type and size. No side effects. */
    public GateDecision prefilter(HttpRequest request, HttpResponse response) {
        if (request == null || response == null) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        String url = request.url();
        if (url == null || url.isBlank()) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        int bodyLength = response.body() != null ? response.body().length() : 0;
        return prefilter(url, api.scope().isInScope(url), response.headerValue("Content-Type"), bodyLength);
    }

    /** Pure form of {@link #prefilter(HttpRequest, HttpResponse)} (unit-testable without Burp). */
    GateDecision prefilter(String url, boolean inScope, String contentType, int bodyLength) {
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
        return GateDecision.ANALYZE;
    }

    /**
     * URL de-duplication and per-host rate limit. On {@link GateDecision#ANALYZE}
     * the URL and the host hit are recorded (atomically with the checks).
     */
    public Reservation reserve(HttpRequest request) {
        return reserve(request.method(), request.url(), System.currentTimeMillis());
    }

    /** Pure form of {@link #reserve(HttpRequest)} with an explicit clock. */
    Reservation reserve(String method, String url, long nowMillis) {
        String dedupKey = method + " " + normalizeUrl(url);
        String host = extractHost(url);
        synchronized (lock) {
            Long seenAt = recentUrls.get(dedupKey);
            if (seenAt != null && (nowMillis - seenAt) < settings.urlDedupTtlMillis()) {
                return new Reservation(GateDecision.SKIP_DUPLICATE, dedupKey, host, nowMillis);
            }
            Deque<Long> window = null;
            if (host != null) {
                pruneHostWindows(nowMillis);
                window = hostWindows.computeIfAbsent(host, h -> new ArrayDeque<>());
                if (window.size() >= settings.hostRequestsPerMinute()) {
                    return new Reservation(GateDecision.SKIP_RATE_LIMIT, dedupKey, host, nowMillis);
                }
            }
            recentUrls.put(dedupKey, nowMillis);
            if (window != null) {
                window.addLast(nowMillis);
            }
            return new Reservation(GateDecision.ANALYZE, dedupKey, host, nowMillis);
        }
    }

    /**
     * Undo an ANALYZE reservation whose job ended without reaching the AI. Only
     * the entries recorded by that reservation are removed, never a newer one.
     */
    public void release(Reservation reservation) {
        if (reservation == null || reservation.decision() != GateDecision.ANALYZE) {
            return;
        }
        synchronized (lock) {
            recentUrls.remove(reservation.dedupKey(), reservation.at());
            if (reservation.host() != null) {
                Deque<Long> window = hostWindows.get(reservation.host());
                if (window != null) {
                    window.removeFirstOccurrence(reservation.at());
                    if (window.isEmpty()) {
                        hostWindows.remove(reservation.host());
                    }
                }
            }
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
