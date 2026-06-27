package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Layered filter that decides whether a captured response is worth submitting
 * to the configured AI provider. Order is cheap-to-expensive: tool source ->
 * in-scope -> content type -> body size -> URL dedup -> per-host rate limit.
 *
 * Thread-safe: all mutable maps are guarded by their own monitor; the method
 * is called from Burp's proxy thread and must return quickly.
 */
public class ScanGate {

    private final MontoyaApi api;
    private final Settings settings;

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

    public boolean shouldAnalyze(HttpResponseReceived response) {
        return evaluate(response) == GateDecision.ANALYZE;
    }

    /**
     * Full decision with skip-reason attribution. Has side effects ONLY when it
     * returns {@link GateDecision#ANALYZE}: it records the URL in the dedup map
     * and the host in the rate-limit window.
     */
    public GateDecision evaluate(HttpResponseReceived response) {
        if (!settings.passiveEnabled()) {
            return GateDecision.SKIP_DISABLED;
        }

        ToolType source = response.toolSource().toolType();
        if (!settings.allowedToolSources().contains(source)) {
            return GateDecision.SKIP_TOOL;
        }

        HttpRequest req = response.initiatingRequest();
        if (req == null) {
            return GateDecision.SKIP_NO_REQUEST;
        }
        String url = req.url();
        if (url == null || url.isBlank()) {
            return GateDecision.SKIP_NO_REQUEST;
        }

        if (settings.inScopeOnly() && !api.scope().isInScope(url)) {
            return GateDecision.SKIP_SCOPE;
        }

        if (!contentTypeAllowed(response)) {
            return GateDecision.SKIP_CONTENT_TYPE;
        }

        if (!responseSizeAllowed(response)) {
            return GateDecision.SKIP_SIZE;
        }

        String dedupKey = req.method() + " " + normalizeUrl(url);
        if (recentlySeen(dedupKey)) {
            return GateDecision.SKIP_DUPLICATE;
        }

        String host = extractHost(url);
        if (host != null && !hostBudgetAvailable(host)) {
            return GateDecision.SKIP_RATE_LIMIT;
        }

        rememberSeen(dedupKey);
        if (host != null) {
            recordHostHit(host);
        }
        return GateDecision.ANALYZE;
    }

    private boolean contentTypeAllowed(HttpResponseReceived response) {
        String contentType = response.headerValue("Content-Type");
        if (contentType == null) {
            return false;
        }
        String normalized = contentType.split(";")[0].trim().toLowerCase();
        return settings.contentTypeAllowList().contains(normalized);
    }

    private boolean responseSizeAllowed(HttpResponseReceived response) {
        int len = response.body() != null ? response.body().length() : 0;
        return len > 0 && len <= settings.maxResponseBytes();
    }

    private boolean recentlySeen(String key) {
        long now = System.currentTimeMillis();
        long ttl = settings.urlDedupTtlMillis();
        synchronized (recentUrls) {
            Long seenAt = recentUrls.get(key);
            return seenAt != null && (now - seenAt) < ttl;
        }
    }

    private void rememberSeen(String key) {
        synchronized (recentUrls) {
            recentUrls.put(key, System.currentTimeMillis());
        }
    }

    private boolean hostBudgetAvailable(String host) {
        long now = System.currentTimeMillis();
        long windowStart = now - 60_000L;
        int limit = settings.hostRequestsPerMinute();
        synchronized (hostWindows) {
            Deque<Long> window = hostWindows.computeIfAbsent(host, h -> new ArrayDeque<>());
            while (!window.isEmpty() && window.peekFirst() < windowStart) {
                window.pollFirst();
            }
            return window.size() < limit;
        }
    }

    private void recordHostHit(String host) {
        long now = System.currentTimeMillis();
        synchronized (hostWindows) {
            hostWindows.computeIfAbsent(host, h -> new ArrayDeque<>()).addLast(now);
        }
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
