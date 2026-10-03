package com.sn1persecurity.silentchain.bapp.scan;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanGateTest {

    private final Settings settings = new Settings();
    private final ScanGate gate = new ScanGate(null, settings);   // pure overload needs no Burp

    private GateDecision eval(String url, boolean inScope, String contentType, int bodyLength, long now) {
        return gate.evaluate("GET", url, inScope, contentType, bodyLength, now);
    }

    @Test
    void outOfScopeIsAlwaysSkipped() {
        assertEquals(GateDecision.SKIP_SCOPE, eval("https://a.example/", false, "text/html", 100, 0));
    }

    @Test
    void contentTypeAndSizeFilters() {
        assertEquals(GateDecision.SKIP_CONTENT_TYPE, eval("https://a.example/1", true, "image/png", 100, 0));
        assertEquals(GateDecision.SKIP_CONTENT_TYPE, eval("https://a.example/1", true, null, 100, 0));
        assertEquals(GateDecision.SKIP_SIZE, eval("https://a.example/1", true, "text/html", 0, 0));
        assertEquals(GateDecision.SKIP_SIZE,
                eval("https://a.example/1", true, "text/html", settings.maxResponseBytes() + 1, 0));
        assertEquals(GateDecision.ANALYZE, eval("https://a.example/1", true, "text/html; charset=utf-8", 100, 0));
    }

    @Test
    void sameUrlIsDeduplicatedUntilTheWindowExpires() {
        long ttl = settings.urlDedupTtlMillis();
        assertEquals(GateDecision.ANALYZE, eval("https://a.example/x#frag", true, "text/html", 100, 0));
        assertEquals(GateDecision.SKIP_DUPLICATE, eval("https://a.example/x", true, "text/html", 100, 1_000));
        assertEquals(GateDecision.ANALYZE, eval("https://a.example/x", true, "text/html", 100, ttl + 1));
    }

    @Test
    void perHostRateLimitAppliesPerMinute() {
        settings.setHostRequestsPerMinute(2);
        assertEquals(GateDecision.ANALYZE, eval("https://h.example/1", true, "text/html", 100, 0));
        assertEquals(GateDecision.ANALYZE, eval("https://h.example/2", true, "text/html", 100, 10));
        assertEquals(GateDecision.SKIP_RATE_LIMIT, eval("https://h.example/3", true, "text/html", 100, 20));
        assertEquals(GateDecision.ANALYZE, eval("https://other.example/3", true, "text/html", 100, 20));
        // After the one-minute window the host has budget again, and the skipped URL was not recorded.
        assertEquals(GateDecision.ANALYZE, eval("https://h.example/3", true, "text/html", 100, 60_100));
    }
}
