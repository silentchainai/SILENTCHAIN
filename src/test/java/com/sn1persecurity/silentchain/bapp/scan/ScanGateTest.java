package com.sn1persecurity.silentchain.bapp.scan;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanGateTest {

    private final Settings settings = new Settings();
    private final ScanGate gate = new ScanGate(null, settings);   // pure overloads need no Burp

    private GateDecision reserve(String url, long now) {
        return gate.reserve("GET", url, now).decision();
    }

    @Test
    void outOfScopeIsAlwaysSkipped() {
        assertEquals(GateDecision.SKIP_SCOPE, gate.prefilter("https://a.example/", false, "text/html", 100));
    }

    @Test
    void contentTypeAndSizeFilters() {
        assertEquals(GateDecision.SKIP_CONTENT_TYPE, gate.prefilter("https://a.example/1", true, "image/png", 100));
        assertEquals(GateDecision.SKIP_CONTENT_TYPE, gate.prefilter("https://a.example/1", true, null, 100));
        assertEquals(GateDecision.SKIP_SIZE, gate.prefilter("https://a.example/1", true, "text/html", 0));
        assertEquals(GateDecision.SKIP_SIZE,
                gate.prefilter("https://a.example/1", true, "text/html", settings.maxResponseBytes() + 1));
        assertEquals(GateDecision.ANALYZE,
                gate.prefilter("https://a.example/1", true, "text/html; charset=utf-8", 100));
    }

    @Test
    void sameUrlIsDeduplicatedUntilTheWindowExpires() {
        long ttl = settings.urlDedupTtlMillis();
        assertEquals(GateDecision.ANALYZE, reserve("https://a.example/x#frag", 0));
        assertEquals(GateDecision.SKIP_DUPLICATE, reserve("https://a.example/x", 1_000));
        assertEquals(GateDecision.ANALYZE, reserve("https://a.example/x", ttl + 1));
    }

    @Test
    void perHostRateLimitAppliesPerMinute() {
        settings.setHostRequestsPerMinute(2);
        assertEquals(GateDecision.ANALYZE, reserve("https://h.example/1", 0));
        assertEquals(GateDecision.ANALYZE, reserve("https://h.example/2", 10));
        assertEquals(GateDecision.SKIP_RATE_LIMIT, reserve("https://h.example/3", 20));
        assertEquals(GateDecision.ANALYZE, reserve("https://other.example/3", 20));
        // After the one-minute window the host has budget again, and the skipped URL was not recorded.
        assertEquals(GateDecision.ANALYZE, reserve("https://h.example/3", 60_100));
    }

    @Test
    void releasedReservationFreesTheUrlAndTheHostBudget() {
        settings.setHostRequestsPerMinute(1);
        ScanGate.Reservation first = gate.reserve("GET", "https://h.example/a", 0);
        assertEquals(GateDecision.SKIP_RATE_LIMIT, reserve("https://h.example/b", 5));

        gate.release(first);

        assertEquals(GateDecision.ANALYZE, reserve("https://h.example/a", 10));
    }

    @Test
    void releaseNeverErasesANewerReservation() {
        ScanGate.Reservation old = gate.reserve("GET", "https://a.example/x", 0);
        long later = settings.urlDedupTtlMillis() + 1;
        assertEquals(GateDecision.ANALYZE, reserve("https://a.example/x", later));

        gate.release(old);

        assertEquals(GateDecision.SKIP_DUPLICATE, reserve("https://a.example/x", later + 1));
    }
}
