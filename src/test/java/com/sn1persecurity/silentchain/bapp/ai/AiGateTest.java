package com.sn1persecurity.silentchain.bapp.ai;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiGateTest {

    @Test
    void reflectsTheCurrentStateOnEveryCall() {
        AtomicBoolean enabled = new AtomicBoolean(true);
        AiGate gate = new AiGate(enabled::get, m -> { });

        assertTrue(gate.isEnabled());
        enabled.set(false);
        assertFalse(gate.isEnabled(), "must not cache: the user can untick 'Use AI' at any time");
        enabled.set(true);
        assertTrue(gate.isEnabled());
    }

    @Test
    void failsClosedWhenTheProbeThrows() {
        AiGate gate = new AiGate(() -> { throw new IllegalStateException("no AI in this edition"); }, m -> { });
        assertFalse(gate.isEnabled());
    }

    @Test
    void logsOnlyStateChanges() {
        AtomicBoolean enabled = new AtomicBoolean(false);
        List<String> log = new ArrayList<>();
        AiGate gate = new AiGate(enabled::get, log::add);

        gate.isEnabled();
        gate.isEnabled();
        assertEquals(1, log.size(), "disabled at first check is reported once");
        enabled.set(true);
        gate.isEnabled();
        gate.isEnabled();
        assertEquals(2, log.size());
        enabled.set(false);
        gate.isEnabled();
        assertEquals(3, log.size());
        assertTrue(log.get(2).contains("Use AI"));
    }

    @Test
    void doesNotLogWhenEnabledFromTheStart() {
        List<String> log = new ArrayList<>();
        AiGate gate = new AiGate(() -> true, log::add);
        gate.isEnabled();
        assertTrue(log.isEmpty());
    }
}
