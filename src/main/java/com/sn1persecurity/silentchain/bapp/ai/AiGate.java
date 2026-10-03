package com.sn1persecurity.silentchain.bapp.ai;

import burp.api.montoya.MontoyaApi;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Single source of truth for "may this extension send anything to an AI
 * provider right now?". Wraps {@code api.ai().isEnabled()}, which is true only
 * when the Burp edition supports AI and the user has ticked "Use AI" for this
 * extension.
 *
 * PortSwigger's AI policy applies the check to EVERY outgoing AI request,
 * regardless of provider, so this gate is consulted by every provider, by the
 * dispatcher, and as a hard block in the single third-party egress point
 * ({@code MontoyaHttpClient.send}). It is evaluated per call and never cached,
 * because the user can toggle "Use AI" at runtime. Any failure reads as
 * disabled (fail closed).
 */
public final class AiGate {

    public static final String DISABLED_MESSAGE =
            "AI is disabled for SILENTCHAIN in Burp, so no AI request was sent. Tick 'Use AI' for "
            + "SILENTCHAIN in Extensions > Installed (Burp Suite Professional), and check AI is not "
            + "turned off in Burp's AI settings. This applies to every provider, including Ollama.";

    private final BooleanSupplier probe;
    private final Consumer<String> log;
    private final AtomicReference<Boolean> last = new AtomicReference<>();

    public AiGate(BooleanSupplier probe, Consumer<String> log) {
        this.probe = probe;
        this.log = log;
    }

    public static AiGate forApi(MontoyaApi api) {
        return new AiGate(() -> api.ai().isEnabled(), api.logging()::logToOutput);
    }

    public boolean isEnabled() {
        boolean enabled;
        try {
            enabled = probe.getAsBoolean();
        } catch (Throwable t) {
            enabled = false;
        }
        Boolean previous = last.getAndSet(enabled);
        if (previous == null ? !enabled : previous != enabled) {
            log.accept(enabled
                    ? "SILENTCHAIN: AI is now enabled for this extension."
                    : "SILENTCHAIN: " + DISABLED_MESSAGE);
        }
        return enabled;
    }
}
