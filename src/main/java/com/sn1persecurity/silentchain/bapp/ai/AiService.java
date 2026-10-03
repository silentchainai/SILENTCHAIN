package com.sn1persecurity.silentchain.bapp.ai;

import java.util.Optional;

/**
 * Analysis facade over {@link AiDispatcher}: pairs every user prompt with the
 * SILENTCHAIN system prompt so callers never handle it.
 */
public class AiService {

    private final AiDispatcher dispatcher;

    public AiService(AiDispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    /** AI enabled for the extension AND the selected provider is configured. */
    public boolean isAvailable() {
        return dispatcher.isAvailable();
    }

    /** The selected provider has the endpoint/credentials it needs (ignores the AI gate). */
    public boolean isConfigured() {
        return dispatcher.isConfigured();
    }

    /** @throws AiNotSentException if nothing could be sent (see {@link AiDispatcher#analyze}) */
    public Optional<String> analyze(String userPrompt) {
        return dispatcher.analyze(PromptLibrary.systemPrompt(), userPrompt);
    }
}
