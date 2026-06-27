package com.sn1persecurity.silentchain.bapp.ai.providers;

import java.util.List;
import java.util.Optional;

/**
 * Common interface for every LLM provider supported by the BApp edition.
 *
 * Implementations:
 *   - {@link BurpAiProvider}            (default, in-process via Montoya AI)
 *   - {@link OllamaProvider}            (third-party, via Montoya HTTP)
 *   - {@link OpenAiProvider}            (third-party, via Montoya HTTP)
 *   - {@link ClaudeProvider}            (third-party, via Montoya HTTP)
 *   - {@link GeminiProvider}            (third-party, via Montoya HTTP)
 *   - {@link AzureFoundryProvider}      (third-party, via Montoya HTTP)
 */
public interface LlmProvider {

    /** Stable identifier (enum). */
    ProviderId id();

    /** Human-readable name shown in the AI Provider dropdown. */
    default String displayName() { return id().displayName(); }

    /** True if usable right now. Cheap; may not make a network call. */
    boolean isAvailable();

    /** True if the provider authenticates with an API key. */
    boolean usesApiKey();

    /** Default endpoint URL for the provider (for the UI to auto-fill). */
    default String defaultUrl() { return id().defaultUrl(); }

    /** Live model list. May make a network call. Empty list on failure. */
    List<String> listModels();

    /**
     * Submit a system+user prompt and return the raw AI response content
     * (NOT yet parsed by {@link com.sn1persecurity.silentchain.bapp.ai.ResponseParser}).
     * Empty if the call failed or returned nothing.
     */
    Optional<String> analyze(String systemPrompt, String userPrompt);

    /** Round-trip test: availability + a tiny prompt + response receipt. */
    TestResult testConnection();
}
