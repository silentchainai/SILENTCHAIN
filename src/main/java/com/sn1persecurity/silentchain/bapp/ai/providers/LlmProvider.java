package com.sn1persecurity.silentchain.bapp.ai.providers;

import java.util.List;
import java.util.Optional;

/**
 * Common interface for every LLM provider supported by the BApp edition.
 *
 * Implementations:
 *   - {@link BurpAiProvider}            (default, Burp AI via Montoya; uses Burp AI credits)
 *   - {@link OllamaProvider}            (third-party, via Montoya HTTP)
 *   - {@link OpenAiProvider}            (third-party, via Montoya HTTP)
 *   - {@link ClaudeProvider}            (third-party, via Montoya HTTP)
 *   - {@link GeminiProvider}            (third-party, via Montoya HTTP)
 *   - {@link AzureFoundryProvider}      (third-party, via Montoya HTTP)
 *
 * Every provider, including the third-party ones, is gated on Burp's AI
 * permission ({@link com.sn1persecurity.silentchain.bapp.ai.AiGate}): when it is
 * off, {@link #isAvailable()} is false and no request is sent.
 */
public interface LlmProvider {

    /** Stable identifier (enum). */
    ProviderId id();

    /** Human-readable name shown in the AI Provider dropdown. */
    default String displayName() { return id().displayName(); }

    /**
     * True if usable right now: AI is enabled for the extension in Burp AND the
     * provider is configured. Cheap; never makes a network call.
     */
    boolean isAvailable();

    /** True if the provider has the endpoint/credentials it needs (ignores the AI gate). */
    boolean isConfigured();

    /** True if the provider authenticates with an API key. */
    boolean usesApiKey();

    /** Default endpoint URL for the provider (for the UI to auto-fill). */
    default String defaultUrl() { return id().defaultUrl(); }

    /** Live model list. May make a network call. Empty list on failure or when AI is disabled. */
    List<String> listModels();

    /**
     * Submit a system+user prompt and return the raw AI response content
     * (NOT yet parsed by {@link com.sn1persecurity.silentchain.bapp.ai.ResponseParser}).
     * Empty if the request was sent but failed or returned nothing.
     *
     * @throws com.sn1persecurity.silentchain.bapp.ai.AiNotSentException if nothing
     *         was sent (AI disabled for the extension, or the provider not configured)
     */
    Optional<String> analyze(String systemPrompt, String userPrompt);

    /** Round-trip test: availability + a tiny request + response receipt. */
    TestResult testConnection();
}
