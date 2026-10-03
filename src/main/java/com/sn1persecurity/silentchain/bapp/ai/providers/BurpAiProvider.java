package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.ai.chat.PromptException;
import burp.api.montoya.ai.chat.PromptResponse;
import burp.api.montoya.logging.Logging;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiNotSentException;

import java.util.List;
import java.util.Optional;

/**
 * Default provider - Burp AI via {@code MontoyaApi.ai()}. Prompts are sent
 * through Burp to PortSwigger's Burp AI service and consume Burp AI credits.
 * Requires EnhancedCapability.AI_FEATURES (declared by the extension entry
 * point) and "Use AI" enabled for the extension.
 */
public class BurpAiProvider implements LlmProvider {

    private final MontoyaApi api;
    private final Logging logging;
    private final AiGate aiGate;

    public BurpAiProvider(MontoyaApi api, AiGate aiGate) {
        this.api = api;
        this.logging = api.logging();
        this.aiGate = aiGate;
    }

    @Override public ProviderId id() { return ProviderId.BURP_AI; }

    @Override public boolean usesApiKey() { return false; }

    @Override public boolean isConfigured() { return true; }

    @Override
    public boolean isAvailable() {
        return aiGate.isEnabled();
    }

    @Override
    public List<String> listModels() {
        return List.of("Burp AI default");
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!aiGate.isEnabled()) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);
        }
        try {
            Prompt prompt = api.ai().prompt();
            PromptResponse response = prompt.execute(
                    Message.systemMessage(systemPrompt),
                    Message.userMessage(userPrompt)
            );
            return Optional.ofNullable(response.content());
        } catch (PromptException e) {
            logging.logToError("Burp AI prompt failed: " + e.getMessage());
            return Optional.empty();
        } catch (Throwable t) {
            logging.logToError("Unexpected error invoking Burp AI: " + t.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (!aiGate.isEnabled()) {
            return TestResult.fail(AiGate.DISABLED_MESSAGE);
        }
        Optional<String> reply;
        try {
            reply = analyze("Reply with the literal string OK and nothing else.", "ping");
        } catch (AiNotSentException e) {
            return TestResult.fail(e.getMessage());
        }
        if (reply.isEmpty()) {
            return TestResult.fail("Burp AI returned no content (check your Burp AI credits).");
        }
        return TestResult.ok("Burp AI responded.");
    }
}
