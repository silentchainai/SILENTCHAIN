package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.ai.chat.PromptException;
import burp.api.montoya.ai.chat.PromptResponse;
import burp.api.montoya.logging.Logging;

import java.util.List;
import java.util.Optional;

/**
 * Default provider — wraps the in-process Burp AI API exposed via
 * {@code MontoyaApi.ai()}. Requires EnhancedCapability.AI_FEATURES (declared
 * by the extension entry point).
 */
public class BurpAiProvider implements LlmProvider {

    private final MontoyaApi api;
    private final Logging logging;

    public BurpAiProvider(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
    }

    @Override public ProviderId id() { return ProviderId.BURP_AI; }

    @Override public boolean usesApiKey() { return false; }

    @Override
    public boolean isAvailable() {
        try {
            return api.ai().isEnabled();
        } catch (Throwable t) {
            logging.logToError("Burp AI availability check failed: " + t.getMessage());
            return false;
        }
    }

    @Override
    public List<String> listModels() {
        return List.of("Burp AI default");
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!isAvailable()) {
            logging.logToOutput("Burp AI not enabled — analysis skipped.");
            return Optional.empty();
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
        if (!isAvailable()) {
            return TestResult.fail("Burp AI is not enabled in this Burp Pro project.");
        }
        try {
            Optional<String> reply = analyze(
                    "Reply with the literal string OK and nothing else.",
                    "ping");
            if (reply.isEmpty()) {
                return TestResult.fail("Burp AI returned no content.");
            }
            return TestResult.ok("Burp AI responded.");
        } catch (Throwable t) {
            return TestResult.fail("Burp AI test failed: " + t.getMessage());
        }
    }
}
