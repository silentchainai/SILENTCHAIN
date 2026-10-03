package com.sn1persecurity.silentchain.bapp.ai;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.providers.AzureFoundryProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.BurpAiProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.ClaudeProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.GeminiProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.LlmProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.OllamaProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.OpenAiProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.ai.providers.TestResult;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Constructs every {@link LlmProvider}, holds them in an enum-keyed map, and
 * routes every analyze / test / listModels call based on the currently
 * configured {@link Settings#provider()}.
 *
 * Every entry point checks {@link AiGate} first, so no provider is reached when
 * AI is disabled for the extension (the providers and the HTTP egress point
 * check it again).
 */
public class AiDispatcher {

    /** Model names shown in the UI must look like model names (they come from the provider). */
    private static final Pattern MODEL_NAME = Pattern.compile("[A-Za-z0-9._:/@+\\-]{1,200}");

    private final MontoyaApi api;
    private final Settings settings;
    private final AiGate aiGate;
    private final Map<ProviderId, LlmProvider> providers = new EnumMap<>(ProviderId.class);

    public AiDispatcher(MontoyaApi api, MontoyaHttpClient http, Settings settings, AiGate aiGate) {
        this.api = api;
        this.settings = settings;
        this.aiGate = aiGate;

        providers.put(ProviderId.BURP_AI,       new BurpAiProvider(api, aiGate));
        providers.put(ProviderId.OLLAMA,        new OllamaProvider(api, http, settings, aiGate));
        providers.put(ProviderId.OPENAI,        new OpenAiProvider(api, http, settings, aiGate));
        providers.put(ProviderId.CLAUDE,        new ClaudeProvider(api, http, settings, aiGate));
        providers.put(ProviderId.GEMINI,        new GeminiProvider(api, http, settings, aiGate));
        providers.put(ProviderId.AZURE_FOUNDRY, new AzureFoundryProvider(api, http, settings, aiGate));
    }

    public LlmProvider current() {
        return providers.get(settings.provider());
    }

    /** AI enabled for the extension AND the selected provider is configured. */
    public boolean isAvailable() {
        return aiGate.isEnabled() && current().isAvailable();
    }

    /** The selected provider has the endpoint/credentials it needs (ignores the AI gate). */
    public boolean isConfigured() {
        return current().isConfigured();
    }

    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!aiGate.isEnabled()) {
            return Optional.empty();
        }
        return current().analyze(systemPrompt, userPrompt);
    }

    public List<String> listModels(ProviderId which) {
        if (!aiGate.isEnabled()) {
            return List.of();
        }
        return plausibleModelNames(providers.get(which).listModels());
    }

    private List<String> plausibleModelNames(List<String> names) {
        List<String> kept = new ArrayList<>();
        for (String name : names) {
            if (name != null && MODEL_NAME.matcher(name).matches()) {
                kept.add(name);
            }
        }
        if (kept.size() < names.size()) {
            api.logging().logToError("SILENTCHAIN: ignored " + (names.size() - kept.size())
                    + " model name(s) with unexpected characters from the provider.");
        }
        return kept;
    }

    public TestResult testConnection(ProviderId which) {
        if (!aiGate.isEnabled()) {
            return TestResult.fail(AiGate.DISABLED_MESSAGE);
        }
        return providers.get(which).testConnection();
    }
}
