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
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Constructs every {@link LlmProvider}, holds them in an enum-keyed map, and
 * routes every analyze / test / listModels call based on the currently
 * configured {@link Settings#provider()}.
 */
public class AiDispatcher {

    private final Settings settings;
    private final ThreadPool threadPool;
    private final Map<ProviderId, LlmProvider> providers = new EnumMap<>(ProviderId.class);

    public AiDispatcher(MontoyaApi api, MontoyaHttpClient http, Settings settings, ThreadPool threadPool) {
        this.settings = settings;
        this.threadPool = threadPool;

        providers.put(ProviderId.BURP_AI,       new BurpAiProvider(api));
        providers.put(ProviderId.OLLAMA,        new OllamaProvider(api, http, settings));
        providers.put(ProviderId.OPENAI,        new OpenAiProvider(api, http, settings));
        providers.put(ProviderId.CLAUDE,        new ClaudeProvider(api, http, settings));
        providers.put(ProviderId.GEMINI,        new GeminiProvider(api, http, settings));
        providers.put(ProviderId.AZURE_FOUNDRY, new AzureFoundryProvider(api, http, settings));
    }

    public LlmProvider current() {
        return providers.get(settings.provider());
    }

    public LlmProvider get(ProviderId id) {
        return providers.get(id);
    }

    public boolean isAvailable() {
        return current().isAvailable();
    }

    public List<String> listModels() {
        return current().listModels();
    }

    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        return current().analyze(systemPrompt, userPrompt);
    }

    public void analyzeAsync(String systemPrompt, String userPrompt, Consumer<Optional<String>> callback) {
        threadPool.submit(() -> callback.accept(analyze(systemPrompt, userPrompt)));
    }

    public TestResult testConnection(ProviderId which) {
        return providers.get(which).testConnection();
    }
}
