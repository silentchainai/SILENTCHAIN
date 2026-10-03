package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Azure Foundry / Azure OpenAI provider. Ported from Community
 * {@code _ask_azure_foundry()} (silentchain_ai_community.py:2792-2813).
 *
 * Endpoint shape (default URL https://YOUR-RESOURCE.openai.azure.com):
 *   POST /openai/deployments/{deployment}/chat/completions?api-version={ver}
 *
 * The provider's "model" field stores the Azure deployment name, NOT a model
 * id. Azure does not expose a /models list per deployment; we report the
 * single configured deployment as the available "model".
 *
 * Auth: api-key header.
 */
public class AzureFoundryProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;
    private final AiGate aiGate;

    public AzureFoundryProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings, AiGate aiGate) {
        this.api = api;
        this.http = http;
        this.settings = settings;
        this.aiGate = aiGate;
    }

    @Override public ProviderId id() { return ProviderId.AZURE_FOUNDRY; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isConfigured() {
        ProviderConfig cfg = cfg();
        return !baseUrl().isBlank()
                && !cfg.apiKey().isBlank()
                && !cfg.model().isBlank()
                && !settings.azureApiVersion().isBlank();
    }

    @Override
    public boolean isAvailable() {
        return aiGate.isEnabled() && isConfigured();
    }

    @Override
    public List<String> listModels() {
        String deployment = cfg().model();
        return deployment.isBlank() ? List.of() : List.of(deployment);
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!aiGate.isEnabled()) {
            return Optional.empty();
        }
        if (!isConfigured()) {
            api.logging().logToError("Azure Foundry: missing URL / key / deployment / api-version.");
            return Optional.empty();
        }
        ProviderConfig cfg = cfg();

        String url = baseUrl()
                + "/openai/deployments/" + enc(cfg.model())
                + "/chat/completions?api-version=" + enc(settings.azureApiVersion());

        JSONObject body = new JSONObject();
        body.put("max_tokens", settings.maxTokens());
        body.put("temperature", 0.0);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
        messages.put(new JSONObject().put("role", "user").put("content", userPrompt));
        body.put("messages", messages);

        Map<String, String> headers = Map.of("api-key", cfg.apiKey());

        HttpReply r = http.postJson(url, headers, body.toString());
        if (!r.ok()) {
            api.logging().logToError("Azure HTTP " + r.status() + ": " + truncate(r.body()));
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray choices = obj.optJSONArray("choices");
            if (choices == null || choices.length() == 0) return Optional.empty();
            JSONObject msg = choices.getJSONObject(0).optJSONObject("message");
            if (msg == null) return Optional.empty();
            String content = msg.optString("content", "");
            return content.isBlank() ? Optional.empty() : Optional.of(content);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (!aiGate.isEnabled()) return TestResult.fail(AiGate.DISABLED_MESSAGE);
        if (baseUrl().isBlank()) return TestResult.fail("Azure URL is empty.");
        if (cfg().apiKey().isBlank()) return TestResult.fail("Azure API key is empty.");
        if (cfg().model().isBlank()) return TestResult.fail("Azure deployment name is empty.");

        // Minimal round-trip via a one-token prompt.
        Optional<String> reply = analyze(
                "Reply with the literal string OK and nothing else.",
                "ping");
        if (reply.isEmpty()) {
            return TestResult.fail("Azure deployment did not return content. Check URL, key, deployment name, and api-version.");
        }
        return TestResult.ok("Azure deployment responded.");
    }

    private ProviderConfig cfg() {
        return settings.config(id());
    }

    private String baseUrl() {
        String configured = cfg().apiUrl();
        String url = !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 240 ? s.substring(0, 240) + "..." : s;
    }
}
