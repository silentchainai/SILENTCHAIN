package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
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
 * The {@link Settings#model()} field stores the Azure deployment name, NOT a
 * model id. Azure does not expose a /models list per deployment; we report the
 * single configured deployment as the available "model".
 *
 * Auth: api-key header.
 */
public class AzureFoundryProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;

    public AzureFoundryProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings) {
        this.api = api;
        this.http = http;
        this.settings = settings;
    }

    @Override public ProviderId id() { return ProviderId.AZURE_FOUNDRY; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isAvailable() {
        return !baseUrl().isBlank()
                && !settings.apiKey().isBlank()
                && !settings.model().isBlank()
                && !settings.azureApiVersion().isBlank();
    }

    @Override
    public List<String> listModels() {
        return settings.model().isBlank() ? List.of() : List.of(settings.model());
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!isAvailable()) {
            api.logging().logToError("Azure Foundry: missing URL / key / deployment / api-version.");
            return Optional.empty();
        }

        String url = baseUrl()
                + "/openai/deployments/" + enc(settings.model())
                + "/chat/completions?api-version=" + enc(settings.azureApiVersion());

        JSONObject body = new JSONObject();
        body.put("max_tokens", settings.maxTokens());
        body.put("temperature", 0.0);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
        messages.put(new JSONObject().put("role", "user").put("content", userPrompt));
        body.put("messages", messages);

        Map<String, String> headers = Map.of("api-key", settings.apiKey());

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
        if (baseUrl().isBlank()) return TestResult.fail("Azure URL is empty.");
        if (settings.apiKey().isBlank()) return TestResult.fail("Azure API key is empty.");
        if (settings.model().isBlank()) return TestResult.fail("Azure deployment name is empty.");

        // Minimal round-trip via a one-token prompt.
        Optional<String> reply = analyze(
                "Reply with the literal string OK and nothing else.",
                "ping");
        if (reply.isEmpty()) {
            return TestResult.fail("Azure deployment did not return content. Check URL, key, deployment name, and api-version.");
        }
        return TestResult.ok("Azure deployment responded.");
    }

    private String baseUrl() {
        String configured = settings.apiUrl();
        String url = configured != null && !configured.isBlank() ? configured : id().defaultUrl();
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
