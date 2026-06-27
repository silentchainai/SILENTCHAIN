package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Anthropic Claude provider. Ported from Community {@code _ask_claude()}
 * (silentchain_ai_community.py:2754-2772).
 *
 * Endpoints (default URL https://api.anthropic.com/v1):
 *   POST /messages
 *   GET  /models
 *
 * Auth: x-api-key + anthropic-version: 2023-06-01
 */
public class ClaudeProvider implements LlmProvider {

    private static final String ANTHROPIC_VERSION = "2023-06-01";

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;

    public ClaudeProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings) {
        this.api = api;
        this.http = http;
        this.settings = settings;
    }

    @Override public ProviderId id() { return ProviderId.CLAUDE; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isAvailable() {
        return !baseUrl().isBlank() && !settings.apiKey().isBlank();
    }

    @Override
    public List<String> listModels() {
        if (settings.apiKey().isBlank()) return List.of();
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (!r.ok()) return List.of();
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray arr = obj.optJSONArray("data");
            if (arr == null) return List.of();
            List<String> models = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject m = arr.optJSONObject(i);
                if (m != null) {
                    String id = m.optString("id", "");
                    if (!id.isBlank()) models.add(id);
                }
            }
            return models;
        } catch (JSONException e) {
            return List.of();
        }
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!isAvailable()) {
            api.logging().logToError("Claude: missing API URL or API key.");
            return Optional.empty();
        }
        String model = settings.model();
        if (model.isBlank()) model = "claude-3-5-sonnet-latest";

        JSONObject body = new JSONObject();
        body.put("model", model);
        body.put("max_tokens", settings.maxTokens());
        body.put("system", systemPrompt);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "user").put("content", userPrompt));
        body.put("messages", messages);

        HttpReply r = http.postJson(baseUrl() + "/messages", authHeaders(), body.toString());
        if (!r.ok()) {
            api.logging().logToError("Claude HTTP " + r.status() + ": " + truncate(r.body()));
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray content = obj.optJSONArray("content");
            if (content == null || content.length() == 0) return Optional.empty();
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < content.length(); i++) {
                JSONObject block = content.optJSONObject(i);
                if (block != null && "text".equals(block.optString("type"))) {
                    out.append(block.optString("text", ""));
                }
            }
            return out.length() == 0 ? Optional.empty() : Optional.of(out.toString());
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (baseUrl().isBlank()) return TestResult.fail("Claude URL is empty.");
        if (settings.apiKey().isBlank()) return TestResult.fail("Claude API key is empty.");
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (r.status() == 0) return TestResult.fail("Claude unreachable (DNS / TLS / connection error).");
        if (r.status() == 401) return TestResult.fail("Claude rejected the API key (HTTP 401).");
        if (!r.ok()) return TestResult.fail("Claude returned HTTP " + r.status() + ".");
        return TestResult.ok("Claude reachable.");
    }

    private Map<String, String> authHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("x-api-key", settings.apiKey());
        h.put("anthropic-version", ANTHROPIC_VERSION);
        return h;
    }

    private String baseUrl() {
        String configured = settings.apiUrl();
        String url = configured != null && !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 240 ? s.substring(0, 240) + "..." : s;
    }
}
