package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiNotSentException;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Google Gemini provider. Ported from Community {@code _ask_gemini()}
 * (silentchain_ai_community.py:2774-2790).
 *
 * Endpoints (default URL https://generativelanguage.googleapis.com/v1):
 *   POST /models/{model}:generateContent
 *   GET  /models
 *
 * Auth: x-goog-api-key header. The key is never put in the URL, where it would
 * end up in Burp's Logger and any upstream proxy logs.
 */
public class GeminiProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;
    private final AiGate aiGate;

    public GeminiProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings, AiGate aiGate) {
        this.api = api;
        this.http = http;
        this.settings = settings;
        this.aiGate = aiGate;
    }

    @Override public ProviderId id() { return ProviderId.GEMINI; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isConfigured() {
        return !baseUrl().isBlank() && !cfg().apiKey().isBlank();
    }

    @Override
    public boolean isAvailable() {
        return aiGate.isEnabled() && isConfigured();
    }

    @Override
    public List<String> listModels() {
        if (!aiGate.isEnabled() || cfg().apiKey().isBlank()) return List.of();
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (!r.ok()) return List.of();
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray arr = obj.optJSONArray("models");
            if (arr == null) return List.of();
            List<String> models = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject m = arr.optJSONObject(i);
                if (m != null) {
                    String name = m.optString("name", "");
                    if (!name.isBlank()) {
                        if (name.startsWith("models/")) name = name.substring(7);
                        models.add(name);
                    }
                }
            }
            return models;
        } catch (JSONException e) {
            return List.of();
        }
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        if (!aiGate.isEnabled()) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);
        }
        if (!isConfigured()) {
            api.logging().logToError("Gemini: missing API URL or API key.");
            throw new AiNotSentException("Gemini is not configured.");
        }
        String model = cfg().model();
        if (model.isBlank()) model = "gemini-1.5-flash";

        String url = generateContentUrl(baseUrl(), model);

        JSONObject body = new JSONObject();

        JSONObject systemInstruction = new JSONObject();
        JSONArray sysParts = new JSONArray();
        sysParts.put(new JSONObject().put("text", systemPrompt));
        systemInstruction.put("parts", sysParts);
        body.put("system_instruction", systemInstruction);

        JSONArray contents = new JSONArray();
        JSONObject userContent = new JSONObject();
        userContent.put("role", "user");
        JSONArray userParts = new JSONArray();
        userParts.put(new JSONObject().put("text", userPrompt));
        userContent.put("parts", userParts);
        contents.put(userContent);
        body.put("contents", contents);

        JSONObject genConfig = new JSONObject();
        genConfig.put("temperature", 0.0);
        genConfig.put("maxOutputTokens", settings.maxTokens());
        body.put("generationConfig", genConfig);

        HttpReply r = http.postJson(url, authHeaders(), body.toString());
        if (r.status() == MontoyaHttpClient.STATUS_AI_DISABLED) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);
        }
        if (!r.ok()) {
            api.logging().logToError("Gemini HTTP " + r.status() + ": " + truncate(r.body()));
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(r.body());
            JSONArray candidates = obj.optJSONArray("candidates");
            if (candidates == null || candidates.length() == 0) return Optional.empty();
            JSONObject first = candidates.getJSONObject(0);
            JSONObject content = first.optJSONObject("content");
            if (content == null) return Optional.empty();
            JSONArray parts = content.optJSONArray("parts");
            if (parts == null || parts.length() == 0) return Optional.empty();
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < parts.length(); i++) {
                JSONObject p = parts.optJSONObject(i);
                if (p != null) {
                    out.append(p.optString("text", ""));
                }
            }
            return out.length() == 0 ? Optional.empty() : Optional.of(out.toString());
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (!aiGate.isEnabled()) return TestResult.fail(AiGate.DISABLED_MESSAGE);
        if (baseUrl().isBlank()) return TestResult.fail("Gemini URL is empty.");
        if (cfg().apiKey().isBlank()) return TestResult.fail("Gemini API key is empty.");
        HttpReply r = http.get(baseUrl() + "/models", authHeaders());
        if (r.status() == 0) return TestResult.fail("Gemini unreachable (DNS / TLS / connection error).");
        if (r.status() == 400 || r.status() == 401 || r.status() == 403) {
            return TestResult.fail("Gemini rejected the API key (HTTP " + r.status() + ").");
        }
        if (!r.ok()) return TestResult.fail("Gemini returned HTTP " + r.status() + ".");
        return TestResult.ok("Gemini reachable.");
    }

    /** {base}/models/{model}:generateContent with the model as one encoded path segment. */
    static String generateContentUrl(String baseUrl, String model) {
        String segment = URLEncoder.encode(model, StandardCharsets.UTF_8).replace("+", "%20");
        return baseUrl + "/models/" + segment + ":generateContent";
    }

    private Map<String, String> authHeaders() {
        return Map.of("x-goog-api-key", cfg().apiKey());
    }

    private ProviderConfig cfg() {
        return settings.config(id());
    }

    private String baseUrl() {
        String configured = cfg().apiUrl();
        String url = !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 240 ? s.substring(0, 240) + "..." : s;
    }
}
