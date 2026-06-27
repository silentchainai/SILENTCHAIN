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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Google Gemini provider. Ported from Community {@code _ask_gemini()}
 * (silentchain_ai_community.py:2774-2790).
 *
 * Endpoints (default URL https://generativelanguage.googleapis.com/v1):
 *   POST /models/{model}:generateContent?key={apiKey}
 *   GET  /models?key={apiKey}
 *
 * Auth: API key passed as query parameter.
 */
public class GeminiProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;

    public GeminiProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings) {
        this.api = api;
        this.http = http;
        this.settings = settings;
    }

    @Override public ProviderId id() { return ProviderId.GEMINI; }

    @Override public boolean usesApiKey() { return true; }

    @Override
    public boolean isAvailable() {
        return !baseUrl().isBlank() && !settings.apiKey().isBlank();
    }

    @Override
    public List<String> listModels() {
        if (settings.apiKey().isBlank()) return List.of();
        String url = baseUrl() + "/models?key=" + enc(settings.apiKey());
        HttpReply r = http.get(url, Collections.emptyMap());
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
        if (!isAvailable()) {
            api.logging().logToError("Gemini: missing API URL or API key.");
            return Optional.empty();
        }
        String model = settings.model();
        if (model.isBlank()) model = "gemini-1.5-flash";

        String url = baseUrl() + "/models/" + model + ":generateContent?key=" + enc(settings.apiKey());

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

        HttpReply r = http.postJson(url, Collections.emptyMap(), body.toString());
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
        if (baseUrl().isBlank()) return TestResult.fail("Gemini URL is empty.");
        if (settings.apiKey().isBlank()) return TestResult.fail("Gemini API key is empty.");
        HttpReply r = http.get(baseUrl() + "/models?key=" + enc(settings.apiKey()), Collections.emptyMap());
        if (r.status() == 0) return TestResult.fail("Gemini unreachable (DNS / TLS / connection error).");
        if (r.status() == 400 || r.status() == 401 || r.status() == 403) {
            return TestResult.fail("Gemini rejected the API key (HTTP " + r.status() + ").");
        }
        if (!r.ok()) return TestResult.fail("Gemini returned HTTP " + r.status() + ".");
        return TestResult.ok("Gemini reachable.");
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
