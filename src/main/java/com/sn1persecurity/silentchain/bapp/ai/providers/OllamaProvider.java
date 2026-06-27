package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Ollama provider. Ported from Community {@code _ask_ollama()}
 * (silentchain_ai_community.py:2676-2732).
 *
 * Endpoints (default URL http://localhost:11434):
 *   POST /api/generate  -> single-turn completion
 *   GET  /api/tags      -> model list
 *
 * No API key.
 */
public class OllamaProvider implements LlmProvider {

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;

    public OllamaProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings) {
        this.api = api;
        this.http = http;
        this.settings = settings;
    }

    @Override public ProviderId id() { return ProviderId.OLLAMA; }

    @Override public boolean usesApiKey() { return false; }

    @Override
    public boolean isAvailable() {
        return !baseUrl().isBlank();
    }

    @Override
    public List<String> listModels() {
        String url = baseUrl() + "/api/tags";
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
                    if (!name.isBlank()) models.add(name);
                }
            }
            return models;
        } catch (JSONException e) {
            return List.of();
        }
    }

    @Override
    public Optional<String> analyze(String systemPrompt, String userPrompt) {
        String model = settings.model();
        if (model.isBlank()) {
            api.logging().logToError("Ollama: no model configured.");
            return Optional.empty();
        }
        String url = baseUrl() + "/api/generate";

        // Ollama /api/generate takes a single prompt; concatenate system + user.
        String combined = "[SYSTEM]\n" + systemPrompt + "\n\n[USER]\n" + userPrompt;

        JSONObject body = new JSONObject();
        body.put("model", model);
        body.put("prompt", combined);
        body.put("stream", false);
        body.put("format", "json");

        JSONObject options = new JSONObject();
        options.put("temperature", 0.0);
        options.put("num_predict", settings.maxTokens());
        body.put("options", options);

        HttpReply r = http.postJson(url, Collections.emptyMap(), body.toString());
        if (!r.ok()) {
            api.logging().logToError("Ollama HTTP " + r.status() + ": " + r.body());
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(r.body());
            String response = obj.optString("response", "");
            return response.isBlank() ? Optional.empty() : Optional.of(response);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public TestResult testConnection() {
        if (!isAvailable()) {
            return TestResult.fail("Ollama URL is empty.");
        }
        HttpReply r = http.get(baseUrl() + "/api/tags", Collections.emptyMap());
        if (r.status() == 0) {
            return TestResult.fail("Ollama unreachable (DNS / TLS / connection error).");
        }
        if (!r.ok()) {
            return TestResult.fail("Ollama returned HTTP " + r.status() + ".");
        }
        return TestResult.ok("Ollama reachable. " + listModels().size() + " models found.");
    }

    private String baseUrl() {
        String configured = settings.apiUrl();
        String url = configured != null && !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
