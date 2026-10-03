package com.sn1persecurity.silentchain.bapp.ai.providers;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiNotSentException;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.Settings.StructuredOutput;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient.HttpReply;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Ollama provider.
 *
 * Endpoints (default URL http://localhost:11434):
 *   POST /api/chat      -> chat completion with system/user roles (applies the
 *                          model's chat template; far more reliable on small
 *                          local instruct/coder models than a raw /api/generate
 *                          prompt blob)
 *   GET  /api/tags      -> model list
 *
 * Structured output: by default the request sends a JSON *schema* (Ollama
 * structured outputs, since 0.5.0) that forces the shape {"findings":[...]},
 * which {@link com.sn1persecurity.silentchain.bapp.ai.ResponseParser} unwraps.
 * This is the fix for small models emitting a bare "{}" under the legacy
 * format:"json" grammar. Also sets num_ctx so the prompt is never silently
 * truncated, keep_alive to avoid model reloads between requests, and think:false
 * so reasoning models (qwen3, deepseek-r1) skip the slow &lt;think&gt; phase that
 * otherwise overruns the request timeout.
 *
 * No API key. Gated on Burp's AI permission like every other provider: the
 * endpoint is user-configurable and need not be local.
 */
public class OllamaProvider implements LlmProvider {

    private static final String CHAT_ENDPOINT = "/api/chat";
    private static final double TEMPERATURE = 0.0;
    private static final String KEEP_ALIVE = "10m";
    private static final Pattern EMPTY_OBJECT = Pattern.compile("\\{\\s*\\}");

    private final MontoyaApi api;
    private final MontoyaHttpClient http;
    private final Settings settings;
    private final AiGate aiGate;

    public OllamaProvider(MontoyaApi api, MontoyaHttpClient http, Settings settings, AiGate aiGate) {
        this.api = api;
        this.http = http;
        this.settings = settings;
        this.aiGate = aiGate;
    }

    @Override public ProviderId id() { return ProviderId.OLLAMA; }

    @Override public boolean usesApiKey() { return false; }

    @Override
    public boolean isConfigured() {
        return !baseUrl().isBlank();
    }

    @Override
    public boolean isAvailable() {
        return aiGate.isEnabled() && isConfigured();
    }

    @Override
    public List<String> listModels() {
        if (!aiGate.isEnabled()) return List.of();
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
        if (!aiGate.isEnabled()) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);
        }
        String model = resolveModel();
        if (model.isBlank()) {
            return Optional.empty();
        }

        JSONObject body = buildChatBody(model, systemPrompt, userPrompt,
                settings.maxTokens(), settings.ollamaNumCtx(), TEMPERATURE,
                settings.ollamaStructuredOutput(), KEEP_ALIVE);

        HttpReply r = http.postJson(baseUrl() + CHAT_ENDPOINT, Collections.emptyMap(), body.toString());
        if (r.status() == MontoyaHttpClient.STATUS_AI_DISABLED) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);
        }
        if (!r.ok()) {
            api.logging().logToError("Ollama HTTP " + r.status() + ": " + r.body());
            return Optional.empty();
        }

        Optional<String> content = extractContent(r.body());
        if (content.isEmpty()) {
            return Optional.empty();
        }

        if (isDegenerateEmptyObject(content.get())) {
            api.logging().logToError("Ollama: model '" + model + "' returned an empty JSON object {} "
                    + "(zero findings, likely NOT benign). The prompt may have overflowed the context "
                    + "window or the model ignored the output schema. Try: raise 'Ollama context (num_ctx)', "
                    + "keep 'Structured output' = schema, or use a more capable local model.");
        }
        return content;
    }

    @Override
    public TestResult testConnection() {
        if (!aiGate.isEnabled()) {
            return TestResult.fail(AiGate.DISABLED_MESSAGE);
        }
        if (!isConfigured()) {
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

    // ---- Request building (pure, testable) ---------------------------------

    /**
     * Build the /api/chat request body. Pure and static so it can be unit-tested
     * without a live Burp/Ollama.
     */
    static JSONObject buildChatBody(String model, String systemPrompt, String userPrompt,
                                    int numPredict, int numCtx, double temperature,
                                    StructuredOutput mode, String keepAlive) {
        JSONObject body = new JSONObject();
        body.put("model", model);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
        messages.put(new JSONObject().put("role", "user").put("content", userPrompt));
        body.put("messages", messages);

        body.put("stream", false);

        // Disable model "thinking". Reasoning models (qwen3, deepseek-r1, ...) otherwise emit a
        // long <think> block before the answer - e.g. qwen3:8b spends ~75s thinking vs ~15s with
        // it off, for identical findings - which blows past the request timeout. Harmless / ignored
        // on non-reasoning models (verified on llama3.1/mistral/codellama/deepseek-coder-v2).
        body.put("think", false);

        switch (mode) {
            case SCHEMA -> body.put("format", findingsSchema());
            case JSON -> body.put("format", "json");
            case OFF -> { /* no format field; rely on the prompt (matches cloud providers) */ }
        }

        JSONObject options = new JSONObject();
        options.put("temperature", temperature);
        options.put("num_predict", numPredict);
        options.put("num_ctx", numCtx);
        // Discourage the repetition loops small models fall into at temperature 0 (a runaway
        // string field otherwise fills num_predict and truncates the JSON). Complements the
        // schema maxLength hard-bound in findingsSchema().
        options.put("repeat_penalty", 1.3);
        body.put("options", options);

        body.put("keep_alive", keepAlive);
        return body;
    }

    /**
     * JSON schema forcing {@code {"findings":[{finding}, ...]}}. Only title + severity
     * are required per item so the model is not forced to hallucinate CWE/OWASP/detail
     * on benign traffic; an empty findings array is valid ({@code {"findings":[]}}).
     * Field names match {@code ResponseParser.parseFinding} (Community's 8-field finding -
     * no {@code background}).
     *
     * The string fields carry {@code maxLength} and the array carries {@code maxItems}:
     * Ollama hard-enforces these in the generation grammar, so a small model that falls
     * into a repetition loop (a known greedy-decoding failure) has its string forced
     * closed instead of running to num_predict and truncating the JSON mid-string
     * (which parses to zero findings). Limits are generous - full multi-sentence
     * writeups fit well within them.
     */
    static JSONObject findingsSchema() {
        JSONObject props = new JSONObject();
        props.put("title", strField(200));
        props.put("severity", new JSONObject()
                .put("type", "string")
                .put("enum", new JSONArray().put("High").put("Medium").put("Low").put("Information")));
        props.put("confidence", new JSONObject()
                .put("type", "integer").put("minimum", 0).put("maximum", 100));
        props.put("cwe", strField(16));
        props.put("owasp", strField(16));
        props.put("detail", strField(1200));
        props.put("evidence", strField(1000));
        props.put("remediation", strField(1000));

        JSONObject item = new JSONObject();
        item.put("type", "object");
        item.put("properties", props);
        item.put("required", new JSONArray().put("title").put("severity"));

        JSONObject findings = new JSONObject();
        findings.put("type", "array");
        findings.put("items", item);
        findings.put("maxItems", 25);

        JSONObject schema = new JSONObject();
        schema.put("type", "object");
        schema.put("properties", new JSONObject().put("findings", findings));
        schema.put("required", new JSONArray().put("findings"));
        return schema;
    }

    private static JSONObject strField(int maxLength) {
        return new JSONObject().put("type", "string").put("maxLength", maxLength);
    }

    // ---- Response handling (pure, testable) --------------------------------

    /**
     * Extract the assistant text from an Ollama response. Handles both the
     * /api/chat shape ({@code {"message":{"content":"..."}}}) and the legacy
     * /api/generate shape ({@code {"response":"..."}}). Empty/blank -> empty.
     */
    static Optional<String> extractContent(String rawJson) {
        if (rawJson == null || rawJson.isBlank()) {
            return Optional.empty();
        }
        try {
            JSONObject obj = new JSONObject(rawJson);
            JSONObject message = obj.optJSONObject("message");
            if (message != null) {
                String c = message.optString("content", "");
                if (!c.isBlank()) {
                    return Optional.of(c);
                }
            }
            String r = obj.optString("response", "");
            return r.isBlank() ? Optional.empty() : Optional.of(r);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    /**
     * True if the model returned a degenerate empty object ("{}" possibly wrapped
     * in code fences / whitespace) - the classic small-model failure under grammar
     * constraint. A legitimate empty array ("[]") or {"findings":[]} returns false.
     */
    static boolean isDegenerateEmptyObject(String content) {
        if (content == null) {
            return false;
        }
        String t = content.trim();
        if (t.startsWith("```")) {
            int nl = t.indexOf('\n');
            if (nl > 0) {
                t = t.substring(nl + 1);
            }
            if (t.endsWith("```")) {
                t = t.substring(0, t.length() - 3);
            }
            t = t.trim();
        }
        return EMPTY_OBJECT.matcher(t).matches();
    }

    // ---- Helpers ------------------------------------------------------------

    /**
     * The configured model, or - if none is set - the first installed tag as a
     * convenience default. Logs an actionable error and returns "" if nothing is
     * available.
     */
    private String resolveModel() {
        String model = settings.config(id()).model();
        if (!model.isBlank()) {
            return model;
        }
        List<String> installed = listModels();
        if (installed.isEmpty() && !aiGate.isEnabled()) {
            throw new AiNotSentException(AiGate.DISABLED_MESSAGE);   // switched off during the lookup
        }
        if (installed.isEmpty()) {
            api.logging().logToError("Ollama: no model configured and none installed at " + baseUrl()
                    + ". Pull one (e.g. `ollama pull qwen2.5-coder:7b`) and select it in "
                    + "Settings > AI Provider.");
            return "";
        }
        String first = installed.get(0);
        api.logging().logToError("Ollama: no model configured; defaulting to '" + first
                + "'. Set an explicit model in Settings > AI Provider.");
        return first;
    }

    private String baseUrl() {
        String configured = settings.config(id()).apiUrl();
        String url = !configured.isBlank() ? configured : id().defaultUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
