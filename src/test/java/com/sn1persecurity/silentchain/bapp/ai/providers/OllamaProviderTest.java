package com.sn1persecurity.silentchain.bapp.ai.providers;

import com.sn1persecurity.silentchain.bapp.config.Settings.StructuredOutput;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for OllamaProvider's pure, static request/response helpers. These do not
 * touch Montoya (no live Burp), following the "extract pure static, test that" pattern.
 */
class OllamaProviderTest {

    @Test
    void chatBodyHasSystemUserRolesSchemaAndOptions() {
        JSONObject b = OllamaProvider.buildChatBody("qwen3:8b", "SYS", "USR",
                2048, 8192, 0.0, StructuredOutput.SCHEMA, "10m");

        assertEquals("qwen3:8b", b.getString("model"));
        assertFalse(b.getBoolean("stream"));
        assertEquals("10m", b.getString("keep_alive"));
        assertFalse(b.getBoolean("think"));   // reasoning models skip the slow <think> phase

        JSONArray msgs = b.getJSONArray("messages");
        assertEquals(2, msgs.length());
        assertEquals("system", msgs.getJSONObject(0).getString("role"));
        assertEquals("SYS", msgs.getJSONObject(0).getString("content"));
        assertEquals("user", msgs.getJSONObject(1).getString("role"));
        assertEquals("USR", msgs.getJSONObject(1).getString("content"));

        JSONObject opts = b.getJSONObject("options");
        assertEquals(0.0, opts.getDouble("temperature"));
        assertEquals(2048, opts.getInt("num_predict"));
        assertEquals(8192, opts.getInt("num_ctx"));
        assertEquals(1.3, opts.getDouble("repeat_penalty"));

        // SCHEMA mode -> format is a JSON schema object forcing {"findings":[...]}.
        JSONObject fmt = b.getJSONObject("format");
        assertEquals("object", fmt.getString("type"));
        assertTrue(fmt.getJSONObject("properties").has("findings"));
        assertEquals("array", fmt.getJSONObject("properties").getJSONObject("findings").getString("type"));
        assertTrue(fmt.getJSONArray("required").toList().contains("findings"));
    }

    @Test
    void jsonModeUsesLiteralStringAndOffOmitsFormat() {
        JSONObject json = OllamaProvider.buildChatBody("m", "s", "u", 2048, 8192, 0.0,
                StructuredOutput.JSON, "10m");
        assertEquals("json", json.getString("format"));

        JSONObject off = OllamaProvider.buildChatBody("m", "s", "u", 2048, 8192, 0.0,
                StructuredOutput.OFF, "10m");
        assertFalse(off.has("format"));
    }

    @Test
    void findingsSchemaRequiresTitleAndSeverityOnly() {
        JSONObject item = OllamaProvider.findingsSchema()
                .getJSONObject("properties").getJSONObject("findings").getJSONObject("items");
        JSONArray required = item.getJSONArray("required");
        assertEquals(2, required.length());
        assertTrue(required.toList().contains("title"));
        assertTrue(required.toList().contains("severity"));
        assertTrue(item.getJSONObject("properties").getJSONObject("severity")
                .getJSONArray("enum").toList().contains("Information"));
    }

    @Test
    void findingsSchemaBoundsStringsAndArrayToStopRunawayGeneration() {
        JSONObject findings = OllamaProvider.findingsSchema()
                .getJSONObject("properties").getJSONObject("findings");
        assertEquals(25, findings.getInt("maxItems"));
        JSONObject props = findings.getJSONObject("items").getJSONObject("properties");
        assertTrue(props.getJSONObject("detail").getInt("maxLength") > 0);
        assertTrue(props.getJSONObject("title").getInt("maxLength") > 0);
        assertTrue(props.getJSONObject("remediation").getInt("maxLength") > 0);
    }

    @Test
    void extractContentHandlesChatAndGenerateShapes() {
        assertEquals("X", OllamaProvider.extractContent("{\"message\":{\"content\":\"X\"}}").orElse(""));
        assertEquals("Y", OllamaProvider.extractContent("{\"response\":\"Y\"}").orElse(""));
        assertTrue(OllamaProvider.extractContent("{\"message\":{\"content\":\"\"}}").isEmpty());
        assertTrue(OllamaProvider.extractContent("").isEmpty());
        assertTrue(OllamaProvider.extractContent(null).isEmpty());
        assertTrue(OllamaProvider.extractContent("not json").isEmpty());
    }

    @Test
    void detectsDegenerateEmptyObject() {
        assertTrue(OllamaProvider.isDegenerateEmptyObject("{}"));
        assertTrue(OllamaProvider.isDegenerateEmptyObject("  {\n}  "));
        assertTrue(OllamaProvider.isDegenerateEmptyObject("```json\n{ }\n```"));
        assertFalse(OllamaProvider.isDegenerateEmptyObject("{\"findings\":[]}"));
        assertFalse(OllamaProvider.isDegenerateEmptyObject("[]"));
        assertFalse(OllamaProvider.isDegenerateEmptyObject(null));
    }
}
