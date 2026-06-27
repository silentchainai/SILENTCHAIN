package com.sn1persecurity.silentchain.bapp.ai;

import com.sn1persecurity.silentchain.bapp.data.OwaspCategory;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public final class ResponseParser {

    private ResponseParser() {}

    public static List<ParsedFinding> parse(String aiResponse) {
        List<ParsedFinding> out = new ArrayList<>();
        if (aiResponse == null || aiResponse.isBlank()) {
            return out;
        }

        String stripped = stripCodeFences(aiResponse.trim());

        JSONArray arr = extractArray(stripped);
        if (arr == null) {
            return out;
        }

        for (int i = 0; i < arr.length(); i++) {
            try {
                JSONObject obj = arr.getJSONObject(i);
                ParsedFinding f = parseFinding(obj);
                if (f != null) {
                    out.add(f);
                }
            } catch (JSONException ignored) {
                // skip malformed entries
            }
        }

        return out;
    }

    private static ParsedFinding parseFinding(JSONObject obj) {
        String title = obj.optString("title", "").trim();
        if (title.isEmpty()) {
            return null;
        }
        String severity = obj.optString("severity", "Information").trim();
        int confidence = clampConfidence(obj.optInt("confidence", 50));
        String cwe = obj.optString("cwe", "").trim();
        String owaspCode = obj.optString("owasp", "").trim();
        String detail = obj.optString("detail", "").trim();
        String evidence = obj.optString("evidence", "").trim();
        String remediation = obj.optString("remediation", "").trim();

        OwaspCategory owasp = OwaspCategory.fromCode(owaspCode);

        return new ParsedFinding(title, severity, confidence, cwe, owasp, detail, evidence, remediation);
    }

    private static int clampConfidence(int c) {
        if (c < 0) return 0;
        if (c > 100) return 100;
        return c;
    }

    private static String stripCodeFences(String s) {
        String t = s;
        if (t.startsWith("```")) {
            int firstNl = t.indexOf('\n');
            if (firstNl > 0) {
                t = t.substring(firstNl + 1);
            }
        }
        if (t.endsWith("```")) {
            t = t.substring(0, t.length() - 3).trim();
        }
        return t.trim();
    }

    private static JSONArray extractArray(String s) {
        // Try direct array parse first
        try {
            return new JSONArray(s);
        } catch (JSONException ignored) {
            // fall through
        }

        // Try single object - wrap in array
        try {
            JSONObject obj = new JSONObject(s);
            JSONArray wrapper = new JSONArray();
            wrapper.put(obj);
            return wrapper;
        } catch (JSONException ignored) {
            // fall through
        }

        // Try to locate a [...] substring
        int start = s.indexOf('[');
        int end = s.lastIndexOf(']');
        if (start >= 0 && end > start) {
            try {
                return new JSONArray(s.substring(start, end + 1));
            } catch (JSONException ignored) {
                // fall through
            }
        }

        // Try to locate a {...} substring and wrap
        int objStart = s.indexOf('{');
        int objEnd = s.lastIndexOf('}');
        if (objStart >= 0 && objEnd > objStart) {
            try {
                JSONObject obj = new JSONObject(s.substring(objStart, objEnd + 1));
                JSONArray wrapper = new JSONArray();
                wrapper.put(obj);
                return wrapper;
            } catch (JSONException ignored) {
                // fall through
            }
        }

        return null;
    }
}
