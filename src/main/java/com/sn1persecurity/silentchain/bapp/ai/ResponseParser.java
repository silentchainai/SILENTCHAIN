package com.sn1persecurity.silentchain.bapp.ai;

import com.sn1persecurity.silentchain.bapp.data.OwaspCategory;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public final class ResponseParser {

    private static final String[] WRAPPER_KEYS = {"findings", "results", "vulnerabilities", "issues"};

    /** Longest finding title kept (titles are shown in tables and used as Burp issue names). */
    static final int MAX_TITLE_CHARS = 200;

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
        String title = sanitizeTitle(obj.optString("title", ""));
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

        // Try single object - could be a wrapper {"findings":[...]} or a lone finding
        try {
            JSONObject obj = new JSONObject(s);
            JSONArray unwrapped = unwrapFindings(obj);
            if (unwrapped != null) {
                return unwrapped;
            }
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

        // Try to locate a {...} substring - unwrap if it's an envelope, else wrap as one finding
        int objStart = s.indexOf('{');
        int objEnd = s.lastIndexOf('}');
        if (objStart >= 0 && objEnd > objStart) {
            try {
                JSONObject obj = new JSONObject(s.substring(objStart, objEnd + 1));
                JSONArray unwrapped = unwrapFindings(obj);
                if (unwrapped != null) {
                    return unwrapped;
                }
                JSONArray wrapper = new JSONArray();
                wrapper.put(obj);
                return wrapper;
            } catch (JSONException ignored) {
                // fall through
            }
        }

        // Last resort: the whole JSON is malformed/truncated (e.g. a local model ran a field
        // into num_predict, cutting off the response mid-object). Salvage every COMPLETE finding
        // object by brace-matching so findings emitted before the truncation still survive.
        return salvageFindingObjects(s);
    }

    /**
     * Scan for balanced {@code {...}} objects that parse as JSON and carry a non-empty
     * "title", collecting them into an array. Tolerates a truncated tail (the unterminated
     * final object is simply skipped). Returns null if none are recoverable.
     */
    private static JSONArray salvageFindingObjects(String s) {
        JSONArray out = new JSONArray();
        int i = 0;
        int n = s.length();
        while (i < n) {
            if (s.charAt(i) == '{') {
                int end = matchBrace(s, i);
                if (end >= 0) {
                    try {
                        JSONObject o = new JSONObject(s.substring(i, end + 1));
                        if (!o.optString("title", "").trim().isEmpty()) {
                            out.put(o);
                            i = end + 1;
                            continue;
                        }
                    } catch (JSONException ignored) {
                        // not a standalone object; fall through and advance
                    }
                }
            }
            i++;
        }
        return out.isEmpty() ? null : out;
    }

    /** Index of the {@code }} matching the {@code {} at {@code start}, or -1 if unterminated. */
    private static int matchBrace(String s, int start) {
        int depth = 0;
        boolean inStr = false;
        boolean esc = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    inStr = false;
                }
            } else if (c == '"') {
                inStr = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * If {@code obj} is an envelope wrapping the findings array (e.g. {"findings":[...]} as
     * emitted by Ollama/Mistral in JSON mode), return the inner array; otherwise null so the
     * caller treats {@code obj} as a single bare finding.
     */
    private static JSONArray unwrapFindings(JSONObject obj) {
        for (String key : WRAPPER_KEYS) {
            JSONArray inner = obj.optJSONArray(key);
            if (inner != null) {
                return inner;
            }
        }
        // Safety net: an envelope with no "title" of its own but exactly one array-valued key is
        // almost certainly a wrapper under an unexpected key name.
        if (obj.optString("title", "").trim().isEmpty()) {
            JSONArray sole = null;
            int arrays = 0;
            for (String key : obj.keySet()) {
                JSONArray val = obj.optJSONArray(key);
                if (val != null) {
                    sole = val;
                    arrays++;
                }
            }
            if (arrays == 1) {
                return sole;
            }
        }
        return null;
    }

    /**
     * AI output is untrusted (the model reads attacker-controlled traffic), and the
     * title is displayed in Swing tables and as the Burp issue name. Strip control
     * characters and angle brackets (no markup can survive), collapse whitespace
     * and cap the length.
     */
    static String sanitizeTitle(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(raw.length(), MAX_TITLE_CHARS));
        boolean lastWasSpace = false;
        for (int i = 0; i < raw.length() && out.length() < MAX_TITLE_CHARS; i++) {
            char c = raw.charAt(i);
            if (c == '<' || c == '>') {
                continue;
            }
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                if (!lastWasSpace && out.length() > 0) {
                    out.append(' ');
                    lastWasSpace = true;
                }
                continue;
            }
            out.append(c);
            lastWasSpace = false;
        }
        return out.toString().trim();
    }
}
