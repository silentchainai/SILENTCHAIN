package com.sn1persecurity.silentchain.bapp.data;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bidirectional sanitizer that redacts secrets / PII before sending content to
 * Burp AI and neutralizes prompt-injection patterns in adversarial traffic.
 *
 * Ported from SILENTCHAIN Community Jython (silentchain_ai_community.py:157).
 */
public class DataSanitizer {

    private static final Set<String> ALLOWLIST = Set.of(
            "127.0.0.1", "0.0.0.0", "::1", "localhost",
            "example.com", "example.org", "example.net", "test.com"
    );

    private record SanitizePattern(String label, Pattern pattern) {}

    private static final List<SanitizePattern> SANITIZE_PATTERNS = List.of(
            new SanitizePattern("KEY", Pattern.compile(
                    "(?:sk-[A-Za-z0-9_\\-]{20,}" +
                    "|ghp_[A-Za-z0-9]{36,}" +
                    "|AKIA[A-Z0-9]{16}" +
                    "|glpat-[A-Za-z0-9_\\-]{20,}" +
                    "|xoxb-[A-Za-z0-9\\-]{20,})")),
            new SanitizePattern("AUTH", Pattern.compile(
                    "(?:Bearer\\s+[A-Za-z0-9_\\-.]{10,}" +
                    "|Basic\\s+[A-Za-z0-9+/=]{8,})")),
            new SanitizePattern("CRED", Pattern.compile(
                    "(?:[A-Za-z0-9_.+\\-]+:[A-Za-z0-9_.+\\-]+@" +
                    "|(?:password|passwd|pwd|secret|token)\\s*[=:]\\s*\\S+)",
                    Pattern.CASE_INSENSITIVE)),
            new SanitizePattern("COOKIE", Pattern.compile(
                    "(?:(?:session|sess|token|csrf|xsrf|jwt|sid|ssid|auth_token|access_token|refresh_token)" +
                    "=[A-Za-z0-9_\\-%.+/=]{4,})",
                    Pattern.CASE_INSENSITIVE)),
            new SanitizePattern("EMAIL", Pattern.compile(
                    "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}")),
            new SanitizePattern("IP", Pattern.compile(
                    "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")),
            new SanitizePattern("HOST", Pattern.compile(
                    "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b"))
    );

    private record InjectionPattern(String name, Pattern pattern) {}

    private static final List<InjectionPattern> INJECTION_PATTERNS = List.of(
            new InjectionPattern("instruction_override", Pattern.compile(
                    "(?:ignore|disregard|forget|override|bypass)\\s+" +
                    "(?:all\\s+)?(?:previous|prior|above|earlier|the)\\s+" +
                    "(?:instructions?|prompts?|rules?|guidelines?|context)",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("instruction_override", Pattern.compile(
                    "(?:do\\s+not\\s+follow|stop\\s+being|new\\s+instructions|from\\s+now\\s+on\\s+you)",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("system_prompt_extraction", Pattern.compile(
                    "(?:print|show|display|reveal|output|repeat|echo)\\s+" +
                    "(?:your\\s+)?(?:system\\s+prompt|initial\\s+prompt|" +
                    "instructions|configuration|rules)",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("role_hijacking", Pattern.compile(
                    "you\\s+are\\s+(?:now|no\\s+longer|actually|really)\\s+(?:a|an|the)\\b",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("role_hijacking", Pattern.compile(
                    "(?:act\\s+as|pretend\\s+(?:you\\s+are|to\\s+be)|assume\\s+the\\s+role\\s+of)",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("delimiter_escape", Pattern.compile(
                    "</?(?:system|user|assistant|instruction|prompt|human|ai|context|role)>",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("delimiter_escape", Pattern.compile(
                    "^#{1,3}\\s*(?:SYSTEM|INSTRUCTIONS?|RULES?|CONTEXT)\\s*$",
                    Pattern.CASE_INSENSITIVE | Pattern.MULTILINE)),
            new InjectionPattern("output_manipulation", Pattern.compile(
                    "(?:report|classify|mark|flag|set|assign)\\s+" +
                    "(?:this|it|the\\s+\\w+)\\s+as\\s+" +
                    "(?:High|Critical|100\\s*%|confirmed|verified)",
                    Pattern.CASE_INSENSITIVE)),
            new InjectionPattern("output_injection", Pattern.compile(
                    "(?:include|add|insert|append)\\s+" +
                    "(?:the\\s+following|this)\\s+" +
                    "(?:in|to|into)\\s+(?:your|the)\\s+" +
                    "(?:response|output|report|findings)",
                    Pattern.CASE_INSENSITIVE))
    );

    private final boolean enabled;
    private final Map<String, String> placeholderToOriginal = new LinkedHashMap<>();
    private final Map<String, String> originalToPlaceholder = new HashMap<>();
    private final Map<String, Integer> counters = new HashMap<>();
    private final List<String[]> injectionLog = new ArrayList<>();

    public DataSanitizer() {
        this(true);
    }

    public DataSanitizer(boolean enabled) {
        this.enabled = enabled;
    }

    public String sanitize(String text) {
        if (!enabled || text == null || text.isEmpty()) {
            return text;
        }

        String result = text;
        for (SanitizePattern sp : SANITIZE_PATTERNS) {
            Matcher m = sp.pattern.matcher(result);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String value = m.group();
                String replacement = ALLOWLIST.contains(value) ? value : addMapping(value, sp.label);
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            m.appendTail(sb);
            result = sb.toString();
        }

        for (InjectionPattern ip : INJECTION_PATTERNS) {
            Matcher m = ip.pattern.matcher(result);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String value = m.group();
                injectionLog.add(new String[]{ip.name, value.length() > 120 ? value.substring(0, 120) : value});
                String neutralized = neutralizeInjection(value, ip.name);
                m.appendReplacement(sb, Matcher.quoteReplacement(neutralized));
            }
            m.appendTail(sb);
            result = sb.toString();
        }

        return result;
    }

    public String restore(String text) {
        if (!enabled || text == null || text.isEmpty() || placeholderToOriginal.isEmpty()) {
            return text;
        }
        List<String> keys = new ArrayList<>(placeholderToOriginal.keySet());
        keys.sort(Comparator.comparingInt(String::length).reversed());
        String result = text;
        for (String placeholder : keys) {
            result = result.replace(placeholder, placeholderToOriginal.get(placeholder));
        }
        return result;
    }

    public boolean injectionDetected() {
        return !injectionLog.isEmpty();
    }

    public String injectionSummary() {
        if (injectionLog.isEmpty()) {
            return "none";
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String[] entry : injectionLog) {
            counts.merge(entry[0], 1, Integer::sum);
        }
        List<String> parts = new ArrayList<>();
        counts.forEach((name, count) -> parts.add(count + " " + name));
        return String.join(", ", parts);
    }

    public String redactedSummary() {
        if (counters.isEmpty()) {
            return "nothing";
        }
        List<String> parts = new ArrayList<>();
        counters.forEach((label, count) -> parts.add(count + " " + label.toLowerCase() + "(s)"));
        return String.join(", ", parts);
    }

    private String addMapping(String value, String label) {
        String existing = originalToPlaceholder.get(value);
        if (existing != null) {
            return existing;
        }
        int next = counters.merge(label, 1, Integer::sum);
        String placeholder = "[REDACTED_" + label + "_" + next + "]";
        placeholderToOriginal.put(placeholder, value);
        originalToPlaceholder.put(value, placeholder);
        return placeholder;
    }

    private String neutralizeInjection(String value, String patternName) {
        if ("delimiter_escape".equals(patternName)) {
            return value.replace("<", "&lt;").replace(">", "&gt;");
        }
        if (value.length() < 2) {
            return value;
        }
        return value.charAt(0) + "‎" + value.substring(1);
    }
}
