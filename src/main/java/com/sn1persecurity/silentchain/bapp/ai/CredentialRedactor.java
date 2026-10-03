package com.sn1persecurity.silentchain.bapp.ai;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural credential redaction applied to every AI prompt, whatever the
 * sanitizer toggle says. PortSwigger's AI guidance is to keep authentication
 * tokens and session cookies out of AI requests, and value-pattern matching
 * alone misses most of them (JSESSIONID values, JSON passwords, ?api_key=...).
 *
 * Redaction is by NAME: cookie values, and the values of headers, URL/form/JSON
 * parameters and multipart fields whose name looks like a credential. Names are
 * kept, because "a session cookie / password field is present" matters to the
 * analysis; values are replaced with {@link #REDACTED}.
 */
public final class CredentialRedactor {

    public static final String REDACTED = "[REDACTED]";

    /** Name segments (split on - _ . [ ]) that mark a credential. */
    private static final Set<String> CREDENTIAL_SEGMENTS = Set.of(
            "token", "secret", "password", "passwd", "pwd", "pass", "passphrase", "apikey",
            "credential", "credentials", "session", "sessionid", "sessid", "sid", "jwt",
            "csrf", "xsrf", "signature", "sig", "auth", "authorization", "authenticity", "key",
            "otp", "pin", "cookie");

    /** Substrings of the name with separators removed that mark a credential. */
    private static final String[] CREDENTIAL_FRAGMENTS = {
            "apikey", "accesskey", "secretkey", "privatekey", "subscriptionkey", "clientsecret",
            "sessionid", "sessid", "password", "passwd", "authtoken", "accesstoken", "refreshtoken",
            "idtoken", "csrf", "xsrf", "bearer"};

    /** Headers that look credential-like by name but carry no secret and matter to the analysis. */
    private static final Set<String> NON_CREDENTIAL_HEADERS = Set.of(
            "www-authenticate", "proxy-authenticate", "sec-websocket-key", "sec-websocket-accept",
            "public-key-pins", "public-key-pins-report-only", "content-security-policy",
            "content-security-policy-report-only");

    /** Authorization schemes kept in front of a redacted value ("Bearer [REDACTED]"). */
    private static final Set<String> AUTH_SCHEMES = Set.of(
            "bearer", "basic", "token", "digest", "negotiate", "ntlm", "hoba", "mutual", "aws4-hmac-sha256");

    private static final Pattern SEGMENT_SPLIT = Pattern.compile("[-_.\\[\\]]+");
    private static final Pattern SEPARATORS = Pattern.compile("[-_.\\[\\]\\s]+");

    /** "name": value (string possibly cut off at the end, number, literal) inside JSON-ish text. */
    private static final Pattern JSON_MEMBER = Pattern.compile(
            "\"((?:[^\"\\\\]|\\\\.){1,100})\"(\\s*:\\s*)(\"(?:[^\"\\\\]|\\\\.)*(?:\"|$)|[^,}\\]\\s]+)");

    /** Multipart field: name="x" ... blank line ... value (up to the line end). */
    private static final Pattern MULTIPART_FIELD = Pattern.compile(
            "(name=\"([^\"]{1,100})\"[^\\r\\n]*\\r?\\n(?:[^\\r\\n]+\\r?\\n)*\\r?\\n)([^\\r\\n]*)");

    private CredentialRedactor() {}

    /** True if a header, parameter, cookie or JSON key with this name carries a credential. */
    public static boolean isCredentialName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String lower = name.trim().toLowerCase(Locale.ROOT);
        for (String segment : SEGMENT_SPLIT.split(lower)) {
            if (CREDENTIAL_SEGMENTS.contains(segment)) {
                return true;
            }
        }
        String compact = SEPARATORS.matcher(lower).replaceAll("");
        for (String fragment : CREDENTIAL_FRAGMENTS) {
            if (compact.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    /** True if this header's value must be redacted. */
    public static boolean isCredentialHeader(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.trim().toLowerCase(Locale.ROOT);
        if (NON_CREDENTIAL_HEADERS.contains(lower) || lower.startsWith("access-control-")) {
            return false;
        }
        return isCredentialName(lower);
    }

    /**
     * Header value as it may be shown to the AI: cookie names and Set-Cookie
     * attributes are kept, cookie values and credential header values are not;
     * an Authorization-style scheme ("Bearer", "Basic") is kept.
     */
    public static String redactHeaderValue(String name, String value) {
        if (value == null) {
            return "";
        }
        String lower = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        if (lower.equals("cookie")) {
            return redactCookiePairs(value);
        }
        if (lower.equals("set-cookie")) {
            int semi = value.indexOf(';');
            return semi >= 0 ? redactCookiePairs(value.substring(0, semi)) + value.substring(semi)
                             : redactCookiePairs(value);
        }
        if (isCredentialHeader(lower)) {
            String trimmed = value.trim();
            int space = trimmed.indexOf(' ');
            if (space > 0 && AUTH_SCHEMES.contains(trimmed.substring(0, space).toLowerCase(Locale.ROOT))) {
                return trimmed.substring(0, space) + " " + REDACTED;
            }
            return REDACTED;
        }
        return value;
    }

    /** Value of a request parameter as it may be shown to the AI. */
    public static String redactParameterValue(String name, String value, boolean isCookie) {
        return isCookie || isCredentialName(name) ? REDACTED : value;
    }

    /** The URL with credential-named query parameter values replaced. */
    public static String redactUrl(String url) {
        if (url == null) {
            return "";
        }
        int q = url.indexOf('?');
        if (q < 0) {
            return url;
        }
        int hash = url.indexOf('#', q);
        String query = hash >= 0 ? url.substring(q + 1, hash) : url.substring(q + 1);
        String fragment = hash >= 0 ? url.substring(hash) : "";
        return url.substring(0, q + 1) + redactPairs(query) + fragment;
    }

    /**
     * A request body with credential values replaced: form-urlencoded pairs,
     * JSON members (also when the text was cut off) and multipart fields.
     */
    public static String redactBody(String body) {
        if (body == null || body.isEmpty()) {
            return body == null ? "" : body;
        }
        String trimmed = body.stripLeading();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return redactJsonMembers(body);
        }
        if (body.contains("Content-Disposition") && body.contains("name=\"")) {
            return redactMultipart(body);
        }
        if (body.indexOf('=') > 0 && body.indexOf('\n') < 0) {
            return redactPairs(body);
        }
        return redactJsonMembers(body);   // e.g. JSON embedded in other text
    }

    // ---- helpers --------------------------------------------------------------

    /** "a=1; b=2" -> "a=[REDACTED]; b=[REDACTED]". */
    private static String redactCookiePairs(String value) {
        StringBuilder out = new StringBuilder();
        for (String pair : value.split(";")) {
            String p = pair.trim();
            if (p.isEmpty()) {
                continue;
            }
            if (out.length() > 0) {
                out.append("; ");
            }
            int eq = p.indexOf('=');
            out.append(eq >= 0 ? p.substring(0, eq).trim() : p).append('=').append(REDACTED);
        }
        return out.toString();
    }

    /** "a=1&password=x" -> "a=1&password=[REDACTED]" (names compared URL-decoded). */
    private static String redactPairs(String pairs) {
        StringBuilder out = new StringBuilder(pairs.length());
        String[] parts = pairs.split("&", -1);
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                out.append('&');
            }
            String part = parts[i];
            int eq = part.indexOf('=');
            if (eq > 0 && isCredentialName(urlDecode(part.substring(0, eq)))) {
                out.append(part, 0, eq + 1).append(REDACTED);
            } else {
                out.append(part);
            }
        }
        return out.toString();
    }

    private static String redactJsonMembers(String text) {
        Matcher m = JSON_MEMBER.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            if (isCredentialName(m.group(1))) {
                m.appendReplacement(out, Matcher.quoteReplacement(
                        "\"" + m.group(1) + "\"" + m.group(2) + "\"" + REDACTED + "\""));
            } else {
                m.appendReplacement(out, Matcher.quoteReplacement(m.group()));
            }
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String redactMultipart(String body) {
        Matcher m = MULTIPART_FIELD.matcher(body);
        StringBuilder out = new StringBuilder(body.length());
        while (m.find()) {
            String replacement = isCredentialName(m.group(2)) ? m.group(1) + REDACTED : m.group();
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }
}
