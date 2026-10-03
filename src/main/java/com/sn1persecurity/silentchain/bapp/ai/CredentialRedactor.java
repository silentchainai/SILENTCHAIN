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
 * Redaction is by NAME: cookie values, and the values of headers, URL / form /
 * JSON / multipart / XML / HTML-input fields whose name looks like a credential.
 * Names are kept, because "a session cookie / password field is present"
 * matters to the analysis. An EMPTY value is kept as empty, so a missing token
 * is never shown as a present one.
 *
 * Everything here is linear-time (no backtracking regex over values), because
 * it runs on attacker-controlled bodies inside analysis workers.
 */
public final class CredentialRedactor {

    public static final String REDACTED = "[REDACTED]";

    /** Bodies are scanned up to this length before they are capped for the prompt. */
    static final int MAX_SCAN_CHARS = 65_536;

    /** Name segments (after camelCase / separator split, plural 's' removed) that mark a credential. */
    private static final Set<String> CREDENTIAL_SEGMENTS = Set.of(
            "token", "secret", "password", "passwd", "pwd", "pass", "passphrase", "passcode", "apikey",
            "credential", "session", "sessionid", "sessid", "sid", "jwt", "csrf", "xsrf", "signature",
            "sig", "auth", "authorization", "authentication", "authn", "authenticity", "key", "otp", "totp",
            "mfa", "2fa", "pin", "cookie", "assertion", "samlresponse", "samlart", "bearer");

    /** Substrings of the lower-case name with separators removed that mark a credential. */
    private static final String[] CREDENTIAL_FRAGMENTS = {
            "token", "secret", "passw", "pwd", "apikey", "authkey", "sessionkey", "privatekey", "accesskey",
            "secretkey", "subscriptionkey", "sessionid", "sessid", "csrf", "xsrf", "samlresponse", "passcode",
            "bearer"};

    /** Headers that look credential-like by name but carry no secret and matter to the analysis. */
    private static final Set<String> NON_CREDENTIAL_HEADERS = Set.of(
            "www-authenticate", "proxy-authenticate", "sec-websocket-key", "sec-websocket-accept",
            "public-key-pins", "public-key-pins-report-only", "content-security-policy",
            "content-security-policy-report-only");

    /** Headers whose value is (or contains) a URL whose query / fragment may carry tokens. */
    private static final Set<String> URL_HEADERS = Set.of(
            "referer", "location", "content-location", "refresh", "link");

    /** Authorization schemes kept in front of a redacted value ("Bearer [REDACTED]"). */
    private static final Set<String> AUTH_SCHEMES = Set.of(
            "bearer", "basic", "token", "digest", "negotiate", "ntlm", "hoba", "mutual", "aws4-hmac-sha256");

    private static final Pattern CAMEL_BOUNDARY = Pattern.compile("(?<=[a-z0-9])(?=[A-Z])");
    private static final Pattern SEGMENT_SPLIT = Pattern.compile("[-_.\\[\\]\\s]+");
    private static final Pattern SEPARATORS = Pattern.compile("[-_.\\[\\]\\s]+");

    /** Servlet path parameter (;jsessionid=...): the value ends at '?', '/', '#' or ';'. */
    private static final Pattern PATH_PARAM = Pattern.compile(
            "(;)([^=&;#?/\\s<>\"']{1,100})=([^&;#?/\\s<>\"']*)");

    /** name=value pairs after ? & # (query and fragment parameters). */
    private static final Pattern URL_PAIR = Pattern.compile(
            "([?&#])([^=&;#?/\\s<>\"']{1,100})=([^&#\\s<>\"']*)");

    /** Multipart part header naming a field. */
    private static final Pattern MULTIPART_NAME = Pattern.compile(
            "(?i)content-disposition:[^\\r\\n]*?\\bname=\"([^\"]{1,100})\"[^\\r\\n]*");

    /** XML element with only text content: <ns:name attr>text</ns:name>. */
    private static final Pattern XML_ELEMENT = Pattern.compile(
            "<((?:[\\w.-]{1,50}:)?([\\w.-]{1,100}))\\b[^<>]{0,500}>([^<]*)</\\1\\s*>");

    /** Attribute: name="value" or name='value'. */
    private static final Pattern ATTRIBUTE = Pattern.compile(
            "([\\w:.-]{1,100})\\s*=\\s*(\"[^\"]*\"|'[^']*')");

    /** An HTML input or meta tag (possibly cut off at the end of the body). */
    private static final Pattern INPUT_OR_META = Pattern.compile("(?i)<(?:input|meta)\\b[^>]{0,2000}>?");

    /** name: "value" / name = 'value' / name:\"value\" outside JSON keys (JS, GraphQL, stringified JSON). */
    private static final Pattern NAMED_ASSIGNMENT = Pattern.compile(
            "(?<![\\w$\"'])([A-Za-z_$][\\w$.-]{0,99})(\\s*[:=]\\s*)(\\\\{0,2}[\"'])([^\"'\\\\\\r\\n]{1,500})(\\3)");

    private CredentialRedactor() {}

    // ---- Names --------------------------------------------------------------

    /** True if a header, parameter, cookie or JSON key with this name carries a credential. */
    public static boolean isCredentialName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String decoded = urlDecode(name.trim());
        String split = CAMEL_BOUNDARY.matcher(decoded).replaceAll("_").toLowerCase(Locale.ROOT);
        for (String segment : SEGMENT_SPLIT.split(split)) {
            if (CREDENTIAL_SEGMENTS.contains(segment)
                    || (segment.length() > 3 && segment.endsWith("s")
                        && CREDENTIAL_SEGMENTS.contains(segment.substring(0, segment.length() - 1)))) {
                return true;
            }
        }
        String compact = SEPARATORS.matcher(decoded.toLowerCase(Locale.ROOT)).replaceAll("");
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

    // ---- Headers, parameters, URLs -------------------------------------------

    /**
     * Header value as it may be shown to the AI: cookie names and Set-Cookie
     * attributes are kept, cookie values and credential header values are not;
     * an Authorization-style scheme ("Bearer", "Basic") is kept, and so are
     * empty values and the client-bug placeholders "undefined" / "null".
     * URL-bearing headers (Referer, Location...) get their token parameters redacted.
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
        if (URL_HEADERS.contains(lower)) {
            return redactUrl(value);
        }
        if (!isCredentialHeader(lower)) {
            return value;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || AUTH_SCHEMES.contains(trimmed.toLowerCase(Locale.ROOT)) || isPlaceholder(trimmed)) {
            return value;
        }
        int space = trimmed.indexOf(' ');
        if (space > 0 && AUTH_SCHEMES.contains(trimmed.substring(0, space).toLowerCase(Locale.ROOT))) {
            String credential = trimmed.substring(space + 1).trim();
            return isPlaceholder(credential) || credential.isEmpty()
                    ? value : trimmed.substring(0, space) + " " + REDACTED;
        }
        return REDACTED;
    }

    /** Value of a request parameter as it may be shown to the AI. */
    public static String redactParameterValue(String name, String value, boolean isCookie) {
        return isCookie || isCredentialName(name) ? mask(value) : value;
    }

    /**
     * Token-carrying pairs redacted in a URL or URL-bearing text: query
     * parameters, servlet path parameters (;jsessionid=...) and fragment pairs
     * (#access_token=...).
     */
    public static String redactUrl(String url) {
        if (url == null) {
            return "";
        }
        return redactPairsMatching(URL_PAIR, redactPairsMatching(PATH_PARAM, url));
    }

    private static String redactPairsMatching(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            String replacement = isCredentialName(m.group(2))
                    ? m.group(1) + m.group(2) + "=" + mask(m.group(3))
                    : m.group();
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    // ---- Bodies ---------------------------------------------------------------

    /**
     * A request body with credential values replaced. Every applicable redactor
     * runs (form pairs, multipart fields, JSON members including nested values,
     * XML elements/attributes, unquoted-name assignments such as GraphQL
     * arguments); over-redaction is preferred to a leak. Values that were
     * redacted are added to {@code redactedValues} (may be null) so callers can
     * hide the same values elsewhere (e.g. Burp's parsed parameter list).
     */
    public static String redactRequestBody(String body, String contentType, Set<String> redactedValues) {
        String text = limit(body);
        if (text.isEmpty()) {
            return text;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (ct.contains("x-www-form-urlencoded") || looksLikeForm(text)) {
            text = redactPairs(text, redactedValues);
        }
        if (ct.contains("multipart/") || text.toLowerCase(Locale.ROOT).contains("content-disposition")) {
            text = redactMultipart(text, redactedValues);
        }
        text = redactJsonMembers(text, redactedValues);
        if (ct.contains("xml") || text.stripLeading().startsWith("<")) {
            text = redactXml(text);
        }
        return redactNamedAssignments(text);
    }

    /**
     * A response body with credential values replaced: JSON members (also JSON
     * embedded in HTML/JS), HTML input/meta values whose name/id marks a
     * credential (CSRF tokens, session ids), XML, JS assignments, and
     * form-encoded token responses.
     */
    public static String redactResponseBody(String body, String contentType) {
        String text = limit(body);
        if (text.isEmpty()) {
            return text;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (ct.contains("x-www-form-urlencoded") || looksLikeForm(text)) {
            text = redactPairs(text, null);
        }
        text = redactJsonMembers(text, null);
        if (text.indexOf('<') >= 0) {
            text = redactInputsAndMeta(text);
            if (ct.contains("xml") || text.stripLeading().startsWith("<?xml")) {
                text = redactXml(text);
            }
        }
        return redactNamedAssignments(text);
    }

    // ---- helpers --------------------------------------------------------------

    private static String limit(String body) {
        if (body == null) {
            return "";
        }
        return body.length() > MAX_SCAN_CHARS ? body.substring(0, MAX_SCAN_CHARS) : body;
    }

    /** Empty stays empty (an absent token must not look present); anything else is redacted. */
    private static String mask(String value) {
        return value == null || value.isBlank() ? (value == null ? "" : value) : REDACTED;
    }

    private static boolean isPlaceholder(String s) {
        return s.equalsIgnoreCase("undefined") || s.equalsIgnoreCase("null");
    }

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
            if (eq < 0) {
                out.append(p);
            } else {
                out.append(p, 0, eq).append('=').append(mask(p.substring(eq + 1)));
            }
        }
        return out.toString();
    }

    /** A single line of name=value pairs joined by '&' (trailing CR/LF allowed). */
    static boolean looksLikeForm(String text) {
        String t = text.stripTrailing();
        if (t.isEmpty() || t.indexOf('=') <= 0) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (Character.isWhitespace(c) || c == '<' || c == '>' || c == '{' || c == '"') {
                return false;
            }
        }
        for (String part : t.split("&")) {
            if (part.indexOf('=') <= 0) {
                return false;
            }
        }
        return true;
    }

    /** "a=1&password=x" -> "a=1&password=[REDACTED]" (names compared URL-decoded, value to the end of the pair). */
    private static String redactPairs(String pairs, Set<String> redactedValues) {
        StringBuilder out = new StringBuilder(pairs.length());
        String[] parts = pairs.split("&", -1);
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                out.append('&');
            }
            String part = parts[i];
            int eq = part.indexOf('=');
            if (eq > 0 && isCredentialName(part.substring(0, eq))) {
                String value = part.substring(eq + 1);
                String trailing = value.substring(value.stripTrailing().length());
                remember(redactedValues, value.stripTrailing());
                out.append(part, 0, eq + 1).append(mask(value.stripTrailing())).append(trailing);
            } else {
                out.append(part);
            }
        }
        return out.toString();
    }

    /** Credential-named multipart fields: the whole part body up to the next boundary line. */
    private static String redactMultipart(String body, Set<String> redactedValues) {
        Matcher m = MULTIPART_NAME.matcher(body);
        StringBuilder out = new StringBuilder(body.length());
        int copied = 0;
        while (m.find()) {
            if (!isCredentialName(m.group(1)) || m.end() < copied) {
                continue;
            }
            int headersEnd = indexOfBlankLine(body, m.end());
            if (headersEnd < 0) {
                continue;
            }
            int valueStart = headersEnd;
            int valueEnd = indexOfBoundary(body, valueStart);
            String value = body.substring(valueStart, valueEnd);
            remember(redactedValues, value);
            out.append(body, copied, valueStart).append(mask(value));
            copied = valueEnd;
        }
        out.append(body, copied, body.length());
        return out.toString();
    }

    private static int indexOfBlankLine(String s, int from) {
        int crlf = s.indexOf("\r\n\r\n", from);
        int lf = s.indexOf("\n\n", from);
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) {
            return crlf + 4;
        }
        return lf >= 0 ? lf + 2 : -1;
    }

    private static int indexOfBoundary(String s, int from) {
        int crlf = s.indexOf("\r\n--", from);
        int lf = s.indexOf("\n--", from);
        int end = crlf >= 0 ? crlf : lf;
        if (lf >= 0 && (crlf < 0 || lf < crlf)) {
            end = lf;
        }
        return end >= 0 ? end : s.length();
    }

    /**
     * JSON members whose key is credential-like get their value replaced, whether
     * the value is a string, number, object or array (the whole container goes).
     * Works on JSON embedded in other text and on text cut off at any point.
     * Empty strings and null/true/false literals are kept.
     */
    static String redactJsonMembers(String text, Set<String> redactedValues) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        int i = 0;
        while (i < n) {
            char c = text.charAt(i);
            if (c != '"') {
                out.append(c);
                i++;
                continue;
            }
            int close = closingQuote(text, i);
            if (close < 0) {
                out.append(text, i, n);
                break;
            }
            out.append(text, i, close + 1);
            int colon = skipWhitespace(text, close + 1);
            if (colon < n && text.charAt(colon) == ':' && close - i - 1 <= 200
                    && isCredentialName(unescapeJson(text.substring(i + 1, close)))) {
                int valueStart = skipWhitespace(text, colon + 1);
                int valueEnd = endOfJsonValue(text, valueStart);
                out.append(text, close + 1, valueStart);
                out.append(maskJsonValue(text.substring(valueStart, valueEnd), redactedValues));
                i = valueEnd;
            } else {
                i = close + 1;
            }
        }
        return out.toString();
    }

    private static String maskJsonValue(String raw, Set<String> redactedValues) {
        if (raw.isEmpty() || raw.equals("null") || raw.equals("true") || raw.equals("false")) {
            return raw;
        }
        char first = raw.charAt(0);
        if (first == '"') {
            int close = closingQuote(raw, 0);
            String inner = raw.substring(1, close >= 0 ? close : raw.length());
            if (inner.isBlank()) {
                return raw;
            }
            remember(redactedValues, unescapeJson(inner));
            return "\"" + REDACTED + "\"";
        }
        if (first == '{' || first == '[') {
            collectLeaves(raw, redactedValues);
            return "\"" + REDACTED + "\"";
        }
        remember(redactedValues, raw);
        return "\"" + REDACTED + "\"";
    }

    /** Index of the closing quote of the string starting at {@code open}, or -1 if it runs off the end. */
    private static int closingQuote(String s, int open) {
        int n = s.length();
        for (int i = open + 1; i < n; i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '"') {
                return i;
            }
        }
        return -1;
    }

    private static int skipWhitespace(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    /** End (exclusive) of the JSON value starting at {@code start}; tolerant of truncation. */
    private static int endOfJsonValue(String s, int start) {
        int n = s.length();
        if (start >= n) {
            return n;
        }
        char c = s.charAt(start);
        if (c == '"') {
            int close = closingQuote(s, start);
            return close < 0 ? n : close + 1;
        }
        if (c == '{' || c == '[') {
            int depth = 0;
            for (int i = start; i < n; i++) {
                char ch = s.charAt(i);
                if (ch == '"') {
                    int close = closingQuote(s, i);
                    if (close < 0) {
                        return n;
                    }
                    i = close;
                } else if (ch == '{' || ch == '[') {
                    depth++;
                } else if (ch == '}' || ch == ']') {
                    depth--;
                    if (depth == 0) {
                        return i + 1;
                    }
                }
            }
            return n;
        }
        int i = start;
        while (i < n) {
            char ch = s.charAt(i);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                break;
            }
            i++;
        }
        return i;
    }

    /** Every string and scalar inside a redacted container, so the same values can be hidden elsewhere. */
    private static void collectLeaves(String container, Set<String> redactedValues) {
        if (redactedValues == null) {
            return;
        }
        int n = container.length();
        int i = 0;
        while (i < n) {
            char c = container.charAt(i);
            if (c == '"') {
                int close = closingQuote(container, i);
                int end = close < 0 ? n : close;
                int after = skipWhitespace(container, end + 1);
                boolean isKey = close >= 0 && after < n && container.charAt(after) == ':';
                if (!isKey) {
                    remember(redactedValues, unescapeJson(container.substring(i + 1, end)));
                }
                i = end + 1;
            } else if (Character.isLetterOrDigit(c) || c == '-') {
                int start = i;
                while (i < n && (Character.isLetterOrDigit(container.charAt(i)) || container.charAt(i) == '.'
                        || container.charAt(i) == '-' || container.charAt(i) == '+')) {
                    i++;
                }
                String scalar = container.substring(start, i);
                if (!scalar.equals("null") && !scalar.equals("true") && !scalar.equals("false")) {
                    remember(redactedValues, scalar);
                }
            } else {
                i++;
            }
        }
    }

    private static String unescapeJson(String s) {
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                out.append(c);
                continue;
            }
            char e = s.charAt(++i);
            switch (e) {
                case 'n' -> out.append('\n');
                case 't' -> out.append('\t');
                case 'r' -> out.append('\r');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'u' -> {
                    if (i + 4 < s.length()) {
                        try {
                            out.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException ex) {
                            out.append('u');
                        }
                    } else {
                        out.append('u');
                    }
                }
                default -> out.append(e);
            }
        }
        return out.toString();
    }

    /** XML elements and attributes whose (local) name is credential-like. */
    private static String redactXml(String text) {
        Matcher m = XML_ELEMENT.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            String replacement = isCredentialName(m.group(2)) && !m.group(3).isBlank()
                    ? m.group().substring(0, m.start(3) - m.start()) + REDACTED + m.group().substring(m.end(3) - m.start())
                    : m.group();
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return redactCredentialAttributes(out.toString());
    }

    private static String redactCredentialAttributes(String text) {
        Matcher m = ATTRIBUTE.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            String name = m.group(1);
            int colon = name.lastIndexOf(':');
            String local = colon >= 0 ? name.substring(colon + 1) : name;
            String replacement = isCredentialName(local) ? quotedMask(m.group(), m.group(2)) : m.group();
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    /** <input name="csrf_token" value="..."> / <meta name="csrf-token" content="..."> and credential-named attributes. */
    private static String redactInputsAndMeta(String text) {
        Matcher tag = INPUT_OR_META.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (tag.find()) {
            String t = tag.group();
            boolean credential = false;
            Matcher a = ATTRIBUTE.matcher(t);
            while (a.find()) {
                String attr = a.group(1).toLowerCase(Locale.ROOT);
                if ((attr.equals("name") || attr.equals("id") || attr.equals("property") || attr.equals("http-equiv"))
                        && isCredentialName(unquote(a.group(2)))) {
                    credential = true;
                    break;
                }
            }
            String replacement = t;
            if (credential) {
                Matcher v = ATTRIBUTE.matcher(t);
                StringBuilder tagOut = new StringBuilder(t.length());
                while (v.find()) {
                    String attr = v.group(1).toLowerCase(Locale.ROOT);
                    String rep = attr.equals("value") || attr.equals("content") ? quotedMask(v.group(), v.group(2)) : v.group();
                    v.appendReplacement(tagOut, Matcher.quoteReplacement(rep));
                }
                v.appendTail(tagOut);
                replacement = tagOut.toString();
            }
            tag.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        tag.appendTail(out);
        return out.toString();
    }

    /** name="secret" -> name="[REDACTED]" (empty values kept). */
    private static String quotedMask(String whole, String quotedValue) {
        String inner = unquote(quotedValue);
        if (inner.isBlank()) {
            return whole;
        }
        char q = quotedValue.charAt(0);
        return whole.substring(0, whole.length() - quotedValue.length()) + q + REDACTED + q;
    }

    private static String unquote(String quoted) {
        return quoted.length() >= 2 ? quoted.substring(1, quoted.length() - 1) : quoted;
    }

    /** JS / GraphQL / stringified-JSON assignments with an unquoted credential name. */
    private static String redactNamedAssignments(String text) {
        Matcher m = NAMED_ASSIGNMENT.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            String value = m.group(4);
            String replacement = isCredentialName(m.group(1)) && !value.isBlank() && !isPlaceholder(value.trim())
                    ? m.group(1) + m.group(2) + m.group(3) + REDACTED + m.group(5)
                    : m.group();
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static void remember(Set<String> redactedValues, String value) {
        if (redactedValues != null && value != null && !value.isBlank()) {
            redactedValues.add(value);
            String decoded = urlDecode(value);
            if (!decoded.equals(value)) {
                redactedValues.add(decoded);
            }
        }
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }
}
