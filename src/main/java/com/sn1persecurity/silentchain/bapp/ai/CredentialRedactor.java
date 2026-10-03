package com.sn1persecurity.silentchain.bapp.ai;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
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

    /**
     * Attribute: name="value", name='value' or name=value (unquoted). Starts only
     * at the beginning of a name run and never backtracks into it, so a long run
     * of name characters costs one pass.
     */
    private static final Pattern ATTRIBUTE = Pattern.compile(
            "(?<![\\w:.-])([\\w:.-]++)\\s*+=\\s*+(\"[^\"]*\"|'[^']*'|[^\\s\"'=<>`]++)");

    /** Form-control tags whose value may carry a credential named by name/id/property/http-equiv. */
    private static final Set<String> FORM_CONTROL_TAGS = Set.of(
            "input", "meta", "button", "textarea", "option", "select", "param");

    /** name: "value" / name = 'value' / name:\"value\" outside JSON keys (JS, GraphQL, stringified JSON). */
    private static final Pattern NAMED_ASSIGNMENT = Pattern.compile(
            "(?<![\\w$\"'])([A-Za-z_$][\\w$.-]{0,99})(\\s*[:=]\\s*)(\\\\{0,2}[\"'])([^\"'\\\\\\r\\n]{1,500})(\\3)");

    private CredentialRedactor() {}

    // ---- Names --------------------------------------------------------------

    /** True if a header, parameter, cookie or JSON key with this name carries a credential. */
    public static boolean isCredentialName(String name) {
        if (name == null || name.isBlank() || name.length() > 300) {
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
        if (ct.isBlank() || ct.contains("x-www-form-urlencoded") || ct.contains("text/plain")) {
            text = redactPairs(text, redactedValues);
        }
        if (ct.contains("multipart/") || text.toLowerCase(Locale.ROOT).contains("content-disposition")) {
            text = redactMultipart(text, redactedValues);
        }
        text = redactJsonMembers(text, redactedValues);
        if (text.indexOf('<') >= 0) {
            text = redactMarkup(text);
        }
        return redactNamedAssignments(text);
    }

    /**
     * A response body with credential values replaced: JSON members (also JSON
     * embedded in HTML/JS), HTML form controls whose name/id marks a credential
     * (CSRF tokens, session ids), credential-named XML elements and attributes,
     * JS assignments, and form-encoded / line-based token responses.
     */
    public static String redactResponseBody(String body, String contentType) {
        String text = limit(body);
        if (text.isEmpty()) {
            return text;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (ct.isBlank() || ct.contains("x-www-form-urlencoded") || ct.contains("text/plain")) {
            text = redactPairs(text, null);
        }
        text = redactJsonMembers(text, null);
        if (text.indexOf('<') >= 0) {
            text = redactMarkup(text);
        }
        return redactNamedAssignments(text);
    }

    /**
     * A single parameter value with any credentials nested inside it removed
     * (a JSON / form / GraphQL / URL string held in an ordinary parameter).
     */
    public static String redactInsideValue(String value) {
        if (value == null || value.isEmpty()) {
            return value == null ? "" : value;
        }
        return redactUrl(redactRequestBody(value, null, null));
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

    /**
     * name=value segments separated by '&', CR or LF (form-urlencoded, text/plain
     * form posts, line-based token responses). A segment is only treated as a
     * pair when the text before '=' is a plausible name (no whitespace, quotes,
     * braces or angle brackets); its value runs to the end of the segment.
     */
    private static String redactPairs(String text, Set<String> redactedValues) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        int i = 0;
        while (i <= n) {
            int end = i;
            while (end < n) {
                char c = text.charAt(end);
                if (c == '&' || c == '\r' || c == '\n') {
                    break;
                }
                end++;
            }
            String segment = text.substring(i, end);
            int eq = segment.indexOf('=');
            if (eq > 0 && eq <= 100 && isPlausibleName(segment, eq) && isCredentialName(segment.substring(0, eq))) {
                String value = segment.substring(eq + 1);
                remember(redactedValues, value);
                out.append(segment, 0, eq + 1).append(mask(value));
            } else {
                out.append(segment);
            }
            if (end >= n) {
                break;
            }
            out.append(text.charAt(end));
            i = end + 1;
        }
        return out.toString();
    }

    private static boolean isPlausibleName(String segment, int eq) {
        for (int k = 0; k < eq; k++) {
            char c = segment.charAt(k);
            if (Character.isWhitespace(c) || c == '"' || c == '\'' || c == '<' || c == '>' || c == '{' || c == '}') {
                return false;
            }
        }
        return true;
    }

    /**
     * Credential-named multipart fields: the whole part body up to the next
     * boundary line. Linear: each header line is examined once.
     */
    private static String redactMultipart(String body, Set<String> redactedValues) {
        String lower = lowerSameLength(body);
        int n = body.length();
        StringBuilder out = new StringBuilder(n);
        int copied = 0;
        int pos = 0;
        while (pos < n) {
            int cd = lower.indexOf("content-disposition:", pos);
            if (cd < 0) {
                break;
            }
            int lineEnd = lineEnd(body, cd);
            pos = Math.max(lineEnd, cd + 1);
            int nameAt = findNameAttribute(lower, cd + 20, lineEnd);
            if (nameAt < 0 || cd < copied) {
                continue;
            }
            int q1 = nameAt + 6;
            int q2 = body.indexOf('"', q1);
            if (q2 < 0 || q2 > lineEnd || q2 - q1 > 100 || !isCredentialName(body.substring(q1, q2))) {
                continue;
            }
            int valueStart = indexOfBlankLine(body, lineEnd);
            if (valueStart < 0) {
                break;             // no part body anywhere after this point
            }
            int valueEnd = indexOfBoundary(body, valueStart);
            String value = body.substring(valueStart, valueEnd);
            remember(redactedValues, value);
            out.append(body, copied, valueStart).append(mask(value));
            copied = valueEnd;
            pos = valueEnd;
        }
        out.append(body, copied, n);
        return out.toString();
    }

    /** Lower-case one char at a time so indexes stay aligned with the original text. */
    private static String lowerSameLength(String s) {
        char[] chars = s.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = Character.toLowerCase(chars[i]);
        }
        return new String(chars);
    }

    private static int lineEnd(String s, int from) {
        int i = from;
        while (i < s.length() && s.charAt(i) != '\r' && s.charAt(i) != '\n') {
            i++;
        }
        return i;
    }

    /** Index of name=" (not filename=") within [from, to), or -1. */
    private static int findNameAttribute(String lower, int from, int to) {
        for (int k = from; k + 6 <= to; k++) {
            if (lower.startsWith("name=\"", k) && (k == 0 || !isWordChar(lower.charAt(k - 1)))) {
                return k;
            }
        }
        return -1;
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '-';
    }

    /** Index just after the first blank line at or after {@code from}, or -1. */
    private static int indexOfBlankLine(String s, int from) {
        int n = s.length();
        for (int k = from; k < n; k++) {
            if (s.charAt(k) != '\n') {
                continue;
            }
            if (k + 1 < n && s.charAt(k + 1) == '\n') {
                return k + 2;
            }
            if (k + 2 < n && s.charAt(k + 1) == '\r' && s.charAt(k + 2) == '\n') {
                return k + 3;
            }
        }
        return -1;
    }

    /** Start of the line break before the next "--" boundary line, or the end of the text. */
    private static int indexOfBoundary(String s, int from) {
        int lf = s.indexOf("\n--", from);
        if (lf < 0) {
            return s.length();
        }
        return lf > from && s.charAt(lf - 1) == '\r' ? lf - 1 : lf;
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
            int colon = skipWhitespace(text, close + 1);
            boolean isKey = colon < n && text.charAt(colon) == ':';
            if (isKey && close - i - 1 <= 200 && isCredentialName(unescapeJson(text.substring(i + 1, close)))) {
                out.append(text, i, close + 1);
                int valueStart = skipWhitespace(text, colon + 1);
                int valueEnd = endOfJsonValue(text, valueStart);
                out.append(text, close + 1, valueStart);
                out.append(maskJsonValue(text.substring(valueStart, valueEnd), redactedValues));
                i = valueEnd;
            } else if (isKey) {
                out.append(text, i, close + 1);
                i = close + 1;
            } else {
                // Not a key: this closing quote may really open the next key (a stray or
                // escaped quote earlier in non-JSON text must not shift the pairing).
                out.append(text, i, close);
                i = close;
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

    /**
     * Markup (XML, SOAP, HTML): credential-named elements lose their content
     * (text, CDATA, children), form controls whose name/id/property marks a
     * credential lose their value/content (and a textarea its text), and
     * credential-named attributes lose their value. Linear: each start tag is
     * parsed only up to the next '<'.
     */
    static String redactMarkup(String text) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        Set<String> unclosed = new HashSet<>();
        int copied = 0;
        int i = text.indexOf('<');
        while (i >= 0 && i < n) {
            int nameStart = i + 1;
            int nameEnd = nameStart;
            while (nameEnd < n && nameEnd - nameStart < 150 && isTagNameChar(text.charAt(nameEnd))) {
                nameEnd++;
            }
            if (nameEnd == nameStart || !Character.isLetter(text.charAt(nameStart))) {
                i = text.indexOf('<', i + 1);
                continue;
            }
            int nextLt = text.indexOf('<', nameEnd);
            int limit = nextLt < 0 ? n : nextLt;     // a start tag never extends past the next '<'
            int tagEnd = endOfStartTag(text, nameEnd, limit);
            String qname = text.substring(nameStart, nameEnd);
            String local = qname.substring(qname.lastIndexOf(':') + 1).toLowerCase(Locale.ROOT);
            String tag = text.substring(i, tagEnd);
            String newTag = redactTagAttributes(tag, local);

            int contentEnd = -1;   // when set, [tagEnd, contentEnd) is replaced by [REDACTED]
            boolean selfClosing = tag.endsWith("/>");
            if (!selfClosing && tag.endsWith(">")
                    && ((local.equals("textarea") && hasCredentialIdentity(tag)) || isCredentialName(local))) {
                contentEnd = elementContentEnd(text, qname, tagEnd, unclosed);
            }

            out.append(text, copied, i).append(newTag);
            copied = tagEnd;
            if (contentEnd > tagEnd) {
                String content = text.substring(tagEnd, contentEnd);
                if (!content.isBlank() && !content.replace("<![CDATA[]]>", "").isBlank()) {
                    out.append(REDACTED);
                    copied = contentEnd;
                }
            }
            i = text.indexOf('<', Math.max(tagEnd, copied));
        }
        out.append(text, copied, n);
        return out.toString();
    }

    private static boolean isTagNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == ':' || c == '.' || c == '-' || c == '_';
    }

    /**
     * Index after the '>' closing the start tag (quote-aware), or {@code limit}
     * if it is cut off. Never looks at or beyond {@code limit} (the next '<').
     */
    private static int endOfStartTag(String s, int from, int limit) {
        int firstGt = -1;
        char quote = 0;
        for (int k = from; k < limit; k++) {
            char c = s.charAt(k);
            if (c == '>' && firstGt < 0) {
                firstGt = k;
            }
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                return k + 1;
            }
        }
        // Cut off, or a quote never closed: fall back to the first raw '>' (if any).
        return quote != 0 && firstGt >= 0 ? firstGt + 1 : limit;
    }

    /** Close-tag searches per body; bounds the work for many distinct unclosed credential elements. */
    private static final int MAX_CLOSE_TAG_SEARCHES = 256;

    /** End of an element's content: its close tag, or (no close tag) the next markup, CDATA included. */
    private static int elementContentEnd(String s, String qname, int from, Set<String> unclosed) {
        if (!unclosed.contains(qname) && unclosed.size() < MAX_CLOSE_TAG_SEARCHES) {
            String close = "</" + qname;
            int k = from;
            while ((k = s.indexOf(close, k)) >= 0) {
                int after = k + close.length();
                if (after >= s.length() || s.charAt(after) == '>' || Character.isWhitespace(s.charAt(after))) {
                    return k;
                }
                k = after;
            }
            unclosed.add(qname);   // no close tag after here, so none after any later position either
        }
        int next = s.indexOf('<', from);
        if (next >= 0 && s.startsWith("<![CDATA[", next)) {
            int cdataEnd = s.indexOf("]]>", next);
            return cdataEnd < 0 ? s.length() : cdataEnd + 3;
        }
        return next < 0 ? s.length() : next;
    }

    /** True if the tag's name/id/property/http-equiv attribute names a credential. */
    private static boolean hasCredentialIdentity(String tag) {
        Matcher a = ATTRIBUTE.matcher(tag);
        while (a.find()) {
            String attr = a.group(1).toLowerCase(Locale.ROOT);
            if ((attr.equals("name") || attr.equals("id") || attr.equals("property") || attr.equals("http-equiv"))
                    && isCredentialName(unquote(a.group(2)))) {
                return true;
            }
        }
        return false;
    }

    /** Mask credential-named attributes, and value/content of a credential form control. */
    private static String redactTagAttributes(String tag, String localName) {
        boolean credentialControl = FORM_CONTROL_TAGS.contains(localName) && hasCredentialIdentity(tag);
        Matcher a = ATTRIBUTE.matcher(tag);
        StringBuilder out = new StringBuilder(tag.length());
        while (a.find()) {
            String name = a.group(1);
            String local = name.substring(name.lastIndexOf(':') + 1);
            String lower = local.toLowerCase(Locale.ROOT);
            boolean maskIt = isCredentialName(local)
                    || (credentialControl && (lower.equals("value") || lower.equals("content")));
            a.appendReplacement(out, Matcher.quoteReplacement(maskIt ? quotedMask(a.group(), a.group(2)) : a.group()));
        }
        a.appendTail(out);
        return out.toString();
    }

    /** name="secret" -> name="[REDACTED]" (empty values kept; unquoted values stay unquoted). */
    private static String quotedMask(String whole, String value) {
        String inner = unquote(value);
        if (inner.isBlank()) {
            return whole;
        }
        String prefix = whole.substring(0, whole.length() - value.length());
        char q = value.charAt(0);
        return q == '"' || q == '\'' ? prefix + q + REDACTED + q : prefix + REDACTED;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && (value.charAt(0) == '"' || value.charAt(0) == '\'')) {
            return value.substring(1, value.length() - 1);
        }
        return value;
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
