package com.sn1persecurity.silentchain.bapp.ai;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Credentials never reach the AI provider, whatever the sanitizer toggle says.
 * JSESSIONID, ASP.NET_SessionId, X-Api-Key, Ocp-Apim-Subscription-Key, JSON
 * passwords and ?api_key= all slipped past value-pattern-only redaction.
 */
class CredentialRedactorTest {

    private static String req(String body) {
        return CredentialRedactor.redactRequestBody(body, null, null);
    }

    private static void assertNoLeak(String out, String... secrets) {
        for (String secret : secrets) {
            assertFalse(out.contains(secret), "leaked " + secret + " in: " + out);
        }
    }

    @Test
    void credentialNames() {
        for (String name : new String[]{"password", "Passwd", "pwd", "api_key", "apikey", "X-Api-Key",
                "access_token", "refresh_token", "id_token", "client_secret", "JSESSIONID", "PHPSESSID",
                "ASP.NET_SessionId", "sessionid", "csrfmiddlewaretoken", "authenticity_token", "jwt", "otp",
                "X-Goog-Api-Key", "Ocp-Apim-Subscription-Key", "Private-Token", "X-Vault-Token",
                "X-Session-Token", "Authorization", "key", "X-Amz-Signature", "auth_code",
                // camelCase, plurals, URL-encoded and MFA / SAML / ASP.NET names
                "sessionToken", "apiToken", "jwtToken", "apiSecret", "appSecret", "authKey", "userPass", "newPwd",
                "tokens", "Authentication", "X-Authentication", "__RequestVerificationToken", "totp", "mfa_code",
                "client_assertion", "SAMLResponse", "user%5Btoken%5D", "account[secret]", "passcode"}) {
            assertTrue(CredentialRedactor.isCredentialName(name), name);
        }
        for (String name : new String[]{"id", "q", "search", "page", "username", "email", "monkey",
                "Content-Type", "Server", "keyword", "redirect", "X-Frame-Options", "X-XSS-Protection",
                "returnUrl", "code", "status", "address", "Content-Security-Policy"}) {
            assertFalse(CredentialRedactor.isCredentialName(name), name);
        }
    }

    @Test
    void cookieValuesAreRedactedButNamesAndEmptyValuesKept() {
        assertEquals("JSESSIONID=[REDACTED]; ASP.NET_SessionId=[REDACTED]; theme=[REDACTED]",
                CredentialRedactor.redactHeaderValue("Cookie", "JSESSIONID=ABC123; ASP.NET_SessionId=xyz; theme=dark"));
        assertEquals("session=; Max-Age=0",
                CredentialRedactor.redactHeaderValue("Set-Cookie", "session=; Max-Age=0"));
    }

    @Test
    void setCookieKeepsSecurityAttributes() {
        assertEquals("session=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax",
                CredentialRedactor.redactHeaderValue("Set-Cookie",
                        "session=deadbeef; Path=/; HttpOnly; Secure; SameSite=Lax"));
    }

    @Test
    void credentialHeadersKeepOnlyAnAuthScheme() {
        assertEquals("Bearer [REDACTED]", CredentialRedactor.redactHeaderValue("Authorization", "Bearer eyJhbGciOi"));
        assertEquals("Token [REDACTED]", CredentialRedactor.redactHeaderValue("authorization", "Token abc"));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("Authorization", "opaque-secret"));
        assertEquals("Basic [REDACTED]", CredentialRedactor.redactHeaderValue("Proxy-Authorization", "Basic dXNlcjpwYXNz"));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("X-Api-Key", "k-123"));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("Ocp-Apim-Subscription-Key", "0123abcd"));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("X-Goog-Api-Key", "AIzaSy..."));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("Private-Token", "glpat-x"));
        assertEquals("[REDACTED]", CredentialRedactor.redactHeaderValue("X-CSRF-Token", "c"));
    }

    /** An absent or placeholder credential must stay visible: it is often the finding. */
    @Test
    void emptyAndPlaceholderCredentialsAreKept() {
        assertEquals("Bearer", CredentialRedactor.redactHeaderValue("Authorization", "Bearer"));
        assertEquals("Bearer undefined", CredentialRedactor.redactHeaderValue("Authorization", "Bearer undefined"));
        assertEquals("", CredentialRedactor.redactHeaderValue("X-Api-Key", ""));
        assertEquals("", CredentialRedactor.redactParameterValue("csrf_token", "", false));
        assertEquals("csrf_token=&user=bob", req("csrf_token=&user=bob"));
        assertEquals("{\"token\":\"\",\"auth\":null}", req("{\"token\":\"\",\"auth\":null}"));
    }

    @Test
    void securityRelevantHeadersThatOnlyLookLikeCredentialsAreKept() {
        assertEquals("Bearer realm=\"api\"", CredentialRedactor.redactHeaderValue("WWW-Authenticate", "Bearer realm=\"api\""));
        assertEquals("dGhlIHNhbXBsZQ==", CredentialRedactor.redactHeaderValue("Sec-WebSocket-Key", "dGhlIHNhbXBsZQ=="));
        assertEquals("true", CredentialRedactor.redactHeaderValue("Access-Control-Allow-Credentials", "true"));
        assertEquals("Authorization, X-Api-Key",
                CredentialRedactor.redactHeaderValue("Access-Control-Allow-Headers", "Authorization, X-Api-Key"));
        assertEquals("nginx/1.25.3", CredentialRedactor.redactHeaderValue("Server", "nginx/1.25.3"));
    }

    @Test
    void urlTokensAreRedactedInQueriesPathParametersFragmentsAndUrlHeaders() {
        assertEquals("https://a.example/p?id=7&api_key=[REDACTED]&q=x#frag",
                CredentialRedactor.redactUrl("https://a.example/p?id=7&api_key=AIzaSyXYZ&q=x#frag"));
        assertEquals("https://a.example/p?access%5Ftoken=[REDACTED]",
                CredentialRedactor.redactUrl("https://a.example/p?access%5Ftoken=abc"));
        assertEquals("https://a.example/app;jsessionid=[REDACTED]?x=1",
                CredentialRedactor.redactUrl("https://a.example/app;jsessionid=V3?x=1"));
        assertEquals("https://a.example/cb?token=[REDACTED]",
                CredentialRedactor.redactHeaderValue("Referer", "https://a.example/cb?token=V1"));
        assertEquals("https://a.example/cb#access_token=[REDACTED]&expires_in=3600",
                CredentialRedactor.redactHeaderValue("Location", "https://a.example/cb#access_token=V2&expires_in=3600"));
        assertEquals("https://a.example/p", CredentialRedactor.redactUrl("https://a.example/p"));
    }

    @Test
    void parameterValues() {
        assertEquals("[REDACTED]", CredentialRedactor.redactParameterValue("theme", "dark", true));
        assertEquals("[REDACTED]", CredentialRedactor.redactParameterValue("password", "hunter2", false));
        assertEquals("42", CredentialRedactor.redactParameterValue("id", "42", false));
    }

    @Test
    void formBodiesIncludingTrailingLineBreaks() {
        assertEquals("user=bob&password=[REDACTED]&remember=1", req("user=bob&password=hunter2&remember=1"));
        assertEquals("user=bob&password=[REDACTED]\r\n", req("user=bob&password=V4\r\n"));
    }

    @Test
    void jsonValuesIncludingNestedContainersAndCutOffText() {
        assertEquals("{\"user\":\"bob\",\"password\":\"[REDACTED]\",\"otp\":\"[REDACTED]\"}",
                req("{\"user\":\"bob\",\"password\":\"Hunter2!xyz\",\"otp\":123456}"));

        String nested = req("{\"password\": {\"current\": \"V8\", \"new\": \"V9\"}, \"ok\": 1}");
        assertEquals("{\"password\": \"[REDACTED]\", \"ok\": 1}", nested);
        assertNoLeak(req("{\"token\":[\"V10\",\"V11\"]}"), "V10", "V11");
        assertNoLeak(req("{\"auth\": {\"password\": \"S1\"}}"), "S1");
        assertNoLeak(req("{\"user\":\"bob\",\"api_key\":\"sk-live-abcdef"), "sk-live");
        assertNoLeak(req("{\"pass\\u0077ord\":\"S2\"}"), "S2");
    }

    @Test
    void redactedContainerLeavesAreReportedForParamsSample() {
        Set<String> redacted = new HashSet<>();
        CredentialRedactor.redactRequestBody("{\"password\":{\"current\":\"V8\",\"new\":\"V9\"},\"id\":7}",
                "application/json", redacted);
        assertTrue(redacted.contains("V8") && redacted.contains("V9"), redacted.toString());
        assertFalse(redacted.contains("7"));
    }

    @Test
    void graphqlAndStringifiedJsonArguments() {
        assertNoLeak(req("{\"query\":\"mutation{login(user:\\\"bob\\\", password:\\\"V13\\\")}\"}"), "V13");
        assertNoLeak(req("mutation { login(user: \"bob\", password: \"V14\") }"), "V14");
    }

    @Test
    void multipartFieldsAnyHeaderCaseAndMultiLineValues() {
        String body = "--b\r\ncontent-disposition: form-data; name=\"user\"\r\n\r\nbob\r\n"
                + "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nV5\r\n"
                + "--b\r\nContent-Disposition: form-data; name=\"private_key\"\r\n\r\n"
                + "-----BEGIN KEY-----\r\nLINE2SECRET\r\n-----END KEY-----\r\n--b--";
        String out = CredentialRedactor.redactRequestBody(body, "multipart/form-data; boundary=b", null);
        assertTrue(out.contains("bob"));
        assertNoLeak(out, "V5", "LINE2SECRET", "BEGIN KEY");
    }

    @Test
    void xmlAndSoapCredentials() {
        String soap = "<soap:Envelope><wsse:UsernameToken><wsse:Username>bob</wsse:Username>"
                + "<wsse:Password Type=\"PasswordText\">V7</wsse:Password></wsse:UsernameToken>"
                + "<login password=\"V15\" user=\"bob\"/></soap:Envelope>";
        String out = CredentialRedactor.redactRequestBody(soap, "text/xml", null);
        assertNoLeak(out, "V7", "V15");
        assertTrue(out.contains("bob"));
    }

    @Test
    void responseBodiesJsonHtmlAndFormTokenResponses() {
        assertNoLeak(CredentialRedactor.redactResponseBody(
                "{\"access_token\":\"AT1\",\"refresh_token\":\"RT1\",\"token_type\":\"Bearer\",\"user\":\"bob\"}",
                "application/json"), "AT1", "RT1");
        String html = "<form><input type=\"hidden\" name=\"csrf_token\" value=\"CS1\">"
                + "<input name=\"q\" value=\"shoes\"></form><meta name=\"csrf-token\" content=\"CS2\">"
                + "<script>window.__STATE__ = {\"sessionToken\":\"ST1\"}; var apiKey = 'AK1';</script>";
        String out = CredentialRedactor.redactResponseBody(html, "text/html");
        assertNoLeak(out, "CS1", "CS2", "ST1", "AK1");
        assertTrue(out.contains("shoes"));
        assertNoLeak(CredentialRedactor.redactResponseBody("access_token=AT2&expires_in=3600", "text/plain"), "AT2");
    }

    /** Linear scanning: long cut-off values must not blow the stack (the old regex did, about 2000 chars). */
    @Test
    void longAndCutOffValuesDoNotOverflowTheStack() throws Exception {
        String longValue = "{\"query\":\"" + "q\\n{ x }".repeat(5_000);
        String withSecret = "{\"note\":\"" + "x".repeat(60_000) + "\",\"password\":\"PW\"}";
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<String> second = new AtomicReference<>();
        Thread t = new Thread(null, () -> {
            try {
                req(longValue);
                CredentialRedactor.redactResponseBody(longValue, "text/html");
                second.set(req(withSecret));
            } catch (Throwable e) {
                failure.set(e);
            }
        }, "small-stack", 256 * 1024);
        t.start();
        t.join(10_000);
        assertNull(failure.get());
        assertNoLeak(second.get(), "PW");
    }

    /** One stray or escaped quote earlier in the body must not switch redaction off for the rest. */
    @Test
    void strayQuotesDoNotDesynchroniseTheScanner() {
        String boot = "<script>window.__BOOT__ = {\"csrf_token\":\"CSRF-LEAK\",\"session\":{\"id\":\"SESS-LEAK\"}};</script>";
        for (String prefix : new String[]{
                "<input type=\"hidden\" id=\"logdir\" value=\"C:\\logs\\\">",
                "<p>The 5\" display</p>",
                "<script>s.replace(/\"/g,'&quot;'); var q='\"';</script>"}) {
            assertNoLeak(CredentialRedactor.redactResponseBody(prefix + boot, "text/html"), "CSRF-LEAK", "SESS-LEAK");
        }
        assertNoLeak(req("{\"note\":\"path C:\\\",\"password\":\"Hunter2!xyz\"}"), "Hunter2!xyz");
    }

    @Test
    void textPlainAndLineBasedPairs() {
        assertNoLeak(CredentialRedactor.redactRequestBody("user=bob\r\npassword=V20 with spaces\r\n", "text/plain", null), "V20");
        assertNoLeak(CredentialRedactor.redactResponseBody("SID=S1\nLSID=S2\nAuth=A3\n", "text/plain"), "A3");
        assertNoLeak(CredentialRedactor.redactRequestBody("user=bob&password={\"a\":1} x", null, null), "{\"a\"");
    }

    @Test
    void htmlFormControlsWhateverTheAttributeOrder() {
        String html = "<input data-x=\"a>b\" name=\"csrf_token\" value=\"T1\">"
                + "<input value=\"T2\" name=\"authenticity_token\">"
                + "<input name=csrf_token value=T3>"
                + "<input " + "data-pad=\"x\" ".repeat(300) + "name=\"_csrf\" value=\"T4\">"
                + "<textarea name=\"api_key\">T5</textarea>"
                + "<button name=\"token\" value=\"T6\">Go</button>"
                + "<input name=\"q\" value=\"shoes\">";
        String out = CredentialRedactor.redactResponseBody(html, "text/html");
        assertNoLeak(out, "T1", "T2", "T3", "T4", "T5", "T6");
        assertTrue(out.contains("shoes"));
    }

    @Test
    void xmlCredentialContentIncludingCdataAndChildren() {
        String xml = "<Envelope><Password><![CDATA[V21&<x>]]></Password>"
                + "<auth><user>bob</user><secret>V22</secret></auth>"
                + "<Token" + " a=\"x\"".repeat(200) + ">V23</Token><name>visible</name></Envelope>";
        String out = CredentialRedactor.redactRequestBody(xml, "application/xml", null);
        assertNoLeak(out, "V21", "V22", "V23");
        assertTrue(out.contains("visible"));
    }

    /** Linear time on hostile bodies (the multipart regex was quadratic: about 1 s for 64 KB). */
    @Test
    void hostileBodiesStayFast() {
        String[] hostile = {
                "content-disposition: ".repeat(4_000),
                "<input '".repeat(9_000),
                "<tokenA".repeat(9_000),
                "\"a\":".repeat(13_000),
                "\"x\\".repeat(16_000),
                "<a ".repeat(20_000),
                "<input " + "a".repeat(65_000),
                "<x " + "a".repeat(65_000) + "<",
                "\u0130".repeat(20) + "Content-Disposition:\n" + "\u0130".repeat(20) + "content-disposition:\r\n"};
        for (String body : hostile) {
            long start = System.nanoTime();
            CredentialRedactor.redactRequestBody(body, "multipart/form-data", null);
            CredentialRedactor.redactResponseBody(body, "text/html");
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis < 500, "took " + millis + " ms on " + body.substring(0, 20));
        }
    }

    @Test
    void longStartTagsAreParsedWhole() {
        String html = "<input name=\"csrf_token\"" + " ".repeat(9_000) + "value=\"S-LONG\"><p>hi</p>";
        String out = CredentialRedactor.redactResponseBody(html, "text/html");
        assertNoLeak(out, "S-LONG");
        assertTrue(out.endsWith("<p>hi</p>"));
    }
}
