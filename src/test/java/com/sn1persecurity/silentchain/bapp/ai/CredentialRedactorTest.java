package com.sn1persecurity.silentchain.bapp.ai;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Credentials never reach the AI provider, whatever the sanitizer toggle says.
 * JSESSIONID, ASP.NET_SessionId, X-Api-Key, Ocp-Apim-Subscription-Key, JSON
 * passwords and ?api_key= all slipped past value-pattern-only redaction.
 */
class CredentialRedactorTest {

    @Test
    void credentialNames() {
        for (String name : new String[]{"password", "Passwd", "pwd", "api_key", "apikey", "X-Api-Key",
                "access_token", "refresh_token", "id_token", "client_secret", "JSESSIONID", "PHPSESSID",
                "ASP.NET_SessionId", "sessionid", "csrfmiddlewaretoken", "authenticity_token", "jwt", "otp",
                "X-Goog-Api-Key", "Ocp-Apim-Subscription-Key", "Private-Token", "X-Vault-Token",
                "X-Session-Token", "Authorization", "key", "X-Amz-Signature", "auth_code"}) {
            assertTrue(CredentialRedactor.isCredentialName(name), name);
        }
        for (String name : new String[]{"id", "q", "search", "page", "username", "email", "monkey",
                "Content-Type", "Server", "keyword", "redirect", "X-Frame-Options", "X-XSS-Protection"}) {
            assertFalse(CredentialRedactor.isCredentialName(name), name);
        }
    }

    @Test
    void cookieValuesAreRedactedButNamesKept() {
        assertEquals("JSESSIONID=[REDACTED]; ASP.NET_SessionId=[REDACTED]; theme=[REDACTED]",
                CredentialRedactor.redactHeaderValue("Cookie", "JSESSIONID=ABC123; ASP.NET_SessionId=xyz; theme=dark"));
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
    void urlQueryCredentialsAreRedacted() {
        assertEquals("https://a.example/p?id=7&api_key=[REDACTED]&q=x#frag",
                CredentialRedactor.redactUrl("https://a.example/p?id=7&api_key=AIzaSyXYZ&q=x#frag"));
        assertEquals("https://a.example/p?access%5Ftoken=[REDACTED]",
                CredentialRedactor.redactUrl("https://a.example/p?access%5Ftoken=abc"));
        assertEquals("https://a.example/p", CredentialRedactor.redactUrl("https://a.example/p"));
    }

    @Test
    void parameterValues() {
        assertEquals("[REDACTED]", CredentialRedactor.redactParameterValue("theme", "dark", true));
        assertEquals("[REDACTED]", CredentialRedactor.redactParameterValue("password", "hunter2", false));
        assertEquals("42", CredentialRedactor.redactParameterValue("id", "42", false));
    }

    @Test
    void formBodyCredentialsAreRedacted() {
        assertEquals("user=bob&password=[REDACTED]&remember=1",
                CredentialRedactor.redactBody("user=bob&password=hunter2&remember=1"));
    }

    @Test
    void jsonBodyCredentialsAreRedactedEvenWhenCutOff() {
        String out = CredentialRedactor.redactBody("{\"user\":\"bob\",\"password\":\"Hunter2!xyz\",\"otp\":123456}");
        assertEquals("{\"user\":\"bob\",\"password\":\"[REDACTED]\",\"otp\":\"[REDACTED]\"}", out);

        String truncated = CredentialRedactor.redactBody("{\"user\":\"bob\",\"api_key\":\"sk-live-abcdef");
        assertFalse(truncated.contains("sk-live"), truncated);
    }

    @Test
    void multipartCredentialFieldsAreRedacted() {
        String body = "--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n"
                + "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--b--";
        String out = CredentialRedactor.redactBody(body);
        assertTrue(out.contains("bob"));
        assertFalse(out.contains("hunter2"), out);
    }
}
