package com.sn1persecurity.silentchain.bapp.ai;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Credential header values never reach the AI provider, whatever the sanitizer
 * toggle says. JSESSIONID, ASP.NET_SessionId, X-Api-Key and "Authorization:
 * Token" all slipped past the old value-pattern-only redaction.
 */
class PromptLibraryTest {

    @Test
    void cookieValuesAreRedactedButNamesKept() {
        assertEquals("JSESSIONID=[REDACTED]; ASP.NET_SessionId=[REDACTED]; theme=[REDACTED]",
                PromptLibrary.redactHeaderValue("Cookie", "JSESSIONID=ABC123; ASP.NET_SessionId=xyz; theme=dark"));
    }

    @Test
    void setCookieKeepsSecurityAttributes() {
        String out = PromptLibrary.redactHeaderValue("Set-Cookie",
                "session=deadbeef; Path=/; HttpOnly; Secure; SameSite=Lax");
        assertEquals("session=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax", out);
    }

    @Test
    void authorizationKeepsOnlyTheScheme() {
        assertEquals("Bearer [REDACTED]", PromptLibrary.redactHeaderValue("Authorization", "Bearer eyJhbGciOi..."));
        assertEquals("Token [REDACTED]", PromptLibrary.redactHeaderValue("authorization", "Token abc"));
        assertEquals("[REDACTED]", PromptLibrary.redactHeaderValue("Authorization", "opaque-secret"));
        assertEquals("Basic [REDACTED]", PromptLibrary.redactHeaderValue("Proxy-Authorization", "Basic dXNlcjpwYXNz"));
    }

    @Test
    void apiKeyAndTokenHeadersAreRedacted() {
        assertEquals("[REDACTED]", PromptLibrary.redactHeaderValue("X-Api-Key", "k-123"));
        assertEquals("[REDACTED]", PromptLibrary.redactHeaderValue("x-auth-token", "t"));
        assertEquals("[REDACTED]", PromptLibrary.redactHeaderValue("X-CSRF-Token", "c"));
    }

    @Test
    void ordinaryHeadersPassThroughButAreCapped() {
        assertEquals("nginx/1.25.3", PromptLibrary.redactHeaderValue("Server", "nginx/1.25.3"));
        String longValue = "a".repeat(5_000);
        String out = PromptLibrary.redactHeaderValue("X-Long", longValue);
        assertTrue(out.length() <= 300);
        assertFalse(out.contains("[REDACTED]"));
    }
}
