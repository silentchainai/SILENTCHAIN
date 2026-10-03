package com.sn1persecurity.silentchain.bapp.ai.providers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class GeminiProviderTest {

    @Test
    void apiKeyIsNeverPutInTheUrl() {
        String url = GeminiProvider.generateContentUrl("https://generativelanguage.googleapis.com/v1", "gemini-2.0-flash");
        assertEquals("https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent", url);
        assertFalse(url.contains("key="));
    }

    @Test
    void modelIsEncodedAsOnePathSegment() {
        String url = GeminiProvider.generateContentUrl("https://g.example/v1", "a b/../c");
        assertEquals("https://g.example/v1/models/a%20b%2F..%2Fc:generateContent", url);
    }
}
