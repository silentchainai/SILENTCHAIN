package com.sn1persecurity.silentchain.bapp.ai;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.sn1persecurity.silentchain.bapp.data.DataSanitizer;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end: what actually goes into the AI prompt. Credentials must be gone
 * from every field (url, params_sample, headers, request_body) with the
 * sanitizer OFF, i.e. without relying on it.
 */
class PromptLibraryTest {

    private static ParsedHttpParameter param(String name, String value, HttpParameterType type) {
        return DeepStub.of(ParsedHttpParameter.class, Map.of(
                "name", a -> name, "value", a -> value, "type", a -> type));
    }

    private static HttpHeader header(String name, String value) {
        return DeepStub.of(HttpHeader.class, Map.of("name", a -> name, "value", a -> value));
    }

    @Test
    void credentialsNeverReachThePromptEvenWithTheSanitizerOff() {
        HttpRequest request = DeepStub.of(HttpRequest.class, Map.of(
                "url", a -> "https://app.example.org/login?api_key=AIzaSyLEAK1&next=/home",
                "method", a -> "POST",
                "parameters", a -> List.of(
                        param("JSESSIONID", "8F3A9C0B1D2E4F50", HttpParameterType.COOKIE),
                        // Session cookies often have arbitrary names: redacted because they are cookies.
                        param("BIGipServerPool", "COOKIE-LEAK3", HttpParameterType.COOKIE),
                        param("password", "Hunter2!xyz", HttpParameterType.JSON),
                        param("next", "/home", HttpParameterType.URL)),
                "headers", a -> List.of(
                        header("Cookie", "JSESSIONID=8F3A9C0B1D2E4F50"),
                        header("X-Api-Key", "k-LEAK2"),
                        header("Content-Type", "application/json")),
                "bodyToString", a -> "{\"user\":\"bob\",\"password\":\"Hunter2!xyz\"}"));
        HttpRequestResponse rr = DeepStub.of(HttpRequestResponse.class, Map.of(
                "request", a -> request, "response", a -> null));

        String prompt = PromptLibrary.buildAnalysisPrompt(rr, new DataSanitizer(false));

        for (String secret : new String[]{"8F3A9C0B1D2E4F50", "COOKIE-LEAK3", "Hunter2!xyz", "AIzaSyLEAK1", "k-LEAK2"}) {
            assertFalse(prompt.contains(secret), "leaked " + secret + ":\n" + prompt);
        }
        // Names and non-secret values stay, so the model can still reason about them.
        assertTrue(prompt.contains("JSESSIONID"));
        assertTrue(prompt.contains("/home"));
        assertTrue(prompt.contains("bob"));
    }

    @Test
    void longHeadersAreCutWithAVisibleMarkerAndPolicyHeadersGetMoreRoom() {
        String csp = "default-src 'self'; " + "script-src 'self' https://cdn.example; ".repeat(40);
        String shownCsp = PromptLibrary.headerValueForPrompt("Content-Security-Policy", csp);
        assertTrue(shownCsp.length() > 300 && shownCsp.length() < 2_100, "length " + shownCsp.length());

        String shownOther = PromptLibrary.headerValueForPrompt("X-Long", "a".repeat(5_000));
        assertTrue(shownOther.startsWith("a".repeat(300)));
        assertTrue(shownOther.endsWith("...[truncated 4700 chars]"));
        assertEquals("nginx", PromptLibrary.headerValueForPrompt("Server", "nginx"));
    }

    @Test
    void responseCredentialsAndRedactedBodyValuesNeverReachThePrompt() {
        HttpRequest request = DeepStub.of(HttpRequest.class, Map.of(
                "url", a -> "https://app.example.org/token",
                "headerValue", a -> "application/json",
                "parameters", a -> List.of(param("current", "NESTED-LEAK", HttpParameterType.JSON)),
                "bodyToString", a -> "{\"password\":{\"current\":\"NESTED-LEAK\"}}"));
        HttpResponse response = DeepStub.of(HttpResponse.class, Map.of(
                "headerValue", a -> "application/json",
                "headers", a -> List.of(header("Set-Cookie", "sid=SC-LEAK; HttpOnly")),
                "bodyToString", a -> "{\"access_token\":\"AT-LEAK\",\"refresh_token\":\"RT-LEAK\",\"user\":\"bob\"}"));
        HttpRequestResponse rr = DeepStub.of(HttpRequestResponse.class, Map.of(
                "request", a -> request, "response", a -> response));

        String prompt = PromptLibrary.buildAnalysisPrompt(rr, new DataSanitizer(false));

        for (String secret : new String[]{"NESTED-LEAK", "AT-LEAK", "RT-LEAK", "SC-LEAK"}) {
            assertFalse(prompt.contains(secret), "leaked " + secret + ":\n" + prompt);
        }
        assertTrue(prompt.contains("HttpOnly"));
        assertTrue(prompt.contains("bob"));
    }

    @Test
    void securityHeadersAreNeverPushedOutByALongHeaderList() {
        List<HttpHeader> hdrs = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            hdrs.add(header("X-Filler-" + i, "v"));
        }
        hdrs.add(header("Content-Security-Policy", "default-src 'self'"));
        hdrs.add(header("Strict-Transport-Security", "max-age=63072000"));

        String shown = PromptLibrary.headers(hdrs).toString();

        assertTrue(shown.contains("Content-Security-Policy"), shown);
        assertTrue(shown.contains("Strict-Transport-Security"), shown);
        assertTrue(shown.contains("more headers omitted"), shown);
    }

    @Test
    void cutsAreMarked() {
        assertEquals("abc", PromptLibrary.capMarked("abc", 5));
        assertEquals("abcde ...[truncated 3 chars]", PromptLibrary.capMarked("abcdefgh", 5));
    }
}
