package com.sn1persecurity.silentchain.bapp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Right-click analysis is limited to Burp's target scope, like passive analysis. */
class ContextMenuProviderTest {

    private static HttpRequestResponse item(String url) {
        HttpRequest request = url == null ? null : DeepStub.of(HttpRequest.class, Map.of("url", a -> url));
        return DeepStub.of(HttpRequestResponse.class, Map.of("request", a -> request));
    }

    @Test
    void keepsOnlyInScopeItems() {
        HttpRequestResponse inScope = item("https://target.example/a");
        HttpRequestResponse idp = item("https://login.thirdparty.example/oauth");
        List<HttpRequestResponse> kept = ContextMenuProvider.inScope(
                Arrays.asList(inScope, idp, item(null), null),
                url -> url.startsWith("https://target.example/"));

        assertEquals(1, kept.size());
        assertSame(inScope, kept.get(0));
    }

    @Test
    void allOutOfScopeQueuesNothing() {
        assertTrue(ContextMenuProvider.inScope(List.of(item("https://elsewhere.example/")), url -> false).isEmpty());
    }
}
