package com.sn1persecurity.silentchain.bapp.net;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;
import com.sn1persecurity.silentchain.bapp.testutil.MontoyaFactoryStub;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class MontoyaHttpClientTest {

    private final AtomicInteger sendRequests = new AtomicInteger();

    private MontoyaApi api() {
        return DeepStub.of(MontoyaApi.class, Map.of(
                "sendRequest", a -> {
                    sendRequests.incrementAndGet();
                    return DeepStub.of(HttpRequestResponse.class, Map.of("response", x -> null));
                }));
    }

    @Test
    void aiDisabledBlocksBeforeAnythingIsBuiltOrSent() {
        try (MontoyaFactoryStub ignored = MontoyaFactoryStub.install()) {
            MontoyaHttpClient client = new MontoyaHttpClient(api(), new AiGate(() -> false, m -> { }), new Settings());

            MontoyaHttpClient.HttpReply reply = client.postJson("https://ai.example/v1/chat", Map.of(), "{}");

            assertEquals(MontoyaHttpClient.STATUS_AI_DISABLED, reply.status());
            assertFalse(reply.ok());
            assertEquals(0, sendRequests.get());
        }
    }

    @Test
    void appliesUpstreamTlsVerificationAndTheConfiguredTimeout() {
        AtomicInteger tlsVerification = new AtomicInteger();
        List<Long> timeouts = new ArrayList<>();
        RequestOptions[] options = new RequestOptions[1];
        options[0] = DeepStub.of(RequestOptions.class, Map.of(
                "withUpstreamTLSVerification", x -> {
                    tlsVerification.incrementAndGet();
                    return options[0];
                },
                "withResponseTimeout", x -> {
                    timeouts.add((Long) x[0]);
                    return options[0];
                }));
        try (MontoyaFactoryStub ignored = MontoyaFactoryStub.install(Map.of("requestOptions", a -> options[0]))) {
            Settings settings = new Settings();
            settings.setRequestTimeoutSeconds(42);
            MontoyaHttpClient client = new MontoyaHttpClient(api(), new AiGate(() -> true, m -> { }), settings);

            client.get("https://ai.example/v1/models", Map.of());

            assertEquals(1, sendRequests.get());
            assertEquals(1, tlsVerification.get());
            assertEquals(List.of(42_000L), timeouts);
        }
    }

    @Test
    void malformedProviderUrlBecomesAFailedReplyNotAnException() {
        try (MontoyaFactoryStub ignored = MontoyaFactoryStub.install(Map.of(
                "httpRequestFromUrl", a -> { throw new IllegalArgumentException("bad url"); }))) {
            MontoyaHttpClient client = new MontoyaHttpClient(api(), new AiGate(() -> true, m -> { }), new Settings());

            MontoyaHttpClient.HttpReply reply = client.get("localhost:11434", Map.of());

            assertEquals(0, reply.status());
            assertEquals(0, sendRequests.get());
        }
    }
}
