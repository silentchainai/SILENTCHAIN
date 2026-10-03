package com.sn1persecurity.silentchain.bapp.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.http.message.HttpRequestResponse;

import com.sn1persecurity.silentchain.bapp.ai.providers.LlmProvider;
import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.ai.providers.TestResult;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;
import com.sn1persecurity.silentchain.bapp.net.MontoyaHttpClient;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;
import com.sn1persecurity.silentchain.bapp.testutil.MontoyaFactoryStub;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PortSwigger policy: api.ai().isEnabled() must gate EVERY outgoing AI request,
 * whatever the provider (extension-portal #231, #244). These tests drive every
 * entry point that can reach a provider (analysis, model refresh, Test
 * Connection, through the dispatcher and directly on the provider) with AI
 * disabled and assert that nothing reaches Burp's HTTP stack or Burp AI.
 */
class AiGatingTest {

    private final AtomicBoolean aiEnabled = new AtomicBoolean();
    private final AtomicInteger sendRequests = new AtomicInteger();
    private final AtomicInteger burpAiPrompts = new AtomicInteger();

    private MontoyaFactoryStub factory;
    private MontoyaApi api;

    @BeforeEach
    void setUp() {
        factory = MontoyaFactoryStub.install();
        api = DeepStub.of(MontoyaApi.class, Map.of(
                "sendRequest", a -> {
                    sendRequests.incrementAndGet();
                    return DeepStub.of(HttpRequestResponse.class, Map.of("response", x -> null));
                },
                "isEnabled", a -> aiEnabled.get(),
                "prompt", a -> {
                    burpAiPrompts.incrementAndGet();
                    return DeepStub.of(Prompt.class);
                }));
    }

    @AfterEach
    void tearDown() {
        factory.close();
    }

    private AiDispatcher dispatcherFor(Settings settings) {
        AiGate gate = new AiGate(aiEnabled::get, message -> { });
        return new AiDispatcher(api, new MontoyaHttpClient(api, gate, settings), settings, gate);
    }

    private static Settings configured(ProviderId provider) {
        Settings s = new Settings();
        s.setProvider(provider);
        s.setConfig(provider, new ProviderConfig("https://ai.example/v1", "secret-key", "some-model"));
        return s;
    }

    @ParameterizedTest
    @EnumSource(ProviderId.class)
    void noAiRequestLeavesWhenAiIsDisabled(ProviderId provider) {
        aiEnabled.set(false);
        AiDispatcher dispatcher = dispatcherFor(configured(provider));

        assertFalse(dispatcher.isAvailable());
        assertTrue(dispatcher.analyze("system", "user").isEmpty());
        assertTrue(dispatcher.listModels(provider).isEmpty());
        TestResult viaDispatcher = dispatcher.testConnection(provider);
        assertFalse(viaDispatcher.success());
        assertEquals(AiGate.DISABLED_MESSAGE, viaDispatcher.message());

        // Calling the provider directly (bypassing the dispatcher) is gated too.
        LlmProvider direct = dispatcher.current();
        assertTrue(direct.isConfigured());
        assertFalse(direct.isAvailable());
        assertTrue(direct.analyze("system", "user").isEmpty());
        direct.listModels();
        TestResult viaProvider = direct.testConnection();
        assertFalse(viaProvider.success());

        assertEquals(0, sendRequests.get(), "third-party AI request sent while AI was disabled");
        assertEquals(0, burpAiPrompts.get(), "Burp AI prompt issued while AI was disabled");
    }

    /** Control: the same calls DO reach the stubbed network once AI is enabled. */
    @ParameterizedTest
    @EnumSource(value = ProviderId.class, names = {"OLLAMA", "OPENAI", "CLAUDE", "GEMINI", "AZURE_FOUNDRY"})
    void thirdPartyRequestsAreSentWhenAiIsEnabled(ProviderId provider) {
        aiEnabled.set(true);
        AiDispatcher dispatcher = dispatcherFor(configured(provider));

        assertTrue(dispatcher.isAvailable());
        dispatcher.analyze("system", "user");
        assertTrue(sendRequests.get() > 0, "the stub should have seen the analysis request");
    }

    @Test
    void burpAiIsPromptedWhenAiIsEnabled() {
        aiEnabled.set(true);
        AiDispatcher dispatcher = dispatcherFor(configured(ProviderId.BURP_AI));

        dispatcher.analyze("system", "user");
        assertEquals(1, burpAiPrompts.get());
        assertEquals(0, sendRequests.get());
    }

    @Test
    void ollamaModelResolutionIsGatedToo() {
        aiEnabled.set(false);
        Settings settings = configured(ProviderId.OLLAMA);
        settings.setConfig(ProviderId.OLLAMA, new ProviderConfig("http://localhost:11434", "", ""));

        // No model configured: analyze() would otherwise call GET /api/tags to pick one.
        assertTrue(dispatcherFor(settings).current().analyze("system", "user").isEmpty());
        assertEquals(0, sendRequests.get());
    }

    @Test
    void switchingProviderNeverSendsAnotherProvidersKey() {
        aiEnabled.set(true);
        Settings settings = new Settings();
        settings.setConfig(ProviderId.OPENAI, new ProviderConfig("https://api.openai.com/v1", "openai-key", "m"));
        settings.setProvider(ProviderId.GEMINI);

        AiDispatcher dispatcher = dispatcherFor(settings);
        assertFalse(dispatcher.isConfigured(), "Gemini has no key of its own");
        assertTrue(dispatcher.analyze("system", "user").isEmpty());
        assertEquals(0, sendRequests.get());
    }
}
