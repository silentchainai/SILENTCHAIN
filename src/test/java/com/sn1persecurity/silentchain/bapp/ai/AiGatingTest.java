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
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        assertThrows(AiNotSentException.class, () -> dispatcher.analyze("system", "user"));
        assertTrue(dispatcher.listModels(provider).isEmpty());
        TestResult viaDispatcher = dispatcher.testConnection(provider);
        assertFalse(viaDispatcher.success());
        assertEquals(AiGate.DISABLED_MESSAGE, viaDispatcher.message());

        // Calling the provider directly (bypassing the dispatcher) is gated too.
        LlmProvider direct = dispatcher.current();
        assertTrue(direct.isConfigured());
        assertFalse(direct.isAvailable());
        assertThrows(AiNotSentException.class, () -> direct.analyze("system", "user"));
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
        assertThrows(AiNotSentException.class, () -> dispatcherFor(settings).current().analyze("system", "user"));
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
        assertThrows(AiNotSentException.class, () -> dispatcher.analyze("system", "user"));
        assertEquals(0, sendRequests.get());
    }

    /** Provider-supplied model names are shown in Swing; anything that is not a plain name is dropped. */
    @Test
    void implausibleModelNamesFromTheProviderAreDropped() {
        aiEnabled.set(true);
        Settings s = configured(ProviderId.AZURE_FOUNDRY);   // Azure lists its configured deployment name
        assertEquals(java.util.List.of("some-model"), dispatcherFor(s).listModels(ProviderId.AZURE_FOUNDRY));

        s.setConfig(ProviderId.AZURE_FOUNDRY, new ProviderConfig("https://x.openai.azure.com", "k",
                "<html><img src='http://evil/x'>"));
        assertTrue(dispatcherFor(s).listModels(ProviderId.AZURE_FOUNDRY).isEmpty());
    }

    /**
     * AI switched off between the dispatcher's check and the provider's request:
     * the provider (or the egress block) must report "not sent", not an empty reply.
     */
    @ParameterizedTest
    @EnumSource(ProviderId.class)
    void aiSwitchedOffMidCallIsReportedAsNotSent(ProviderId provider) {
        java.util.concurrent.atomic.AtomicInteger checks = new java.util.concurrent.atomic.AtomicInteger();
        AiGate flipping = new AiGate(() -> checks.incrementAndGet() <= 1, m -> { });   // only the first check passes
        Settings settings = configured(provider);
        AiDispatcher dispatcher = new AiDispatcher(api, new MontoyaHttpClient(api, flipping, settings), settings, flipping);

        assertThrows(AiNotSentException.class, () -> dispatcher.analyze("system", "user"));
        assertEquals(0, sendRequests.get());
        assertEquals(0, burpAiPrompts.get());
    }

    /** Switched off after the provider's own check: the egress block must still report "not sent". */
    @ParameterizedTest
    @EnumSource(value = ProviderId.class, names = {"OLLAMA", "OPENAI", "CLAUDE", "GEMINI", "AZURE_FOUNDRY"})
    void aiSwitchedOffAtTheEgressPointIsReportedAsNotSent(ProviderId provider) {
        java.util.concurrent.atomic.AtomicInteger checks = new java.util.concurrent.atomic.AtomicInteger();
        AiGate flipping = new AiGate(() -> checks.incrementAndGet() <= 2, m -> { });   // dispatcher + provider pass
        Settings settings = configured(provider);
        AiDispatcher dispatcher = new AiDispatcher(api, new MontoyaHttpClient(api, flipping, settings), settings, flipping);

        assertThrows(AiNotSentException.class, () -> dispatcher.analyze("system", "user"));
        assertEquals(0, sendRequests.get());
    }
}
