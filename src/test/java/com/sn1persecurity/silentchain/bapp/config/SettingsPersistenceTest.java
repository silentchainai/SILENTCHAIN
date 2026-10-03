package com.sn1persecurity.silentchain.bapp.config;

import burp.api.montoya.persistence.Preferences;

import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;
import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SettingsPersistenceTest {

    /** Map-backed Preferences: one map per value type, like Burp's store. */
    private static Preferences preferences(Map<String, Object> store) {
        Map<String, Function<Object[], Object>> ops = new HashMap<>();
        for (String type : new String[]{"String", "Boolean", "Integer", "Long"}) {
            ops.put("get" + type, a -> store.get(type + ":" + a[0]));
            ops.put("set" + type, a -> {
                store.put(type + ":" + a[0], a[1]);
                return null;
            });
        }
        return DeepStub.of(Preferences.class, ops);
    }

    @Test
    void legacySharedValuesMigrateToTheSelectedProviderOnly() {
        Map<String, Object> store = new HashMap<>();
        store.put("String:silentchain.provider", "OPENAI");
        store.put("String:silentchain.apiUrl", "https://api.openai.com/v1");
        store.put("String:silentchain.apiKey", "sk-legacy");
        store.put("String:silentchain.model", "gpt-4o");

        Settings s = new Settings();
        new SettingsPersistence(preferences(store)).load(s);

        assertEquals(ProviderId.OPENAI, s.provider());
        assertEquals(new ProviderConfig("https://api.openai.com/v1", "sk-legacy", "gpt-4o"), s.config(ProviderId.OPENAI));
        assertEquals(ProviderConfig.EMPTY, s.config(ProviderId.GEMINI));
        assertEquals("gpt-4o", s.model());
    }

    @Test
    void perProviderValuesRoundTripAndLegacyKeysTrackTheSelectedProvider() {
        Map<String, Object> store = new HashMap<>();
        SettingsPersistence persistence = new SettingsPersistence(preferences(store));

        Settings s = new Settings();
        s.setConfig(ProviderId.OPENAI, new ProviderConfig("https://api.openai.com/v1", "openai-key", "gpt-4o"));
        s.setConfig(ProviderId.CLAUDE, new ProviderConfig("", "claude-key", "claude-x"));
        s.setProvider(ProviderId.CLAUDE);
        persistence.save(s);

        Settings reloaded = new Settings();
        persistence.load(reloaded);

        assertEquals(ProviderId.CLAUDE, reloaded.provider());
        assertEquals(s.config(ProviderId.OPENAI), reloaded.config(ProviderId.OPENAI));
        assertEquals(s.config(ProviderId.CLAUDE), reloaded.config(ProviderId.CLAUDE));
        // Downgrade compatibility: the old single keys hold the selected provider's values.
        assertEquals("claude-key", store.get("String:silentchain.apiKey"));
    }

    @Test
    void perProviderKeysWinOverLegacyKeys() {
        Map<String, Object> store = new HashMap<>();
        store.put("String:silentchain.provider", "OPENAI");
        store.put("String:silentchain.apiKey", "stale-legacy");
        store.put("String:silentchain.provider.OPENAI.apiKey", "current");

        Settings s = new Settings();
        new SettingsPersistence(preferences(store)).load(s);

        assertEquals("current", s.config(ProviderId.OPENAI).apiKey());
    }

    /** 1.3.x saved the shared values even with Burp AI selected: give them to the provider they identify. */
    @Test
    void legacyValuesSavedUnderBurpAiGoToTheProviderTheyIdentify() {
        Map<String, Object> store = new HashMap<>();
        store.put("String:silentchain.provider", "BURP_AI");
        store.put("String:silentchain.apiUrl", "https://api.anthropic.com/v1");
        store.put("String:silentchain.apiKey", "sk-ant-legacy");
        store.put("String:silentchain.model", "claude-x");

        Settings s = new Settings();
        new SettingsPersistence(preferences(store)).load(s);

        assertEquals(ProviderId.BURP_AI, s.provider(), "the selection is unchanged");
        assertEquals(ProviderConfig.EMPTY, s.config(ProviderId.BURP_AI));
        assertEquals("sk-ant-legacy", s.config(ProviderId.CLAUDE).apiKey());
    }

    @Test
    void legacyOllamaValuesDropTheUnusedKey() {
        Map<String, Object> store = new HashMap<>();
        store.put("String:silentchain.provider", "OLLAMA");
        store.put("String:silentchain.apiUrl", "http://10.0.0.2:11434");
        store.put("String:silentchain.apiKey", "stale-openai-key");

        Settings s = new Settings();
        new SettingsPersistence(preferences(store)).load(s);

        assertEquals(new ProviderConfig("http://10.0.0.2:11434", "", ""), s.config(ProviderId.OLLAMA));
    }

    @Test
    void ownerInference() {
        assertEquals(ProviderId.OPENAI, SettingsPersistence.inferLegacyOwner("https://api.openai.com/v1", "", ""));
        assertEquals(ProviderId.GEMINI, SettingsPersistence.inferLegacyOwner("", "AIzaSy123", ""));
        assertEquals(ProviderId.AZURE_FOUNDRY,
                SettingsPersistence.inferLegacyOwner("https://x.openai.azure.com", "k", "deploy"));
        assertEquals(ProviderId.OLLAMA, SettingsPersistence.inferLegacyOwner("", "", "qwen3:8b"));
        assertNull(SettingsPersistence.inferLegacyOwner("", "", ""));
    }

    /** 1.3.x always saved the unused default timeout of 60 s; it migrates to the new default once. */
    @Test
    void legacyDefaultTimeoutMigratesButAUserChoiceIsKept() {
        Map<String, Object> legacy = new HashMap<>();
        legacy.put("Integer:silentchain.requestTimeoutSeconds", 60);
        Settings migrated = new Settings();
        new SettingsPersistence(preferences(legacy)).load(migrated);
        assertEquals(Settings.DEFAULT_REQUEST_TIMEOUT_SECONDS, migrated.requestTimeoutSeconds());

        Map<String, Object> custom = new HashMap<>();
        custom.put("Integer:silentchain.requestTimeoutSeconds", 300);
        Settings kept = new Settings();
        new SettingsPersistence(preferences(custom)).load(kept);
        assertEquals(300, kept.requestTimeoutSeconds());

        // Once saved by this version, 60 is an explicit choice.
        SettingsPersistence persistence = new SettingsPersistence(preferences(legacy));
        Settings s = new Settings();
        s.setRequestTimeoutSeconds(60);
        persistence.save(s);
        Settings reloaded = new Settings();
        persistence.load(reloaded);
        assertEquals(60, reloaded.requestTimeoutSeconds());
    }
}
