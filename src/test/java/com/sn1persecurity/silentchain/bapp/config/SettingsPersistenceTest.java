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
}
