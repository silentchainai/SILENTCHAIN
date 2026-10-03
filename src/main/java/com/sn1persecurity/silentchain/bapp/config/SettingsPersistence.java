package com.sn1persecurity.silentchain.bapp.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;

import java.net.URI;
import java.util.Locale;

public class SettingsPersistence {

    // Scan toggles
    private static final String K_PASSIVE_ENABLED   = "silentchain.passiveEnabled";
    private static final String K_SANITIZER_ENABLED = "silentchain.sanitizerEnabled";
    private static final String K_VERBOSE           = "silentchain.verbose";

    // Safety rails
    private static final String K_MAX_RESPONSE_BYTES = "silentchain.maxResponseBytes";
    private static final String K_HOST_RPM           = "silentchain.hostRequestsPerMinute";
    private static final String K_DEDUP_TTL          = "silentchain.urlDedupTtlMillis";

    // Provider config
    private static final String K_PROVIDER          = "silentchain.provider";
    private static final String K_MAX_TOKENS        = "silentchain.maxTokens";
    private static final String K_AZURE_API_VERSION = "silentchain.azureApiVersion";
    private static final String K_REQUEST_TIMEOUT   = "silentchain.requestTimeoutSeconds";
    private static final String K_OLLAMA_STRUCTURED = "silentchain.ollamaStructuredOutput";
    private static final String K_OLLAMA_NUM_CTX    = "silentchain.ollamaNumCtx";

    // Per-provider endpoint/key/model: silentchain.provider.<ID>.apiUrl / .apiKey / .model
    private static final String K_PER_PROVIDER = "silentchain.provider.";

    // Pre-1.4 single (shared) endpoint/key/model. Read once to migrate them into
    // the selected provider's slot, and still written for the selected provider so
    // a downgrade keeps working.
    private static final String K_LEGACY_API_URL = "silentchain.apiUrl";
    private static final String K_LEGACY_API_KEY = "silentchain.apiKey";
    private static final String K_LEGACY_MODEL   = "silentchain.model";

    // UI
    private static final String K_THEME             = "silentchain.theme";

    // Settings schema version. Absent = written by 1.3.x or earlier.
    private static final String K_SETTINGS_VERSION  = "silentchain.settingsVersion";
    private static final int SETTINGS_VERSION       = 2;
    /** 1.3.x saved this default although it never applied it; it is not a user choice. */
    private static final int LEGACY_DEFAULT_TIMEOUT_SECONDS = 60;

    // First-run consent
    private static final String K_FIRST_RUN_ACK     = "silentchain.firstRunAcknowledged";

    private final Preferences prefs;

    public SettingsPersistence(MontoyaApi api) {
        this(api.persistence().preferences());
    }

    SettingsPersistence(Preferences prefs) {
        this.prefs = prefs;
    }

    public void load(Settings into) {
        Boolean b;
        Integer i;
        Long l;
        String s;

        b = prefs.getBoolean(K_PASSIVE_ENABLED);   if (b != null) into.setPassiveEnabled(b);
        b = prefs.getBoolean(K_SANITIZER_ENABLED); if (b != null) into.setSanitizerEnabled(b);
        b = prefs.getBoolean(K_VERBOSE);           if (b != null) into.setVerbose(b);

        i = prefs.getInteger(K_MAX_RESPONSE_BYTES); if (i != null) into.setMaxResponseBytes(i);
        i = prefs.getInteger(K_HOST_RPM);           if (i != null) into.setHostRequestsPerMinute(i);
        l = prefs.getLong(K_DEDUP_TTL);             if (l != null) into.setUrlDedupTtlMillis(l);

        s = prefs.getString(K_PROVIDER);          if (s != null) into.setProvider(safeProvider(s));
        i = prefs.getInteger(K_MAX_TOKENS);       if (i != null) into.setMaxTokens(i);
        s = prefs.getString(K_AZURE_API_VERSION); if (s != null) into.setAzureApiVersion(s);
        i = prefs.getInteger(K_REQUEST_TIMEOUT);
        boolean legacy = prefs.getInteger(K_SETTINGS_VERSION) == null;
        if (i != null && !(legacy && i == LEGACY_DEFAULT_TIMEOUT_SECONDS)) {
            into.setRequestTimeoutSeconds(i);
        }
        s = prefs.getString(K_OLLAMA_STRUCTURED); if (s != null) into.setOllamaStructuredOutput(safeStructured(s));
        i = prefs.getInteger(K_OLLAMA_NUM_CTX);   if (i != null) into.setOllamaNumCtx(i);

        boolean anyPerProvider = false;
        for (ProviderId p : ProviderId.values()) {
            String url = prefs.getString(providerKey(p, "apiUrl"));
            String key = prefs.getString(providerKey(p, "apiKey"));
            String model = prefs.getString(providerKey(p, "model"));
            if (url != null || key != null || model != null) {
                anyPerProvider = true;
                into.setConfig(p, new ProviderConfig(url, key, model));
            }
        }
        if (!anyPerProvider) {
            migrateLegacyProviderConfig(into);
        }

        s = prefs.getString(K_THEME);             if (s != null) into.setTheme(safeTheme(s));
    }

    /**
     * Pre-1.4 kept one URL/key/model shared by all providers and saved them even
     * while Burp AI (which uses none of them) was selected. Give them to the
     * provider they belong to: the selected one, or, when Burp AI is selected,
     * the provider they identify. Ollama takes no key.
     */
    private void migrateLegacyProviderConfig(Settings into) {
        String url = prefs.getString(K_LEGACY_API_URL);
        String key = prefs.getString(K_LEGACY_API_KEY);
        String model = prefs.getString(K_LEGACY_MODEL);
        if (url == null && key == null && model == null) {
            return;
        }
        ProviderId owner = into.provider();
        if (owner == ProviderId.BURP_AI) {
            owner = inferLegacyOwner(url, key, model);
            if (owner == null) {
                return;
            }
        }
        into.setConfig(owner, new ProviderConfig(url, owner == ProviderId.OLLAMA ? "" : key, model));
    }

    /** The third-party provider the legacy URL / key / model identify, or null. */
    static ProviderId inferLegacyOwner(String url, String key, String model) {
        String u = url == null ? "" : url.trim().toLowerCase(Locale.ROOT);
        if (!u.isEmpty()) {
            String host = hostOf(u);
            if (host != null) {
                if (host.equals("api.openai.com")) return ProviderId.OPENAI;
                if (host.equals("api.anthropic.com")) return ProviderId.CLAUDE;
                if (host.equals("generativelanguage.googleapis.com")) return ProviderId.GEMINI;
                if (host.endsWith(".azure.com")) return ProviderId.AZURE_FOUNDRY;
                if (u.contains(":11434")) return ProviderId.OLLAMA;
            }
        }
        String k = key == null ? "" : key.trim();
        if (k.startsWith("sk-ant-")) return ProviderId.CLAUDE;
        if (k.startsWith("sk-")) return ProviderId.OPENAI;
        if (k.startsWith("AIza")) return ProviderId.GEMINI;
        String m = model == null ? "" : model.trim().toLowerCase(Locale.ROOT);
        if (m.startsWith("claude")) return ProviderId.CLAUDE;
        if (m.startsWith("gemini")) return ProviderId.GEMINI;
        if (m.startsWith("gpt") || m.matches("o\\d.*")) return ProviderId.OPENAI;
        if (m.contains(":")) return ProviderId.OLLAMA;
        return null;
    }

    private static String hostOf(String url) {
        try {
            return new URI(url).getHost();
        } catch (Exception e) {
            return null;
        }
    }

    public void save(Settings from) {
        prefs.setBoolean(K_PASSIVE_ENABLED, from.passiveEnabled());
        prefs.setBoolean(K_SANITIZER_ENABLED, from.sanitizerEnabled());
        prefs.setBoolean(K_VERBOSE, from.verbose());

        prefs.setInteger(K_MAX_RESPONSE_BYTES, from.maxResponseBytes());
        prefs.setInteger(K_HOST_RPM, from.hostRequestsPerMinute());
        prefs.setLong(K_DEDUP_TTL, from.urlDedupTtlMillis());

        prefs.setString(K_PROVIDER, from.provider().name());
        prefs.setInteger(K_MAX_TOKENS, from.maxTokens());
        prefs.setString(K_AZURE_API_VERSION, from.azureApiVersion());
        prefs.setInteger(K_REQUEST_TIMEOUT, from.requestTimeoutSeconds());
        prefs.setString(K_OLLAMA_STRUCTURED, from.ollamaStructuredOutput().name());
        prefs.setInteger(K_OLLAMA_NUM_CTX, from.ollamaNumCtx());

        for (ProviderId p : ProviderId.values()) {
            ProviderConfig cfg = from.config(p);
            prefs.setString(providerKey(p, "apiUrl"), cfg.apiUrl());
            prefs.setString(providerKey(p, "apiKey"), cfg.apiKey());
            prefs.setString(providerKey(p, "model"), cfg.model());
        }
        ProviderConfig current = from.config(from.provider());
        prefs.setString(K_LEGACY_API_URL, current.apiUrl());
        prefs.setString(K_LEGACY_API_KEY, current.apiKey());
        prefs.setString(K_LEGACY_MODEL, current.model());

        prefs.setString(K_THEME, from.theme().name());
        prefs.setInteger(K_SETTINGS_VERSION, SETTINGS_VERSION);
    }

    public boolean firstRunAcknowledged() {
        Boolean b = prefs.getBoolean(K_FIRST_RUN_ACK);
        return b != null && b;
    }

    public void setFirstRunAcknowledged(boolean v) {
        prefs.setBoolean(K_FIRST_RUN_ACK, v);
    }

    private static String providerKey(ProviderId p, String field) {
        return K_PER_PROVIDER + p.name() + "." + field;
    }

    private static ProviderId safeProvider(String name) {
        try {
            return ProviderId.valueOf(name);
        } catch (Throwable t) {
            return ProviderId.BURP_AI;
        }
    }

    private static Settings.ThemeChoice safeTheme(String name) {
        try {
            return Settings.ThemeChoice.valueOf(name);
        } catch (Throwable t) {
            return Settings.ThemeChoice.DARK;
        }
    }

    private static Settings.StructuredOutput safeStructured(String name) {
        try {
            return Settings.StructuredOutput.valueOf(name);
        } catch (Throwable t) {
            return Settings.StructuredOutput.SCHEMA;
        }
    }
}
