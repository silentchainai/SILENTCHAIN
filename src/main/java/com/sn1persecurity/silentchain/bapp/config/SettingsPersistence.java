package com.sn1persecurity.silentchain.bapp.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;

public class SettingsPersistence {

    // Scan toggles
    private static final String K_PASSIVE_ENABLED   = "silentchain.passiveEnabled";
    private static final String K_SANITIZER_ENABLED = "silentchain.sanitizerEnabled";
    private static final String K_IN_SCOPE_ONLY     = "silentchain.inScopeOnly";
    private static final String K_VERBOSE           = "silentchain.verbose";

    // Safety rails
    private static final String K_MAX_RESPONSE_BYTES = "silentchain.maxResponseBytes";
    private static final String K_HOST_RPM           = "silentchain.hostRequestsPerMinute";
    private static final String K_DEDUP_TTL          = "silentchain.urlDedupTtlMillis";

    // Provider config
    private static final String K_PROVIDER          = "silentchain.provider";
    private static final String K_API_URL           = "silentchain.apiUrl";
    private static final String K_API_KEY           = "silentchain.apiKey";
    private static final String K_MODEL             = "silentchain.model";
    private static final String K_MAX_TOKENS        = "silentchain.maxTokens";
    private static final String K_AZURE_API_VERSION = "silentchain.azureApiVersion";
    private static final String K_REQUEST_TIMEOUT   = "silentchain.requestTimeoutSeconds";

    // UI
    private static final String K_THEME             = "silentchain.theme";

    // First-run consent
    private static final String K_FIRST_RUN_ACK     = "silentchain.firstRunAcknowledged";

    private final Preferences prefs;

    public SettingsPersistence(MontoyaApi api) {
        this.prefs = api.persistence().preferences();
    }

    public void load(Settings into) {
        Boolean b;
        Integer i;
        Long l;
        String s;

        b = prefs.getBoolean(K_PASSIVE_ENABLED);   if (b != null) into.setPassiveEnabled(b);
        b = prefs.getBoolean(K_SANITIZER_ENABLED); if (b != null) into.setSanitizerEnabled(b);
        b = prefs.getBoolean(K_IN_SCOPE_ONLY);     if (b != null) into.setInScopeOnly(b);
        b = prefs.getBoolean(K_VERBOSE);           if (b != null) into.setVerbose(b);

        i = prefs.getInteger(K_MAX_RESPONSE_BYTES); if (i != null) into.setMaxResponseBytes(i);
        i = prefs.getInteger(K_HOST_RPM);           if (i != null) into.setHostRequestsPerMinute(i);
        l = prefs.getLong(K_DEDUP_TTL);             if (l != null) into.setUrlDedupTtlMillis(l);

        s = prefs.getString(K_PROVIDER);          if (s != null) into.setProvider(safeProvider(s));
        s = prefs.getString(K_API_URL);           if (s != null) into.setApiUrl(s);
        s = prefs.getString(K_API_KEY);           if (s != null) into.setApiKey(s);
        s = prefs.getString(K_MODEL);             if (s != null) into.setModel(s);
        i = prefs.getInteger(K_MAX_TOKENS);       if (i != null) into.setMaxTokens(i);
        s = prefs.getString(K_AZURE_API_VERSION); if (s != null) into.setAzureApiVersion(s);
        i = prefs.getInteger(K_REQUEST_TIMEOUT);  if (i != null) into.setRequestTimeoutSeconds(i);

        s = prefs.getString(K_THEME);             if (s != null) into.setTheme(safeTheme(s));
    }

    public void save(Settings from) {
        prefs.setBoolean(K_PASSIVE_ENABLED, from.passiveEnabled());
        prefs.setBoolean(K_SANITIZER_ENABLED, from.sanitizerEnabled());
        prefs.setBoolean(K_IN_SCOPE_ONLY, from.inScopeOnly());
        prefs.setBoolean(K_VERBOSE, from.verbose());

        prefs.setInteger(K_MAX_RESPONSE_BYTES, from.maxResponseBytes());
        prefs.setInteger(K_HOST_RPM, from.hostRequestsPerMinute());
        prefs.setLong(K_DEDUP_TTL, from.urlDedupTtlMillis());

        prefs.setString(K_PROVIDER, from.provider().name());
        prefs.setString(K_API_URL, from.apiUrl());
        prefs.setString(K_API_KEY, from.apiKey());
        prefs.setString(K_MODEL, from.model());
        prefs.setInteger(K_MAX_TOKENS, from.maxTokens());
        prefs.setString(K_AZURE_API_VERSION, from.azureApiVersion());
        prefs.setInteger(K_REQUEST_TIMEOUT, from.requestTimeoutSeconds());

        prefs.setString(K_THEME, from.theme().name());
    }

    public boolean firstRunAcknowledged() {
        Boolean b = prefs.getBoolean(K_FIRST_RUN_ACK);
        return b != null && b;
    }

    public void setFirstRunAcknowledged(boolean v) {
        prefs.setBoolean(K_FIRST_RUN_ACK, v);
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
}
