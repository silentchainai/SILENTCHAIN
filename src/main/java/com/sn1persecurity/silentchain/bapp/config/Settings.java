package com.sn1persecurity.silentchain.bapp.config;

import burp.api.montoya.core.ToolType;

import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;

import java.util.EnumSet;
import java.util.Set;

/**
 * Mutable runtime configuration. Defaults are safe / opt-in: passive analysis
 * is OFF by default per PortSwigger best-practice for credit-consuming AI
 * extensions.
 *
 * Persisted via {@link SettingsPersistence} which is backed by
 * api.persistence().preferences().
 */
public class Settings {

    // ---- Scan toggles -------------------------------------------------------

    // AI analysis is OFF by default (opt-in) per PortSwigger best-practice for
    // credit-consuming AI extensions.
    private volatile boolean passiveEnabled = false;
    private volatile boolean sanitizerEnabled = true;
    private volatile boolean inScopeOnly = true;
    private volatile boolean verbose = true;

    // ---- Safety rails -------------------------------------------------------

    private volatile int maxResponseBytes = 200_000;
    private volatile int hostRequestsPerMinute = 10;
    private volatile long urlDedupTtlMillis = 3_600_000L; // 1 hour
    private volatile int urlDedupCapacity = 500;

    // ---- AI provider config -------------------------------------------------

    private volatile ProviderId provider = ProviderId.BURP_AI;
    private volatile String apiUrl = "";
    private volatile String apiKey = "";
    private volatile String model = "";
    private volatile int maxTokens = 2048;
    private volatile String azureApiVersion = "2024-06-01";
    private volatile int requestTimeoutSeconds = 60;

    // ---- UI -----------------------------------------------------------------

    public enum ThemeChoice { LIGHT, DARK }

    private volatile ThemeChoice theme = ThemeChoice.DARK;

    // ---- Filter sets --------------------------------------------------------

    private volatile Set<String> contentTypeAllowList = Set.of(
            "text/html",
            "application/xhtml+xml",
            "application/json",
            "application/xml",
            "text/xml"
    );

    private volatile Set<ToolType> allowedToolSources = EnumSet.of(
            ToolType.PROXY,
            ToolType.REPEATER,
            ToolType.TARGET
    );

    // ---- Accessors ----------------------------------------------------------

    public boolean passiveEnabled() { return passiveEnabled; }
    public void setPassiveEnabled(boolean v) { this.passiveEnabled = v; }

    public boolean sanitizerEnabled() { return sanitizerEnabled; }
    public void setSanitizerEnabled(boolean v) { this.sanitizerEnabled = v; }

    public boolean inScopeOnly() { return inScopeOnly; }
    public void setInScopeOnly(boolean v) { this.inScopeOnly = v; }

    public boolean verbose() { return verbose; }
    public void setVerbose(boolean v) { this.verbose = v; }

    public int maxResponseBytes() { return maxResponseBytes; }
    public void setMaxResponseBytes(int v) { this.maxResponseBytes = Math.max(1024, v); }

    public int hostRequestsPerMinute() { return hostRequestsPerMinute; }
    public void setHostRequestsPerMinute(int v) { this.hostRequestsPerMinute = Math.max(1, v); }

    public long urlDedupTtlMillis() { return urlDedupTtlMillis; }
    public void setUrlDedupTtlMillis(long v) { this.urlDedupTtlMillis = Math.max(60_000L, v); }

    public int urlDedupCapacity() { return urlDedupCapacity; }
    public void setUrlDedupCapacity(int v) { this.urlDedupCapacity = Math.max(10, v); }

    public ProviderId provider() { return provider; }
    public void setProvider(ProviderId v) { this.provider = v != null ? v : ProviderId.BURP_AI; }

    public String apiUrl() { return apiUrl; }
    public void setApiUrl(String v) { this.apiUrl = v != null ? v : ""; }

    public String apiKey() { return apiKey; }
    public void setApiKey(String v) { this.apiKey = v != null ? v : ""; }

    public String model() { return model; }
    public void setModel(String v) { this.model = v != null ? v : ""; }

    public int maxTokens() { return maxTokens; }
    public void setMaxTokens(int v) { this.maxTokens = Math.max(1, v); }

    public String azureApiVersion() { return azureApiVersion; }
    public void setAzureApiVersion(String v) { this.azureApiVersion = v != null ? v : ""; }

    public int requestTimeoutSeconds() { return requestTimeoutSeconds; }
    public void setRequestTimeoutSeconds(int v) { this.requestTimeoutSeconds = Math.max(5, v); }

    public ThemeChoice theme() { return theme; }
    public void setTheme(ThemeChoice v) { this.theme = v != null ? v : ThemeChoice.DARK; }

    public Set<String> contentTypeAllowList() { return contentTypeAllowList; }
    public void setContentTypeAllowList(Set<String> v) { this.contentTypeAllowList = Set.copyOf(v); }

    public Set<ToolType> allowedToolSources() { return allowedToolSources; }
    public void setAllowedToolSources(Set<ToolType> v) { this.allowedToolSources = EnumSet.copyOf(v); }
}
