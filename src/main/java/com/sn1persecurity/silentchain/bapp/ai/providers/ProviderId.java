package com.sn1persecurity.silentchain.bapp.ai.providers;

/**
 * Provider identifiers + Community-style default endpoint URLs
 * (ported from silentchain_ai_community.py:1341-1370).
 *
 * Order matters: this is the order shown in the Settings dialog dropdown,
 * with BURP_AI first so it is the default selection per PortSwigger
 * BApp AI guidelines.
 */
public enum ProviderId {
    BURP_AI       ("Burp AI",        ""),
    OLLAMA        ("Ollama",         "http://localhost:11434"),
    OPENAI        ("OpenAI",         "https://api.openai.com/v1"),
    CLAUDE        ("Claude",         "https://api.anthropic.com/v1"),
    GEMINI        ("Gemini",         "https://generativelanguage.googleapis.com/v1"),
    AZURE_FOUNDRY ("Azure Foundry",  "https://YOUR-RESOURCE.openai.azure.com");

    private final String displayName;
    private final String defaultUrl;

    ProviderId(String displayName, String defaultUrl) {
        this.displayName = displayName;
        this.defaultUrl = defaultUrl;
    }

    public String displayName() { return displayName; }
    public String defaultUrl() { return defaultUrl; }

    public static ProviderId fromDisplayName(String name) {
        if (name == null) return BURP_AI;
        for (ProviderId p : values()) {
            if (p.displayName.equalsIgnoreCase(name.trim())) {
                return p;
            }
        }
        return BURP_AI;
    }
}
