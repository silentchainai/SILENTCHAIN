package com.sn1persecurity.silentchain.bapp.util;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.SilentchainExtension;

/**
 * ASCII logo block printed to Burp's Extensions Output on load
 * (Community silentchain_ai_community.py:2054-2075), updated for the BApp
 * edition with the mandatory non-affiliation line.
 */
public final class Banner {

    private Banner() {}

    public static void print(MontoyaApi api) {
        String v = SilentchainExtension.EXTENSION_VERSION;
        String banner = String.join("\n",
            "=================================================================",
            "",
            "     SILENTCHAIN Community Edition",
            "     -----------------------------",
            "     AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite",
            "",
            "     v" + v + "  |  Intelligent | Silent | Adaptive | Comprehensive",
            "",
            "     Default provider: Burp AI",
            "     Optional: Ollama | OpenAI | Claude | Gemini | Azure Foundry",
            "",
            "     Upgrade to SILENTCHAIN Pro for active verification",
            "     https://silentchain.ai",
            "",
            "=================================================================",
            "",
            "  Independent extension by Sn1persecurity LLC. Not affiliated with,",
            "  endorsed by, or sponsored by PortSwigger Ltd. PortSwigger has not",
            "  evaluated or tested this extension.",
            "",
            "  For authorized security testing only. You are responsible for",
            "  obtaining written permission before scanning any target.",
            "================================================================="
        );
        api.logging().logToOutput(banner);
    }
}
