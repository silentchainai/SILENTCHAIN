# Getting Started with SILENTCHAIN Community Edition

SILENTCHAIN Community Edition is a Java (Montoya API) Burp Suite extension that performs
AI-powered passive vulnerability scanning of HTTP traffic. It detects OWASP Top 10
vulnerabilities using LLM-based analysis of request/response pairs.

## Quick Start

1. Ensure Burp Suite (Professional or Community) is installed. Burp Suite **Professional**
   plus an active Burp AI subscription is required for the default **Burp AI** provider;
   Community works with external providers such as Ollama.
2. Download the latest `silentchain-community-edition-X.Y.Z.jar` from the Releases page.
3. In Burp Suite: **Extensions > Installed > Add > Extension type: Java** and select the `.jar`.
4. Open the **SILENTCHAIN Community** tab to configure your AI provider (Burp AI, Ollama,
   OpenAI, Claude, Gemini, or Azure).
5. Set your target scope in Burp, enable passive analysis (off by default), and browse the
   target through the proxy.
6. Findings appear in the SILENTCHAIN Community tab and as native Burp Scanner issues.

## Supported AI Providers

| Provider | Default Model | API Key Required |
|----------|--------------|-----------------|
| Burp AI  | (in-process; Burp Suite Professional) | No (uses Burp AI Credits) |
| Ollama   | (configurable, e.g. `deepseek-r1:latest`) | No |
| OpenAI   | gpt-4o-mini  | Yes             |
| Claude   | claude-3-5-sonnet-latest | Yes  |
| Gemini   | gemini-1.5-flash | Yes         |
| Azure    | (your deployment name) | Yes   |

## Data Privacy

The built-in DataSanitizer automatically redacts sensitive data (API keys, credentials, PII,
internal IPs) before sending prompts to cloud AI providers. It is enabled by default and can
be toggled in **Settings > Advanced**. The Burp AI and Ollama (local) providers keep traffic
in-process / on-machine. See [Configuration](configuration.md#data-privacy-datasanitizer).

## Requirements

- Burp Suite (Professional or Community Edition); Professional + AI subscription for Burp AI
- Java 21 runtime (bundled with current Burp releases)
- An AI provider (in-process Burp AI, local Ollama, or a cloud API key)
