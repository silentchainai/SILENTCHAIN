# Getting Started with SILENTCHAIN Community Edition

SILENTCHAIN Community Edition is a Java (Montoya API) Burp Suite extension that performs
AI-powered passive vulnerability scanning of HTTP traffic. It detects OWASP Top 10
vulnerabilities using LLM-based analysis of request/response pairs.

## Quick Start

1. Ensure **Burp Suite Professional 2025.8 or later** is installed. Burp Suite Community
   Edition and Burp Suite DAST are not supported: on Community Edition the extension loads,
   logs why, and stays idle.
2. Download the latest `silentchain-community-edition-X.Y.Z.jar` from the Releases page, or
   build it from source with `./gradlew shadowJar`.
3. In Burp Suite: **Extensions > Installed > Add > Extension type: Java** and select the `.jar`.
4. In **Extensions > Installed**, enable **Use AI** for SILENTCHAIN. It is off by default for
   manually loaded extensions (Burp asks when installing from the BApp Store), and it gates
   every provider, including Ollama.
5. Configure your AI provider (Burp AI, Ollama, OpenAI, Claude, Gemini, or Azure) in
   SILENTCHAIN's settings: click **Settings** on the **SILENTCHAIN Community** tab, or search
   Burp's Settings for `SILENTCHAIN`. Changes apply immediately.
6. Set your target scope in Burp, enable passive analysis (off by default), and browse the
   target through the proxy. Burp's default live passive audit of Proxy traffic hands
   in-scope items to SILENTCHAIN's passive scan check, which never sends requests to the
   target. You can also right-click any request and choose **Analyze Request (SILENTCHAIN)**.
7. Findings appear in the SILENTCHAIN Community tab and as native Burp issues (Dashboard /
   Target > Site map issues).

## Supported AI Providers

| Provider | Default Model | API Key Required |
|----------|--------------|-----------------|
| Burp AI  | (chosen by Burp AI; Burp Suite Professional) | No (uses Burp AI Credits) |
| Ollama   | (configurable, e.g. `deepseek-r1:latest`; first installed model if none is set) | No |
| OpenAI   | gpt-4o-mini  | Yes             |
| Claude   | claude-3-5-sonnet-latest | Yes  |
| Gemini   | gemini-1.5-flash | Yes         |
| Azure    | (your deployment name) | Yes   |

## Data Privacy

Credentials (cookie values, `Authorization` and API-key/token header values, and parameters or
JSON fields named like credentials, in requests and responses) are always replaced with `[REDACTED]`
before any AI request. The built-in DataSanitizer
additionally redacts sensitive data (API keys, credentials, PII, internal IPs) and neutralizes
prompt-injection patterns before prompts are sent to any provider. It is enabled by default
and can be toggled in SILENTCHAIN's settings (**Advanced** tab). Burp AI sends prompts through
Burp to PortSwigger's Burp AI service; Ollama sends them to the host you configure (localhost
by default). See [Configuration](configuration.md#data-privacy-datasanitizer).

## Requirements

- Burp Suite Professional 2025.8 or later, with **Use AI** enabled for SILENTCHAIN
- Java 21 runtime (bundled with current Burp releases)
- An AI provider (Burp AI, local Ollama, or a cloud API key)
