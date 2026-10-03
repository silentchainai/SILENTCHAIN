# SILENTCHAIN Community Documentation

SILENTCHAIN Community is a Java (Montoya API) Burp Suite extension that provides AI-powered
security analysis of HTTP traffic. It analyzes in-scope requests and responses as a Burp
Scanner passive scan check (for example during Burp's live passive audit of Proxy traffic)
and on demand from the right-click menu, identifying OWASP Top 10 vulnerabilities using
configurable AI providers.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Quick start guide for first-time setup |
| [Installation](installation.md) | Detailed prerequisites and installation steps |
| [Configuration](configuration.md) | Settings reference |
| [Usage](usage.md) | Scanning workflow, findings, and export |
| [Architecture](architecture.md) | Internal design and code structure |
| [API Reference](api-reference.md) | Montoya integration points and provider endpoints |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |

## Overview

- **Type:** Burp Suite Extension (passive scan check + on-demand analysis)
- **Requires:** Burp Suite Professional 2025.8 or later, with **Use AI** enabled for SILENTCHAIN
  (Community Edition and Burp Suite DAST are not supported)
- **Language:** Java 21 (Burp Montoya API)
- **AI Providers:** Burp AI (default), Ollama, OpenAI, Claude, Gemini, Azure OpenAI/Foundry
- **Coverage:** OWASP Top 10 vulnerability categories

## Quick Start

1. Download the latest `silentchain-community-edition-X.Y.Z.jar` from the Releases page (or
   build it with `./gradlew shadowJar`).
2. In Burp Suite: **Extensions > Installed > Add**, set Extension type to **Java**, and select the `.jar`.
3. In **Extensions > Installed**, enable **Use AI** for SILENTCHAIN (required for every provider).
4. Configure your AI provider in SILENTCHAIN's settings: click **Settings** on the
   **SILENTCHAIN Community** tab or search Burp's Settings for `SILENTCHAIN` (Burp AI works
   with no setup).
5. Enable passive analysis (off by default), proxy traffic through Burp, and review findings.
