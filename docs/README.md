# SILENTCHAIN Community Documentation

SILENTCHAIN Community is a Java (Montoya API) Burp Suite extension that provides AI-powered
security analysis of HTTP traffic. It passively analyzes proxied requests and responses,
identifying OWASP Top 10 vulnerabilities using configurable AI providers.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Quick start guide for first-time setup |
| [Installation](installation.md) | Detailed prerequisites and installation steps |
| [Configuration](configuration.md) | Config file reference and settings |
| [Usage](usage.md) | Scanning workflow, findings, and export |
| [Architecture](architecture.md) | Internal design and code structure |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |

## Overview

- **Type:** Burp Suite Extension (passive scanner)
- **Language:** Java 21 (Burp Montoya API)
- **AI Providers:** Burp AI (default), Ollama, OpenAI, Claude, Gemini, Azure OpenAI/Foundry
- **Coverage:** OWASP Top 10 vulnerability categories

## Quick Start

1. Download the latest `silentchain-community-edition-X.Y.Z.jar` from the Releases page.
2. In Burp Suite: **Extensions > Installed > Add**, set Extension type to **Java**, and select the `.jar`.
3. Configure your AI provider in the **SILENTCHAIN Community** tab (Burp AI works with no setup).
4. Enable passive analysis (off by default), proxy traffic through Burp, and review findings.
