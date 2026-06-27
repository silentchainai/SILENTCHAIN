![SILENTCHAIN-AI-Intro.gif](images/SILENTCHAIN-AI-Intro.gif)

# SILENTCHAIN AI™ - Community Edition

<div align="center">

![SILENTCHAIN Logo](https://img.shields.io/badge/SILENTCHAIN-AI%20Security-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)

### 🔗 ⛓️ 🔒

**AI-Powered Passive Vulnerability Analysis for Burp Suite**

*Intelligent • Silent • Adaptive • Comprehensive*

[🚀 Getting Started](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 Configuration](#-configuration) • [📊 Benchmarks](BENCHMARK.md) • [⬆️ Upgrade to Pro](https://silentchain.ai)

[![Watch the Professional Demo](https://img.shields.io/badge/▶_Watch_Demo-SILENTCHAIN_Professional-red?style=for-the-badge&logo=youtube)](https://youtu.be/yWJK4CvS5pE)

</div>

---
![SILENTCHAINAI-professional-burp-findings1.PNG](images/SILENTCHAINAI-professional-burp-findings1.PNG)

![SILENTCHAINAI-burp-findings1.PNG](images/SILENTCHAINAI-burp-findings1.PNG)
---

> **Note:** This is the Community Edition. Commercial and Professional Editions with advanced features are available separately.

## 🌟 Overview

**SILENTCHAIN AI™ - Community Edition** is a Burp Suite extension that brings the power of artificial intelligence to web application security testing. Using advanced AI models, SILENTCHAIN performs intelligent passive analysis of HTTP traffic to identify OWASP Top 10 vulnerabilities, security misconfigurations, and potential attack vectors.

### Why SILENTCHAIN?

Traditional security scanners rely on predefined signatures and patterns. **SILENTCHAIN AI™** goes beyond with:

- **🧠 AI-Powered Analysis**: Leverages state-of-the-art language models (Burp AI, Ollama, OpenAI, Claude, Gemini, Azure) for intelligent vulnerability detection
- **🎯 Context-Aware Detection**: Understands application logic and business context, not just pattern matching
- **⚡ Real-Time Scanning**: Analyzes traffic as it flows through Burp's proxy
- **📊 Professional Reporting**: Generates detailed findings with CWE, OWASP mappings, and remediation guidance
- **🔄 Zero False Positives**: AI validation reduces noise and focuses on real vulnerabilities
- **🆓 Community Edition**: Free passive analysis capabilities

---

## ✨ Features

### Core Capabilities

#### 🔍 **Passive AI Analysis**
- Real-time traffic analysis through Burp Proxy
- OWASP Top 10 vulnerability detection
- CWE-mapped security findings
- Intelligent confidence scoring

#### 🎨 **Professional UI**
- Modern, intuitive dashboard
- Live findings panel with severity color-coding
- Task tracking and management
- Integrated console logging

#### 🤖 **Multi-AI Support**
- **Burp AI** (default; in-process, zero-config; Burp Suite Professional)
- **Ollama** (local, free, privacy-focused)
- **OpenAI** (GPT-4 / GPT-4o)
- **Claude** (Anthropic)
- **Gemini** (Google)
- **Azure OpenAI / Foundry**

#### 📋 **Smart Reporting**
- Detailed vulnerability descriptions
- Affected parameters identification
- CWE and OWASP mappings
- Remediation recommendations
- Direct links to security resources

#### 🛡️ **Data Privacy (DataSanitizer)**
- **Enabled by default** — automatically protects sensitive data before it leaves your machine
- Bidirectional redaction: sensitive values are replaced with `[REDACTED_*]` placeholders before sending to cloud AI providers, then restored in the response
- Detects and redacts:
  - **API keys** — OpenAI (`sk-`), GitHub (`ghp_`), AWS (`AKIA`), GitLab (`glpat-`), Slack (`xoxb-`)
  - **Authorization headers** — Bearer tokens, Basic auth
  - **Credentials** — password/secret/token fields, `user:pass@host` URIs
  - **Session cookies** — session IDs, CSRF tokens, JWTs, auth tokens
  - **Email addresses**
  - **IP addresses & hostnames** — target infrastructure details
- Skipped entirely for **Ollama** (local-only, no data leaves your machine)
- Can be toggled off in Settings for advanced users

### Vulnerability Detection

SILENTCHAIN AI™ detects a wide range of security issues including:

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL Injection, NoSQL Injection, Command Injection, LDAP Injection, XPath Injection |
| **Cross-Site Scripting** | Reflected XSS, Stored XSS, DOM-based XSS |
| **Authentication** | Broken Authentication, Session Management Issues, Credential Exposure |
| **Access Control** | IDOR, Broken Authorization, Privilege Escalation |
| **Cryptography** | Weak Encryption, Insecure SSL/TLS, Sensitive Data Exposure |
| **Configuration** | Security Misconfigurations, Default Credentials, Debug Enabled |
| **XXE** | XML External Entity Attacks |
| **Deserialization** | Insecure Deserialization |
| **Components** | Vulnerable Dependencies, Outdated Libraries |

---

## 🚀 Quick Start

### Prerequisites

- **Burp Suite Professional** 2025.2+ (recommended — required for the default **Burp AI** provider) or **Burp Suite Community** (works with external providers such as Ollama)
- **Java 21 runtime** (bundled with current Burp releases)
- **An AI provider** (one of the following):
   - **Burp AI** (default; zero-config; requires Burp Suite Professional + an active Burp AI subscription)
   - [Ollama](https://ollama.ai) (free, local, privacy-focused)
   - OpenAI API key
   - Claude (Anthropic) API key
   - Gemini (Google) API key
   - Azure OpenAI / Foundry

### Installation

1. **Download the extension**
   - Grab the latest `silentchain-community-edition-X.Y.Z.jar` from the [Releases](https://github.com/silentchainai/SILENTCHAIN/releases) page.

2. **Load it in Burp Suite**
   - Go to **Extensions** → **Installed** → **Add**
   - Set Extension type: **Java**
   - Select the downloaded `.jar` and click **Next**

3. **Configure your AI provider**
   - Open the **SILENTCHAIN Community** tab → **⚙ Settings**
   - Pick a provider — **Burp AI** works with no configuration. For an external provider, set the API URL / key / model, click **Test Connection**, then **Save**.

4. **Start scanning**
   - Set your target scope in Burp (**Target** → **Scope**)
   - Enable **passive analysis** in the SILENTCHAIN Community tab (it is OFF by default), then browse the target through Burp's proxy — or right-click any request → **Analyze (SILENTCHAIN)** for on-demand analysis
   - Findings appear in the SILENTCHAIN Community tab and as native Burp Scanner issues

### Requirements

- **Cross-platform**: Windows, macOS, Linux
- **Burp Suite** Community or Professional (Professional + AI subscription for the Burp AI provider)
- **Java 21** (bundled with current Burp releases)

---

## 🔧 Configuration

### AI Provider Setup

#### Option 1: Burp AI (Default — zero configuration)

**Requires Burp Suite Professional + an active Burp AI subscription.** No API URL or key
needed — analysis runs in-process through PortSwigger's Burp AI service and consumes Burp AI
Credits from your account.

- Provider: `Burp AI`
- API URL / Key / Model: *(not required)*

#### Option 2: Ollama (Recommended for local / private use)

**Free, local, no API keys required**

1. Install Ollama:
   ```bash
   # macOS/Linux
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Windows
   # Download from https://ollama.ai/download
   ```

2. Pull a model:
   ```bash
   ollama pull deepseek-r1
   # or
   ollama pull llama3
   ```

3. Configure SILENTCHAIN:
   - Provider: `Ollama`
   - API URL: `http://localhost:11434`
   - Model: `deepseek-r1:latest`

#### Option 3: OpenAI

1. Get API key from [platform.openai.com](https://platform.openai.com)

2. Configure SILENTCHAIN:
   - Provider: `OpenAI`
   - API URL: `https://api.openai.com/v1`
   - API Key: `sk-...`
   - Model: `gpt-4` or `gpt-3.5-turbo`

#### Option 4: Claude (Anthropic)

1. Get API key from [console.anthropic.com](https://console.anthropic.com)

2. Configure SILENTCHAIN:
   - Provider: `Claude`
   - API URL: `https://api.anthropic.com/v1`
   - API Key: Your Anthropic API key
   - Model: `claude-3-5-sonnet-20241022`

#### Option 5: Google Gemini

1. Get API key from [makersuite.google.com](https://makersuite.google.com)

2. Configure SILENTCHAIN:
   - Provider: `Gemini`
   - API URL: `https://generativelanguage.googleapis.com/v1`
   - API Key: Your Google API key
   - Model: `gemini-1.5-pro`

### Settings Reference

| Setting | Description | Default |
|---------|-------------|---------|
| **AI Provider** | AI service to use | `Burp AI` |
| **Passive Analysis** | Auto-analyze in-scope proxy traffic | `Off` (opt-in) |
| **API URL** | Provider endpoint (external providers) | *(provider default)* |
| **API Key** | Authentication key (external providers) | *(empty)* |
| **Model** | AI model name (external providers) | *(provider default)* |
| **Max Tokens** | Response length limit | `2048` |
| **Sanitizer** | Redact secrets/PII before sending | `On` |
| **Verbose Logging** | Enable detailed logs | `On` |

---

## 📖 Documentation

### How It Works

1. **Traffic Interception**: SILENTCHAIN monitors HTTP requests/responses through Burp Proxy
2. **Scope Filtering**: Only analyzes in-scope targets (configure in Burp's Target Scope)
3. **AI Analysis**: Sends request/response data to AI for security analysis
4. **Vulnerability Detection**: AI identifies security issues based on OWASP Top 10 patterns
5. **Finding Generation**: Creates detailed reports with severity, confidence, and remediation
6. **Deduplication**: Prevents duplicate findings for the same URL/parameter combination

### Finding Confidence Levels

| Level | AI Confidence | Meaning |
|-------|---------------|---------|
| **Certain** | 90-100% | High confidence, verified vulnerability pattern |
| **Firm** | 75-89% | Strong indicators, likely vulnerable |
| **Tentative** | 50-74% | Potential issue, requires manual verification |

### UI Components

#### 📊 **Statistics Panel**
- Total Requests: HTTP requests analyzed
- Analyzed: Successfully processed
- Skipped (Duplicate): Prevented redundant analysis
- Findings Created: Total vulnerabilities found
- Errors: Analysis failures

#### 📋 **Active Tasks**
- Shows currently processing requests
- Status tracking (Queued, Analyzing, Completed)
- Duration timing

#### 🔍 **Findings Panel**
- All detected vulnerabilities
- Severity-based color coding:
   - 🔴 **High** - Critical vulnerabilities
   - 🟠 **Medium** - Important security issues
   - 🟡 **Low** - Minor vulnerabilities
   - 🔵 **Information** - Security notes
- Confidence levels
- Discovery timestamps

#### 🖥️ **Console**
- Real-time logging
- AI connection status
- Analysis progress
- Error messages

---

## 🎯 Usage Examples

### Basic Workflow

1. **Set Target Scope**
   ```
   Burp → Target → Scope → Add
   Example: https://example.com/*
   ```

2. **Browse Application**
   - Configure browser proxy to Burp (127.0.0.1:8080)
   - Navigate through the target application
   - SILENTCHAIN analyzes in the background

3. **Review Findings**
   - Check `SILENTCHAIN` → `Findings` panel
   - Or `Target` → `Issue Activity` (integrated with Burp)

### Context Menu Analysis

Right-click any request in:
- Proxy History
- Site Map
- Repeater

Select: `SILENTCHAIN - Analyze Request`

This forces analysis even if the URL was previously scanned.

### Manual Verification

1. Select a finding in the Findings panel
2. Review the detailed description
3. Check affected parameters
4. Follow CWE/OWASP links for more information
5. Manually test using Burp Repeater/Intruder

---

## 🆚 Community vs Professional

| Feature | Community (Free) | Professional |
|---------|------------------|--------------|
| **AI-Powered Passive Analysis** | ✅ | ✅ |
| **OWASP Top 10 Detection** | ✅ | ✅ |
| **Multi-AI Support** | ✅ | ✅ |
| **Professional UI** | ✅ | ✅ |
| **CWE/OWASP Mapping** | ✅ | ✅ |
| **Deduplication** | ✅ | ✅ |
| **Phase 2 Active Verification** | ❌ | ✅ |
| **Advanced Payload Libraries** | ❌ | ✅ |
| **WAF Detection & Evasion** | ❌ | ✅ |
| **Out-of-Band (OOB) Testing** | ❌ | ✅ |
| **Burp Intruder Integration** | ❌ | ✅ |
| **Automatic Fuzzing** | ❌ | ✅ |
| **Priority Support** | ❌ | ✅ |

### ⬆️ Upgrade to Professional

**SILENTCHAIN Professional** adds active verification capabilities:

- 🎯 **Phase 2 Verification**: Automatically validates findings with exploit payloads
- 🛡️ **WAF Detection**: Identifies and adapts to web application firewalls
- 📚 **Curated Payload Libraries**: Battle-tested OWASP payloads
- 🌐 **OOB Testing**: Detects blind vulnerabilities (SSRF, XXE, etc.)
- 🔄 **Burp Intruder Integration**: Auto-configures fuzzing attacks
- ⚡ **Smart Fuzzing**: AI-generated payloads for maximum coverage

[![Watch the Professional Demo](https://img.shields.io/badge/▶_Watch_Demo-SILENTCHAIN_Professional-red?style=for-the-badge&logo=youtube)](https://youtu.be/yWJK4CvS5pE)

**See it in action** — watch the full [SILENTCHAIN Professional demo](https://youtu.be/yWJK4CvS5pE) to see AI-powered active verification, WAF evasion, and automated fuzzing at work.

**Contact us for commercial licensing and professional editions:** support@sn1persecurity.com

---

## 🛠️ Troubleshooting

### Common Issues

#### "AI connection test failed"

**Solution:**
- Check AI provider is running (Ollama: `ollama list`)
- Verify API URL is correct
- For cloud providers, confirm API key is valid
- Check network connectivity

#### "No findings detected"

**Solution:**
- Verify target is in scope (`Target` → `Scope`)
- Ensure traffic is flowing through Burp Proxy
- Check Console for errors
- Try manual analysis (right-click → `SILENTCHAIN - Analyze Request`)

#### "Extension fails to load"

**Solution:**
- Confirm the extension type was set to **Java** when loading the `.jar`
- Verify Burp Suite is current (2025.2+ for the Burp AI provider) with a Java 21 runtime
- Review **Extensions → Installed → (SILENTCHAIN Community) → Errors / Output**
- Re-download the `.jar` if the file may be corrupted

#### High Memory Usage

**Solution:**
- Reduce Max Tokens setting (Settings → AI Provider)
- Clear completed tasks regularly
- Use lighter AI models (e.g., `llama3` instead of `deepseek-r1`)

### Debug Mode

Enable verbose logging:
1. `Settings` → `Advanced`
2. Check `Verbose Logging`
3. Review Console for detailed output

---

## 🤝 Contributing

This project does **not accept outside contributions**. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Reporting Bugs

1. Check [existing issues](https://github.com/silentchainai/SILENTCHAIN/issues)
2. Create a new issue with:
   - Burp Suite version
   - SILENTCHAIN version
   - AI provider/model
   - Steps to reproduce
   - Error messages (from Console)

### Feature Requests

Open an issue with tag `enhancement`:
- Describe the feature
- Explain use case
- Provide examples if possible

---

## 📄 License

SILENTCHAIN AI™ CE is **source-visible but proprietary software**. By using this software, you agree to the terms in the [LICENSE](LICENSE) file.

### PortSwigger BApp Store

PortSwigger Ltd. is granted explicit permission to redistribute, host, and bundle this software within Burp Suite and the BApp Store free of charge to users. All other redistribution is prohibited without written permission.

---

## ⚖️ Responsible Use

**Do not use this software for unauthorized access or activities outside systems you own or have explicit permission to test.**

### Data Handling and Third-Party AI Disclosure

> **See [PRIVACY.md](PRIVACY.md) for the full privacy notice**, including the per-provider data-residency table and your responsibilities when scanning sensitive targets.

SILENTCHAIN analyzes HTTP requests and responses intercepted by Burp Suite. Depending on the AI provider you select, this data may be transmitted to third-party cloud services.

#### Which providers see your data

| Provider | Data Destination | Data Transmitted |
|----------|-----------------|------------------|
| **Ollama** | Local machine only | Nothing leaves your machine |
| **OpenAI** | OpenAI, L.L.C. servers (`api.openai.com`) | HTTP request/response content from in-scope targets |
| **Claude** | Anthropic, PBC servers (`api.anthropic.com`) | HTTP request/response content from in-scope targets |
| **Gemini** | Google LLC servers (`generativelanguage.googleapis.com`) | HTTP request/response content from in-scope targets |
| **Azure OpenAI** | Your Azure OpenAI / Foundry resource | HTTP request/response content from in-scope targets |
| **Burp AI** | PortSwigger Burp AI (in-process) | HTTP request/response content from in-scope targets |

When a cloud AI provider is selected, SILENTCHAIN sends the HTTP request method, URL, headers, body, and response data for each in-scope request to the provider's API for analysis. The built-in **DataSanitizer** (enabled by default) redacts API keys, credentials, session tokens, and other sensitive patterns before transmission, but it cannot guarantee removal of all sensitive data from request/response bodies.

#### Regulated data restriction

**Do not submit regulated data to cloud AI providers.** This includes:

- **PHI** (Protected Health Information) under HIPAA
- **PCI DSS** cardholder data (credit card numbers, CVVs, etc.)
- **EU personal data** subject to GDPR (Art. 13 requires disclosure of sub-processors)
- **CCPA-covered personal information** (Cal. Civ. Code 1798.100 et seq.)

If your target application processes any of the above data categories, you **must** use a local AI provider (Ollama) or ensure you have appropriate data processing agreements with the cloud provider and legal authorization to transmit such data.

#### No telemetry

SILENTCHAIN itself does not collect, store, or transmit any usage data, telemetry, or analytics. All data flows are directly between your Burp Suite instance and your selected AI provider.

#### Best practices

1. **Use Ollama** for sensitive or regulated environments (100% local, private)
2. **Enable DataSanitizer** (on by default) when using cloud providers
3. **Review your AI provider's data retention and privacy policies** before use
4. **Never test production systems** without authorization
5. **Sanitize findings and logs** before sharing externally

---

## 💬 Support & Community

### Get Help

- 📚 **Documentation**: [Documentation](#-documentation)
- 🐛 **Issues**: [GitHub Issues](https://github.com/silentchainai/SILENTCHAIN/issues)
- ✉️ **Email**: support@silentchain.ai

### Stay Updated

- ⭐ **Star** this repository
- 👁️ **Watch** for updates
- 🐦 **X (Twitter)**: [@silentchainai](https://x.com/silentchainai)

---

## 🙏 Acknowledgments

Built by:
- [@xer0dayz](https://x.com/xer0dayz) at [@Sn1perSecurity](https://sn1persecurity.com) LLC

Built with:
- [Burp Suite](https://portswigger.net/burp) by PortSwigger
- [Ollama](https://ollama.ai) for local AI
- [OpenAI](https://openai.com) for GPT models
- [Anthropic](https://anthropic.com) for Claude
- [Google](https://ai.google) for Gemini

Inspired by the security community's dedication to making the web safer.

---

## ™️ Trademark Notice

"SILENTCHAIN AI™", "SILENTCHAIN™", and the SILENTCHAIN AI logo are trademarks of SN1PERSECURITY LLC. Unauthorized use is prohibited.

## Legal Notices

See [NOTICE](NOTICE) for third-party trademark attributions.

---

<div align="center">

### 🔗 ⛓️ 🔒

**SILENTCHAIN AI™** - *Intelligent Security Testing for the Modern Web*

[Website](https://silentchain.ai) • [Documentation](#-documentation) • [Professional Edition](https://silentchain.ai/) • [Professional Demo](https://youtu.be/yWJK4CvS5pE)

**Copyright © 2026 SN1PERSECURITY LLC. All rights reserved.**

</div>