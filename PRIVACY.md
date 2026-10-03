# SILENTCHAIN Community Privacy Notice

**Effective Date:** June 18, 2026
**Applies to:** SILENTCHAIN Community (Burp Suite extension)

For the full privacy policy, visit: https://silentchain.ai/privacy.html

---

## 1. Local-First Architecture

SILENTCHAIN Community runs entirely inside your local Burp Suite instance. Sn1perSecurity LLC does **not** receive, store, or have access to:

- Target URLs, domains, or IP addresses you scan
- HTTP requests, responses, or traffic content
- Vulnerability findings or scan results
- Any files on your system

The extension performs no telemetry, analytics, or "phone-home" of any kind. SILENTCHAIN Community is unlicensed and does not contact Sn1perSecurity servers.

---

## 2. AI Provider Data Transmission (Important)

**When you use Burp AI (the default) or a cloud-based AI provider, portions of the HTTP traffic intercepted by Burp Suite are transmitted to that provider for analysis.** This is the primary data flow you should be aware of.

Nothing is sent to any AI provider, including Ollama, unless **Use AI** is enabled for SILENTCHAIN in Burp (Extensions > Installed). If AI is turned off globally in Burp's AI settings, nothing is sent.

### What data is sent to AI providers

- HTTP request and response content for the traffic the extension analyzes: URL, method, status and MIME type, a sample of up to 5 parameters, the first 10 request and response headers, and the request and response bodies (truncated). Both passive and right-click analysis only cover in-scope targets (Target > Scope); out-of-scope items you right-click are skipped.
- SILENTCHAIN's fixed analysis instructions (system prompt)

Credentials are always replaced with `[REDACTED]` before any AI request, whatever the sanitizer setting: cookie values (in the `Cookie` / `Set-Cookie` headers and in the parameter sample), `Authorization`-style and API-key/token header values, and parameters, JSON fields and multipart fields named like credentials (password, token, api_key, session...) in the URL, URL-bearing headers (Referer, Location), the parameter sample and the request and response bodies (form, JSON including nested values, multipart, XML, HTML form inputs). Cookie and parameter names, `Set-Cookie` attributes and the `Authorization` scheme are kept, and an empty value stays empty so a missing token is still visible.

This data is sent to **whichever AI provider you select**. If you select Burp AI or a cloud provider, that traffic leaves your machine.

### AI providers and data residency

| Provider | Data Destination | Data Leaves Your Machine? |
|----------|-----------------|---------------------------|
| **Burp AI** (default) | PortSwigger's Burp AI service, via Burp | **Yes** - subject to PortSwigger's AI data-handling policy; consumes Burp AI credits |
| **Ollama** | The Ollama host you configure (default `http://localhost:11434`) | **No** when Ollama runs on your machine - fully local processing |
| **OpenAI** | OpenAI API servers | **Yes** - subject to [OpenAI Privacy Policy](https://openai.com/policies/privacy-policy) |
| **Anthropic (Claude)** | Anthropic API servers | **Yes** - subject to [Anthropic Privacy Policy](https://www.anthropic.com/privacy) |
| **Google (Gemini)** | Google API servers | **Yes** - subject to [Google Gemini API Terms](https://ai.google.dev/gemini-api/terms) |
| **Azure Foundry** | Microsoft Azure servers | **Yes** - subject to [Microsoft Privacy Statement](https://www.microsoft.com/privacy/privacystatement) and your Azure agreement |

### Your responsibility

Sn1perSecurity does not control how third-party AI providers process, store, or retain data sent to their APIs, and the provider's own terms of service and data processing agreements apply to that data. **If your scan targets contain sensitive information** (PII, PHI, customer data, credentials, proprietary data), you must:

1. Evaluate whether transmitting that traffic to a third-party AI provider complies with your organization's data protection policies and applicable regulations (GDPR, CCPA, HIPAA, contractual obligations).
2. Review and accept the third-party AI provider's terms of service and data processing agreements, including any terms related to training on submitted data.
3. **Use Ollama on your own machine as your AI provider if data must not leave your machine.**

### Data sanitization

In addition to the credential-header redaction above, SILENTCHAIN Community applies a `DataSanitizer` layer (enabled by default) before transmitting data to any AI provider, including Burp AI and Ollama. It performs bidirectional redaction: sensitive values (e.g., bearer tokens, API keys, credentials, session cookies, email addresses, IP addresses and hostnames) are replaced with `[REDACTED_*]` placeholders before the request is sent, then restored in the response. It also neutralizes prompt-injection patterns found in the traffic. You can turn it off in SILENTCHAIN's settings; the credential-header redaction still applies.

This redaction is **best-effort**. It relies on pattern and heuristic matching and does **not** guarantee removal of all sensitive data from HTTP traffic. Treat any cloud AI provider as receiving the unredacted portions of the traffic you submit.

---

## 3. Your Rights

You may request access to, correction of, or deletion of any personal data held by Sn1perSecurity by contacting **privacy@silentchain.ai**. We respond within 30 days.

- **GDPR (EEA/UK):** Right to access, rectification, erasure, restriction, portability, objection, and withdrawal of consent.
- **CCPA (California):** Right to know, delete, opt out of sale (we do not sell personal information), and non-discrimination.

---

## 4. Contact

Sn1perSecurity LLC
Email: privacy@silentchain.ai
Website: https://silentchain.ai
Full Privacy Policy: https://silentchain.ai/privacy.html
