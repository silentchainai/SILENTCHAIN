# API Reference — SILENTCHAIN Community Edition

SILENTCHAIN Community is a Burp Suite extension — it does not expose a standalone HTTP API.
All interaction happens through Burp Suite's **Montoya API**.

---

## Montoya integration points

The extension wires itself into Burp from `SilentchainExtension.initialize(MontoyaApi api)`:

### Entry point
- `BurpExtension.initialize(MontoyaApi)` — registers handlers, the context menu, and the suite
  tab; sets the extension name; loads persisted settings.

### HTTP interception
- `api.http().registerHttpHandler(PassiveHttpHandler)` — passive analysis of in-scope proxy
  traffic. Gating (scope, content-type, rate limit, URL dedup) is applied by `ScanGate`.

### UI tab
- `api.userInterface().registerSuiteTab("SILENTCHAIN Community", MainTab)` — the dashboard
  (settings, findings table, task table, console, statistics).

### Context menu
- `api.userInterface().registerContextMenuItemsProvider(ContextMenuProvider)` — adds
  **Analyze (SILENTCHAIN)** to Proxy / Site map / Repeater for on-demand analysis.

### Findings
- `api.siteMap().add(AuditIssue)` — each finding is emitted as a native Burp Scanner issue
  (built by `FindingBuilder`).

### Persistence
- `api.persistence().preferences()` — settings storage (`config/SettingsPersistence`).

---

## AI Provider APIs

The extension communicates with one configured AI provider, routed by `ai/AiDispatcher`:

| Provider | Endpoint | Auth |
|----------|----------|------|
| Burp AI | In-process (Montoya AI); no external endpoint | Burp AI subscription / credits |
| Ollama | `POST {api_url}/api/generate` | None |
| OpenAI | `POST {api_url}/chat/completions` | `Authorization: Bearer {key}` |
| Claude | `POST {api_url}/messages` | `x-api-key: {key}` |
| Gemini | `POST {api_url}/models/{model}:generateContent` | `?key={key}` |
| Azure | `POST {api_url}/openai/deployments/{deployment}/chat/completions?api-version=...` | `api-key: {key}` |

All external-provider HTTP goes through `net/MontoyaHttpClient` (Burp's networking). Every
provider is sent the same structured prompt requesting JSON output with OWASP classification,
severity, confidence, CWE, evidence, and remediation, parsed by `ai/ResponseParser`.
