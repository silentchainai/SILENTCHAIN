# API Reference - SILENTCHAIN Community Edition

SILENTCHAIN Community is a Burp Suite extension - it does not expose a standalone HTTP API.
All interaction happens through Burp Suite's **Montoya API**.

---

## Montoya integration points

The extension wires itself into Burp from `SilentchainExtension.initialize(MontoyaApi api)`:

### Entry point
- `BurpExtension.initialize(MontoyaApi)` - sets the extension name, loads persisted settings,
  and registers the passive scan check, the context menu, the settings panel, the suite tab
  and an unloading handler.
- `BurpExtension.enhancedCapabilities()` - declares `EnhancedCapability.AI_FEATURES`.

### Passive scan check
- `api.scanner().registerPassiveScanCheck(AiPassiveScanCheck, ScanCheckType.PER_REQUEST)` -
  automatic analysis of the items Burp's live audit tasks and scans audit. `doCheck` returns an
  empty `AuditResult` immediately and queues in-scope items in the background; it never sends
  requests to the target. Gating (scope, content-type, size, URL dedup, rate limit) is applied
  by `ScanGate`. Not registered on Burp Suite Community Edition, where the extension stays idle.

### AI
- `api.ai().isEnabled()` - wrapped by `AiGate` and checked before every AI request, for every
  provider (including Test Connection, model refresh and Ollama model resolution).
- `api.ai().prompt().execute(...)` - the Burp AI provider; prompts are sent through Burp to
  PortSwigger's Burp AI service.

### Networking
- `api.http().sendRequest(...)` with `RequestOptions.withUpstreamTLSVerification()` and the
  **Third-party AI timeout** - all third-party AI traffic, through `MontoyaHttpClient`.
- `api.http().sendRequest(...)` - right-click analysis only, to capture a missing response
  (sent once, with the **Third-party AI timeout** as the response timeout).

### UI tab
- `api.userInterface().registerSuiteTab("SILENTCHAIN Community", MainTab)` - the dashboard
  (findings table, task table, console, statistics, controls). Its **Settings** button calls
  `api.userInterface().openSettingsWindow()`.

### Settings panel
- `api.userInterface().registerSettingsPanel(SilentchainSettingsPanel)` - SILENTCHAIN's
  **AI Provider** and **Advanced** tabs inside Burp's Settings window (searchable as
  `SILENTCHAIN`). Values apply as they are committed.

### Context menu
- `api.userInterface().registerContextMenuItemsProvider(ContextMenuProvider)` - adds
  **Analyze Request (SILENTCHAIN)** to Proxy / Site map / Repeater for on-demand analysis.

### Findings
- `api.siteMap().add(AuditIssue)` - each finding is emitted as a native Burp Scanner issue
  (built by `FindingBuilder`).

### Persistence
- `api.persistence().preferences()` - settings storage (`config/SettingsPersistence`).

### Unloading
- `api.extension().registerUnloadingHandler(...)` - cancels tasks, stops the UI refresh timer
  and shuts down all executors.

---

## AI Provider APIs

The extension communicates with one configured AI provider, routed by `ai/AiDispatcher`:

| Provider | Endpoint | Auth |
|----------|----------|------|
| Burp AI | Montoya AI (`api.ai().prompt()`); sent through Burp to PortSwigger's Burp AI service | Burp AI credits |
| Ollama | `POST {api_url}/api/chat` (models: `GET {api_url}/api/tags`) | None |
| OpenAI | `POST {api_url}/chat/completions` | `Authorization: Bearer {key}` |
| Claude | `POST {api_url}/messages` | `x-api-key: {key}`, `anthropic-version: 2023-06-01` |
| Gemini | `POST {api_url}/models/{model}:generateContent` | `x-goog-api-key: {key}` header |
| Azure | `POST {api_url}/openai/deployments/{deployment}/chat/completions?api-version=...` | `api-key: {key}` |

All external-provider HTTP goes through `net/MontoyaHttpClient` (Burp's networking), which
refuses to send anything when AI is disabled for the extension. Every provider is sent the
same structured prompt requesting JSON output with OWASP classification, severity, confidence,
CWE, evidence, and remediation, parsed by `ai/ResponseParser`.
