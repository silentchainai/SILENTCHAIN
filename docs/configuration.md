# Configuration

All settings live in SILENTCHAIN's panel in Burp's **Settings** window: click **Settings** on
the **SILENTCHAIN Community** tab, or search Burp's Settings for `SILENTCHAIN`. The panel has
an **AI Provider** tab and an **Advanced** tab. Changes apply immediately (there is no Save or
Cancel); text fields apply on Enter or when you leave them. Settings are stored in Burp's
preferences and survive extension reloads and Burp restarts. Settings from earlier versions
are migrated automatically.

AI analysis only runs when **Use AI** is enabled for SILENTCHAIN in **Extensions > Installed**.
This gates every provider, including Ollama.

## AI Provider Settings

| Setting | Default | Description |
|---------|---------|-------------|
| AI Provider | Burp AI | Active provider: Burp AI, Ollama, OpenAI, Claude, Gemini, or Azure Foundry |
| API URL | (provider default) | Provider API endpoint (external providers) |
| API Key | (empty) | API key for cloud providers (not needed for Burp AI or Ollama) |
| Model | (provider default) | Model name to use for analysis (external providers; for Azure, the deployment name) |
| Max Tokens | `2048` | Response length limit |
| Azure API Version | `2024-06-01` | Azure Foundry only |
| Ollama structured output | `schema` | Ollama only: `schema` (forces `{"findings":[...]}`), `json` or `off` |
| Ollama context (num_ctx) | `8192` | Ollama only: context window in tokens; must exceed prompt + Max Tokens |

API URL, API Key and Model are stored **per provider**: switching provider loads that
provider's values and never reuses another provider's key. **Test Connection** and the model
**Refresh** button also require **Use AI**.

How each provider authenticates:

| Provider | Auth |
|----------|------|
| Burp AI | None; prompts are sent through Burp to PortSwigger's Burp AI service and consume Burp AI credits |
| Ollama | None (`/api/chat` on the host you configure) |
| OpenAI | `Authorization: Bearer` key |
| Claude | `x-api-key` header |
| Gemini | `x-goog-api-key` header (the key is never put in the URL) |
| Azure Foundry | `api-key` header |

## Scan Settings (Advanced tab)

| Setting | Default | Description |
|---------|---------|-------------|
| Scope | Always (not configurable) | Passive analysis only covers targets in Burp's target scope |
| Enable automatic passive scanning | Disabled (opt-in) | Analyze in-scope items that Burp's live audit tasks and scans pass to SILENTCHAIN's passive scan check (same as **Start Scanning** on the tab) |
| Third-party AI timeout (s) | `120` | Response timeout for third-party providers and for the right-click response fetch; Burp AI uses Burp's own limits |
| Max Response Size (KB) | `195` (200,000 bytes) | Skip responses with bodies larger than this |
| Per-host Requests/Minute | `10` | Cap passive analyses per host per minute; extra items are skipped |
| URL Dedup Window (min) | `60` | Skip a method + URL already analyzed passively within this window |
| Verbose Logging | Enabled | Log per-request results to the console and extension output |
| Console Theme | Dark | Console pane theme (Light / Dark) |

Passive analysis also skips items while SILENTCHAIN's tasks are paused, skips content types
other than HTML, XHTML, JSON and XML, and holds at most 16 passive items queued or running
(**Skipped (Backlog)** counts the rest). Right-click analysis is not subject to de-dup,
rate-limit or backlog checks, but like passive analysis it only covers in-scope targets:
out-of-scope items you select are skipped and reported in the console.

## Severity and Confidence

- **Severity levels:** High, Medium, Low, Information
- **Confidence mapping from AI percentage:**
  - 90-100%: Certain
  - 75-89%: Firm
  - 50-74%: Tentative
  - Below 50%: Not reported (counted as **Skipped (Low Confidence)**)

## Data Privacy (DataSanitizer)

| Setting | Default | Description |
|---------|---------|-------------|
| Sanitizer ("Redact secrets / PII and neutralize prompt injection before sending to AI") | Enabled | Redact sensitive data and neutralize prompt-injection patterns before sending to any AI provider |

Independently of this setting, credentials are always replaced with `[REDACTED]` before any AI
request: cookie values (headers and the parameter sample), `Authorization`-style and
API-key/token header values (for example `X-Api-Key`, `Ocp-Apim-Subscription-Key`,
`X-CSRF-Token`), and parameters, JSON fields and multipart fields named like credentials
(password, token, api_key, session...) in the URL, URL-bearing headers (Referer, Location), the
parameter sample and the request and response bodies (form, JSON including nested values,
multipart, XML, HTML form inputs). Cookie and parameter names, `Set-Cookie` attributes and the
`Authorization` scheme are kept, and an empty value stays empty. Long bodies, values and header
lists are cut with a visible marker, and security headers (CSP, HSTS, Set-Cookie...) are listed
first so they are never cut.
The 1.3.x default timeout of 60 s (saved but never applied) migrates to 120 s once; a value you
chose yourself is kept.

When enabled, the DataSanitizer automatically strips sensitive information from prompts before they are sent to AI providers. It applies to every provider (Burp AI, Ollama and the cloud providers). This prevents accidental leakage of credentials, tokens, PII, and internal infrastructure details.

### What Gets Redacted

| Category | Examples |
|----------|----------|
| API Keys | OpenAI (`sk-...`), GitHub (`ghp_...`), AWS (`AKIA...`), GitLab (`glpat-...`), Slack (`xoxb-...`) |
| Auth Tokens | `Bearer` and `Basic` authorization values |
| Credentials | `password=`, `secret=`, `token=` key-value pairs, `user:pass@` URL credentials |
| Session Cookies | `session=`, `csrf=`, `jwt=`, `auth_token=`, `sid=` values |
| Email Addresses | Any `user@domain.tld` pattern |
| IP Addresses | IPv4 addresses (e.g., `192.168.1.100`) |
| Hostnames | Fully qualified domain names (e.g., `internal.corp.example.com`) |

### How It Works

1. Before sending a prompt to the AI, each sensitive value is replaced with a placeholder like `[REDACTED_KEY_1]`
2. Prompt-injection patterns in the traffic (instruction overrides, role hijacking, delimiter escapes) are neutralized
3. The AI analyzes the sanitized prompt and returns findings referencing the placeholders
4. The DataSanitizer restores the original values in the AI response, so findings display correctly in Burp

Safe values like `localhost`, `127.0.0.1`, and `example.com` are allowlisted and never redacted. The sanitizer can be disabled for fully local providers (e.g., Ollama on localhost) where data never leaves the machine; the credential-header redaction still applies.

AI output is treated as untrusted: finding titles are sanitized (no markup, length capped), issue text is HTML-escaped, and SILENTCHAIN's tables never render HTML.

## Deduplication

Passive analysis skips a request whose method and URL (fragment removed) were already analyzed
within the **URL Dedup Window** (default 60 minutes; up to 500 URLs are remembered).
These are counted as **Skipped (Duplicate)**. Right-click **Analyze Request (SILENTCHAIN)**
always analyzes the selected request.
