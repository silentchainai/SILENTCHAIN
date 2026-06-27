# Configuration

All settings are configured via the in-extension Settings dialog within Burp Suite.

## AI Provider Settings

| Setting | Default | Description |
|---------|---------|-------------|
| AI Provider | Burp AI | Active provider: Burp AI, Ollama, OpenAI, Claude, Gemini, or Azure |
| API URL | (provider default) | Provider API endpoint (external providers) |
| API Key | (empty) | API key for cloud providers (not needed for Burp AI or Ollama) |
| Model | (provider default) | Model name to use for analysis (external providers) |
| Max Tokens | `2048` | Response length limit |

## Scan Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Scope Only | Enabled | Only analyze requests within Burp's target scope |
| Passive Analysis | Disabled (opt-in) | Automatically analyze new in-scope proxy traffic |
| Max Response Size | 200KB | Skip responses with bodies larger than this |
| Per-host Rate Limit | 10 / min | Cap analyses per host per minute |

## Severity and Confidence

- **Severity levels:** High, Medium, Low, Information
- **Confidence mapping from AI percentage:**
  - 90-100%: Certain
  - 75-89%: Firm
  - 50-74%: Tentative
  - Below 50%: Not reported

## Data Privacy (DataSanitizer)

| Setting | Default | Description |
|---------|---------|-------------|
| Sanitize Enabled | Enabled | Redact sensitive data before sending to cloud AI providers |

When enabled, the DataSanitizer automatically strips sensitive information from prompts before they are sent to AI providers. This prevents accidental leakage of credentials, tokens, PII, and internal infrastructure details to third-party APIs.

### What Gets Redacted

| Category | Examples |
|----------|----------|
| API Keys | OpenAI (`sk-...`), GitHub (`ghp_...`), AWS (`AKIA...`), GitLab (`glpat-...`), Slack (`xoxb-...`) |
| Auth Tokens | `Bearer` and `Basic` authorization headers |
| Credentials | `password=`, `secret=`, `token=` key-value pairs, `user:pass@` URL credentials |
| Session Cookies | `session=`, `csrf=`, `jwt=`, `auth_token=`, `sid=` values |
| Email Addresses | Any `user@domain.tld` pattern |
| IP Addresses | IPv4 addresses (e.g., `192.168.1.100`) |
| Hostnames | Fully qualified domain names (e.g., `internal.corp.example.com`) |
| File Paths | Unix (`/etc/shadow`) and Windows (`C:\Users\...`) paths |

### How It Works

1. Before sending a prompt to the AI, each sensitive value is replaced with a placeholder like `[REDACTED_KEY_1]`
2. The AI analyzes the sanitized prompt and returns findings referencing the placeholders
3. The DataSanitizer restores the original values in the AI response, so findings display correctly in Burp

Safe values like `localhost`, `127.0.0.1`, and `example.com` are allowlisted and never redacted. The sanitizer can be disabled for fully local providers (e.g., Ollama on localhost) where data never leaves the machine.

## Deduplication

Findings are deduplicated using SHA256 hashing of URL + parameter combinations. Duplicate findings for the same endpoint and parameter are suppressed.
