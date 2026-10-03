# Installation Guide - SILENTCHAIN AI™ Community Edition

Complete step-by-step installation and setup guide for SILENTCHAIN AI™.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [AI Provider Setup](#ai-provider-setup)
4. [First-Time Configuration](#first-time-configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Required Software

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **Burp Suite** | Professional 2025.8 or later | Burp Suite Community Edition and Burp Suite DAST are not supported (on Community Edition the extension loads, logs why, and stays idle) · [Releases](https://portswigger.net/burp/releases) |
| **Use AI** | Enabled for SILENTCHAIN in `Extensions` → `Installed` | Required for every provider, including Ollama. Off by default for manually loaded extensions; Burp asks when installing from the BApp Store. If AI is turned off globally in Burp's AI settings, nothing is sent |
| **Java** | Version 21 | Bundled with current Burp releases |

### AI Provider (Choose One)

| Provider | Cost | Setup Complexity | Privacy |
|----------|------|------------------|---------|
| **Burp AI** | Burp AI Credits | None (default) | Sent through Burp to PortSwigger's Burp AI service |
| **Ollama** | Free | Easy | 100% Local |
| **OpenAI** | Paid | Easy | Cloud |
| **Claude** | Paid | Easy | Cloud |
| **Gemini** | Free/Paid | Easy | Cloud |
| **Azure OpenAI** | Paid | Moderate | Cloud (your tenant) |

### System Resources

- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB minimum (more for Ollama models)
- **Network**: Internet connection (except for Ollama-only setups)

---

## Installation Methods

### Method 1: Direct Download (Recommended)

#### Step 1: Download SILENTCHAIN

Download the latest build straight from GitHub Releases - it is always named
**`silentchain-community-edition.jar`**:

[**Download the latest release**](https://github.com/silentchainai/SILENTCHAIN/releases/latest/download/silentchain-community-edition.jar)

That link always serves the newest release, so it never changes. Need a specific version? Grab
`silentchain-community-edition-X.Y.Z.jar` from the
[Releases](https://github.com/silentchainai/SILENTCHAIN/releases) page.

#### Step 2: Load in Burp Suite

1. **Open Burp Suite**
   - Launch Burp Suite Professional (2025.8 or later)

2. **Navigate to Extensions**
   ```
   Extensions → Installed → Add
   ```

3. **Configure Extension**
   - **Extension type**: Select `Java`
   - **Extension file**: Click `Select file...`
   - Navigate to the downloaded `silentchain-community-edition.jar`
   - Click `Open`, then `Next`

4. **Verify Loading**
   - Extension should appear in the list
   - Check for errors in the `Errors` tab
   - Look for the "SILENTCHAIN Community" tab in the main Burp window

5. **Enable AI**
   - In `Extensions` → `Installed`, enable **Use AI** for SILENTCHAIN
   - It is off by default for manually loaded extensions, and no provider (Burp AI, Ollama or
     a cloud provider) is used until it is on

#### Step 3: Verify Installation

- A new `SILENTCHAIN Community` tab should appear in Burp
- The Output tab should display the SILENTCHAIN banner
- The extension shows as loaded in the Extensions list
- The **Runtime Status** line on the tab shows `AI: Enabled`

---

### Method 2: BApp Store (Coming Soon)

SILENTCHAIN will be available in the Burp Suite BApp Store for one-click installation. When
installing from the BApp Store, Burp asks whether the extension may use AI.

---

### Method 3: Build from Source

The Gradle wrapper is included, and the JDK 21 toolchain is auto-provisioned if it is missing:

```bash
./gradlew shadowJar
```

This produces `build/libs/silentchain-community-edition-<version>.jar`. Load it as described
in Method 1, Step 2.

---

## AI Provider Setup

Choose and configure one AI provider below.

SILENTCHAIN's settings live in Burp's **Settings** window: click **Settings** on the
`SILENTCHAIN Community` tab, or search Burp's Settings for `SILENTCHAIN`. Changes apply
immediately (there is no Save or Cancel; text fields apply on Enter or when you leave them).
Each provider keeps its own API URL, API key and model, so switching provider never reuses
another provider's key. Settings from earlier versions are migrated automatically.

### Burp AI (Default, No Setup)

Burp AI is selected by default and needs no URL or key. Prompts are sent through Burp to
PortSwigger's Burp AI service under PortSwigger's AI data-handling policy and consume Burp AI
credits from your account. Like every provider, it only runs when **Use AI** is enabled for
SILENTCHAIN.

### Option 1: Ollama (Recommended for Beginners)

**Why Ollama?**
- ✅ Completely free
- ✅ 100% local and private
- ✅ No API keys required
- ✅ No usage limits

#### Installation

**macOS / Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Windows:**
1. Download installer from [ollama.ai/download](https://ollama.ai/download)
2. Run the installer
3. Restart terminal/command prompt

#### Download a Model

```bash
# Recommended models:

# Option 1: DeepSeek R1 (Best quality, larger size ~40GB)
ollama pull deepseek-r1

# Option 2: Llama 3 (Good balance ~4.7GB)
ollama pull llama3

# Option 3: Phi-3 (Lightweight ~2.3GB)
ollama pull phi3
```

#### Verify Ollama

```bash
# Check Ollama is running
ollama list

# Test a model
ollama run llama3 "Hello, test"
```

#### Configure in SILENTCHAIN

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)
2. **AI Provider**: Select `Ollama`
3. **API URL**: `http://localhost:11434` (the default; SILENTCHAIN calls `/api/chat` on the host you configure)
4. **Model**: `llama3:latest` (or your chosen model)
5. Click `Test Connection` → Should show "OK: Ollama reachable. N models found."
6. Changes apply immediately (there is no Save button)

---

### Option 2: OpenAI

#### Get API Key

1. Visit [platform.openai.com](https://platform.openai.com)
2. Sign up or log in
3. Go to [API Keys](https://platform.openai.com/api-keys)
4. Click `Create new secret key`
5. Copy the key (starts with `sk-`)

#### Configure in SILENTCHAIN

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)
2. **AI Provider**: Select `OpenAI`
3. **API URL**: `https://api.openai.com/v1`
4. **API Key**: Paste your key (sent as a Bearer token)
5. **Model**: Select `gpt-4` or `gpt-3.5-turbo`
6. Click `Test Connection`
7. Changes apply immediately (there is no Save button)

#### Cost Estimation

| Model | Cost per 1M tokens | Typical request |
|-------|-------------------|-----------------|
| GPT-4 | $30 input / $60 output | ~$0.10 |
| GPT-3.5 Turbo | $3 input / $6 output | ~$0.01 |

*Expect 50-100 requests per hour of active testing*

---

### Option 3: Claude (Anthropic)

#### Get API Key

1. Visit [console.anthropic.com](https://console.anthropic.com)
2. Sign up or log in
3. Go to [API Keys](https://console.anthropic.com/account/keys)
4. Click `Create Key`
5. Copy the key

#### Configure in SILENTCHAIN

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)
2. **AI Provider**: Select `Claude`
3. **API URL**: `https://api.anthropic.com/v1`
4. **API Key**: Paste your key (sent in the `x-api-key` header)
5. **Model**: Select `claude-3-5-sonnet-20241022`
6. Click `Test Connection`
7. Changes apply immediately (there is no Save button)

#### Recommended Models

- **claude-3-5-sonnet-20241022**: Best for security analysis
- **claude-3-opus-20240229**: Highest quality, slower
- **claude-3-haiku-20240307**: Fast, economical

---

### Option 4: Google Gemini

#### Get API Key

1. Visit [makersuite.google.com](https://makersuite.google.com/app/apikey)
2. Sign in with Google account
3. Click `Create API Key`
4. Copy the key

#### Configure in SILENTCHAIN

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)
2. **AI Provider**: Select `Gemini`
3. **API URL**: `https://generativelanguage.googleapis.com/v1`
4. **API Key**: Paste your key (sent in the `x-goog-api-key` header, never in the URL)
5. **Model**: Select `gemini-1.5-pro`
6. Click `Test Connection`
7. Changes apply immediately (there is no Save button)

---

### Option 5: Azure OpenAI / Foundry

#### Configure in SILENTCHAIN

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)
2. **AI Provider**: Select `Azure Foundry`
3. **API URL**: your resource endpoint, e.g. `https://YOUR-RESOURCE.openai.azure.com`
4. **API Key**: Paste your key (sent in the `api-key` header)
5. **Model**: your **deployment name**
6. **Azure API Version**: e.g. `2024-06-01` (the default)
7. Click `Test Connection`; changes apply immediately (there is no Save button)

---

## First-Time Configuration

### Step 1: Set Burp Scope

SILENTCHAIN's passive analysis only covers in-scope targets:

1. Go to `Target` → `Scope` in Burp
2. Click `Add` under "Include in scope"
3. Enter target(s):
   ```
   Example: https://testsite.com
   ```
4. Configure protocol, host, and path as needed

**Tip**: Start with a single test application to verify everything works.

### Step 2: Configure Browser Proxy

1. **Browser Settings** → **Network/Proxy**
2. **Manual proxy configuration**:
   - HTTP Proxy: `127.0.0.1`
   - Port: `8080`
   - HTTPS Proxy: `127.0.0.1`
   - Port: `8080`

3. **Install Burp CA Certificate**:
   - Browse to `http://burpsuite`
   - Click "CA Certificate"
   - Install in browser (important for HTTPS)

### Step 3: Adjust SILENTCHAIN Settings

1. Open SILENTCHAIN's settings (`Settings` button on the `SILENTCHAIN Community` tab)

2. **Advanced Tab**:
   - ☑ Verbose Logging (on by default; recommended initially)
   - ☑ Enable automatic passive scanning (OFF by default; same as **Start Scanning** on the
     SILENTCHAIN tab). The first time, SILENTCHAIN asks for data-handling consent.

3. Changes apply immediately (there is no Save button)

Passive analysis runs as a Burp Scanner passive scan check. Burp's live audit tasks and scans
(for example Burp's default live passive audit of Proxy traffic) hand in-scope items to it;
it never sends requests to the target. Repeater traffic is analyzed automatically only if a
live audit task covers Repeater; otherwise use the right-click menu.

### Step 4: Test the Setup

1. **Browse a test site** through your proxy-configured browser
2. **Check SILENTCHAIN Console**:
   - Should show analysis log lines such as `SILENTCHAIN [passive] finding: ...`
   - With Verbose Logging, per-URL results are logged too
3. **Check Findings Panel**:
   - Detected vulnerabilities appear here
4. **Check Burp Issues**:
   - `Dashboard` or `Target` → `Site map` issues
   - SILENTCHAIN findings appear alongside Burp Scanner

---

## Verification

### Health Check

Run through this checklist to verify installation:

- [ ] SILENTCHAIN Community tab visible in Burp
- [ ] No errors in Extensions → Installed → (SILENTCHAIN) → Errors
- [ ] **Use AI** enabled for SILENTCHAIN in Extensions → Installed
- [ ] AI connection test passes (Test Connection)
- [ ] Output tab shows the banner and initialization message
- [ ] Target scope is configured
- [ ] Browser proxy is set to Burp (127.0.0.1:8080)
- [ ] Passive analysis enabled (or use right-click **Analyze Request (SILENTCHAIN)**)
- [ ] Findings appear in the Findings panel

### Test Request

Force analysis of a single request:

1. Browse any in-scope URL
2. Go to `Proxy` → `HTTP history`
3. Right-click on a request
4. Select `Analyze Request (SILENTCHAIN)` (the first analysis asks for data-handling consent;
   if the item has no response, SILENTCHAIN sends the request once to capture one)
5. Check the Output/Console for analysis logs
6. Check the Findings panel for results

---

## Troubleshooting

### Extension Won't Load

**Error**: "Failed to load extension"

**Solutions**:
1. Confirm the extension type was set to **Java** when loading the `.jar`
2. Verify you are running Burp Suite Professional 2025.8 or later with a Java 21 runtime
   (on Burp Suite Community Edition the extension loads, logs why, and stays idle)
3. Check **Extensions → Installed → (SILENTCHAIN Community Edition) → Errors** for details
4. Re-download the `.jar` if it may be corrupted

---

### AI Connection Fails

**Error**: "AI connection test failed"

**Solutions**:

#### All providers:
- If the message says AI is disabled for SILENTCHAIN, enable **Use AI** for SILENTCHAIN in
  `Extensions` → `Installed` and check AI is not turned off in Burp's AI settings. This
  applies to every provider, including Ollama.

#### Ollama:
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
# macOS/Linux:
ollama serve

# Windows: Restart Ollama from Start Menu
```

#### Cloud Providers:
- Verify API key is correct (no extra spaces)
- Check account has credits/active subscription
- Verify API URL is exact (copy from provider docs)
- Test with curl:
  ```bash
  # OpenAI
  curl https://api.openai.com/v1/models \
    -H "Authorization: Bearer YOUR_KEY"
  ```

---

### No Findings Detected

**Symptoms**: Traffic analyzed but no vulnerabilities found

**Checklist**:
1. **Verify target is in scope**:
   ```
   Target → Scope → Ensure URL is listed
   ```

2. **Check traffic flow**:
   ```
   Proxy → HTTP history → Verify requests appear
   ```

3. **Check SILENTCHAIN is running**:
   ```
   Use AI enabled for SILENTCHAIN (Extensions → Installed)
   Passive analysis ON (Start Scanning) and tasks not paused (SILENTCHAIN's or Burp's)
   A live passive audit task covers the traffic (Burp's default covers Proxy traffic)
   ```
   The **Runtime Status** line shows `Waiting for Burp Scanner (needs a live audit task)`
   until Burp first calls SILENTCHAIN's passive check.

4. **Enable Verbose Logging**:
   ```
   Settings → Advanced → ☑ Verbose Logging
   Console will show detailed analysis
   ```

5. **Test with known vulnerable site**:
   ```
   DVWA: http://dvwa.local
   WebGoat: http://localhost:8080/WebGoat
   ```

---

### High Memory Usage

**Symptoms**: Burp Suite consuming excessive RAM

**Solutions**:
1. **Reduce Max Tokens**:
   ```
   Settings → AI Provider → Max Tokens: 1024 (instead of 2048)
   ```

2. **Use lighter AI model**:
   ```
   Ollama: phi3 instead of deepseek-r1
   OpenAI: gpt-3.5-turbo instead of gpt-4
   ```

3. **Clear completed tasks**:
   ```
   Click "Clear Completed" button in SILENTCHAIN
   ```

4. **Increase Burp memory**:
   ```
   # Edit the .vmoptions file in Burp's install directory
   -Xmx4g  # Increase to 4GB (or more)
   ```

---

### Rate Limiting Issues

**Symptoms**: "Skipped (Rate Limit)" or "Skipped (Backlog)" counts rising

**Explanation**: Passive analysis is throttled to:
- Prevent AI provider rate limits
- Reduce costs (cloud providers and Burp AI credits)
- Maintain system stability

Each host gets at most **Per-host Requests/Minute** passive analyses (default 10; Advanced
tab); extra items are skipped, not queued, and counted as **Skipped (Rate Limit)**. When 16
passive items are already queued or running, new ones are counted as **Skipped (Backlog)**.
A method + URL analyzed within the **URL Dedup Window** (default 60 minutes) is counted as
**Skipped (Duplicate)**. Burp scans and crawls also feed in-scope items, so these counters
(and AI usage) can rise during scans.

**Not a bug**: This is intentional design. Passive analysis doesn't require real-time speed.
Use right-click **Analyze Request (SILENTCHAIN)** for a specific request; it bypasses these
limits.

---

### Extension Crashes

**Symptoms**: SILENTCHAIN stops responding, errors in console, or tasks end with status **Error**

**Solutions**:
1. **Check Burp logs** (failed analyses log a stack trace here):
   ```
   Extensions → Installed → (SILENTCHAIN Community Edition) → Errors
   ```

2. **Restart extension**:
   ```
   Extensions → Installed → uncheck "Loaded" → re-check
   ```

3. **Report the bug**:
   - Copy error log
   - Create GitHub issue
   - Include: Burp version, AI provider, error message

---

## Getting Help

### Documentation
- [Main README](README.md)
- [Usage](docs/usage.md)
- [Troubleshooting](docs/troubleshooting.md)

### Community Support
- [GitHub Issues](https://github.com/silentchainai/SILENTCHAIN/issues)
- Email: support@silentchain.ai

### Professional Support
Upgrade to SILENTCHAIN Professional for priority support:
- [silentchain.ai/pro](https://silentchain.ai/pro)

---

## Next Steps

Once installation is complete:

1. **Read the [Usage guide](docs/usage.md)** for detailed usage
2. **Review the [Configuration reference](docs/configuration.md)** for every setting
3. **Star the repository** to stay updated

Happy hunting! 🔒🔗⛓️
