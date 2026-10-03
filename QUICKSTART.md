# Quick Start Guide - SILENTCHAIN AI™

Get up and running with SILENTCHAIN AI™ in under 5 minutes.

---

## Prerequisites

- Burp Suite Professional 2025.8 or later (Burp Suite Community Edition and Burp Suite DAST
  are not supported; on Community Edition the extension loads, logs why, and stays idle)
- One AI provider:
  - **Burp AI** (default, zero-config; uses Burp AI credits)
  - Ollama (free, local) - **RECOMMENDED for local/private use**
  - OpenAI API key
  - Claude API key
  - Gemini API key
  - Azure OpenAI / Foundry

---

## Installation

### Step 1: Download SILENTCHAIN

Download the latest `silentchain-community-edition-X.Y.Z.jar` from
[GitHub Releases](https://github.com/silentchainai/SILENTCHAIN/releases), or build it from
source with `./gradlew shadowJar` (output: `build/libs/silentchain-community-edition-<version>.jar`).

### Step 2: Load in Burp Suite

1. Open Burp Suite Professional
2. Go to: `Extensions` → `Installed` → `Add`
3. Extension type: `Java`
4. Select the downloaded `.jar`
5. Click `Next`
6. In `Extensions` → `Installed`, enable **Use AI** for SILENTCHAIN. It is off by default for
   manually loaded extensions, and it is required for **every** provider, including Ollama.

> Using the default **Burp AI** provider? You can skip Step 3 - it works with no setup
> (uses Burp AI credits).

### Step 3: Install Ollama (optional, for local/private analysis)

**macOS/Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
```

**Windows:**
Download from [ollama.ai/download](https://ollama.ai/download)

### Step 4: Configure SILENTCHAIN

1. Go to the `SILENTCHAIN Community` tab in Burp
2. Click `Settings` (or search Burp's Settings window for `SILENTCHAIN`)
3. Configure:
   - Provider: `Ollama`
   - API URL: `http://localhost:11434`
   - Model: `llama3:latest`
4. Click `Test Connection` (should show `OK: Ollama reachable.`)
5. Changes apply immediately - there is no Save button

---

## First Scan

### Set Target Scope

1. Go to `Target` → `Scope`
2. Click `Add` under "Include in scope"
3. Enter your target URL

Example:
```
Protocol: https
Host: testsite.com
File: (empty for all paths)
```

### Configure Browser

Set browser proxy to Burp:
- HTTP Proxy: `127.0.0.1:8080`
- HTTPS Proxy: `127.0.0.1:8080`

### Start Browsing

> In the `SILENTCHAIN Community` tab, click **Start Scanning** to enable **passive analysis**
> first - it is OFF by default, and the first time SILENTCHAIN asks for data-handling consent.
> (Or skip this and right-click any request → **Analyze Request (SILENTCHAIN)**.)

Passive analysis runs as a Burp Scanner passive scan check: Burp's default live passive audit
of Proxy traffic hands in-scope items to SILENTCHAIN. It never sends requests to the target.

1. Navigate to your target site through the browser
2. Watch the `SILENTCHAIN Community` tab:
   - **Console**: Shows real-time analysis
   - **Findings**: Displays detected vulnerabilities
3. Check Burp's `Dashboard` or `Target` → `Site map` issues for Burp-integrated findings

---

## Understanding Results

### Severity Levels

- 🔴 **High**: Critical vulnerabilities requiring immediate attention
- 🟠 **Medium**: Important security issues
- 🟡 **Low**: Minor vulnerabilities
- 🔵 **Information**: Security notes and observations

### Confidence Levels

- **Certain** (90-100%): High confidence, verified pattern
- **Firm** (75-89%): Strong indicators, likely vulnerable
- **Tentative** (50-74%): Potential issue, needs manual verification

---

## Common Commands

### View Available Models (Ollama)
```bash
ollama list
```

### Pull New Model
```bash
ollama pull deepseek-r1
```

### Test AI Connection
```bash
curl http://localhost:11434/api/tags
```

---

## Troubleshooting

### "No findings detected"

✓ Check target is in scope (`Target` → `Scope`)  
✓ Check **Use AI** is enabled for SILENTCHAIN (`Extensions` → `Installed`)  
✓ Check passive analysis is ON and tasks are not paused  
✓ Verify traffic flows through Burp (`Proxy` → `HTTP history`)  
✓ Enable Verbose Logging (SILENTCHAIN settings → `Advanced`; on by default)

### "AI connection failed"

✓ Check **Use AI** is enabled for SILENTCHAIN (`Extensions` → `Installed`)  
✓ Check Ollama is running: `ollama list`  
✓ Verify API URL is correct  
✓ For cloud providers, check API key

---

## Next Steps

- **Read the [Usage guide](docs/usage.md)** for detailed usage
- **Star the repo** to stay updated
- **Upgrade to Professional** for active verification

---

## Support

- 📚 [Full Documentation](README.md)
- 🐛 [Report Issues](https://github.com/silentchainai/SILENTCHAIN/issues)
- ✉️ support@silentchain.ai

Happy hunting! 🔒🔗⛓️
