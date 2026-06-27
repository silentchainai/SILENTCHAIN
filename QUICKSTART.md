# Quick Start Guide - SILENTCHAIN AI™

Get up and running with SILENTCHAIN AI™ in under 5 minutes.

---

## Prerequisites

- Burp Suite (Professional recommended; Community works with external providers)
- One AI provider:
  - **Burp AI** (default, zero-config; Burp Suite Professional + AI subscription)
  - Ollama (free, local) - **RECOMMENDED for local/private use**
  - OpenAI API key
  - Claude API key
  - Gemini API key
  - Azure OpenAI / Foundry

---

## Installation

### Step 1: Download SILENTCHAIN

Download the latest `silentchain-community-edition-X.Y.Z.jar` from
[GitHub Releases](https://github.com/silentchainai/SILENTCHAIN/releases).

### Step 2: Load in Burp Suite

1. Open Burp Suite
2. Go to: `Extensions` → `Installed` → `Add`
3. Extension type: `Java`
4. Select the downloaded `.jar`
5. Click `Next`

> Using the default **Burp AI** provider? You can skip Step 3 — it works with no setup
> (Burp Suite Professional + an active Burp AI subscription required).

### Step 3: Install Ollama (optional, for local/private analysis)

**macOS/Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
```

**Windows:**
Download from [ollama.ai/download](https://ollama.ai/download)

### Step 4: Configure SILENTCHAIN

1. Go to `SILENTCHAIN` tab in Burp
2. Click `⚙ Settings`
3. Configure:
   - Provider: `Ollama`
   - API URL: `http://localhost:11434`
   - Model: `llama3:latest`
4. Click `Test Connection` (should show ✓)
5. Click `Save`

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

> In the `SILENTCHAIN Community` tab, enable **passive analysis** first — it is OFF by
> default. (Or skip this and right-click any request → **Analyze (SILENTCHAIN)**.)

1. Navigate to your target site through the browser
2. Watch the `SILENTCHAIN Community` tab:
   - **Console**: Shows real-time analysis
   - **Findings**: Displays detected vulnerabilities
3. Check `Target` → `Issue Activity` for Burp-integrated findings

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
✓ Verify traffic flows through Burp (`Proxy` → `HTTP history`)  
✓ Enable Verbose Logging (`Settings` → `Advanced`)

### "AI connection failed"

✓ Check Ollama is running: `ollama list`  
✓ Verify API URL is correct  
✓ For cloud providers, check API key

---

## Next Steps

- **Read the [User Guide](docs/USER_GUIDE.md)** for detailed usage
- **Join [Discord](https://discord.gg/silentchain)** for community support
- **Star the repo** to stay updated
- **Upgrade to Professional** for active verification

---

## Support

- 📚 [Full Documentation](README.md)
- 💬 [Discord Community](https://discord.gg/silentchain)
- 🐛 [Report Issues](https://github.com/silentchainai/SILENTCHAIN/issues)
- ✉️ support@silentchain.ai

Happy hunting! 🔒🔗⛓️
