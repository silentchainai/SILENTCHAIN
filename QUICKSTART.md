# Quick Start Guide - SILENTCHAIN AI™

Get up and running with SILENTCHAIN AI™ in under 5 minutes.

---

## Prerequisites

- Burp Suite (Community or Professional)
- One of the following:
  - Ollama (free, local) - **RECOMMENDED**
  - OpenAI API key
  - Claude API key
  - Gemini API key
   - Azure Foundry API key

---

## Installation

### Step 1: Download SILENTCHAIN

```bash
git clone https://github.com/yourusername/silentchain-ai.git
cd silentchain-ai
```

Or download the latest release: [GitHub Releases](https://github.com/yourusername/silentchain-ai/releases)

### Step 2: Load in Burp Suite

1. Open Burp Suite
2. Go to: `Extender` → `Extensions` → `Add`
3. Extension type: `Python`
4. Select `silentchain_ai_community.py`
5. Click `Next`

### Step 3: Install Ollama (Recommended)

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

1. Navigate to your target site through the browser
2. Watch the `SILENTCHAIN` tab:
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

### Validate Azure .env Configuration
```bash
./tools/test_azure_env.sh ./.env
```

Look for `STATUS: VALID` before testing in Burp.
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
✓ For cloud providers (OpenAI, Claude, Gemini, Azure Foundry), check API key

---

## Next Steps

- **Read the [User Guide](docs/USER_GUIDE.md)** for detailed usage
- **Join [Discord](https://discord.gg/silentchain)** for community support
- **Star the repo** to stay updated

---

## Support

- 📚 [Full Documentation](README.md)
- 💬 [Discord Community](https://discord.gg/silentchain)
- 🐛 [Report Issues](https://github.com/yourusername/silentchain-ai/issues)
- ✉️ support@silentchain.ai

Happy hunting! 🔒🔗⛓️
