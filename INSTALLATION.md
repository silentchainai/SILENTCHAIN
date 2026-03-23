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
| **Burp Suite** | Community or Professional (latest) | [Download here](https://portswigger.net/burp/communitydownload) |
| **Java** | Version 8 or higher | Required by Burp Suite |
| **Python** | 2.7 (Jython) | Included with Burp Suite |

### AI Provider (Choose One)

| Provider | Cost | Setup Complexity | Privacy |
|----------|------|------------------|---------|
| **Ollama** | Free | Easy | 100% Local |
| **OpenAI** | Paid | Easy | Cloud |
| **Claude** | Paid | Easy | Cloud |
| **Gemini** | Free/Paid | Easy | Cloud |
| **Azure Foundry** | Paid | Medium | Cloud |

### System Resources

- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB minimum (more for Ollama models)
- **Network**: Internet connection (except for Ollama-only setups)

---

## Installation Methods

### Method 1: Direct Download (Recommended)

#### Step 1: Download SILENTCHAIN

```bash
# Clone the repository
git clone https://github.com/silentchainai/SILENTCHAIN.git

# Or download ZIP
# https://github.com/silentchainai/SILENTCHAIN/archive/refs/heads/main.zip
```

#### Step 2: Load in Burp Suite

1. **Open Burp Suite**
   - Launch Burp Suite Community or Professional

2. **Navigate to Extensions**
   ```
   Burp Menu → Extender → Extensions → Add
   ```

3. **Configure Extension**
   - **Extension type**: Select `Python`
   - **Extension file**: Click `Select file...`
   - Navigate to `silentchain_ai_community.py`
   - Click `Open`

4. **Verify Loading**
   - Extension should appear in the list
   - Check for errors in the `Errors` tab
   - Look for "SILENTCHAIN" tab in main Burp window

#### Step 3: Verify Installation

- A new `SILENTCHAIN` tab should appear in Burp
- Console should display the SILENTCHAIN logo
- Status bar should show extension loaded

---

### Method 2: BApp Store (Coming Soon)

SILENTCHAIN will be available in the Burp Suite BApp Store for one-click installation.

---

## AI Provider Setup

Choose and configure one AI provider below.

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

1. Go to `SILENTCHAIN` → `⚙ Settings`
2. **AI Provider**: Select `Ollama`
3. **API URL**: `http://localhost:11434`
4. **Model**: `llama3:latest` (or your chosen model)
5. Click `Test Connection` → Should show "✓ Connected to Ollama"
6. Click `Save`

---

### Option 2: OpenAI

#### Get API Key

1. Visit [platform.openai.com](https://platform.openai.com)
2. Sign up or log in
3. Go to [API Keys](https://platform.openai.com/api-keys)
4. Click `Create new secret key`
5. Copy the key (starts with `sk-`)

#### Configure in SILENTCHAIN

1. Go to `SILENTCHAIN` → `⚙ Settings`
2. **AI Provider**: Select `OpenAI`
3. **API URL**: `https://api.openai.com/v1`
4. **API Key**: Paste your key
5. **Model**: Select `gpt-4` or `gpt-3.5-turbo`
6. Click `Test Connection`
7. Click `Save`

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

1. Go to `SILENTCHAIN` → `⚙ Settings`
2. **AI Provider**: Select `Claude`
3. **API URL**: `https://api.anthropic.com/v1`
4. **API Key**: Paste your key
5. **Model**: Select `claude-3-5-sonnet-20241022`
6. Click `Test Connection`
7. Click `Save`

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

1. Go to `SILENTCHAIN` → `⚙ Settings`
2. **AI Provider**: Select `Gemini`
3. **API URL**: `https://generativelanguage.googleapis.com/v1`
4. **API Key**: Paste your key
5. **Model**: Select `gemini-1.5-pro`
6. Click `Test Connection`
7. Click `Save`

---

### Option 5: Azure Foundry (Azure OpenAI)

#### Get API Key and Endpoint

1. Open your Azure AI Foundry project (or Azure OpenAI resource)
2. Copy your endpoint, for example:
   - `https://YOUR-RESOURCE.openai.azure.com`
3. Copy your API key from the Keys/Endpoint page
4. Confirm the deployment name you want to use (for example, `gpt-4o-security`)

#### Configure in SILENTCHAIN

1. Go to `SILENTCHAIN` → `⚙ Settings`
2. **AI Provider**: Select `Azure Foundry`
3. **API URL**: `https://YOUR-RESOURCE.openai.azure.com`
4. **API Key**: Paste your Azure key
5. **Model**: Enter your deployment name (not the raw model family name)
6. Click `Test Connection`
7. Click `Save`

---

## First-Time Configuration

### Step 1: Set Burp Scope

SILENTCHAIN only analyzes in-scope targets:

1. Go to `Target` → `Scope` in Burp
2. Click `Add` under "Include in scope"
3. Enter target(s):
   ```
   Example: https://testsite.com
   ```
4. Configure protocol, host, and path as needed

**Tip**: Start with a single test application to verify everything works.

### Validate Azure .env (Optional but Recommended)

If you are using Azure Foundry with a local `.env` file, run:

```bash
./tools/test_azure_env.sh ./.env
```

Proceed when the script reports `STATUS: VALID`.

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

1. Go to `SILENTCHAIN` → `⚙ Settings`

2. **Advanced Tab**:
   - ☑ Verbose Logging (recommended initially)

3. Click `Save`

### Step 4: Test the Setup

1. **Browse a test site** through your proxy-configured browser
2. **Check SILENTCHAIN Console**:
   - Should show "[HTTP] URL: ..." messages
   - AI analysis logs
3. **Check Findings Panel**:
   - Detected vulnerabilities appear here
4. **Check Burp Issues**:
   - `Target` → `Issue Activity`
   - SILENTCHAIN findings appear alongside Burp Scanner

---

## Verification

### Health Check

Run through this checklist to verify installation:

- [ ] SILENTCHAIN tab visible in Burp
- [ ] No errors in Extender → Errors tab
- [ ] AI connection test passes (green ✓)
- [ ] Console shows logo and initialization message
- [ ] Target scope is configured
- [ ] Browser proxy is set to Burp (127.0.0.1:8080)
- [ ] Test request analyzed (check Console for "[HTTP]" logs)
- [ ] Findings appear in Findings panel

### Test Request

Force analysis of a single request:

1. Browse any in-scope URL
2. Go to `Proxy` → `HTTP history`
3. Right-click on a request
4. Select `SILENTCHAIN - Analyze Request`
5. Check Console for analysis logs
6. Check Findings panel for results

---

## Troubleshooting

### Extension Won't Load

**Error**: "Failed to load extension"

**Solutions**:
1. Check Python environment:
   ```
   Extender → Options → Python Environment
   Ensure "Jython standalone JAR file" is set
   ```
2. Verify file permissions (must be readable)
3. Check for syntax errors in `Extender` → `Errors`

---

### AI Connection Fails

**Error**: "AI connection test failed"

**Solutions**:

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

3. **Enable Verbose Logging**:
   ```
   Settings → Advanced → ☑ Verbose Logging
   Console will show detailed analysis
   ```

4. **Test with known vulnerable site**:
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
   # Edit burp.sh (Linux/Mac) or burpsuite_community.vmoptions (Windows)
   -Xmx4g  # Increase to 4GB (or more)
   ```

---

### Rate Limiting Issues

**Symptoms**: "Skipped (Rate Limit)" messages

**Explanation**: SILENTCHAIN enforces 4-second delay between AI requests to:
- Prevent AI provider rate limits
- Reduce costs (cloud providers)
- Maintain system stability

**Not a bug**: This is intentional design. Passive analysis doesn't require real-time speed.

---

### Extension Crashes

**Symptoms**: SILENTCHAIN stops responding, errors in console

**Solutions**:
1. **Check Burp logs**:
   ```
   Extender → Errors tab
   ```

2. **Restart extension**:
   ```
   Extender → Extensions → Unload → Re-load
   ```

3. **Report the bug**:
   - Copy error log
   - Create GitHub issue
   - Include: Burp version, AI provider, error message

---

## Getting Help

### Documentation
- [Main README](README.md)
- [User Guide](docs/USER_GUIDE.md)
- [FAQ](docs/FAQ.md)

### Community Support
- [GitHub Issues](https://github.com/silentchainai/SILENTCHAIN/issues)
- [Discord Community](https://discord.gg/silentchain)

---

## Next Steps

Once installation is complete:

1. **Read the [User Guide](docs/USER_GUIDE.md)** for detailed usage
2. **Review [Best Practices](docs/BEST_PRACTICES.md)** for effective testing
3. **Join the [Discord Community](https://discord.gg/silentchain)** for tips and updates
4. **Star the repository** to stay updated

Happy hunting! 🔒🔗⛓️
