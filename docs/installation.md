# Installation

## Prerequisites

- **Burp Suite** Professional or Community Edition (2025.2+ recommended; Professional is
  required for the default **Burp AI** provider)
- **Java 21 runtime** (bundled with current Burp releases)
- **AI Provider** — at least one of:
  - Burp AI (default; in-process; Burp Suite Professional + AI subscription)
  - Ollama running locally (free, no API key needed)
  - OpenAI API key
  - Anthropic (Claude) API key
  - Google (Gemini) API key
  - Azure OpenAI / Foundry (endpoint, key, deployment, api-version)

## Step 1: Load the Extension

1. Download the latest `silentchain-community-edition-X.Y.Z.jar` from the Releases page.
2. In Burp Suite: **Extensions > Installed > Add**.
3. Set **Extension type** to **Java**.
4. Browse to the `.jar` and click **Next**.
5. The extension loads and a **SILENTCHAIN Community** tab appears.

## Step 2: Configure AI Provider

1. Click the **SILENTCHAIN Community** tab.
2. Open **Settings**.
3. Select your AI provider. **Burp AI** (default) needs no URL or key.
4. For an external provider, set the API URL:
   - Ollama: `http://localhost:11434` (default)
   - OpenAI: `https://api.openai.com/v1`
   - Claude: `https://api.anthropic.com/v1`
   - Gemini: `https://generativelanguage.googleapis.com/v1`
   - Azure: your resource endpoint (`https://YOUR-RESOURCE.openai.azure.com`)
5. Enter your API key (not required for Burp AI or Ollama).
6. Select the model name, click **Test Connection**, then **Save**.

## Updating

To update the extension:
1. Download the new `silentchain-community-edition-X.Y.Z.jar`.
2. In Burp Suite: **Extensions > Installed**, select SILENTCHAIN Community, and **Remove**.
3. **Add** the new `.jar` (type **Java**).

## Troubleshooting

- **Extension fails to load:** Confirm you selected extension type **Java** and are running a
  current Burp with a Java 21 runtime; check **Extensions > Installed > (SILENTCHAIN) > Errors**.
- **No findings generated:** Ensure your target is in Burp's scope, passive analysis is
  enabled, and proxy traffic is flowing.
- **AI timeout errors:** Check that your AI provider is reachable (e.g.
  `curl http://localhost:11434/api/tags` for Ollama).
