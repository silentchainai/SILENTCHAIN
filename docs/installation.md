# Installation

## Prerequisites

- **Burp Suite Professional 2025.8 or later.** Burp Suite Community Edition and Burp Suite
  DAST are not supported: on Community Edition the extension loads, logs why, and stays idle.
- **Use AI** enabled for SILENTCHAIN in **Extensions > Installed**. It is off by default for
  manually loaded extensions (Burp asks when installing from the BApp Store) and gates every
  provider, including Ollama. If AI is turned off globally in Burp's AI settings, nothing is
  sent.
- **Java 21 runtime** (bundled with current Burp releases)
- **AI Provider** - at least one of:
  - Burp AI (default; prompts are sent through Burp to PortSwigger's Burp AI service and use
    Burp AI credits)
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
6. In **Extensions > Installed**, enable **Use AI** for SILENTCHAIN.

### Build from Source

The Gradle wrapper is included, and the JDK 21 toolchain is auto-provisioned if it is missing:

```bash
./gradlew shadowJar
```

This produces `build/libs/silentchain-community-edition-<version>.jar`; load it as above.

## Step 2: Configure AI Provider

1. Click **Settings** on the **SILENTCHAIN Community** tab, or search Burp's Settings window
   for `SILENTCHAIN`.
2. On the **AI Provider** tab, select your AI provider. **Burp AI** (default) needs no URL or key.
3. For an external provider, set the API URL:
   - Ollama: `http://localhost:11434` (default)
   - OpenAI: `https://api.openai.com/v1`
   - Claude: `https://api.anthropic.com/v1`
   - Gemini: `https://generativelanguage.googleapis.com/v1`
   - Azure: your resource endpoint (`https://YOUR-RESOURCE.openai.azure.com`)
4. Enter your API key (not required for Burp AI or Ollama).
5. Select the model name (for Azure, the deployment name) and click **Test Connection**.
   Changes apply immediately; there is no Save button.

Each provider keeps its own API URL, API key and model, so switching provider never reuses
another provider's key. Settings from earlier versions are migrated automatically.

## Updating

To update the extension:
1. Download the new `silentchain-community-edition-X.Y.Z.jar`.
2. In Burp Suite: **Extensions > Installed**, select SILENTCHAIN Community Edition, and **Remove**.
3. **Add** the new `.jar` (type **Java**), then make sure **Use AI** is enabled for it.

## Troubleshooting

- **Extension fails to load:** Confirm you selected extension type **Java** and are running
  Burp Suite Professional 2025.8 or later with a Java 21 runtime; check
  **Extensions > Installed > (SILENTCHAIN Community Edition) > Errors**.
- **No findings generated:** Ensure **Use AI** is enabled, your target is in Burp's scope,
  passive analysis is enabled, and proxy traffic is flowing.
- **AI timeout errors:** Check that your AI provider is reachable (e.g.
  `curl http://localhost:11434/api/tags` for Ollama), or raise **Third-party AI timeout (s)**
  on the **Advanced** tab (default 120).
