# Quick Start - SILENTCHAIN AI

Get the extension running quickly with a stable baseline configuration.

## Prerequisites

- Burp Suite
- One AI provider (Ollama recommended for local/private usage)

## 1. Clone and Open

git clone <your-fork-url>
cd <your-fork-folder>

## 2. Load Extension in Burp

1. Open Burp.
2. Go to Extender -> Extensions -> Add.
3. Choose Python extension type.
4. Load `silentchain_ai_community.py`.

## 3. Configure Provider

In SILENTCHAIN Settings:

- Provider: choose one of Ollama/OpenAI/Claude/Gemini/Azure Foundry
- API URL: provider endpoint
- API key: if required
- Model: provider model/deployment name

Run Test Connection, then Save.

## 4. Define Scope and Browse

1. Set target scope in Burp (Target -> Scope).
2. Route browser traffic through Burp proxy.
3. Browse target endpoints.
4. Watch SILENTCHAIN findings and Burp Issue Activity.

## 5. Verify Azure Environment (If Using Azure)

./tools/test_azure_env.sh ./.env

Expected: STATUS: VALID

## Troubleshooting Fast Path

- No findings: verify scope and proxy flow
- Connection failure: verify URL/key/model
- Extension load issues: check Extender -> Errors

## Next Reading

- Internal architecture: `docs/INTERNAL_WORKING.md`
- Maintainer workflow: `docs/DEVELOPER_WORKFLOW.md`
- Full installation matrix: `docs/guides/INSTALLATION.md`
