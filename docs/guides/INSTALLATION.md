# Installation and Provider Configuration

This guide covers full setup for each supported AI provider.

## System Requirements

- Burp Suite (Community or Professional)
- Java 8+
- Burp Python extension support (Jython runtime)

## Install Extension

1. Open Burp.
2. Extender -> Extensions -> Add.
3. Extension type: Python.
4. Load `silentchain_ai_community.py`.

## Provider Setup

### Ollama (Local)

- API URL: `http://localhost:11434`
- API key: not required
- Model examples: `llama3:latest`, `deepseek-r1:latest`

### OpenAI

- API URL: `https://api.openai.com/v1`
- API key: required
- Model examples: `gpt-4o`, `gpt-4o-mini`

### Claude

- API URL: `https://api.anthropic.com/v1`
- API key: required
- Model example: `claude-3-5-sonnet-20241022`

### Gemini

- API URL: `https://generativelanguage.googleapis.com/v1`
- API key: required
- Model examples: `gemini-1.5-pro`, `gemini-1.5-flash`

### Azure Foundry

- API URL: Azure OpenAI-compatible endpoint
- API key: required
- Model: Azure deployment name

## Connection Validation

After provider configuration, run Settings -> Test Connection.

If using Azure environment variables, validate before Burp testing:

./tools/test_azure_env.sh ./.env

Expected result: STATUS: VALID

## Common Failures

- Wrong endpoint path or API version
- Wrong deployment/model name
- Invalid API key
- Provider service unreachable

## Documentation

- `README.md`
- `docs/guides/QUICKSTART.md`
- `docs/INTERNAL_WORKING.md`
- `docs/DEVELOPER_WORKFLOW.md`
