# SILENTCHAIN AI - Community Edition (Fork)

AI-powered passive vulnerability analysis extension for Burp Suite.

## What This Project Is

SILENTCHAIN AI runs inside Burp Suite and uses an AI provider to analyze proxied HTTP traffic for likely security issues. It is passive-first and designed to improve analyst throughput by surfacing high-signal findings with severity, confidence, and remediation context.

## Which File Should You Load?

- Stable path: `silentchain_ai_community.py` (recommended for daily use)
- Experimental path: `variants/silentchain_v2_1_0_with_scope.py` (includes custom scope manager and expanded UI)

If reliability matters most, use the stable file.

## Key Capabilities

- Passive HTTP analysis integrated with Burp workflow
- Multi-provider support: Ollama, OpenAI, Claude, Gemini, Azure Foundry
- Burp Issue Activity integration through custom scan issues
- Persistent request-signature cache to reduce repeated AI calls
- CSV export of findings

## Repository Layout

- `silentchain_ai_community.py`: stable baseline and primary integration target
- `variants/silentchain_v2_0_0.py`: older v2 variant
- `variants/silentchain_v2_1_0_with_scope.py`: v2.1 scope-manager variant
- `variants/silentchain_v2_enhanced.py`: alternative enhanced variant
- `docs/guides/QUICKSTART.md`: first run in minutes
- `docs/guides/INSTALLATION.md`: complete provider setup
- `docs/INTERNAL_WORKING.md`: internal architecture and processing pipeline
- `docs/DEVELOPER_WORKFLOW.md`: maintainer verification workflow
- `.github/copilot-instructions.md`: workspace coding/agent rules

## Requirements

- Burp Suite (Community or Professional)
- Java runtime required by Burp
- Burp Python extension support (Jython runtime)
- One configured AI provider

## Install

1. Open Burp Suite.
2. Navigate to Extender -> Extensions -> Add.
3. Select extension type Python.
4. Load `silentchain_ai_community.py`.
5. Open SILENTCHAIN tab and configure provider settings.

## First Validation

1. Set provider URL, API key (if required), and model in Settings.
2. Click Test Connection.
3. Put a target in Burp scope.
4. Proxy traffic and verify findings appear in SILENTCHAIN and Issue Activity.

For Azure-related setup checks, run:

./tools/test_azure_env.sh ./.env

## Documentation Index

- Setup: `docs/guides/QUICKSTART.md`, `docs/guides/INSTALLATION.md`
- Internal behavior: `docs/INTERNAL_WORKING.md`
- Maintenance flow: `docs/DEVELOPER_WORKFLOW.md`
- Change history: `CHANGELOG.md`
- Optimization context: `docs/project/OPTIMIZATION_PLAN.md`
- Legal/license: `docs/project/NOTICE.md`, `LICENSE`

## Responsible Use

Use only on systems you own or are explicitly authorized to test.

## Fork Notes

This repository is a maintained fork with sanitized ownership/contact references. Track support and issues through this fork's issue tracker.
