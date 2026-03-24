# Internal Working

This document explains the runtime flow and architectural constraints of SILENTCHAIN.

## Runtime Context

- Burp extension running on Jython 2.7
- Main entry point: `silentchain_ai_community.py`

## Core Pipeline

1. Burp traffic enters passive handlers.
2. Requests are scope-filtered and static assets are skipped.
3. Tasks are submitted to a fixed thread pool.
4. Analysis acquires semaphores and applies request pacing.
5. Request signature is generated for cache lookup.
6. Cache hit reuses findings; cache miss calls selected AI provider.
7. AI response is parsed/normalized.
8. Findings are deduplicated and emitted as Burp issues and UI entries.

## Concurrency Model

- Fixed worker pool for analysis tasks
- Global semaphore cap for total AI concurrency
- Per-host semaphore cap for host fairness
- Preserve acquisition order in standard analysis flow: host then global

## Persistence

- Config: `~/.silentchain_config.json`
- Cache: `~/.silentchain_vuln_cache.json`

## Provider Dispatch

The provider router calls one adapter per selected provider:

- Ollama
- OpenAI
- Claude
- Gemini
- Azure Foundry

## Output Artifacts

- Burp Issue Activity entries
- Findings table in SILENTCHAIN UI
- CSV export with format `SILENTCHAIN_Findings_YYYYMMDD_HHMMSS.csv`

## Safe-Change Constraints

- Keep Jython 2.7 compatibility
- Keep UI updates EDT-safe
- Preserve confidence/severity mapping behavior
- Preserve cache signature semantics unless intentionally changing reuse behavior
