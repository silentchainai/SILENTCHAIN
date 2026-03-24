# Project Guidelines

## Code Style
- Keep compatibility with Jython 2.7 and Burp extension APIs.
- Prefer simple, defensive Python over modern Python 3-only features.
- Preserve existing naming and class structure in `silentchain_ai_community.py`.
- Keep UI changes EDT-safe: mutate Swing UI on `SwingUtilities.invokeLater`.

## Architecture
- Primary entry point is `silentchain_ai_community.py`.
- `BurpExtender` owns lifecycle, UI, settings, provider dispatch, caching, and scan orchestration.
- Passive analysis pipeline is `doPassiveScan/processHttpMessage -> AnalyzeTask -> analyze -> _perform_analysis -> ask_ai -> addScanIssue`.
- Threading model uses fixed thread pool (`Executors.newFixedThreadPool(5)`) and semaphores:
  - global cap: 5 concurrent AI calls
  - per-host cap: 2 concurrent calls
- Persistent files are in home directory:
  - `~/.silentchain_config.json`
  - `~/.silentchain_vuln_cache.json`

## Build and Test
- There is no local build/test harness; this is a Burp runtime extension.
- Main verification path is manual load in Burp:
  1. `Extender -> Extensions -> Add -> Python`
  2. Load `silentchain_ai_community.py`
  3. Use Settings -> Test Connection
- Optional Azure env validation:
  - `./tools/test_azure_env.sh ./.env`

## Conventions
- Prefer new work in `silentchain_ai_community.py` unless a task explicitly targets v2 variants.
- Keep exported CSV filename pattern unchanged: `SILENTCHAIN_Findings_YYYYMMDD_HHMMSS.csv`.
- Preserve confidence mapping and severity normalization behavior.
- Keep request signature logic stable unless intentional cache behavior change is requested.

## Pitfalls
- Burp/Jython imports will appear unresolved outside Burp; this is expected.
- Avoid blocking calls on the UI thread.
- Keep semaphore acquisition order in `analyze` (host, then global) to avoid deadlock regressions.
- If changing config schema, update migration path and config versioning.

## Documentation
- Architecture internals: `docs/INTERNAL_WORKING.md`
- Developer flow and release checks: `docs/DEVELOPER_WORKFLOW.md`
- Setup and provider configuration: `docs/guides/QUICKSTART.md`, `docs/guides/INSTALLATION.md`
- Change history and optimization rationale: `CHANGELOG.md`, `docs/project/OPTIMIZATION_PLAN.md`
