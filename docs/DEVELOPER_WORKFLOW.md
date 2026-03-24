# Developer Workflow

This workflow is for maintainers of this fork.

## 1. Change Target

- Default to `silentchain_ai_community.py` for production-facing fixes.
- Treat v2 files as experimental unless explicitly promoted.

## 2. Verification Path

There is no standalone build/test harness. Validation is Burp runtime based.

1. Load extension in Burp (Extender -> Extensions -> Add -> Python).
2. Open SILENTCHAIN tab.
3. Run Settings -> Test Connection.
4. Proxy in-scope traffic and verify findings/issue activity behavior.

## 3. Azure Validation (When Applicable)

./tools/test_azure_env.sh ./.env

Expected: STATUS: VALID

## 4. Regression Checklist

- Scope filtering remains correct
- Static extension skipping remains correct
- Semaphore behavior does not deadlock
- Cache hit/reuse behavior remains intact
- Confidence mapping and severity normalization remain unchanged
- CSV naming pattern remains unchanged

## 5. Release Hygiene

- Update `CHANGELOG.md` for user-visible behavior changes.
- Update docs for setup or workflow changes.
- If config schema changes, update migration logic and config versioning.
