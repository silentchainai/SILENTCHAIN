# Architecture

## Overview

SILENTCHAIN Community Edition is a Java Burp Suite extension built on the **Montoya API** and
packaged as a single shaded `.jar`. It registers a Burp Scanner passive scan check that
receives in-scope traffic from Burp's live audit tasks and scans, analyzes it with a
configurable AI provider, and reports findings as native Burp Scanner issues plus a live table
in its own suite tab.

## Component Diagram

```
Burp Suite (Montoya API)
  |
  v
SilentchainExtension  (implements BurpExtension; declares AI_FEATURES)
  |
  +-- PassiveScanCheck (AiPassiveScanCheck, PER_REQUEST) --> items from Burp live audit tasks / scans
  +-- ContextMenuItemsProvider -----------------------------> right-click "Analyze Request (SILENTCHAIN)"
  +-- Settings panel (SilentchainSettingsPanel) ------------> SILENTCHAIN in Burp's Settings window
  +-- Suite tab (MainTab) ----------------------------------> SILENTCHAIN Community UI (Swing)
  +-- Unloading handler ------------------------------------> Lifecycle + ThreadPool.shutdownNow()
  |
  v
AnalysisOrchestrator  (bounded analysis executor in util/ThreadPool, off the EDT)
  |
  +-- ScanGate -------------> scope / content-type / size / URL-dedup / per-host rate limit (passive only)
  +-- AiGate ---------------> api.ai().isEnabled(), checked before EVERY AI request
  +-- PromptLibrary --------> structured request/response prompt; credential headers -> [REDACTED]
  +-- DataSanitizer --------> redacts secrets/PII before AI calls (every provider), restores after
  +-- AiDispatcher ---------> routes to the selected provider:
  |     +-- Burp AI (Montoya AI; prompts go through Burp to PortSwigger's Burp AI service)
  |     +-- Ollama / OpenAI / Claude / Gemini / Azure  (via MontoyaHttpClient)
  +-- ResponseParser -------> parses the JSON findings, sanitizes titles
  |
  v
FindingBuilder
  +-- AuditIssue -----------> api.siteMap().add(...)  (native Burp Scanner issue)
  +-- FindingsRegistry -----> SILENTCHAIN Community findings table (+ CSV export)
```

## Data Flow

1. Burp's live audit tasks and scans (for example the default live passive audit of Proxy
   traffic) call `AiPassiveScanCheck.doCheck`. It returns an empty `AuditResult` immediately;
   it never sends a request to the target and skips items without a response.
2. If passive analysis is ON, tasks are not paused and `AiGate` allows AI, `ScanGate` applies
   gating: in-scope only (always), content-type allow-list, response size cap, URL
   de-duplication (TTL + capacity bounded) and per-host rate limit, under one lock.
3. Admitted items are copied to a temp file (`copyToTempFile`) and queued, bounded by a
   passive backlog of 16. Right-click analysis (`analyzeOnDemand`) queues the selected items
   directly and is the only path that may send the request once to capture a missing response.
4. `AnalysisOrchestrator.runJob` (on the analysis pool, inside try/catch/finally) builds the
   prompt via `PromptLibrary`, applies `DataSanitizer`, and calls the selected provider through
   `AiDispatcher`. Cancel, pause, Stop Scanning, the AI permission and unloading are re-checked
   as the job runs.
5. The provider returns JSON findings; `ResponseParser` extracts them and `DataSanitizer`
   restores any redacted values.
6. `FindingBuilder` emits each finding as a Burp `AuditIssue` (`api.siteMap().add`) and a row
   in the findings table. Every task ends in a terminal state (Completed, Skipped, Cancelled or
   Error); failures are logged to the extension error stream.

## Key Design Decisions

- **Montoya API:** Modern Burp extension API; the entry point is
  `SilentchainExtension.initialize(MontoyaApi)`. All outbound LLM HTTP uses Burp's networking
  (`MontoyaHttpClient` → `api.http().sendRequest` with upstream TLS verification) rather than
  a JVM HTTP stack. `MontoyaHttpClient` is the single third-party egress point and blocks
  every request when `AiGate` reports AI disabled.
- **Passive scan check, not an HTTP handler:** Burp decides what is audited, and the passive
  path can never generate traffic to the scanned host.
- **AI gate on every request:** `AiGate` wraps `api.ai().isEnabled()` and is checked by the
  dispatcher, every provider (including Test Connection, model refresh and Ollama model
  resolution) and `MontoyaHttpClient`. It is evaluated per call and fails closed.
- **Multi-module source, single jar:** Code is organized by package
  (`ai`, `config`, `data`, `net`, `scan`, `state`, `ui`, `util`) and built with Gradle +
  the Shadow plugin into one self-contained `.jar`.
- **Bounded executors:** `util/ThreadPool` has a bounded analysis executor (2 threads, queue
  of 128) and a separate interactive executor for Test Connection, model refresh and CSV
  export, so blocking AI calls never touch Burp's scanner threads or the Swing EDT. Every task
  is guarded and logs failures to the extension error stream. The task table is capped at
  1,000 entries (oldest finished tasks are dropped first).
- **Clean unload:** the unloading handler sets `util/Lifecycle`, cancels all tasks, stops the
  `MainTab` refresh timer and calls `ThreadPool.shutdownNow()`.
- **Preferences persistence:** Settings are stored via `api.persistence().preferences()`
  (`config/SettingsPersistence`), with per-provider URL/key/model keys and automatic migration
  of the older shared keys, surviving extension reload / Burp restart.
- **Java Swing UI:** The suite tab, settings panel and dialogs use `javax.swing`, themed to
  match Burp. Dialogs are parented to the Burp window. Table renderers disable HTML because
  finding titles and URLs are untrusted.
- **CSV export:** Findings can be exported to CSV from the extension UI.
