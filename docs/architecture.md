# Architecture

## Overview

SILENTCHAIN Community Edition is a Java Burp Suite extension built on the **Montoya API** and
packaged as a single shaded `.jar`. It registers Burp handlers to intercept HTTP traffic,
analyzes it with a configurable AI provider, and reports findings as native Burp Scanner
issues plus a live table in its own suite tab.

## Component Diagram

```
Burp Suite (Montoya API)
  |
  v
SilentchainExtension  (implements BurpExtension)
  |
  +-- HttpHandler (PassiveHttpHandler) --> intercepts in-scope proxy traffic
  +-- ContextMenuItemsProvider ----------> right-click "Analyze (SILENTCHAIN)"
  +-- Suite tab (MainTab) ---------------> SILENTCHAIN Community UI (Swing)
  |
  v
AnalysisOrchestrator  (runs on a worker ThreadPool, off the EDT)
  |
  +-- ScanGate -------------> scope / content-type / rate-limit / URL-dedup gating
  +-- DataSanitizer --------> redacts secrets/PII before cloud AI calls, restores after
  +-- PromptLibrary --------> structured request/response prompt + system instructions
  +-- AiDispatcher ---------> routes to the selected provider:
  |     +-- Burp AI (in-process, Montoya AI)
  |     +-- Ollama / OpenAI / Claude / Gemini / Azure  (via MontoyaHttpClient)
  +-- ResponseParser -------> parses the JSON finding array
  |
  v
FindingBuilder
  +-- AuditIssue -----------> api.siteMap().add(...)  (native Burp Scanner issue)
  +-- FindingsRegistry -----> SILENTCHAIN Community findings table (+ CSV export)
```

## Data Flow

1. HTTP request/response passes through Burp's proxy; `PassiveHttpHandler` receives it.
2. `ScanGate` applies gating: in-scope-only, allowed tool source, content-type allow-list,
   per-host rate limit, and URL deduplication (TTL + capacity bounded).
3. `DataSanitizer` redacts sensitive values (API keys, credentials, PII) from the prompt
   (skipped for local/in-process providers).
4. `AnalysisOrchestrator` (on the worker pool) builds the prompt via `PromptLibrary` and calls
   the selected provider through `AiDispatcher`.
5. The provider returns a JSON array of findings; `ResponseParser` extracts them and
   `DataSanitizer` restores any redacted values.
6. `FindingBuilder` emits each finding as a Burp `AuditIssue` and a row in the findings table.

## Key Design Decisions

- **Montoya API:** Modern Burp extension API; the entry point is
  `SilentchainExtension.initialize(MontoyaApi)`. All outbound LLM HTTP uses Burp's networking
  (`MontoyaHttpClient` → `api.http().sendRequest`) rather than a JVM HTTP stack.
- **Multi-module source, single jar:** Code is organized by package
  (`ai`, `config`, `data`, `net`, `scan`, `state`, `ui`, `util`) and built with Gradle +
  the Shadow plugin into one self-contained `.jar`.
- **Worker thread pool:** Analysis runs on a background pool (`util/ThreadPool`) so blocking
  AI calls never touch Burp's HTTP-handler thread or the Swing EDT.
- **Preferences persistence:** Settings are stored via `api.persistence().preferences()`
  (`config/SettingsPersistence`), surviving extension reload / Burp restart.
- **Java Swing UI:** The suite tab and dialogs use `javax.swing`, themed to match Burp.
- **CSV export:** Findings can be exported to CSV from the extension UI.
