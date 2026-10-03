# Usage

## Basic Workflow

1. **Enable AI** for SILENTCHAIN in **Extensions > Installed** (**Use AI**). Every provider,
   including Ollama, requires it.
2. **Set target scope** in Burp Suite: **Target > Scope > Add**.
3. **Start passive analysis** with **Start Scanning** on the **SILENTCHAIN Community** tab (it
   is OFF by default; the first time, SILENTCHAIN asks for data-handling consent).
4. **Browse the target** through Burp's proxy.
5. **View findings** in the **SILENTCHAIN** tab as requests are analyzed in the background.
6. **Review details** by opening the issue in Burp's **Dashboard** or **Target > Site map**
   issues to see the full AI analysis (detail, evidence, remediation).

## Automatic (Passive) Analysis

Automatic analysis is a Burp Scanner passive scan check. It runs on items that Burp's live
audit tasks and scans audit (for example Burp's default live passive audit of Proxy traffic),
and only:

- for in-scope targets (**Target > Scope**),
- while SILENTCHAIN's passive analysis is ON (**Start Scanning**), and
- while tasks are not paused. If Burp pauses its tasks (for example when a project is
  reopened), passive analysis pauses too.

The passive check never sends requests to the target. Repeater traffic is analyzed
automatically only if a live audit task covers Repeater; otherwise use the context menu.

Burp scans and crawls also feed in-scope items, bounded by URL de-duplication, the per-host
rate limit (default 10/min) and a passive backlog cap (16), so AI usage can rise during scans.

## Manual Analysis

Right-click any request in Burp's **Proxy History**, **Site map**, or **Repeater** and select **Analyze Request (SILENTCHAIN)** to analyze a specific request on demand, even if it was previously analyzed. If the item has no response, SILENTCHAIN sends the request once to capture one. The first analysis asks for data-handling consent.

## Task Controls

- **Cancel All Tasks** cancels queued, paused and running analyses (results of in-flight AI
  calls are discarded).
- **Pause All Tasks** / **Resume All Tasks** holds queued work until you resume.
- **Stop Scanning** turns passive analysis off and cancels queued passive work.
- **Clear Completed** removes finished tasks from the table.
- A failed analysis shows as an **Error** task, with a stack trace in the extension's
  **Errors** tab (**Extensions > Installed**).

## Findings Table

The findings table shows:
- **Discovered At** - when the finding was created
- **URL** - the endpoint where the vulnerability was found
- **Finding** - the finding title
- **Severity** - High, Medium, Low, or Information
- **Confidence** - Certain, Firm, or Tentative

## Sorting

Click column headers to sort.

## Export

Findings are registered as Burp issues and appear in Burp's **Dashboard** and **Target > Site map** issues. They can be exported using Burp's built-in report generation, or via the extension's **Export CSV** button.

## Statistics

The statistics panel counts Total Requests, Analyzed, Skipped (Duplicate), Skipped (Rate
Limit), Skipped (Low Confidence), Findings Created, Skipped (Backlog) and Errors.
**Skipped (Backlog)** replaces the old **Cache Hits** counter and counts passive items dropped
because the backlog was full.

## Tips

- Use **Burp AI** (default) for zero-config analysis (Burp Suite Professional); prompts are sent through Burp to PortSwigger's Burp AI service and use Burp AI credits.
- Use **Ollama** with a local model for fully offline scanning (no data leaves your machine).
- Credential headers are always redacted, and the **DataSanitizer** (enabled by default) redacts other sensitive data before sending to any provider. Disable it for local-only setups if desired.
- For large applications, start with a targeted crawl of key functionality rather than full-site spidering.
- Review Tentative findings carefully - they may need manual verification.
- Passive analysis covers whatever Burp's live audit tasks and scans pass to it; active browsing of key functionality through the proxy usually gives the most relevant coverage.
