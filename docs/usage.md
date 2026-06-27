# Usage

## Basic Workflow

1. **Set target scope** in Burp Suite: **Target > Scope > Add**.
2. **Browse the target** through Burp's proxy.
3. **View findings** in the **SILENTCHAIN** tab as requests are analyzed in the background.
4. **Review details** by clicking a finding in the table to see the full AI analysis.

## Manual Analysis

Right-click any request in Burp's **Proxy History**, **Site map**, or **Repeater** and select **Analyze (SILENTCHAIN)** to analyze a specific request on demand, even if it was previously analyzed.

## Findings Table

The findings table shows:
- **URL** — the endpoint where the vulnerability was found
- **Vulnerability** — OWASP category (e.g., A03:2021 Injection)
- **Severity** — High, Medium, Low, or Information
- **Confidence** — Certain, Firm, or Tentative
- **Parameter** — the affected parameter (if applicable)

## Filtering

Use the severity filter buttons to show/hide findings by severity level. Click column headers to sort.

## Export

Findings are registered as Burp Scanner Issues and appear in Burp's **Target > Issues** panel. They can be exported using Burp's built-in report generation, or via the extension's **Export CSV** button.

## Tips

- Use **Burp AI** (default) for zero-config, in-process analysis (Burp Suite Professional).
- Use **Ollama** with a local model for fully offline scanning (no data leaves your machine).
- The **DataSanitizer** (enabled by default) redacts sensitive data before sending to cloud providers. Disable it for local-only setups if desired.
- For large applications, start with a targeted crawl of key functionality rather than full-site spidering.
- Review Tentative findings carefully — they may need manual verification.
- The extension analyzes requests as they flow through the proxy, so active browsing produces better coverage than automated crawling alone.
