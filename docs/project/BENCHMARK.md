# Benchmark Notes

This file tracks practical scan performance observations. Treat values as environment-dependent and not absolute throughput guarantees.

## Baseline Method

- Runtime: Burp + Jython extension
- Scan mode: passive traffic analysis
- AI request path: provider chat/completions equivalent
- Cache behavior: request-signature cache enabled

## Result Table Template

| Provider | Model/Deployment | Target Profile | Total Requests | AI Calls | Cache Hits | Duration | Notes |
|----------|------------------|----------------|----------------|----------|------------|----------|-------|
| Ollama | deepseek-r1:latest | local test app | TBD | TBD | TBD | TBD | baseline local |
| OpenAI | gpt-4o-mini | local test app | TBD | TBD | TBD | TBD | cloud latency |
| Claude | claude-3-5-sonnet | local test app | TBD | TBD | TBD | TBD | cloud latency |
| Gemini | gemini-1.5-pro | local test app | TBD | TBD | TBD | TBD | cloud latency |
| Azure Foundry | deployment-name | local test app | TBD | TBD | TBD | TBD | endpoint/version sensitive |

## Measurement Guidance

- Capture cache hit ratio to avoid misleading provider comparisons.
- Record request mix (static vs dynamic endpoints).
- Record provider timeout and model token settings.
- Run with same scope and identical traffic replay for fair comparison.
