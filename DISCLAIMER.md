# DISCLAIMER

## Independent extension - not affiliated with PortSwigger

SILENTCHAIN Community Edition is an independent extension developed by Sn1perSecurity LLC.
It is not affiliated with, endorsed by, or sponsored by PortSwigger Ltd. PortSwigger has not
evaluated, tested, or approved this extension. "Burp Suite", "Burp", and the Burp logo are
trademarks of PortSwigger Ltd., used here for nominative descriptive purposes only.

## Authorized use only

SILENTCHAIN Community Edition is an offensive-security tool designed for authorized security
testing, penetration testing, and vulnerability research.

1. **You may not use this software for illegal or nefarious purposes**, or in any manner that
   violates the laws of your jurisdiction, the jurisdiction in which the software is running,
   the jurisdiction in which the software is targeting, or the United States of America.

2. **You agree not to scan a target in a manner that is considered unlawful or illegal, or
   that you do not have explicit written permission to do so.** Users are solely responsible
   for obtaining proper authorization before scanning any target system, network, or
   application.

## Burp AI credit consumption

When the **Burp AI** provider (the default) is selected, vulnerability analysis is performed
by PortSwigger's Burp AI service and each analysis consumes **Burp AI Credits** from your
PortSwigger account; the number of credits varies with request and response size. AI analysis
is **disabled by default** - enable it only after reviewing your credit balance and
consumption preferences. No AI request is sent through any provider unless **Use AI** is
enabled for SILENTCHAIN in Burp (Extensions > Installed). When passive analysis is on, Burp
scans and crawls also feed in-scope items to SILENTCHAIN, so credit usage can rise during
scans.

## Data handling

SILENTCHAIN Community Edition processes HTTP requests and responses intercepted by Burp Suite.
The destination of that data depends on the AI provider you select:

- **Burp AI** - sent through Burp to PortSwigger's Burp AI service and analyzed under
  PortSwigger's AI data-handling policy.
- **Ollama** - analyzed by the Ollama host you configure (localhost by default); when it runs
  on your machine, nothing leaves your machine.
- **Cloud providers** (OpenAI, Claude, Gemini, Azure OpenAI/Foundry) - request/response
  content for in-scope targets is transmitted to that provider's endpoint under its terms.

Credentials (cookie values, `Authorization` and API-key/token header values, and parameters or
JSON fields named like credentials) are always replaced with `[REDACTED]` before any AI request. The extension's built-in
**DataSanitizer** (enabled by default) additionally redacts common secrets and PII (API keys,
bearer tokens, session cookies, emails) and neutralizes prompt-injection patterns before
content is sent to any provider; it is not a guarantee. The extension
itself does not collect, store, or transmit any usage data, telemetry, or analytics, and
contacts no third-party endpoints other than the AI provider you configure. Users handling
regulated data (HIPAA, PCI-DSS, GDPR-restricted) should prefer a local provider (Ollama) and
review the relevant provider terms first. See **PRIVACY.md** for the full per-provider
data-residency notice.

## Liability disclaimer

This software is provided as-is without warranty. Sn1perSecurity LLC, its creators and staff
take no liability for consequential damages to the maximum extent permitted by all applicable
laws. In no event shall Sn1perSecurity LLC or any person be liable for any consequential,
reliance, incidental, special, direct or indirect damages whatsoever (including without
limitation, damages for loss of business profits, business interruption, loss of business
information, personal injury, or any other loss) arising out of or in connection with the use
or inability to use this software, even if Sn1perSecurity LLC has been advised of the
possibility of such damages.

**Sn1perSecurity LLC disclaims all liability for misuse of this software. The user assumes
full responsibility for compliance with all applicable laws and regulations.**

## Summary

> For authorized security testing only. User is responsible for obtaining written permission
> before scanning any target. Sn1perSecurity LLC disclaims liability for misuse. Independent
> extension - not affiliated with PortSwigger Ltd.

---

Copyright (c) 2026 Sn1perSecurity LLC. All rights reserved. Licensed under the SILENTCHAIN
Community Edition License (see LICENSE). "SILENTCHAIN" is a trademark of Sn1perSecurity LLC.
