package com.sn1persecurity.silentchain.bapp.ai;

import com.sn1persecurity.silentchain.bapp.data.OwaspCategory;

import java.util.Optional;

public record ParsedFinding(
        String title,
        String severityRaw,
        int confidence,
        String cwe,
        OwaspCategory owasp,
        String detail,
        String evidence,
        String remediation
) {
    public Optional<String> normalizedCwe() {
        return OwaspCategory.normalizeCweId(cwe);
    }
}
