package com.sn1persecurity.silentchain.bapp.data;

import java.util.Optional;

public enum OwaspCategory {
    A01_BROKEN_ACCESS_CONTROL("A01:2021", "Broken Access Control",                  "CWE-284"),
    A02_CRYPTOGRAPHIC_FAILURES("A02:2021", "Cryptographic Failures",                "CWE-327"),
    A03_INJECTION("A03:2021",              "Injection",                              "CWE-89"),
    A04_INSECURE_DESIGN("A04:2021",        "Insecure Design",                        "CWE-657"),
    A05_SECURITY_MISCONFIGURATION("A05:2021", "Security Misconfiguration",           "CWE-16"),
    A06_VULNERABLE_COMPONENTS("A06:2021",  "Vulnerable and Outdated Components",     "CWE-1104"),
    A07_AUTH_FAILURES("A07:2021",          "Identification and Authentication Failures", "CWE-287"),
    A08_INTEGRITY_FAILURES("A08:2021",     "Software and Data Integrity Failures",   "CWE-502"),
    A09_LOGGING_FAILURES("A09:2021",       "Security Logging and Monitoring Failures", "CWE-778"),
    A10_SSRF("A10:2021",                   "Server-Side Request Forgery",            "CWE-918"),
    UNKNOWN("",                            "Uncategorized",                          "CWE-693");

    private final String code;
    private final String displayName;
    private final String defaultCwe;

    OwaspCategory(String code, String displayName, String defaultCwe) {
        this.code = code;
        this.displayName = displayName;
        this.defaultCwe = defaultCwe;
    }

    public String code() {
        return code;
    }

    public String displayName() {
        return displayName;
    }

    public String defaultCwe() {
        return defaultCwe;
    }

    public static OwaspCategory fromCode(String raw) {
        if (raw == null) {
            return UNKNOWN;
        }
        String upper = raw.trim().toUpperCase();
        for (OwaspCategory c : values()) {
            if (!c.code.isEmpty() && upper.startsWith(c.code.toUpperCase())) {
                return c;
            }
        }
        return UNKNOWN;
    }

    public static Optional<String> normalizeCweId(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String s = raw.trim().toUpperCase();
        if (!s.startsWith("CWE-")) {
            s = "CWE-" + s.replaceAll("[^0-9]", "");
        }
        if (s.matches("CWE-\\d+")) {
            return Optional.of(s);
        }
        return Optional.empty();
    }
}
