package com.sn1persecurity.silentchain.bapp.scan;

/**
 * Outcome of {@link ScanGate#evaluate}. Only {@link #ANALYZE} proceeds to the
 * AI pipeline; the SKIP_* reasons let the caller attribute the skip to the
 * correct statistics counter.
 */
public enum GateDecision {
    ANALYZE,
    SKIP_DISABLED,
    SKIP_TOOL,
    SKIP_NO_REQUEST,
    SKIP_SCOPE,
    SKIP_CONTENT_TYPE,
    SKIP_SIZE,
    SKIP_DUPLICATE,
    SKIP_RATE_LIMIT
}
