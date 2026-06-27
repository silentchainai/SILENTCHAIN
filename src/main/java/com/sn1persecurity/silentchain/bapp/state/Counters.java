package com.sn1persecurity.silentchain.bapp.state;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Eight live statistics counters mirrored on the SILENTCHAIN tab
 * (Community silentchain_ai_community.py:466-497).
 */
public class Counters {

    private final AtomicLong totalRequests = new AtomicLong();
    private final AtomicLong analyzed = new AtomicLong();
    private final AtomicLong skippedDuplicate = new AtomicLong();
    private final AtomicLong skippedRateLimit = new AtomicLong();
    private final AtomicLong skippedLowConfidence = new AtomicLong();
    private final AtomicLong findingsCreated = new AtomicLong();
    private final AtomicLong cacheHits = new AtomicLong();
    private final AtomicLong errors = new AtomicLong();

    public void incTotalRequests()        { totalRequests.incrementAndGet(); }
    public void incAnalyzed()             { analyzed.incrementAndGet(); }
    public void incSkippedDuplicate()     { skippedDuplicate.incrementAndGet(); }
    public void incSkippedRateLimit()     { skippedRateLimit.incrementAndGet(); }
    public void incSkippedLowConfidence() { skippedLowConfidence.incrementAndGet(); }
    public void incFindingsCreated()      { findingsCreated.incrementAndGet(); }
    public void incCacheHits()            { cacheHits.incrementAndGet(); }
    public void incErrors()               { errors.incrementAndGet(); }

    public long totalRequests()        { return totalRequests.get(); }
    public long analyzed()             { return analyzed.get(); }
    public long skippedDuplicate()     { return skippedDuplicate.get(); }
    public long skippedRateLimit()     { return skippedRateLimit.get(); }
    public long skippedLowConfidence() { return skippedLowConfidence.get(); }
    public long findingsCreated()      { return findingsCreated.get(); }
    public long cacheHits()            { return cacheHits.get(); }
    public long errors()               { return errors.get(); }
}
