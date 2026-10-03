package com.sn1persecurity.silentchain.bapp.util;

/**
 * Extension-wide unloading flag. Set first thing in the unloading handler so
 * every worker, timer and scan-check callback can stop issuing new work (and
 * stop logging errors caused by the teardown itself) before the executors are
 * shut down.
 */
public final class Lifecycle {

    private volatile boolean unloading;

    public void markUnloading() {
        unloading = true;
    }

    public boolean isUnloading() {
        return unloading;
    }
}
