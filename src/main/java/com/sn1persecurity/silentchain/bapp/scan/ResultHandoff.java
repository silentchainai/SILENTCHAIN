package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Hands one passive job's issues to the Burp scanner thread waiting in
 * {@link AiPassiveScanCheck#doCheck}, or tells the job nobody is waiting any
 * more so it reports them with {@code api.siteMap().add()} instead.
 *
 * A single compare-and-set from "pending" decides the winner, so every issue is
 * reported exactly once: either in the scan check's {@code AuditResult} or in
 * the site map, never both and never neither.
 */
final class ResultHandoff {

    /** How often a waiting scanner thread re-checks "task ended / unloading". */
    static final long POLL_MILLIS = 200;

    /** Identity sentinel: the waiter has gone (or nothing will be delivered). */
    private static final List<AuditIssue> DETACHED = Collections.unmodifiableList(new ArrayList<>(0));

    private static final ResultHandoff NONE = new ResultHandoff(() -> true);
    static {
        NONE.release();
    }

    /** null = pending; DETACHED; or the delivered issues. */
    private final AtomicReference<List<AuditIssue>> outcome = new AtomicReference<>();
    private final CountDownLatch settled = new CountDownLatch(1);
    private final BooleanSupplier stopWaiting;

    /**
     * @param stopWaiting checked while waiting; true ends the wait early (the
     *                    job's task ended or the extension is unloading)
     */
    ResultHandoff(BooleanSupplier stopWaiting) {
        this.stopWaiting = stopWaiting;
    }

    /** A handoff nobody waits on (user-initiated jobs): {@link #deliver} always returns false. */
    static ResultHandoff none() {
        return NONE;
    }

    /**
     * Worker side: hand the issues to the waiting scan check.
     *
     * @return false if no scanner thread will take them (it stopped waiting, or
     *         there never was one): the caller must report them itself.
     */
    boolean deliver(List<AuditIssue> issues) {
        if (outcome.compareAndSet(null, List.copyOf(issues))) {
            settled.countDown();
            return true;
        }
        return false;
    }

    /**
     * Worker side: nothing will be delivered now (no findings, skipped, failed,
     * cancelled, or parked to run later). Frees the waiting scanner thread at
     * once. Idempotent; a no-op after {@link #deliver}.
     */
    void release() {
        if (outcome.compareAndSet(null, DETACHED)) {
            settled.countDown();
        }
    }

    /**
     * Scan check side: wait up to {@code budgetMillis} for the job's issues.
     * Always detaches before returning, so anything the job finishes later is
     * reported through the site map instead. An interrupted thread stops
     * waiting and keeps its interrupt flag.
     *
     * @return the delivered issues, or an empty list if none were delivered in time
     */
    List<AuditIssue> await(long budgetMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMillis);
        try {
            while (!stopWaiting.getAsBoolean()) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                long slice = Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(POLL_MILLIS));
                if (settled.await(slice, TimeUnit.NANOSECONDS)) {
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            release();
        }
        List<AuditIssue> result = outcome.get();
        return result == DETACHED ? List.of() : result;
    }
}
