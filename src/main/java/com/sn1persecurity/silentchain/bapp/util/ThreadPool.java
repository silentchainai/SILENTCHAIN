package com.sn1persecurity.silentchain.bapp.util;

import burp.api.montoya.logging.Logging;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The extension's only background executors.
 *
 * <ul>
 *   <li><b>analysis</b> - AI analysis jobs (passive scan check + context menu).
 *       Bounded queue, so a slow provider can never accumulate an unbounded
 *       backlog of retained HTTP messages.</li>
 *   <li><b>interactive</b> - user-initiated provider round trips (Test
 *       Connection, model refresh). Kept separate from analysis so they never
 *       queue behind passive work. A Burp AI test has no API timeout.</li>
 *   <li><b>local</b> - local user actions (CSV export, opening a browser), so
 *       they never wait behind a provider round trip.</li>
 * </ul>
 *
 * Every task is wrapped in try/catch(Throwable) and failures are written to the
 * extension error stream: Burp does not report exceptions from extension
 * threads, and {@code ExecutorService.submit} would silently keep them in a
 * discarded Future. {@link #shutdownNow()} is called from the unloading handler.
 */
public class ThreadPool {

    /** Analysis worker threads; also the most passive scan checks that wait for a result at once. */
    public static final int ANALYSIS_THREADS = 2;
    /** Analysis queue capacity; also the orchestrator's limit on outstanding jobs. */
    public static final int ANALYSIS_QUEUE = 128;
    private static final int INTERACTIVE_QUEUE = 8;
    private static final long AWAIT_SECONDS = 2;

    private final Logging logging;
    private final Lifecycle lifecycle;
    private final ThreadPoolExecutor analysis;
    private final ThreadPoolExecutor interactive;
    private final ThreadPoolExecutor local;

    public ThreadPool(Logging logging, Lifecycle lifecycle) {
        this.logging = logging;
        this.lifecycle = lifecycle;
        this.analysis = new ThreadPoolExecutor(ANALYSIS_THREADS, ANALYSIS_THREADS, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(ANALYSIS_QUEUE), daemonThreads("silentchain-ai-"),
                new ThreadPoolExecutor.AbortPolicy());
        this.interactive = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(INTERACTIVE_QUEUE), daemonThreads("silentchain-ui-"),
                new ThreadPoolExecutor.AbortPolicy());
        this.local = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(INTERACTIVE_QUEUE), daemonThreads("silentchain-local-"),
                new ThreadPoolExecutor.AbortPolicy());
    }

    /** Queue an AI analysis job. Returns false if the queue is full or the pool is shut down. */
    public boolean submitAnalysis(String what, Runnable task) {
        return submit(analysis, what, task);
    }

    /** Queue a user-initiated provider round trip. Returns false if it could not be queued. */
    public boolean submitInteractive(String what, Runnable task) {
        return submit(interactive, what, task);
    }

    /** Queue a local user action (file write, browser). Returns false if it could not be queued. */
    public boolean submitLocal(String what, Runnable task) {
        return submit(local, what, task);
    }

    /**
     * Stop everything: queued work is discarded (it must not start after
     * unload), running work is interrupted, then each pool is given a short
     * grace period.
     */
    public void shutdownNow() {
        analysis.shutdownNow();
        interactive.shutdownNow();
        local.shutdownNow();
        awaitQuietly(analysis, "analysis");
        awaitQuietly(interactive, "interactive");
        awaitQuietly(local, "local");
    }

    private boolean submit(ExecutorService executor, String what, Runnable task) {
        try {
            executor.execute(guard(what, task));
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    private Runnable guard(String what, Runnable task) {
        return () -> {
            try {
                task.run();
            } catch (Throwable t) {
                if (!lifecycle.isUnloading()) {
                    logging.logToError("SILENTCHAIN: background task failed (" + what + ")", t);
                }
            }
        };
    }

    private void awaitQuietly(ExecutorService executor, String name) {
        try {
            if (!executor.awaitTermination(AWAIT_SECONDS, TimeUnit.SECONDS)) {
                logging.logToOutput("SILENTCHAIN: " + name + " worker still finishing an in-flight request; "
                        + "it has been interrupted and will exit when the request returns.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
