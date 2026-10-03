package com.sn1persecurity.silentchain.bapp.util;

import burp.api.montoya.logging.Logging;

import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreadPoolTest {

    @Test
    void exceptionsAreLoggedToTheErrorStreamNotSwallowed() throws Exception {
        List<Throwable> logged = new CopyOnWriteArrayList<>();
        CountDownLatch done = new CountDownLatch(1);
        Logging logging = DeepStub.of(Logging.class, Map.of("logToError", a -> {
            logged.add((Throwable) a[1]);
            done.countDown();
            return null;
        }));
        ThreadPool pool = new ThreadPool(logging, new Lifecycle());
        RuntimeException boom = new IllegalStateException("boom");
        try {
            assertTrue(pool.submitAnalysis("test", () -> { throw boom; }));
            assertTrue(done.await(5, TimeUnit.SECONDS));
            assertEquals(1, logged.size());
            assertSame(boom, logged.get(0));

            CountDownLatch next = new CountDownLatch(1);
            assertTrue(pool.submitAnalysis("test", next::countDown));
            assertTrue(next.await(5, TimeUnit.SECONDS), "the pool keeps working after a failed task");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void nothingIsAcceptedAfterShutdown() {
        ThreadPool pool = new ThreadPool(DeepStub.of(Logging.class), new Lifecycle());
        pool.shutdownNow();
        assertFalse(pool.submitAnalysis("late", () -> { }));
        assertFalse(pool.submitInteractive("late", () -> { }));
    }

    @Test
    void shutdownDiscardsQueuedWork() throws Exception {
        ThreadPool pool = new ThreadPool(DeepStub.of(Logging.class), new Lifecycle());
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(2);
        CopyOnWriteArrayList<String> ran = new CopyOnWriteArrayList<>();
        Runnable blocker = () -> {
            started.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        pool.submitAnalysis("block-1", blocker);
        pool.submitAnalysis("block-2", blocker);
        assertTrue(started.await(5, TimeUnit.SECONDS));
        pool.submitAnalysis("queued", () -> ran.add("queued"));

        pool.shutdownNow();
        release.countDown();

        assertTrue(ran.isEmpty(), "queued work must not start after unload");
    }

    @Test
    void failuresDuringUnloadAreNotReported() throws Exception {
        List<Throwable> logged = new CopyOnWriteArrayList<>();
        Logging logging = DeepStub.of(Logging.class, Map.of("logToError", a -> {
            logged.add((Throwable) a[1]);
            return null;
        }));
        Lifecycle lifecycle = new Lifecycle();
        lifecycle.markUnloading();
        ThreadPool pool = new ThreadPool(logging, lifecycle);
        CountDownLatch ran = new CountDownLatch(1);
        pool.submitInteractive("x", () -> {
            ran.countDown();
            throw new IllegalStateException("teardown noise");
        });
        assertTrue(ran.await(5, TimeUnit.SECONDS));
        pool.shutdownNow();
        assertTrue(logged.isEmpty());
    }
}
