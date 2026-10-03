package com.sn1persecurity.silentchain.bapp.scan;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.sn1persecurity.silentchain.bapp.testutil.DeepStub;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultHandoffTest {

    private static final AuditIssue ISSUE = DeepStub.of(AuditIssue.class);

    private static ResultHandoff waiting() {
        return new ResultHandoff(() -> false);
    }

    @Test
    void issuesDeliveredBeforeTheWaitAreReturned() {
        ResultHandoff h = waiting();

        assertTrue(h.deliver(List.of(ISSUE)));

        List<AuditIssue> got = h.await(0);
        assertEquals(1, got.size());
        assertSame(ISSUE, got.get(0));
    }

    @Test
    void timeoutReturnsNothingAndALaterDeliveryIsRefused() {
        ResultHandoff h = waiting();

        assertTrue(h.await(20).isEmpty());
        assertFalse(h.deliver(List.of(ISSUE)), "the caller must then report the issues itself");
    }

    @Test
    void releaseFreesTheWaiterAtOnce() {
        ResultHandoff h = waiting();
        ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
        try {
            worker.schedule(h::release, 50, TimeUnit.MILLISECONDS);

            List<AuditIssue> got = assertTimeout(Duration.ofSeconds(2), () -> h.await(10_000));

            assertTrue(got.isEmpty());
        } finally {
            worker.shutdownNow();
        }
    }

    @Test
    void theStopConditionEndsTheWait() {
        AtomicBoolean stop = new AtomicBoolean();
        ResultHandoff h = new ResultHandoff(stop::get);
        ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
        try {
            worker.schedule(() -> stop.set(true), 50, TimeUnit.MILLISECONDS);

            List<AuditIssue> got = assertTimeout(Duration.ofSeconds(2), () -> h.await(10_000));

            assertTrue(got.isEmpty());
            assertFalse(h.deliver(List.of(ISSUE)));
        } finally {
            worker.shutdownNow();
        }
    }

    @Test
    void releaseAndDeliverExcludeEachOther() {
        ResultHandoff released = waiting();
        released.release();
        released.release();   // idempotent
        assertFalse(released.deliver(List.of(ISSUE)));
        assertTrue(released.await(0).isEmpty());

        ResultHandoff delivered = waiting();
        assertTrue(delivered.deliver(List.of(ISSUE)));
        delivered.release();   // no-op after delivery
        assertFalse(delivered.deliver(List.of(ISSUE, ISSUE)), "a delivery is never overwritten");
        assertEquals(1, delivered.await(0).size());
    }

    @Test
    void anInterruptedWaiterStopsWaitingAndKeepsTheFlag() {
        ResultHandoff h = waiting();
        Thread.currentThread().interrupt();
        try {
            List<AuditIssue> got = assertTimeout(Duration.ofSeconds(2), () -> h.await(10_000));

            assertTrue(got.isEmpty());
            assertTrue(Thread.currentThread().isInterrupted());
            assertFalse(h.deliver(List.of(ISSUE)));
        } finally {
            Thread.interrupted();   // clear for the next test
        }
    }

    @Test
    void noneNeverAcceptsIssuesAndNeverWaits() {
        ResultHandoff none = ResultHandoff.none();

        assertFalse(none.deliver(List.of(ISSUE)));
        assertTrue(assertTimeout(Duration.ofSeconds(1), () -> none.await(10_000)).isEmpty());
    }

    /** Whichever side wins, the issues end up in exactly one place. */
    @Test
    void deliveryRacingTheEndOfTheWaitIsDecidedExactlyOnce() throws Exception {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            for (int i = 0; i < 2_000; i++) {
                ResultHandoff h = waiting();
                CountDownLatch go = new CountDownLatch(1);
                Future<Boolean> delivered = worker.submit(() -> {
                    go.await();
                    return h.deliver(List.of(ISSUE));
                });

                go.countDown();
                List<AuditIssue> got = h.await(0);

                assertEquals(delivered.get(5, TimeUnit.SECONDS), !got.isEmpty(), "iteration " + i);
            }
        } finally {
            worker.shutdownNow();
        }
    }
}
