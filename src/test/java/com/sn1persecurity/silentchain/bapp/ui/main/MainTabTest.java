package com.sn1persecurity.silentchain.bapp.ui.main;

import com.sn1persecurity.silentchain.bapp.scan.PipelineFixtureAccess;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Review point 4: the 1.5s refresh timer must stop when the extension unloads. */
class MainTabTest {

    @Test
    void disposeStopsTheRefreshTimer() {
        try (PipelineFixtureAccess f = new PipelineFixtureAccess()) {
            MainTab tab = f.newMainTab();
            assertTrue(tab.refreshTimerRunning());

            tab.dispose();

            assertFalse(tab.refreshTimerRunning());
        }
    }
}
