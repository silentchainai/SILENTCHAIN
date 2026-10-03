package com.sn1persecurity.silentchain.bapp.scan;

import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.ui.main.MainTab;

/** Lets UI tests in other packages build components on the stubbed pipeline. */
public final class PipelineFixtureAccess implements AutoCloseable {

    private final PipelineFixture f = new PipelineFixture();

    public MainTab newMainTab() {
        return new MainTab(f.api, f.settings, new SettingsPersistence(f.api), f.scanState, f.counters,
                f.tasks, f.findings, f.orchestrator, f.pool, f.aiGate, () -> 0L);
    }

    @Override
    public void close() {
        f.close();
    }
}
