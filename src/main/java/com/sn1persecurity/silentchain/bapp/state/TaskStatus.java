package com.sn1persecurity.silentchain.bapp.state;

/**
 * Lifecycle states for an analysis task, mirroring the Community status
 * cell renderer values (silentchain_ai_community.py:2835-2862).
 */
public enum TaskStatus {
    QUEUED("Queued"),
    WAITING("Waiting"),
    ANALYZING("Analyzing"),
    COMPLETED("Completed"),
    SKIPPED("Skipped"),
    ERROR("Error"),
    CANCELLED("Cancelled"),
    PAUSED("Paused");

    private final String label;

    TaskStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean isTerminal() {
        return this == COMPLETED || this == SKIPPED || this == ERROR || this == CANCELLED;
    }
}
