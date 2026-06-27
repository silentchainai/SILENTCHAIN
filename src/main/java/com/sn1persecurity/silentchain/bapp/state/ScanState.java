package com.sn1persecurity.silentchain.bapp.state;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Global scan state + the console log bridge.
 *
 * Holds the "Pause All Tasks" flag and a console sink so that log lines are
 * mirrored both to Burp's Extensions Output (via MontoyaApi.logging) and to
 * the in-tab ConsolePane (Community used a ConsolePrintWriter for the same
 * effect, silentchain_ai_community.py:259-279).
 */
public class ScanState {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MontoyaApi api;
    private final Settings settings;

    private final AtomicBoolean paused = new AtomicBoolean(false);
    private volatile Consumer<String> consoleSink;

    public ScanState(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    public boolean isPaused() { return paused.get(); }

    /** Toggle the pause flag. Returns the new state. (Called on the EDT.) */
    public boolean togglePaused() {
        boolean newValue = !paused.get();
        paused.set(newValue);
        return newValue;
    }

    public void setPaused(boolean v) { paused.set(v); }

    public void setConsoleSink(Consumer<String> sink) {
        this.consoleSink = sink;
    }

    // ---- Logging bridge -----------------------------------------------------

    public void info(String message) {
        api.logging().logToOutput(message);
        push(message);
    }

    public void error(String message) {
        api.logging().logToError(message);
        push("[ERROR] " + message);
    }

    public void debug(String message) {
        if (settings.verbose()) {
            api.logging().logToOutput(message);
            push("[DEBUG] " + message);
        }
    }

    private void push(String message) {
        Consumer<String> sink = consoleSink;
        if (sink != null) {
            try {
                sink.accept("[" + LocalTime.now().format(CLOCK) + "] " + message);
            } catch (Throwable ignored) {
                // never let UI sink errors break the scan pipeline
            }
        }
    }
}
