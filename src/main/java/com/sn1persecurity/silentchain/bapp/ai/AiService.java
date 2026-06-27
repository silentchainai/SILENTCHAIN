package com.sn1persecurity.silentchain.bapp.ai;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import java.util.Optional;
import java.util.function.Consumer;

/**
 * Backward-compatible facade kept for Phase 1-4 callers. Delegates everything
 * to {@link AiDispatcher} so the provider selection happens in one place.
 *
 * New code should depend on {@link AiDispatcher} directly.
 */
public class AiService {

    private final AiDispatcher dispatcher;
    private final ThreadPool threadPool;

    public AiService(MontoyaApi api, ThreadPool threadPool, AiDispatcher dispatcher) {
        this.dispatcher = dispatcher;
        this.threadPool = threadPool;
    }

    public boolean isAvailable() {
        return dispatcher.isAvailable();
    }

    public Optional<String> analyze(String userPrompt) {
        return dispatcher.analyze(PromptLibrary.systemPrompt(), userPrompt);
    }

    public void analyzeAsync(String userPrompt, Consumer<Optional<String>> callback) {
        threadPool.submit(() -> callback.accept(analyze(userPrompt)));
    }

    /**
     * Run an arbitrary analysis task on the worker pool. Lets a caller resolve a
     * response, build the prompt, call {@link #analyze}, and handle the result as
     * one pooled unit, so a blocking HTTP send never touches the proxy/EDT thread.
     */
    public void submit(Runnable task) {
        threadPool.submit(task);
    }
}
