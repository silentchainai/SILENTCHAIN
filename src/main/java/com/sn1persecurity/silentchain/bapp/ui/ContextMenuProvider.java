package com.sn1persecurity.silentchain.bapp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.ui.dialogs.DataConsentDialog;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public class ContextMenuProvider implements ContextMenuItemsProvider {

    private static final String MENU_LABEL = "Analyze Request (SILENTCHAIN)";

    private final MontoyaApi api;
    private final AiService aiService;
    private final AiGate aiGate;
    private final AnalysisOrchestrator orchestrator;
    private final ScanState scanState;
    private final SettingsPersistence persistence;

    public ContextMenuProvider(MontoyaApi api, AiService aiService, AiGate aiGate,
                               AnalysisOrchestrator orchestrator, ScanState scanState,
                               SettingsPersistence persistence) {
        this.api = api;
        this.aiService = aiService;
        this.aiGate = aiGate;
        this.orchestrator = orchestrator;
        this.scanState = scanState;
        this.persistence = persistence;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelected(event);
        if (selected.isEmpty()) {
            return List.of();
        }

        JMenuItem item = new JMenuItem(MENU_LABEL);
        item.addActionListener(e -> {
            try {
                dispatch(selected, item);
            } catch (Throwable t) {
                api.logging().logToError("SILENTCHAIN: context-menu analysis failed to start", t);
            }
        });
        return List.of(item);
    }

    private List<HttpRequestResponse> collectSelected(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>();
        event.messageEditorRequestResponse().ifPresent(editor -> out.add(editor.requestResponse()));
        out.addAll(event.selectedRequestResponses());
        return out;
    }

    /**
     * Runs on the EDT (menu action): only checks + queueing, never network I/O.
     * Like passive analysis, right-click analysis is limited to Burp's target
     * scope (PortSwigger's AI guidance: send only in-scope traffic).
     */
    private void dispatch(List<HttpRequestResponse> selection, Component invoker) {
        if (!aiGate.isEnabled()) {
            scanState.info("SILENTCHAIN: " + AiGate.DISABLED_MESSAGE);
            return;
        }
        if (!aiService.isConfigured()) {
            scanState.info("SILENTCHAIN: the selected AI provider is not configured. "
                    + "Open SILENTCHAIN's settings (Settings button on the SILENTCHAIN tab).");
            return;
        }
        List<HttpRequestResponse> messages = inScope(selection, url -> api.scope().isInScope(url));
        int outOfScope = selection.size() - messages.size();
        if (outOfScope > 0) {
            scanState.info("SILENTCHAIN [context-menu]: " + outOfScope + " selected item(s) are outside Burp's "
                    + "target scope and were not analyzed (add the target under Target > Scope).");
        }
        if (messages.isEmpty()) {
            return;
        }
        if (!DataConsentDialog.ensureConsent(api, persistence, invoker)) {
            scanState.info("SILENTCHAIN: analysis not started (data-handling consent declined).");
            return;
        }

        int queued = 0;
        for (HttpRequestResponse rr : messages) {
            if (orchestrator.analyzeOnDemand(rr)) {
                queued++;
            }
        }
        scanState.info("SILENTCHAIN [context-menu]: queued " + queued + " of " + messages.size()
                + " message(s) for AI analysis.");
        if (queued < messages.size()) {
            scanState.info("SILENTCHAIN [context-menu]: " + (messages.size() - queued)
                    + " message(s) not queued because the analysis queue is full. Try again when "
                    + "current tasks finish.");
        }
    }

    /** The items whose request URL is in scope (null or URL-less items are dropped). */
    static List<HttpRequestResponse> inScope(List<HttpRequestResponse> items, Predicate<String> isInScope) {
        List<HttpRequestResponse> out = new ArrayList<>();
        for (HttpRequestResponse rr : items) {
            if (rr != null && rr.request() != null) {
                String url = rr.request().url();
                if (url != null && !url.isBlank() && isInScope.test(url)) {
                    out.add(rr);
                }
            }
        }
        return out;
    }
}
