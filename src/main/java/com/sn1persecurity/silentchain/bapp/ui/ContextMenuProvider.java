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

    /** Runs on the EDT (menu action): only checks + queueing, never network I/O. */
    private void dispatch(List<HttpRequestResponse> messages, Component invoker) {
        if (!aiGate.isEnabled()) {
            scanState.info("SILENTCHAIN: " + AiGate.DISABLED_MESSAGE);
            return;
        }
        if (!aiService.isConfigured()) {
            scanState.info("SILENTCHAIN: the selected AI provider is not configured. "
                    + "Open SILENTCHAIN's settings (Settings button on the SILENTCHAIN tab).");
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
}
