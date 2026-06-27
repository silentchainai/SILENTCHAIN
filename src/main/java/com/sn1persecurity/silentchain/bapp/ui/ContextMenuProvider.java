package com.sn1persecurity.silentchain.bapp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.sn1persecurity.silentchain.bapp.ai.AiService;
import com.sn1persecurity.silentchain.bapp.scan.AnalysisOrchestrator;
import com.sn1persecurity.silentchain.bapp.state.ScanState;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuProvider implements ContextMenuItemsProvider {

    private static final String MENU_LABEL = "Analyze Request (SILENTCHAIN)";

    private final MontoyaApi api;
    private final AiService aiService;
    private final AnalysisOrchestrator orchestrator;
    private final ScanState scanState;

    public ContextMenuProvider(MontoyaApi api, AiService aiService,
                               AnalysisOrchestrator orchestrator, ScanState scanState) {
        this.api = api;
        this.aiService = aiService;
        this.orchestrator = orchestrator;
        this.scanState = scanState;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelected(event);
        if (selected.isEmpty()) {
            return List.of();
        }

        JMenuItem item = new JMenuItem(MENU_LABEL);
        item.addActionListener(e -> dispatch(selected));
        return List.of(item);
    }

    private List<HttpRequestResponse> collectSelected(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>();
        event.messageEditorRequestResponse().ifPresent(editor -> out.add(editor.requestResponse()));
        out.addAll(event.selectedRequestResponses());
        return out;
    }

    private void dispatch(List<HttpRequestResponse> messages) {
        if (!aiService.isAvailable()) {
            scanState.info(
                    "SILENTCHAIN: AI provider not available. Configure it in the Settings dialog before analyzing."
            );
            return;
        }

        scanState.info(
                "SILENTCHAIN [context-menu]: dispatching " + messages.size() +
                " message(s) for AI analysis."
        );

        for (HttpRequestResponse rr : messages) {
            orchestrator.analyzeAsync(rr, "context-menu");
        }
    }
}
