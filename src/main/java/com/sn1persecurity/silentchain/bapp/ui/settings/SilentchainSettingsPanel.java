package com.sn1persecurity.silentchain.bapp.ui.settings;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanel;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.state.ScanState;
import com.sn1persecurity.silentchain.bapp.state.TaskRegistry;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import java.awt.BorderLayout;
import java.util.Set;

/**
 * SILENTCHAIN's settings, registered with Burp's own Settings window via
 * {@code api.userInterface().registerSettingsPanel(...)}. Hosts the AI Provider
 * and Advanced tabs; every value applies as it is committed, and the fields
 * are reloaded from the live settings each time the panel is shown (so they
 * reflect, for example, the Start/Stop Scanning button on the main tab).
 */
public class SilentchainSettingsPanel implements SettingsPanel {

    private static final Set<String> KEYWORDS = Set.of(
            "SILENTCHAIN", "AI", "LLM", "Burp AI", "Ollama", "OpenAI", "Claude", "Gemini", "Azure",
            "API key", "model", "passive", "sanitizer", "scope", "rate limit", "timeout");

    private final JPanel root = new JPanel(new BorderLayout());
    private final AiProviderTab aiTab;
    private final AdvancedTab advancedTab;

    public SilentchainSettingsPanel(MontoyaApi api,
                                    Settings settings,
                                    SettingsPersistence persistence,
                                    AiDispatcher dispatcher,
                                    AiGate aiGate,
                                    ScanState scanState,
                                    TaskRegistry taskRegistry,
                                    ThreadPool threadPool,
                                    Runnable onChanged) {
        this.aiTab = new AiProviderTab(settings, persistence, dispatcher, aiGate, threadPool,
                api.logging(), onChanged);
        this.advancedTab = new AdvancedTab(api, settings, persistence, scanState, taskRegistry, onChanged);

        JTextArea note = new JTextArea(
                "Changes apply immediately. AI analysis requires Burp Suite Professional with 'Use AI' "
                + "enabled for SILENTCHAIN in Extensions > Installed; this applies to every provider.");
        note.setEditable(false);
        note.setOpaque(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("AI Provider", new JScrollPane(aiTab));
        tabs.addTab("Advanced", new JScrollPane(advancedTab));

        root.add(note, BorderLayout.NORTH);
        root.add(tabs, BorderLayout.CENTER);
        root.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                reload();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {
                // nothing to do: values were applied as they were committed
            }

            @Override
            public void ancestorMoved(AncestorEvent event) {
                // not relevant
            }
        });

        reload();
    }

    /** Reflect a passive on/off change made on the main tab. */
    public void syncPassive() {
        advancedTab.syncPassive();
    }

    /** Refill both tabs from the live settings. */
    public void reload() {
        aiTab.load();
        advancedTab.load();
    }

    @Override
    public JComponent uiComponent() {
        return root;
    }

    @Override
    public Set<String> keywords() {
        return KEYWORDS;
    }
}
