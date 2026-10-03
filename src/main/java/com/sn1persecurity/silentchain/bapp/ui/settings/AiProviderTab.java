package com.sn1persecurity.silentchain.bapp.ui.settings;

import burp.api.montoya.logging.Logging;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.AiGate;
import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.ai.providers.TestResult;
import com.sn1persecurity.silentchain.bapp.config.Settings;
import com.sn1persecurity.silentchain.bapp.config.Settings.ProviderConfig;
import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;
import com.sn1persecurity.silentchain.bapp.util.ThreadPool;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.List;

/**
 * AI Provider configuration tab, shown inside Burp's Settings window. Mirrors
 * Community's "AI Provider" settings tab (silentchain_ai_community.py:1322-1504)
 * with Burp AI added as the default provider.
 *
 * Values apply as they are committed (Enter / focus loss / selection); there is
 * no Save or Cancel. Each provider keeps its own URL, key and model, so
 * switching provider loads that provider's values and never reuses another
 * vendor's key. When Burp AI is selected the third-party fields are disabled.
 */
public class AiProviderTab extends JPanel {

    private final Settings settings;
    private final SettingsPersistence persistence;
    private final AiDispatcher dispatcher;
    private final AiGate aiGate;
    private final ThreadPool threadPool;
    private final Logging logging;
    private final Runnable onChanged;

    private final JComboBox<String> providerCombo = new JComboBox<>();
    private final JTextField apiUrl = new JTextField(30);
    private final JPasswordField apiKey = new JPasswordField(30);
    private final JComboBox<String> modelCombo = new JComboBox<>();
    private final JButton refreshBtn = new JButton("Refresh");
    private final JTextField maxTokens = new JTextField(8);
    private final JTextField azureApiVersion = new JTextField(16);
    private final JComboBox<String> ollamaStructured =
            new JComboBox<>(new String[] {"schema", "json", "off"});
    private final JTextField ollamaNumCtx = new JTextField(8);
    private final JButton testBtn = new JButton("Test Connection");
    private final JLabel statusLabel = new JLabel(" ");

    /** Provider whose URL/key/model the fields currently show. */
    private ProviderId shownProvider = ProviderId.BURP_AI;
    /** True while fields are being filled programmatically, so listeners do not commit. */
    private boolean loading;

    public AiProviderTab(Settings settings, SettingsPersistence persistence, AiDispatcher dispatcher,
                         AiGate aiGate, ThreadPool threadPool, Logging logging, Runnable onChanged) {
        this.settings = settings;
        this.persistence = persistence;
        this.dispatcher = dispatcher;
        this.aiGate = aiGate;
        this.threadPool = threadPool;
        this.logging = logging;
        this.onChanged = onChanged;

        setLayout(new GridBagLayout());
        modelCombo.setEditable(true);
        statusLabel.putClientProperty("html.disable", Boolean.TRUE);

        for (ProviderId p : ProviderId.values()) {
            providerCombo.addItem(p.displayName());
        }

        ollamaNumCtx.setToolTipText("Ollama context window (num_ctx) in tokens. Too small silently "
                + "truncates the prompt and the model returns no findings. Must exceed prompt + Max "
                + "Tokens; default 8192.");
        ollamaStructured.setToolTipText("How the Ollama request constrains output. 'schema' (default) "
                + "forces {\"findings\":[...]} and is the most reliable on small local models; 'json' "
                + "is the legacy loose JSON mode; 'off' relies on the prompt only.");

        int row = 0;
        addRow(row++, "AI Provider:", providerCombo);
        addRow(row++, "API URL:", apiUrl);
        addRow(row++, "API Key:", apiKey);
        addRow(row++, "Model:", modelRow());
        addRow(row++, "Max Tokens:", maxTokens);
        addRow(row++, "Azure API Version:", azureApiVersion);
        addRow(row++, "Ollama structured output:", ollamaStructured);
        addRow(row++, "Ollama context (num_ctx):", ollamaNumCtx);
        addRow(row++, "", testBtn);
        addRow(row++, "", statusLabel);
        addHelp(row++);

        providerCombo.addActionListener(e -> onProviderChanged());
        CommitListeners.onCommit(apiUrl, this::commitProviderFields);
        CommitListeners.onCommit(apiKey, this::commitProviderFields);
        modelCombo.addActionListener(e -> commitProviderFields());
        Component modelEditor = modelCombo.getEditor().getEditorComponent();
        modelEditor.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                commitProviderFields();
            }
        });
        CommitListeners.onCommit(maxTokens, this::commitGeneral);
        CommitListeners.onCommit(azureApiVersion, this::commitGeneral);
        CommitListeners.onCommit(ollamaNumCtx, this::commitGeneral);
        ollamaStructured.addActionListener(e -> commitGeneral());
        refreshBtn.addActionListener(e -> onRefreshModels());
        testBtn.addActionListener(e -> onTestConnection());
    }

    // ---- Load / commit ------------------------------------------------------

    /** Fill every field from the live settings (called each time the panel is shown). */
    public void load() {
        loading = true;
        try {
            providerCombo.setSelectedItem(settings.provider().displayName());
            showProviderFields(settings.provider());
            maxTokens.setText(Integer.toString(settings.maxTokens()));
            azureApiVersion.setText(settings.azureApiVersion());
            ollamaStructured.setSelectedItem(structuredToCombo(settings.ollamaStructuredOutput()));
            ollamaNumCtx.setText(Integer.toString(settings.ollamaNumCtx()));
        } finally {
            loading = false;
        }
        applyEnablement();
    }

    private void showProviderFields(ProviderId p) {
        ProviderConfig cfg = settings.config(p);
        shownProvider = p;
        apiUrl.setText(cfg.apiUrl().isBlank() ? p.defaultUrl() : cfg.apiUrl());
        apiKey.setText(cfg.apiKey());
        setModels(List.of());
        modelCombo.getEditor().setItem(cfg.model());
    }

    /** Store the URL/key/model fields into the provider they belong to. */
    private void commitProviderFields() {
        if (loading) {
            return;
        }
        ProviderConfig edited = new ProviderConfig(
                apiUrl.getText().trim(),
                new String(apiKey.getPassword()).trim(),
                currentModelText().trim());
        if (!edited.equals(settings.config(shownProvider))) {
            settings.setConfig(shownProvider, edited);
            save();
        }
    }

    private void commitGeneral() {
        if (loading) {
            return;
        }
        settings.setMaxTokens(CommitListeners.parseInt(maxTokens.getText(), settings.maxTokens()));
        settings.setAzureApiVersion(azureApiVersion.getText().trim());
        settings.setOllamaStructuredOutput(comboToStructured(ollamaStructured.getSelectedItem()));
        settings.setOllamaNumCtx(CommitListeners.parseInt(ollamaNumCtx.getText(), settings.ollamaNumCtx()));
        loading = true;
        try {
            // Show the clamped values actually in effect.
            maxTokens.setText(Integer.toString(settings.maxTokens()));
            ollamaNumCtx.setText(Integer.toString(settings.ollamaNumCtx()));
        } finally {
            loading = false;
        }
        save();
    }

    private void save() {
        persistence.save(settings);
        onChanged.run();
    }

    private static String structuredToCombo(Settings.StructuredOutput mode) {
        return switch (mode) {
            case SCHEMA -> "schema";
            case JSON -> "json";
            case OFF -> "off";
        };
    }

    private static Settings.StructuredOutput comboToStructured(Object sel) {
        String s = sel != null ? sel.toString() : "schema";
        return switch (s) {
            case "json" -> Settings.StructuredOutput.JSON;
            case "off" -> Settings.StructuredOutput.OFF;
            default -> Settings.StructuredOutput.SCHEMA;
        };
    }

    // ---- Handlers -----------------------------------------------------------

    private void onProviderChanged() {
        if (loading) {
            return;
        }
        commitProviderFields();    // keep anything typed for the provider being left
        ProviderId p = selectedProvider();
        settings.setProvider(p);
        loading = true;
        try {
            showProviderFields(p);
        } finally {
            loading = false;
        }
        applyEnablement();
        save();
    }

    private void applyEnablement() {
        ProviderId p = selectedProvider();
        boolean burpAi = p == ProviderId.BURP_AI;
        boolean azure = p == ProviderId.AZURE_FOUNDRY;
        boolean ollama = p == ProviderId.OLLAMA;

        apiUrl.setEnabled(!burpAi);
        apiKey.setEnabled(!burpAi && !ollama);
        modelCombo.setEnabled(!burpAi);
        refreshBtn.setEnabled(!burpAi && !azure);
        maxTokens.setEnabled(!burpAi);
        azureApiVersion.setEnabled(azure);
        ollamaStructured.setEnabled(ollama);   // local-model output-shape tuning
        ollamaNumCtx.setEnabled(ollama);

        if (burpAi) {
            statusLabel.setText("Burp AI uses your Burp AI credits; no API key needed.");
        } else {
            statusLabel.setText(" ");
        }
    }

    private void onRefreshModels() {
        commitProviderFields();
        commitGeneral();
        ProviderId p = shownProvider;
        statusLabel.setText("Loading models...");
        refreshBtn.setEnabled(false);
        boolean queued = threadPool.submitInteractive("model refresh", () -> {
            List<String> models = List.of();
            String failure = null;
            try {
                models = dispatcher.listModels(p);
            } catch (RuntimeException e) {
                failure = e.getClass().getSimpleName() + ": " + e.getMessage();
                logging.logToError("SILENTCHAIN: model refresh failed for " + p.displayName(), e);
            } finally {
                List<String> result = models;
                String message;
                if (failure != null) {
                    message = "FAILED: " + failure;
                } else if (result.isEmpty()) {
                    message = aiGate.isEnabled()
                            ? "No models returned (check URL / key)."
                            : "FAILED: " + AiGate.DISABLED_MESSAGE;
                } else {
                    message = result.size() + " models loaded.";
                }
                SwingUtilities.invokeLater(() -> {
                    if (p == shownProvider) {
                        setModels(result);
                    }
                    refreshBtn.setEnabled(true);
                    statusLabel.setText(message);
                });
            }
        });
        if (!queued) {
            refreshBtn.setEnabled(true);
            statusLabel.setText("Busy; try again in a moment.");
        }
    }

    private void onTestConnection() {
        commitProviderFields();
        commitGeneral();
        ProviderId p = shownProvider;
        statusLabel.setText("Testing " + p.displayName() + "...");
        testBtn.setEnabled(false);
        boolean queued = threadPool.submitInteractive("test connection", () -> {
            TestResult result = TestResult.fail("Test did not complete.");
            try {
                result = dispatcher.testConnection(p);
            } catch (RuntimeException e) {
                result = TestResult.fail(e.getClass().getSimpleName() + ": " + e.getMessage());
                logging.logToError("SILENTCHAIN: test connection failed for " + p.displayName(), e);
            } finally {
                TestResult shown = result;
                SwingUtilities.invokeLater(() -> {
                    testBtn.setEnabled(true);
                    statusLabel.setText((shown.success() ? "OK: " : "FAILED: ") + shown.message());
                });
            }
        });
        if (!queued) {
            testBtn.setEnabled(true);
            statusLabel.setText("Busy; try again in a moment.");
        }
    }

    // ---- Helpers ------------------------------------------------------------

    private ProviderId selectedProvider() {
        Object sel = providerCombo.getSelectedItem();
        return ProviderId.fromDisplayName(sel != null ? sel.toString() : "");
    }

    private void setModels(List<String> models) {
        boolean wasLoading = loading;
        loading = true;
        try {
            String current = currentModelText();
            DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
            for (String m : models) {
                model.addElement(m);
            }
            modelCombo.setModel(model);
            modelCombo.getEditor().setItem(current);
        } finally {
            loading = wasLoading;
        }
    }

    private String currentModelText() {
        Object m = modelCombo.getEditor().getItem();
        return m != null ? m.toString() : "";
    }

    private JComponent modelRow() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        p.add(modelCombo, c);
        c.gridx = 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        c.insets = new Insets(0, 6, 0, 0);
        p.add(refreshBtn, c);
        return p;
    }

    private void addRow(int row, String label, JComponent field) {
        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = row;
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(6, 8, 6, 8);
        add(new JLabel(label), lc);

        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1; fc.gridy = row;
        fc.anchor = GridBagConstraints.WEST;
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(6, 0, 6, 8);
        add(field, fc);
    }

    private void addHelp(int row) {
        JTextArea help = new JTextArea(
                "Provider notes (every provider, Ollama included, needs 'Use AI' enabled for\n" +
                "SILENTCHAIN in Extensions > Installed):\n" +
                "  - Burp AI: default; sent through Burp to PortSwigger's Burp AI service; uses\n" +
                "    Burp AI Credits; no key needed.\n" +
                "  - Ollama: default http://localhost:11434; no key. Uses /api/chat with a\n" +
                "    JSON schema forcing findings output. If a model returns no findings, raise\n" +
                "    'Ollama context (num_ctx)' or keep 'Ollama structured output' = schema.\n" +
                "  - OpenAI: https://api.openai.com/v1; Bearer API key.\n" +
                "  - Claude: https://api.anthropic.com/v1; x-api-key.\n" +
                "  - Gemini: https://generativelanguage.googleapis.com/v1; x-goog-api-key.\n" +
                "  - Azure Foundry: https://<resource>.openai.azure.com; api-key header;\n" +
                "    'Model' is the deployment name; set the API version.\n" +
                "Each provider keeps its own URL, key and model. Fields apply on Enter or\n" +
                "when you leave them.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(null);

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0; c.weighty = 1.0;
        c.insets = new Insets(10, 8, 8, 8);
        add(help, c);
    }
}
