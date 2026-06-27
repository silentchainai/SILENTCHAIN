package com.sn1persecurity.silentchain.bapp.ui.settings;

import com.sn1persecurity.silentchain.bapp.ai.AiDispatcher;
import com.sn1persecurity.silentchain.bapp.ai.providers.ProviderId;
import com.sn1persecurity.silentchain.bapp.ai.providers.TestResult;
import com.sn1persecurity.silentchain.bapp.config.Settings;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;

/**
 * AI Provider configuration tab — mirrors Community's "AI Provider" settings
 * tab (silentchain_ai_community.py:1322-1504) but with Burp AI added as the
 * default provider.
 *
 * When Burp AI is selected, the third-party fields (URL / key / model /
 * max-tokens / azure-version) are disabled because Burp AI runs in-process.
 */
public class AiProviderTab extends JPanel {

    private final Settings settings;
    private final AiDispatcher dispatcher;

    private final JComboBox<String> providerCombo = new JComboBox<>();
    private final JTextField apiUrl = new JTextField(30);
    private final JPasswordField apiKey = new JPasswordField(30);
    private final JComboBox<String> modelCombo = new JComboBox<>();
    private final JButton refreshBtn = new JButton("Refresh");
    private final JTextField maxTokens = new JTextField(8);
    private final JTextField azureApiVersion = new JTextField(16);
    private final JButton testBtn = new JButton("Test Connection");
    private final JLabel statusLabel = new JLabel(" ");

    public AiProviderTab(Settings settings, AiDispatcher dispatcher) {
        this.settings = settings;
        this.dispatcher = dispatcher;

        setLayout(new GridBagLayout());
        modelCombo.setEditable(true);

        for (ProviderId p : ProviderId.values()) {
            providerCombo.addItem(p.displayName());
        }

        int row = 0;
        addRow(row++, "AI Provider:", providerCombo);
        addRow(row++, "API URL:", apiUrl);
        addRow(row++, "API Key:", apiKey);
        addRow(row++, "Model:", modelRow());
        addRow(row++, "Max Tokens:", maxTokens);
        addRow(row++, "Azure API Version:", azureApiVersion);
        addRow(row++, "", testBtn);
        addRow(row++, "", statusLabel);
        addHelp(row++);

        providerCombo.addActionListener(e -> onProviderChanged());
        refreshBtn.addActionListener(e -> onRefreshModels());
        testBtn.addActionListener(e -> onTestConnection());
    }

    // ---- Load / store -------------------------------------------------------

    public void load() {
        providerCombo.setSelectedItem(settings.provider().displayName());
        apiUrl.setText(settings.apiUrl());
        apiKey.setText(settings.apiKey());
        setModel(settings.model());
        maxTokens.setText(Integer.toString(settings.maxTokens()));
        azureApiVersion.setText(settings.azureApiVersion());
        applyEnablement();
    }

    public void store() {
        settings.setProvider(selectedProvider());
        settings.setApiUrl(apiUrl.getText().trim());
        settings.setApiKey(new String(apiKey.getPassword()));
        Object m = modelCombo.getEditor().getItem();
        settings.setModel(m != null ? m.toString().trim() : "");
        settings.setMaxTokens(parseInt(maxTokens.getText(), settings.maxTokens()));
        settings.setAzureApiVersion(azureApiVersion.getText().trim());
    }

    // ---- Handlers -----------------------------------------------------------

    private void onProviderChanged() {
        ProviderId p = selectedProvider();
        // Auto-fill the default URL when the field is empty or held a different
        // provider's default (mirrors Community lines 1341-1370).
        String current = apiUrl.getText().trim();
        if (current.isEmpty() || isAnyProviderDefault(current)) {
            apiUrl.setText(p.defaultUrl());
        }
        applyEnablement();
    }

    private void applyEnablement() {
        ProviderId p = selectedProvider();
        boolean burpAi = p == ProviderId.BURP_AI;
        boolean azure = p == ProviderId.AZURE_FOUNDRY;

        apiUrl.setEnabled(!burpAi);
        apiKey.setEnabled(!burpAi && p != ProviderId.OLLAMA);
        modelCombo.setEnabled(!burpAi);
        refreshBtn.setEnabled(!burpAi && !azure);
        maxTokens.setEnabled(!burpAi);
        azureApiVersion.setEnabled(azure);

        if (burpAi) {
            statusLabel.setText("Burp AI runs in-process and uses your Burp AI Credits.");
        } else {
            statusLabel.setText(" ");
        }
    }

    private void onRefreshModels() {
        store();
        ProviderId p = selectedProvider();
        statusLabel.setText("Loading models...");
        refreshBtn.setEnabled(false);
        new Thread(() -> {
            List<String> models = dispatcher.get(p).listModels();
            SwingUtilities.invokeLater(() -> {
                setModels(models);
                refreshBtn.setEnabled(true);
                statusLabel.setText(models.isEmpty()
                        ? "No models returned (check URL / key)."
                        : models.size() + " models loaded.");
            });
        }, "silentchain-models").start();
    }

    private void onTestConnection() {
        store();
        ProviderId p = selectedProvider();
        statusLabel.setText("Testing " + p.displayName() + "...");
        testBtn.setEnabled(false);
        new Thread(() -> {
            TestResult result = dispatcher.testConnection(p);
            SwingUtilities.invokeLater(() -> {
                testBtn.setEnabled(true);
                statusLabel.setText((result.success() ? "OK: " : "FAILED: ") + result.message());
            });
        }, "silentchain-test").start();
    }

    // ---- Helpers ------------------------------------------------------------

    private ProviderId selectedProvider() {
        Object sel = providerCombo.getSelectedItem();
        return ProviderId.fromDisplayName(sel != null ? sel.toString() : "");
    }

    private void setModels(List<String> models) {
        String current = currentModelText();
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        for (String m : models) {
            model.addElement(m);
        }
        modelCombo.setModel(model);
        modelCombo.getEditor().setItem(current);
    }

    private void setModel(String value) {
        modelCombo.getEditor().setItem(value != null ? value : "");
    }

    private String currentModelText() {
        Object m = modelCombo.getEditor().getItem();
        return m != null ? m.toString() : "";
    }

    private static boolean isAnyProviderDefault(String url) {
        for (ProviderId p : ProviderId.values()) {
            if (!p.defaultUrl().isEmpty() && p.defaultUrl().equals(url)) {
                return true;
            }
        }
        return false;
    }

    private static int parseInt(String s, int fallback) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
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
                "Provider notes:\n" +
                "  - Burp AI: default; in-process; uses Burp AI Credits; no key needed.\n" +
                "  - Ollama: local; default http://localhost:11434; no key.\n" +
                "  - OpenAI: https://api.openai.com/v1; Bearer API key.\n" +
                "  - Claude: https://api.anthropic.com/v1; x-api-key.\n" +
                "  - Gemini: https://generativelanguage.googleapis.com/v1; key in query.\n" +
                "  - Azure Foundry: https://<resource>.openai.azure.com; api-key header;\n" +
                "    'Model' is the deployment name; set the API version.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(null);

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0; c.weighty = 1.0;
        c.insets = new Insets(10, 8, 8, 8);
        add(new JScrollPane(help), c);
    }
}
