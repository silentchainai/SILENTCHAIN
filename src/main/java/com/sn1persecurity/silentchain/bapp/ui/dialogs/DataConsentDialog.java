package com.sn1persecurity.silentchain.bapp.ui.dialogs;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.config.SettingsPersistence;

import javax.swing.JEditorPane;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;

/**
 * Data Handling Consent modal shown the first time passive AI analysis is
 * enabled. Merges the Community consent text (silentchain_ai_community.py:
 * 1178-1241) with an AI Credits paragraph for the Burp AI provider.
 *
 * Replaces the Phase-4 FirstRunDialog.
 */
public final class DataConsentDialog {

    private static final String TITLE = "SILENTCHAIN — Data Handling Consent";

    private static final String BODY =
            "<html><body style='margin:4px;'>" +
            "<p><b>Enabling AI analysis sends portions of intercepted HTTP traffic " +
            "to the AI provider you have configured.</b></p>" +

            "<p><b>Burp AI (default provider):</b> traffic is analyzed in-process by " +
            "PortSwigger's Burp AI service under PortSwigger's data-handling terms. " +
            "Each analysis consumes <b>Burp AI Credits</b> from your account; usage " +
            "varies with request and response size.</p>" +

            "<p><b>Third-party providers (Ollama / OpenAI / Claude / Gemini / Azure " +
            "Foundry):</b> if you select one of these, request and response content is " +
            "transmitted to that provider's endpoint (Ollama is local-only). Billing, " +
            "data retention, and privacy are governed by that provider's terms.</p>" +

            "<p><b>Regulated data:</b> do not submit data subject to HIPAA, PCI-DSS, " +
            "GDPR, or similar regimes to a cloud AI provider without an appropriate " +
            "data-processing agreement. Prefer a local provider (Ollama) for such data.</p>" +

            "<p><b>Sanitization:</b> SILENTCHAIN redacts common secrets and PII " +
            "(API keys, bearer tokens, session cookies, emails) and neutralizes " +
            "prompt-injection patterns before content is sent. Sanitization is not a " +
            "guarantee; review your scope and data classification first.</p>" +

            "<p>Safety rails (in-scope-only, per-host rate limit, URL dedup, response " +
            "size cap) bound how much is sent. You can adjust them in the Advanced tab.</p>" +

            "<p><b>Do you acknowledge the above and want to enable AI analysis?</b></p>" +
            "</body></html>";

    private DataConsentDialog() {}

    /**
     * Returns true if the user has already acknowledged, or acknowledges now.
     * Persists the acknowledgement so the modal shows only once.
     */
    public static boolean ensureConsent(MontoyaApi api, SettingsPersistence persistence) {
        if (persistence.firstRunAcknowledged()) {
            return true;
        }
        Component parent = api.userInterface().swingUtils().suiteFrame();
        Object[] options = {"Acknowledge and enable", "Cancel"};
        int choice = JOptionPane.showOptionDialog(
                parent, buildMessage(), TITLE,
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE,
                null, options, options[1]);
        boolean accepted = choice == 0;
        if (accepted) {
            persistence.setFirstRunAcknowledged(true);
        }
        return accepted;
    }

    /**
     * Renders the consent body in a bounded, scrollable HTML pane rather than
     * handing the raw markup to JOptionPane as a String. A String message is
     * "burst" on spaces into per-line JLabels by BasicOptionPaneUI once it
     * exceeds the L&F's OptionPane.maxCharactersPerLineCount (FlatLaf sets a
     * finite value), which defeats JLabel's leading-"<html>" auto-detection —
     * the markup then renders as literal tags and the dialog grows wider than
     * the screen. A Component message is used verbatim with no bursting, and a
     * JEditorPane always parses text/html, so the markup can never show raw.
     */
    private static Component buildMessage() {
        JEditorPane editor = new JEditorPane();
        editor.setEditable(false);
        editor.setContentType("text/html");
        // Make the HTML inherit the L&F font + foreground so it matches Burp's
        // theme (incl. dark mode) instead of the JEditorPane black-on-default.
        editor.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        Font font = UIManager.getFont("OptionPane.messageFont");
        if (font == null) {
            font = UIManager.getFont("Label.font");
        }
        if (font != null) {
            editor.setFont(font);
        }
        Color fg = UIManager.getColor("OptionPane.messageForeground");
        if (fg == null) {
            fg = UIManager.getColor("Label.foreground");
        }
        if (fg != null) {
            editor.setForeground(fg);
        }
        editor.setOpaque(false);             // inherit the dialog background
        editor.setText(BODY);
        editor.setCaretPosition(0);          // show the top, not auto-scrolled

        JScrollPane scroll = new JScrollPane(
                editor,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        // Fixed bound: the dialog can never exceed this; taller content scrolls.
        // No horizontal scrollbar means the HTML wraps to the viewport width.
        scroll.setPreferredSize(new Dimension(520, 460));
        return scroll;
    }
}
