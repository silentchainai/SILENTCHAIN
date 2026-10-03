package com.sn1persecurity.silentchain.bapp.ui.settings;

import javax.swing.JTextField;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

/**
 * Burp's Settings window has no OK/Cancel: values apply as they change. Text
 * fields commit on Enter or when focus leaves the field, never per keystroke,
 * so a half-typed URL or key is never used.
 */
final class CommitListeners {

    private CommitListeners() {}

    static void onCommit(JTextField field, Runnable commit) {
        field.addActionListener(e -> commit.run());
        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                commit.run();
            }
        });
    }

    static int parseInt(String s, int fallback) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
