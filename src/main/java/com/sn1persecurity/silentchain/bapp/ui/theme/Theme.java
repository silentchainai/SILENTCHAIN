package com.sn1persecurity.silentchain.bapp.ui.theme;

import com.sn1persecurity.silentchain.bapp.config.Settings;

import java.awt.Color;

/**
 * Console color palettes ported from Community
 * (silentchain_ai_community.py:693-702) plus the brand accent colors used in
 * the header and control bar.
 */
public final class Theme {

    // Brand accents (Community)
    public static final Color ACCENT_ORANGE = new Color(0xD5, 0x59, 0x35); // edition label + Upgrade button
    public static final Color ACCENT_BLUE   = new Color(0x4D, 0x47, 0xAC); // Settings button
    public static final Color SCAN_GREEN    = new Color(0x00, 0x96, 0x00); // scanning active
    public static final Color SCAN_RED      = new Color(0xCC, 0x00, 0x00); // scanning inactive

    // Console — dark
    public static final Color CONSOLE_DARK_BG   = new Color(0x32, 0x33, 0x34);
    public static final Color CONSOLE_DARK_TEXT = new Color(0x7D, 0xA3, 0x58);

    // Console — light
    public static final Color CONSOLE_LIGHT_BG   = Color.WHITE;
    public static final Color CONSOLE_LIGHT_TEXT = new Color(0x36, 0x45, 0x4F);

    private Theme() {}

    public static Color consoleBackground(Settings.ThemeChoice theme) {
        return theme == Settings.ThemeChoice.DARK ? CONSOLE_DARK_BG : CONSOLE_LIGHT_BG;
    }

    public static Color consoleForeground(Settings.ThemeChoice theme) {
        return theme == Settings.ThemeChoice.DARK ? CONSOLE_DARK_TEXT : CONSOLE_LIGHT_TEXT;
    }
}
