package com.sn1persecurity.silentchain.bapp.scan;

/** Whether the passive scan check could be registered with Burp Scanner. */
public enum ScannerStatus {
    /** Registered; Burp's live audit tasks and scans will call it. */
    REGISTERED,
    /** Burp Suite Community Edition: no Scanner and no AI, so the extension stays idle. */
    COMMUNITY_EDITION,
    /** Registration failed (see Extensions > Errors); right-click analysis still works. */
    FAILED
}
