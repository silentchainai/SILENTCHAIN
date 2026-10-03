package com.sn1persecurity.silentchain.bapp.ai;

/**
 * Thrown by {@link AiDispatcher#analyze} when nothing was sent: AI is disabled
 * for the extension or the selected provider is not configured. Lets the
 * caller tell "not sent" (skip, not counted) from "sent, empty or failed".
 */
public class AiNotSentException extends RuntimeException {

    public AiNotSentException(String message) {
        super(message, null, false, false);
    }
}
