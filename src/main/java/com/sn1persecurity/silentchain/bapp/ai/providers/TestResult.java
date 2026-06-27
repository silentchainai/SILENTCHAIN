package com.sn1persecurity.silentchain.bapp.ai.providers;

public record TestResult(boolean success, String message) {

    public static TestResult ok(String message) {
        return new TestResult(true, message);
    }

    public static TestResult fail(String message) {
        return new TestResult(false, message);
    }
}
