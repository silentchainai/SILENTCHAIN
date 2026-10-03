package com.sn1persecurity.silentchain.bapp.testutil;

import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;

import java.util.Map;
import java.util.function.Function;

/**
 * Montoya's static factories (HttpRequest.httpRequestFromUrl, RequestOptions.requestOptions,
 * AuditResult.auditResult, AuditIssue.auditIssue...) delegate to a factory that Burp installs
 * at runtime. Tests install a {@link DeepStub} instead and restore the previous one afterwards.
 * (ObjectFactoryLocator is Montoya-internal; used by tests only.)
 */
public final class MontoyaFactoryStub implements AutoCloseable {

    private final MontoyaObjectFactory previous;

    private MontoyaFactoryStub(Map<String, Function<Object[], Object>> overrides) {
        previous = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = DeepStub.of(MontoyaObjectFactory.class, overrides);
    }

    public static MontoyaFactoryStub install() {
        return new MontoyaFactoryStub(Map.of());
    }

    public static MontoyaFactoryStub install(Map<String, Function<Object[], Object>> overrides) {
        return new MontoyaFactoryStub(overrides);
    }

    @Override
    public void close() {
        ObjectFactoryLocator.FACTORY = previous;
    }
}
