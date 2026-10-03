package com.sn1persecurity.silentchain.bapp.testutil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Minimal reflection-based stub for Montoya interfaces (no mocking library).
 *
 * Every method returns a harmless default: false / 0 / "" / empty collections /
 * Optional.empty(), the stub itself for fluent methods returning the same
 * interface, and a nested DeepStub (cached per method) for any other interface.
 * Behaviour is customised by method NAME through {@code overrides}, which are
 * inherited by nested stubs, so e.g. {@code "sendRequest"} can be counted no
 * matter how deep {@code api.http().sendRequest(...)} sits.
 */
public final class DeepStub implements InvocationHandler {

    private final Class<?> type;
    private final Map<String, Function<Object[], Object>> overrides;
    private final Map<Method, Object> children = new ConcurrentHashMap<>();
    private Object self;

    private DeepStub(Class<?> type, Map<String, Function<Object[], Object>> overrides) {
        this.type = type;
        this.overrides = overrides;
    }

    public static <T> T of(Class<T> type) {
        return of(type, Map.of());
    }

    public static <T> T of(Class<T> type, Map<String, Function<Object[], Object>> overrides) {
        DeepStub handler = new DeepStub(type, overrides);
        T proxy = type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
        handler.self = proxy;
        return proxy;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (method.getDeclaringClass() == Object.class) {
            return switch (name) {
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                default -> "DeepStub<" + type.getSimpleName() + ">";
            };
        }
        Function<Object[], Object> override = overrides.get(name);
        if (override != null) {
            return override.apply(args != null ? args : new Object[0]);
        }
        if (method.isDefault()) {
            return InvocationHandler.invokeDefault(proxy, method, args);
        }
        return defaultValue(method);
    }

    private Object defaultValue(Method method) {
        Class<?> r = method.getReturnType();
        if (r == void.class) return null;
        if (r == boolean.class) return false;
        if (r == int.class) return 0;
        if (r == long.class) return 0L;
        if (r == short.class) return (short) 0;
        if (r == byte.class) return (byte) 0;
        if (r == double.class) return 0.0d;
        if (r == float.class) return 0.0f;
        if (r == char.class) return '\0';
        if (r == String.class) return "";
        if (r == Optional.class) return Optional.empty();
        if (r == List.class || r == Collection.class) return List.of();
        if (r == Set.class) return Set.of();
        if (r == Map.class) return Map.of();
        if (r == type) return self;
        if (r.isInterface()) {
            return children.computeIfAbsent(method, m -> of(r, overrides));
        }
        return null;
    }
}
