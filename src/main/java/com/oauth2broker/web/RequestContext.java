package com.oauth2broker.web;

/// Per-request data, bound as a [ScopedValue] by [RequestIdFilter] for the whole request. Subtasks
/// forked in a [java.util.concurrent.StructuredTaskScope] inherit the binding.
public record RequestContext(String requestId) {

    public static final ScopedValue<RequestContext> CURRENT = ScopedValue.newInstance();

    /// The current request id, or `-` outside a request (for example while seeding at startup). Every debug log
    /// line starts with it.
    public static String id() {
        return CURRENT.isBound() ? CURRENT.get().requestId() : "-";
    }
}
