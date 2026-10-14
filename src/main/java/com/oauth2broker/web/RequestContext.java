package com.oauth2broker.web;

/**
 * Per-request data, bound as a {@link ScopedValue} by {@link RequestIdFilter} for the whole request. Subtasks
 * forked in a {@link java.util.concurrent.StructuredTaskScope} inherit the binding.
 */
public record RequestContext(String requestId) {

    public static final ScopedValue<RequestContext> CURRENT = ScopedValue.newInstance();
}
