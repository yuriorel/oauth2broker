package com.oauth2broker.web;

import java.util.concurrent.StructuredTaskScope;

/** Helpers for {@link StructuredTaskScope}. */
public final class Subtasks {

    private Subtasks() {
    }

    /** Waits for all subtasks; if one fails, the others are cancelled and its exception is rethrown as is. */
    public static void join(StructuredTaskScope<?, ?> scope) {
        try {
            scope.join();
        } catch (StructuredTaskScope.FailedException e) {
            throw e.getCause() instanceof RuntimeException cause ? cause : e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
