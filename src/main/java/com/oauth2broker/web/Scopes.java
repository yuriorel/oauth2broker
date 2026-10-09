package com.oauth2broker.web;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** The space-delimited {@code scope} parameter (RFC 6749 section 3.3). */
public final class Scopes {

    private Scopes() {
    }

    /** Parses a non-blank scope string, keeping the order and dropping duplicates. */
    public static Set<String> parse(String scope) {
        return Arrays.stream(scope.strip().split(" +")).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String format(Set<String> scope) {
        return String.join(" ", scope);
    }
}
