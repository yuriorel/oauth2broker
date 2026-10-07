package com.oauth2broker.token;

import java.util.Set;

/** Server-side record of an issued access token, keyed by its {@code jti}. */
public record AccessTokenRecord(String clientId, String username, Set<String> scope) {
}
