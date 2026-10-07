package com.oauth2broker.token;

import java.util.Set;

/** Server-side record of an issued refresh token, keyed by the token's SHA-256 hash. */
public record RefreshTokenRecord(String clientId, String username, Set<String> scope) {
}
