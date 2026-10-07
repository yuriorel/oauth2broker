package com.oauth2broker.jose;

import java.time.Instant;

/** A signed access token JWT with the values the token endpoint needs to record it. */
public record SignedAccessToken(String value, String jti, Instant expiresAt) {
}
