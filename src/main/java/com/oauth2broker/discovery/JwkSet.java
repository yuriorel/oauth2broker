package com.oauth2broker.discovery;

import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;

/** A JWK Set (RFC 7517 section 5). */
public record JwkSet(@Schema(description = "Public JWKs (kty, kid, use, alg, n, e)") List<Map<String, Object>> keys) {
}
