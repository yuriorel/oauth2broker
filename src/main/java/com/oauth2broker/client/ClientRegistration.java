package com.oauth2broker.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A registered client. {@code clientSecretHash} is set only for {@code client_secret_basic},
 * {@code jwks} (a JWK Set as JSON) only for {@code private_key_jwt}.
 */
public record ClientRegistration(String clientId, AuthMethod tokenEndpointAuthMethod, String clientSecretHash,
                                 Map<String, Object> jwks, List<String> redirectUris, Set<String> scopes) {
}
