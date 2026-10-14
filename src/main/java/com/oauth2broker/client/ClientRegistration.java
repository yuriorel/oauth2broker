package com.oauth2broker.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

/// A registered client. `clientSecretHash` is set only for `client_secret_basic`,
/// `jwks` (a JWK Set as JSON) only for `private_key_jwt`.
public record ClientRegistration(String clientId, AuthMethod tokenEndpointAuthMethod, String clientSecretHash,
                                 Map<String, Object> jwks, List<String> redirectUris, Set<String> scopes) {
}
