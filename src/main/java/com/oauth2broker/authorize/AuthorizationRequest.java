package com.oauth2broker.authorize;

import java.util.Set;

/** A validated authorization request waiting for the user to sign in. */
public record AuthorizationRequest(String clientId, String redirectUri, Set<String> scope, String state,
                                   String nonce, String codeChallenge) {
}
