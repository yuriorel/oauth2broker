package com.oauth2broker.authorize;

import java.time.Instant;
import java.util.Set;

/** What an issued authorization code stands for, redeemed once at the token endpoint. */
public record AuthorizationCode(String clientId, String redirectUri, String username, Set<String> scope,
                                String nonce, String codeChallenge, Instant authTime) {
}
