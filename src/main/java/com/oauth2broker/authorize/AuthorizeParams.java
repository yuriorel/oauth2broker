package com.oauth2broker.authorize;

/** Query parameters of an authorization request, as sent. Any of them may be null. */
public record AuthorizeParams(String responseType, String clientId, String redirectUri, String scope, String state,
                              String nonce, String codeChallenge, String codeChallengeMethod) {
}
