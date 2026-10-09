package com.oauth2broker.token;

import com.oauth2broker.web.OAuthException.InvalidRequest;
import com.oauth2broker.web.OAuthException.UnsupportedGrantType;

/** A token endpoint request, one record per supported grant. */
public sealed interface TokenRequest {

    record AuthorizationCodeGrant(String code, String redirectUri, String codeVerifier) implements TokenRequest {
    }

    /** {@code scope} is null when the client keeps the original scope. */
    record RefreshTokenGrant(String refreshToken, String scope) implements TokenRequest {
    }

    static TokenRequest of(String grantType, String code, String redirectUri, String codeVerifier,
                           String refreshToken, String scope) {
        return switch (grantType) {
            case null -> throw new InvalidRequest("grant_type is required");
            case "authorization_code" -> new AuthorizationCodeGrant(required("code", code),
                    required("redirect_uri", redirectUri), required("code_verifier", codeVerifier));
            case "refresh_token" -> new RefreshTokenGrant(required("refresh_token", refreshToken), scope);
            default -> throw new UnsupportedGrantType("Supported grant types: authorization_code, refresh_token");
        };
    }

    private static String required(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new InvalidRequest(name + " is required");
        }
        return value;
    }
}
