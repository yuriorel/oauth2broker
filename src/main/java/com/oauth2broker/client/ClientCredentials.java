package com.oauth2broker.client;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidRequest;

/** How a client authenticates at the token or revocation endpoint. */
public sealed interface ClientCredentials {

    String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** {@code client_secret_basic}: id and secret from the HTTP Basic header. */
    record SecretBasic(String clientId, String secret) implements ClientCredentials {
        @Override
        public String toString() {
            return "SecretBasic[clientId=" + clientId + "]";
        }
    }

    /** {@code private_key_jwt} (RFC 7523): a signed assertion; {@code clientId} is optional and may be null. */
    record PrivateKeyJwt(String clientId, String assertion) implements ClientCredentials {
    }

    /** {@code none}: a public client that only identifies itself. */
    record PublicClient(String clientId) implements ClientCredentials {
    }

    /** Picks the method from the request; using more than one is an error. */
    static ClientCredentials from(String authorization, String clientId, String assertionType, String assertion) {
        var basic = authorization != null && authorization.regionMatches(true, 0, "Basic ", 0, 6);
        if (basic && assertion != null) {
            throw new InvalidRequest("Use only one client authentication method");
        }
        if (basic) {
            return basic(authorization.substring(6).strip());
        }
        if (assertion != null) {
            if (!JWT_BEARER.equals(assertionType)) {
                throw new InvalidClient("client_assertion_type must be " + JWT_BEARER);
            }
            return new PrivateKeyJwt(clientId, assertion);
        }
        if (clientId != null) {
            return new PublicClient(clientId);
        }
        throw new InvalidClient("Client authentication is required");
    }

    /** RFC 6749 section 2.3.1: id and secret are form-encoded before they are joined and base64 encoded. */
    private static SecretBasic basic(String encoded) {
        try {
            var decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            var colon = decoded.indexOf(':');
            if (colon < 0) {
                throw new InvalidClient("Malformed Basic credentials");
            }
            return new SecretBasic(URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                    URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException _) {
            throw new InvalidClient("Malformed Basic credentials");
        }
    }
}
