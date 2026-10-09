package com.oauth2broker.revoke;

import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.StructuredTaskScope;

import org.springframework.stereotype.Service;

import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.client.ClientAuthenticator;
import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.token.TokenRepository;
import com.oauth2broker.web.Subtasks;

/**
 * Token revocation (RFC 7009). Client authentication and the token lookup run as parallel subtasks on virtual
 * threads. A token is deleted only if it belongs to the authenticated client; unknown tokens are ignored.
 */
@Service
public class RevocationService {

    private final ClientAuthenticator authenticator;
    private final TokenRepository tokens;

    public RevocationService(ClientAuthenticator authenticator, TokenRepository tokens) {
        this.authenticator = authenticator;
        this.tokens = tokens;
    }

    /** A token found in Redis, with the client it was issued to. */
    private sealed interface Found {
        String clientId();
    }

    private record AccessToken(String jti, String clientId) implements Found {
    }

    private record RefreshToken(String token, String clientId) implements Found {
    }

    public void revoke(String token, String tokenTypeHint, ClientCredentials credentials) {
        try (var scope = StructuredTaskScope.open()) {
            var client = scope.fork(() -> authenticator.authenticate(credentials));
            var found = scope.fork(() -> find(token, tokenTypeHint));
            Subtasks.join(scope);

            found.get().filter(f -> f.clientId().equals(client.get().clientId())).ifPresent(f -> {
                switch (f) {
                    case AccessToken(var jti, _) -> tokens.deleteAccessToken(jti);
                    case RefreshToken(var value, _) -> tokens.deleteRefreshToken(value);
                }
            });
        }
    }

    /** The hint only decides which lookup runs first (RFC 7009 section 2.1). */
    private Optional<Found> find(String token, String tokenTypeHint) {
        return "refresh_token".equals(tokenTypeHint)
                ? findRefreshToken(token).or(() -> findAccessToken(token))
                : findAccessToken(token).or(() -> findRefreshToken(token));
    }

    private Optional<Found> findAccessToken(String token) {
        return jti(token).flatMap(jti -> tokens.findAccessToken(jti).map(record -> new AccessToken(jti, record.clientId())));
    }

    private Optional<Found> findRefreshToken(String token) {
        return tokens.findRefreshToken(token).map(record -> new RefreshToken(token, record.clientId()));
    }

    /** The {@code jti} of a JWT; the signature is not needed because ownership is checked against the Redis record. */
    private static Optional<String> jti(String token) {
        try {
            return Optional.ofNullable(SignedJWT.parse(token).getJWTClaimsSet().getJWTID());
        } catch (ParseException _) {
            return Optional.empty();
        }
    }
}
