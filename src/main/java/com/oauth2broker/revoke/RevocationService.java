package com.oauth2broker.revoke;

import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.StructuredTaskScope;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.client.ClientAuthenticator;
import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.token.TokenRepository;
import com.oauth2broker.web.RequestContext;
import com.oauth2broker.web.Subtasks;

/// Token revocation (RFC 7009). Client authentication and the token lookup run as parallel subtasks on virtual
/// threads. A token is deleted only if it belongs to the authenticated client; unknown tokens are ignored.
@Service
public class RevocationService {

    private static final Logger log = LoggerFactory.getLogger(RevocationService.class);

    private final ClientAuthenticator authenticator;
    private final TokenRepository tokens;

    public RevocationService(ClientAuthenticator authenticator, TokenRepository tokens) {
        this.authenticator = authenticator;
        this.tokens = tokens;
    }

    /// A token found in Redis, with the client it was issued to.
    private sealed interface Found {
        String clientId();
    }

    private record AccessToken(String jti, String clientId) implements Found {
    }

    private record RefreshToken(String token, String clientId) implements Found {
    }

    public void revoke(String token, String tokenTypeHint, ClientCredentials credentials) {
        log.debug("[{}] Revoking {} with hint {}", RequestContext.id(), token, tokenTypeHint);
        try (var scope = StructuredTaskScope.open()) {
            var client = scope.fork(() -> authenticator.authenticate(credentials));
            var found = scope.fork(() -> find(token, tokenTypeHint));
            Subtasks.join(scope);

            var clientId = client.get().clientId();
            switch (found.get().orElse(null)) {
                case null -> log.debug("[{}] Token unknown or expired, nothing to revoke", RequestContext.id());
                case Found f when !f.clientId().equals(clientId) ->
                        log.debug("[{}] {} was issued to another client, not revoked", RequestContext.id(), f);
                case AccessToken(var jti, _) -> {
                    tokens.deleteAccessToken(jti);
                    log.debug("[{}] Access token {} revoked", RequestContext.id(), jti);
                }
                case RefreshToken(var value, _) -> {
                    tokens.deleteRefreshToken(value);
                    log.debug("[{}] Refresh token {} revoked", RequestContext.id(), value);
                }
            }
        }
    }

    /// The hint only decides which lookup runs first (RFC 7009 section 2.1).
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

    /// The `jti` of a JWT; the signature is not needed because ownership is checked against the Redis record.
    private static Optional<String> jti(String token) {
        try {
            return Optional.ofNullable(SignedJWT.parse(token).getJWTClaimsSet().getJWTID());
        } catch (ParseException _) {
            return Optional.empty();
        }
    }
}
