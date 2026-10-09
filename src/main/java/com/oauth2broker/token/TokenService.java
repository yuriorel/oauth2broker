package com.oauth2broker.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

import com.oauth2broker.authorize.AuthorizationCodeRepository;
import com.oauth2broker.client.ClientAuthenticator;
import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.jose.TokenSigner;
import com.oauth2broker.token.TokenRequest.AuthorizationCodeGrant;
import com.oauth2broker.token.TokenRequest.RefreshTokenGrant;
import com.oauth2broker.web.OAuthException.InvalidGrant;
import com.oauth2broker.web.OAuthException.InvalidScope;
import com.oauth2broker.web.Scopes;

/**
 * Redeems authorization codes and refresh tokens. Independent steps run as subtasks of a
 * {@link StructuredTaskScope}, each on its own virtual thread: client authentication runs alongside loading the
 * grant, and the new tokens are stored and signed in parallel.
 */
@Service
public class TokenService {

    private static final Pattern CODE_VERIFIER = Pattern.compile("[A-Za-z0-9._~-]{43,128}");

    private final ClientAuthenticator authenticator;
    private final AuthorizationCodeRepository codes;
    private final TokenRepository tokens;
    private final TokenSigner signer;
    private final long expiresIn;

    public TokenService(ClientAuthenticator authenticator, AuthorizationCodeRepository codes, TokenRepository tokens,
                        TokenSigner signer, BrokerProperties properties) {
        this.authenticator = authenticator;
        this.codes = codes;
        this.tokens = tokens;
        this.signer = signer;
        this.expiresIn = properties.ttl().accessToken().toSeconds();
    }

    public TokenResponse token(TokenRequest request, ClientCredentials credentials) {
        return switch (request) {
            case AuthorizationCodeGrant grant -> redeemCode(grant, credentials);
            case RefreshTokenGrant grant -> refresh(grant, credentials);
        };
    }

    /** The code is consumed even if a check below fails, so a failed attempt cannot be retried. */
    private TokenResponse redeemCode(AuthorizationCodeGrant grant, ClientCredentials credentials) {
        try (var scope = StructuredTaskScope.open()) {
            var client = scope.fork(() -> authenticator.authenticate(credentials));
            var redeemed = scope.fork(() -> codes.take(grant.code()));
            join(scope);

            var code = redeemed.get().orElseThrow(() -> new InvalidGrant("Authorization code is invalid or expired"));
            if (!code.clientId().equals(client.get().clientId())) {
                throw new InvalidGrant("Authorization code was issued to another client");
            }
            if (!code.redirectUri().equals(grant.redirectUri())) {
                throw new InvalidGrant("redirect_uri does not match the authorization request");
            }
            if (!pkceMatches(grant.codeVerifier(), code.codeChallenge())) {
                throw new InvalidGrant("code_verifier does not match the code_challenge");
            }
            var idToken = code.scope().contains("openid") ? new IdTokenClaims(code.nonce(), code.authTime()) : null;
            return issue(code.clientId(), code.username(), code.scope(), code.scope(), idToken);
        }
    }

    /** The refresh token is rotated: the old one is deleted and a new one with the original scope is issued. */
    private TokenResponse refresh(RefreshTokenGrant grant, ClientCredentials credentials) {
        try (var scope = StructuredTaskScope.open()) {
            var client = scope.fork(() -> authenticator.authenticate(credentials));
            var found = scope.fork(() -> tokens.findRefreshToken(grant.refreshToken()));
            join(scope);

            var record = found.get().orElseThrow(() -> new InvalidGrant("Refresh token is invalid or expired"));
            if (!record.clientId().equals(client.get().clientId())) {
                throw new InvalidGrant("Refresh token was issued to another client");
            }
            var requested = grant.scope() == null || grant.scope().isBlank()
                    ? record.scope() : Scopes.parse(grant.scope());
            if (!record.scope().containsAll(requested)) {
                throw new InvalidScope("scope exceeds the originally granted scope");
            }
            // GETDEL: of two concurrent requests with the same token, only one gets the record.
            if (tokens.takeRefreshToken(grant.refreshToken()).isEmpty()) {
                throw new InvalidGrant("Refresh token is invalid or expired");
            }
            return issue(record.clientId(), record.username(), requested, record.scope(), null);
        }
    }

    private record IdTokenClaims(String nonce, Instant authTime) {
    }

    /** Signs the access token, then stores both tokens and signs the ID token in parallel. */
    private TokenResponse issue(String clientId, String username, Set<String> scope, Set<String> grantedScope,
                                IdTokenClaims idTokenClaims) {
        var accessToken = signer.accessToken(clientId, username, scope);
        try (var tasks = StructuredTaskScope.open()) {
            tasks.fork(() -> tokens.saveAccessToken(accessToken.jti(),
                    new AccessTokenRecord(clientId, username, scope)));
            var refreshToken = tasks.fork(() -> tokens.saveRefreshToken(
                    new RefreshTokenRecord(clientId, username, grantedScope)));
            Subtask<String> idToken = idTokenClaims == null ? null : tasks.fork(() -> signer.idToken(
                    clientId, username, idTokenClaims.nonce(), idTokenClaims.authTime(), accessToken.value()));
            join(tasks);
            return new TokenResponse(accessToken.value(), "Bearer", expiresIn, refreshToken.get(),
                    idToken == null ? null : idToken.get(), Scopes.format(scope));
        }
    }

    /** Waits for all subtasks; if one fails, the others are cancelled and its exception is rethrown as is. */
    private static void join(StructuredTaskScope<?, ?> scope) {
        try {
            scope.join();
        } catch (StructuredTaskScope.FailedException e) {
            throw e.getCause() instanceof RuntimeException cause ? cause : e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** RFC 7636 section 4.6: BASE64URL(SHA256(code_verifier)) must equal the stored S256 challenge. */
    static boolean pkceMatches(String verifier, String challenge) {
        if (!CODE_VERIFIER.matcher(verifier).matches()) {
            return false;
        }
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            var computed = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return MessageDigest.isEqual(computed.getBytes(StandardCharsets.US_ASCII),
                    challenge.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
