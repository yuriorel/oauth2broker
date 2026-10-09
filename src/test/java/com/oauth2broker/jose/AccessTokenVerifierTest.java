package com.oauth2broker.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.web.OAuthException.InvalidToken;

class AccessTokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");

    private final TokenSigner signer = signer(TestKeys.signingKey(), TestProperties.create());
    private final AccessTokenVerifier verifier = verifier(NOW);
    private final String token = signer.accessToken("spa-app", "alice", Set.of("openid", "profile")).value();

    private static TokenSigner signer(SigningKey key, BrokerProperties properties) {
        try {
            return new TokenSigner(key, properties, Clock.fixed(NOW, ZoneOffset.UTC));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static AccessTokenVerifier verifier(Instant now) {
        try {
            return new AccessTokenVerifier(TestKeys.signingKey(), TestProperties.create(), Clock.fixed(now, ZoneOffset.UTC));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void assertRejected(AccessTokenVerifier verifier, String token, String message) {
        assertThatThrownBy(() -> verifier.verify(token)).isInstanceOf(InvalidToken.class).hasMessage(message);
    }

    @Test
    void acceptsValidToken() throws Exception {
        var claims = verifier.verify(token);

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getStringClaim("scope")).isEqualTo("openid profile");
        assertThat(claims.getJWTID()).isNotBlank();
    }

    @Test
    void rejectsExpiredToken() {
        assertRejected(verifier(NOW.plusSeconds(15 * 60)), token, "Access token has expired");
    }

    @Test
    void rejectsTamperedPayload() {
        var parts = token.split("\\.");
        var payload = new String(Base64.getUrlDecoder().decode(parts[1])).replace("alice", "bob00");
        var tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes())
                + "." + parts[2];

        assertRejected(verifier, tampered, "Access token signature is invalid");
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        var other = signer(TestKeys.generate(), TestProperties.create()).accessToken("spa-app", "alice", Set.of("openid"));

        assertRejected(verifier, other.value(), "Access token signature is invalid");
    }

    @Test
    void rejectsIdTokenUsedAsAccessToken() {
        var idToken = signer.idToken("spa-app", "alice", null, NOW, token);

        assertRejected(verifier, idToken, "Access token signature is invalid");
    }

    @Test
    void rejectsTokenFromAnotherIssuer() {
        var properties = TestProperties.create();
        var otherIssuer = new BrokerProperties("https://other.example", null, properties.ttl());
        var other = signer(TestKeys.signingKey(), otherIssuer).accessToken("spa-app", "alice", Set.of("openid"));

        assertRejected(verifier, other.value(), "Access token was not issued by this server");
    }

    @Test
    void rejectsMalformedToken() {
        assertRejected(verifier, "opaque-refresh-token", "Malformed access token");
    }
}
