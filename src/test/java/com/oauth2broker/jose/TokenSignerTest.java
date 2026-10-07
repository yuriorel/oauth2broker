package com.oauth2broker.jose;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;

class TokenSignerTest {

    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
    private static final String ISSUER = TestProperties.ISSUER;

    private final SigningKey key = TestKeys.signingKey();
    private final TokenSigner signer = newSigner();

    @Test
    void accessTokenIsAnRfc9068JwtThatVerifiesWithThePublishedJwks() throws Exception {
        var token = signer.accessToken("web-app", "alice", Set.of("openid"));

        var jwt = verifiedWithPublishedKey(token.value());
        assertThat(jwt.getHeader().getType()).isEqualTo(new JOSEObjectType("at+jwt"));
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.keyId());
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getAudience()).containsExactly(ISSUER);
        assertThat(claims.getStringClaim("client_id")).isEqualTo("web-app");
        assertThat(claims.getStringClaim("scope")).isEqualTo("openid");
        assertThat(claims.getIssueTime()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(NOW.plus(Duration.ofMinutes(15))));
        assertThat(claims.getJWTID()).isEqualTo(token.jti());
        assertThat(token.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
    }

    @Test
    void accessTokenScopeIsSpaceSeparated() throws Exception {
        var token = signer.accessToken("web-app", "alice", Set.of("openid", "profile", "email"));

        var scope = SignedJWT.parse(token.value()).getJWTClaimsSet().getStringClaim("scope");
        assertThat(List.of(scope.split(" "))).containsExactlyInAnyOrder("openid", "profile", "email");
    }

    @Test
    void eachAccessTokenHasItsOwnJti() {
        var first = signer.accessToken("web-app", "alice", Set.of("openid"));
        var second = signer.accessToken("web-app", "alice", Set.of("openid"));

        assertThat(first.jti()).isNotEqualTo(second.jti());
    }

    @Test
    void idTokenHasOidcClaims() throws Exception {
        var authTime = NOW.minusSeconds(30);
        var accessToken = signer.accessToken("web-app", "alice", Set.of("openid")).value();

        var jwt = verifiedWithPublishedKey(signer.idToken("web-app", "alice", "n-0S6", authTime, accessToken));

        assertThat(jwt.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.keyId());
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getAudience()).containsExactly("web-app");
        assertThat(claims.getIssueTime()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(NOW.plus(Duration.ofMinutes(15))));
        assertThat(claims.getLongClaim("auth_time")).isEqualTo(authTime.getEpochSecond());
        assertThat(claims.getStringClaim("nonce")).isEqualTo("n-0S6");
        assertThat(claims.getStringClaim("at_hash")).isEqualTo(TokenSigner.atHash(accessToken));
    }

    @Test
    void idTokenWithoutNonceOmitsTheClaim() throws Exception {
        var jwt = SignedJWT.parse(signer.idToken("web-app", "alice", null, NOW, "token"));

        assertThat(jwt.getJWTClaimsSet().getClaims()).doesNotContainKey("nonce");
    }

    @Test
    void atHashMatchesTheOpenIdConnectExample() {
        // OpenID Connect Core 1.0, Appendix A.4
        assertThat(TokenSigner.atHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"))
                .isEqualTo("77QmUPtjPfzWtF2AnpK9RQ");
    }

    @Test
    void tokenSignedWithAnotherKeyDoesNotVerify() throws Exception {
        var forged = new TokenSigner(TestKeys.generate(), TestProperties.create(), Clock.fixed(NOW, ZoneOffset.UTC))
                .accessToken("web-app", "alice", Set.of("openid"));

        assertThat(SignedJWT.parse(forged.value()).verify(new RSASSAVerifier(key.jwk().toRSAPublicKey()))).isFalse();
    }

    private SignedJWT verifiedWithPublishedKey(String token) throws Exception {
        var jwt = SignedJWT.parse(token);
        var published = (RSAKey) key.publicJwkSet().getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(published))).isTrue();
        return jwt;
    }

    private TokenSigner newSigner() {
        try {
            return new TokenSigner(key, TestProperties.create(), Clock.fixed(NOW, ZoneOffset.UTC));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
