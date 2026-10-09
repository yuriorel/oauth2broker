package com.oauth2broker.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.ClientAssertions;
import com.oauth2broker.TestProperties;
import com.oauth2broker.client.ClientCredentials.PrivateKeyJwt;
import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientCredentials.SecretBasic;
import com.oauth2broker.web.OAuthException.InvalidClient;

class ClientAuthenticatorTest {

    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final BCryptPasswordEncoder BCRYPT = new BCryptPasswordEncoder(4);
    private static final List<String> CALLBACKS = List.of("http://localhost:8080/callback");
    private static final Set<String> SCOPES = Set.of("openid");

    private final ClientRepository clients = mock(ClientRepository.class);
    private final AssertionReplayRepository replay = mock(AssertionReplayRepository.class);
    private final ClientAuthenticator authenticator = new ClientAuthenticator(clients, replay, BCRYPT,
            TestProperties.create(), Clock.fixed(NOW, ZoneOffset.UTC));

    private final ClientRegistration webApp = new ClientRegistration("web-app", AuthMethod.CLIENT_SECRET_BASIC,
            BCRYPT.encode("web-app-secret"), null, CALLBACKS, SCOPES);
    private final ClientRegistration jwtApp = jwtClient("jwt-app", new JWKSet(ClientAssertions.jwtAppKey().toPublicJWK()));
    private final ClientRegistration spaApp = new ClientRegistration("spa-app", AuthMethod.NONE, null, null,
            CALLBACKS, SCOPES);

    private static ClientRegistration jwtClient(String clientId, JWKSet jwks) {
        return new ClientRegistration(clientId, AuthMethod.PRIVATE_KEY_JWT, null, jwks.toJSONObject(), CALLBACKS,
                SCOPES);
    }

    @BeforeEach
    void setUp() {
        when(clients.find(anyString())).thenReturn(Optional.empty());
        when(clients.find("web-app")).thenReturn(Optional.of(webApp));
        when(clients.find("jwt-app")).thenReturn(Optional.of(jwtApp));
        when(clients.find("spa-app")).thenReturn(Optional.of(spaApp));
        when(replay.markUsed(anyString(), anyString(), any())).thenReturn(true);
    }

    private void assertRejected(ClientCredentials credentials, String message) {
        assertThatThrownBy(() -> authenticator.authenticate(credentials))
                .isInstanceOf(InvalidClient.class).hasMessage(message);
    }

    @Test
    void secretBasicWithCorrectSecret() {
        assertThat(authenticator.authenticate(new SecretBasic("web-app", "web-app-secret"))).isEqualTo(webApp);
    }

    @Test
    void secretBasicWithWrongSecretOrUnknownClient() {
        assertRejected(new SecretBasic("web-app", "wrong"), "Client authentication failed");
        assertRejected(new SecretBasic("nobody", "web-app-secret"), "Client authentication failed");
    }

    @Test
    void methodMustMatchRegistration() {
        assertRejected(new PublicClient("web-app"), "Client authentication failed");
        assertRejected(new SecretBasic("spa-app", "x"), "Client authentication failed");
        assertRejected(new PublicClient("jwt-app"), "Client authentication failed");
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .issuer("web-app").subject("web-app").build())), "Client authentication failed");
    }

    @Test
    void publicClient() {
        assertThat(authenticator.authenticate(new PublicClient("spa-app"))).isEqualTo(spaApp);
        assertRejected(new PublicClient("nobody"), "Client authentication failed");
    }

    @Test
    void privateKeyJwtWithValidRs256Assertion() {
        var claims = ClientAssertions.claims(NOW).build();

        assertThat(authenticator.authenticate(new PrivateKeyJwt("jwt-app", ClientAssertions.sign(claims))))
                .isEqualTo(jwtApp);
        verify(replay).markUsed("jwt-app", claims.getJWTID(), Duration.ofSeconds(60));
    }

    @Test
    void privateKeyJwtAcceptsIssuerAsAudience() {
        var claims = ClientAssertions.claims(NOW).audience(List.of("https://other", TestProperties.ISSUER)).build();

        assertThat(authenticator.authenticate(new PrivateKeyJwt(null, ClientAssertions.sign(claims))))
                .isEqualTo(jwtApp);
    }

    @Test
    void privateKeyJwtWithValidEs256Assertion() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec-1").generate();
        var ecApp = jwtClient("ec-app", new JWKSet(List.of(ClientAssertions.jwtAppKey().toPublicJWK(),
                ecKey.toPublicJWK())));
        when(clients.find("ec-app")).thenReturn(Optional.of(ecApp));

        var assertion = ClientAssertions.sign(ecKey, ClientAssertions.claims(NOW)
                .issuer("ec-app").subject("ec-app").build());

        assertThat(authenticator.authenticate(new PrivateKeyJwt(null, assertion))).isEqualTo(ecApp);
    }

    @Test
    void assertionSignedWithAnotherKey() throws Exception {
        var other = new RSAKeyGenerator(2048).keyID("jwt-app-1").generate();

        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(other, ClientAssertions.claims(NOW).build())),
                "Assertion signature is invalid");
    }

    @Test
    void assertionWithUnknownKeyId() throws Exception {
        var other = new RSAKeyGenerator(2048).keyID("unknown").generate();

        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(other, ClientAssertions.claims(NOW).build())),
                "Assertion signature is invalid");
    }

    @Test
    void assertionWithDisallowedAlgorithm() throws Exception {
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), ClientAssertions.claims(NOW).build());
        jwt.sign(new MACSigner("a-shared-secret-that-is-at-least-256-bits-long"));

        assertRejected(new PrivateKeyJwt(null, jwt.serialize()), "Assertion must be signed with RS256 or ES256");
    }

    @Test
    void assertionWithWrongIssuerOrSubject() {
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .subject("someone").build())), "Assertion iss and sub must be the client_id");
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .issuer(null).build())), "Assertion iss and sub must be the client_id");
        assertRejected(new PrivateKeyJwt("spa-app", ClientAssertions.sign(ClientAssertions.claims(NOW).build())),
                "Assertion iss and sub must be the client_id");
    }

    @Test
    void assertionWithWrongAudience() {
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .audience("https://evil.example/token").build())), "Assertion aud must be the issuer or the token endpoint");
    }

    @Test
    void expiredAssertion() {
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .expirationTime(Date.from(NOW)).build())), "Assertion has expired");
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .expirationTime(null).build())), "Assertion has expired");
    }

    @Test
    void assertionWithoutJti() {
        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(ClientAssertions.claims(NOW)
                .jwtID(null).build())), "Assertion jti is required");
    }

    @Test
    void replayedAssertion() {
        var claims = ClientAssertions.claims(NOW).build();
        when(replay.markUsed(eq("jwt-app"), eq(claims.getJWTID()), any())).thenReturn(false);

        assertRejected(new PrivateKeyJwt(null, ClientAssertions.sign(claims)), "Assertion has already been used");
    }

    @Test
    void malformedAssertion() {
        assertRejected(new PrivateKeyJwt(null, "not-a-jwt"), "Malformed client assertion");
        verifyNoInteractions(replay);
    }
}
