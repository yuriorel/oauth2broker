package com.oauth2broker.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;
import com.oauth2broker.authorize.AuthorizationCode;
import com.oauth2broker.authorize.AuthorizationCodeRepository;
import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientAuthenticator;
import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.jose.TokenSigner;
import com.oauth2broker.token.TokenRequest.AuthorizationCodeGrant;
import com.oauth2broker.token.TokenRequest.RefreshTokenGrant;
import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidGrant;
import com.oauth2broker.web.OAuthException.InvalidScope;

class TokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final String CALLBACK = "http://localhost:8080/callback";
    // RFC 7636 appendix B.
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Set<String> OPENID_PROFILE = Set.of("openid", "profile");

    private final ClientAuthenticator authenticator = mock(ClientAuthenticator.class);
    private final AuthorizationCodeRepository codes = mock(AuthorizationCodeRepository.class);
    private final TokenRepository tokens = mock(TokenRepository.class);
    private final TokenService service;

    private final ClientCredentials spa = new PublicClient("spa-app");
    private final AuthorizationCode code = new AuthorizationCode("spa-app", CALLBACK, "alice", OPENID_PROFILE,
            "n-1", CHALLENGE, NOW.minusSeconds(5));
    private final RefreshTokenRecord refreshRecord = new RefreshTokenRecord("spa-app", "alice", OPENID_PROFILE);

    TokenServiceTest() throws Exception {
        var properties = TestProperties.create();
        var signer = new TokenSigner(TestKeys.signingKey(), properties, Clock.fixed(NOW, ZoneOffset.UTC));
        service = new TokenService(authenticator, codes, tokens, signer, properties);
    }

    private static ClientRegistration client(String clientId) {
        return new ClientRegistration(clientId, AuthMethod.NONE, null, null, List.of(CALLBACK), OPENID_PROFILE);
    }

    @BeforeEach
    void setUp() {
        when(authenticator.authenticate(spa)).thenReturn(client("spa-app"));
        when(codes.take("code-1")).thenReturn(Optional.of(code));
        when(tokens.saveRefreshToken(any())).thenReturn("rt-new");
        when(tokens.findRefreshToken("rt-1")).thenReturn(Optional.of(refreshRecord));
        when(tokens.takeRefreshToken("rt-1")).thenReturn(Optional.of(refreshRecord));
    }

    private TokenResponse redeem(String verifier) {
        return service.token(new AuthorizationCodeGrant("code-1", CALLBACK, verifier), spa);
    }

    @Test
    void codeGrantIssuesAccessRefreshAndIdToken() throws Exception {
        var response = redeem(VERIFIER);

        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
        assertThat(response.refreshToken()).isEqualTo("rt-new");
        assertThat(Set.of(response.scope().split(" "))).isEqualTo(OPENID_PROFILE);

        var accessToken = SignedJWT.parse(response.accessToken());
        assertThat(accessToken.verify(new RSASSAVerifier(TestKeys.signingKey().jwk()))).isTrue();
        verify(tokens).saveAccessToken(accessToken.getJWTClaimsSet().getJWTID(),
                new AccessTokenRecord("spa-app", "alice", OPENID_PROFILE));
        verify(tokens).saveRefreshToken(new RefreshTokenRecord("spa-app", "alice", OPENID_PROFILE));

        var idToken = SignedJWT.parse(response.idToken()).getJWTClaimsSet();
        assertThat(idToken.getAudience()).containsExactly("spa-app");
        assertThat(idToken.getStringClaim("nonce")).isEqualTo("n-1");
        assertThat(idToken.getLongClaim("auth_time")).isEqualTo(NOW.minusSeconds(5).getEpochSecond());
    }

    @Test
    void codeGrantWithoutOpenidHasNoIdToken() {
        when(codes.take("code-1")).thenReturn(Optional.of(new AuthorizationCode("spa-app", CALLBACK, "alice",
                Set.of("profile"), null, CHALLENGE, NOW)));

        var response = redeem(VERIFIER);

        assertThat(response.idToken()).isNull();
        assertThat(response.scope()).isEqualTo("profile");
    }

    @Test
    void unknownOrReusedCode() {
        when(codes.take("code-1")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> redeem(VERIFIER)).isInstanceOf(InvalidGrant.class)
                .hasMessage("Authorization code is invalid or expired");
    }

    @Test
    void codeIssuedToAnotherClient() {
        var web = new PublicClient("web-app");
        when(authenticator.authenticate(web)).thenReturn(client("web-app"));

        assertThatThrownBy(() -> service.token(new AuthorizationCodeGrant("code-1", CALLBACK, VERIFIER), web))
                .isInstanceOf(InvalidGrant.class).hasMessage("Authorization code was issued to another client");
    }

    @Test
    void redirectUriMismatch() {
        assertThatThrownBy(() -> service.token(new AuthorizationCodeGrant("code-1", CALLBACK + "/x", VERIFIER), spa))
                .isInstanceOf(InvalidGrant.class).hasMessage("redirect_uri does not match the authorization request");
    }

    @Test
    void pkceMismatch() {
        assertThatThrownBy(() -> redeem("x".repeat(43))).isInstanceOf(InvalidGrant.class)
                .hasMessage("code_verifier does not match the code_challenge");
        assertThatThrownBy(() -> redeem("short")).isInstanceOf(InvalidGrant.class);
        verify(tokens, never()).saveRefreshToken(any());
    }

    @Test
    void pkceVerifierRules() {
        assertThat(TokenService.pkceMatches(VERIFIER, CHALLENGE)).isTrue();
        assertThat(TokenService.pkceMatches(VERIFIER + "!", CHALLENGE)).isFalse();
        assertThat(TokenService.pkceMatches("a".repeat(129), CHALLENGE)).isFalse();
    }

    @Test
    void clientAuthenticationFailureIsRethrownUnwrapped() {
        when(authenticator.authenticate(spa)).thenThrow(new InvalidClient("Client authentication failed"));

        assertThatThrownBy(() -> redeem(VERIFIER)).isExactlyInstanceOf(InvalidClient.class)
                .hasMessage("Client authentication failed");
        verify(tokens, never()).saveAccessToken(anyString(), any());
    }

    @Test
    void clientAuthenticationAndCodeLookupRunConcurrentlyOnVirtualThreads() {
        var bothStarted = new CountDownLatch(2);
        var threads = ConcurrentHashMap.<Thread>newKeySet();
        when(authenticator.authenticate(spa)).thenAnswer(_ -> {
            threads.add(Thread.currentThread());
            bothStarted.countDown();
            assertThat(bothStarted.await(5, TimeUnit.SECONDS)).isTrue();
            return client("spa-app");
        });
        when(codes.take("code-1")).thenAnswer(_ -> {
            threads.add(Thread.currentThread());
            bothStarted.countDown();
            assertThat(bothStarted.await(5, TimeUnit.SECONDS)).isTrue();
            return Optional.of(code);
        });

        assertThat(redeem(VERIFIER).accessToken()).isNotBlank();
        assertThat(threads).hasSize(2).allMatch(Thread::isVirtual).doesNotContain(Thread.currentThread());
    }

    @Test
    void refreshGrantRotatesTokenAndKeepsScope() {
        var response = service.token(new RefreshTokenGrant("rt-1", null), spa);

        assertThat(response.refreshToken()).isEqualTo("rt-new");
        assertThat(response.idToken()).isNull();
        assertThat(Set.of(response.scope().split(" "))).isEqualTo(OPENID_PROFILE);
        verify(tokens).takeRefreshToken("rt-1");
        verify(tokens).saveRefreshToken(refreshRecord);
    }

    @Test
    void refreshGrantCanNarrowScopeButNewRefreshTokenKeepsOriginal() {
        var response = service.token(new RefreshTokenGrant("rt-1", "profile"), spa);

        assertThat(response.scope()).isEqualTo("profile");
        verify(tokens).saveAccessToken(anyString(), any(AccessTokenRecord.class));
        verify(tokens).saveRefreshToken(refreshRecord);
    }

    @Test
    void refreshGrantCannotWidenScope() {
        assertThatThrownBy(() -> service.token(new RefreshTokenGrant("rt-1", "openid email"), spa))
                .isInstanceOf(InvalidScope.class);
        verify(tokens, never()).takeRefreshToken(any());
    }

    @Test
    void unknownOrRotatedRefreshToken() {
        when(tokens.findRefreshToken("old")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.token(new RefreshTokenGrant("old", null), spa))
                .isInstanceOf(InvalidGrant.class).hasMessage("Refresh token is invalid or expired");
    }

    @Test
    void refreshTokenOfAnotherClient() {
        var web = new PublicClient("web-app");
        when(authenticator.authenticate(web)).thenReturn(client("web-app"));

        assertThatThrownBy(() -> service.token(new RefreshTokenGrant("rt-1", null), web))
                .isInstanceOf(InvalidGrant.class).hasMessage("Refresh token was issued to another client");
        verify(tokens, never()).takeRefreshToken(any());
    }

    @Test
    void refreshTokenUsedConcurrentlyByAnotherRequest() {
        when(tokens.takeRefreshToken("rt-1")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.token(new RefreshTokenGrant("rt-1", null), spa))
                .isInstanceOf(InvalidGrant.class);
        verify(tokens, never()).saveRefreshToken(any());
    }
}
