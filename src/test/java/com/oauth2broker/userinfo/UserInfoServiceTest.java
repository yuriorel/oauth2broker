package com.oauth2broker.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;
import com.oauth2broker.jose.AccessTokenVerifier;
import com.oauth2broker.jose.SignedAccessToken;
import com.oauth2broker.jose.TokenSigner;
import com.oauth2broker.token.AccessTokenRecord;
import com.oauth2broker.token.TokenRepository;
import com.oauth2broker.user.User;
import com.oauth2broker.user.UserRepository;
import com.oauth2broker.web.OAuthException.InsufficientScope;
import com.oauth2broker.web.OAuthException.InvalidToken;

class UserInfoServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final User ALICE = new User("alice", "hash", "Alice Liddell", "alice@example.com", true);

    private final TokenRepository tokens = mock(TokenRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final TokenSigner signer;
    private final UserInfoService service;

    UserInfoServiceTest() throws Exception {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        signer = new TokenSigner(TestKeys.signingKey(), TestProperties.create(), clock);
        service = new UserInfoService(new AccessTokenVerifier(TestKeys.signingKey(), TestProperties.create(), clock),
                tokens, users);
    }

    @BeforeEach
    void setUp() {
        when(users.find("alice")).thenReturn(Optional.of(ALICE));
    }

    /** An access token with the given scope that is still recorded in Redis. */
    private String token(String... scope) {
        SignedAccessToken token = signer.accessToken("spa-app", "alice", Set.of(scope));
        when(tokens.findAccessToken(token.jti()))
                .thenReturn(Optional.of(new AccessTokenRecord("spa-app", "alice", Set.of(scope))));
        return "Bearer " + token.value();
    }

    @Test
    void openidAloneReturnsOnlySub() {
        assertThat(service.userInfo(token("openid"))).isEqualTo(new UserInfo("alice", null, null, null));
    }

    @Test
    void profileAndEmailScopesReleaseTheirClaims() {
        assertThat(service.userInfo(token("openid", "profile")))
                .isEqualTo(new UserInfo("alice", "Alice Liddell", null, null));
        assertThat(service.userInfo(token("openid", "email")))
                .isEqualTo(new UserInfo("alice", null, "alice@example.com", true));
        assertThat(service.userInfo(token("openid", "profile", "email")))
                .isEqualTo(new UserInfo("alice", "Alice Liddell", "alice@example.com", true));
    }

    @Test
    void schemeIsCaseInsensitive() {
        assertThat(service.userInfo(token("openid").replace("Bearer", "bearer")).sub()).isEqualTo("alice");
    }

    @Test
    void missingOrNonBearerHeaderIsInvalidToken() {
        assertThatThrownBy(() -> service.userInfo(null)).isInstanceOf(InvalidToken.class)
                .hasMessage("Bearer access token is required");
        assertThatThrownBy(() -> service.userInfo("Basic abc")).isInstanceOf(InvalidToken.class);
        verifyNoInteractions(tokens, users);
    }

    @Test
    void revokedTokenIsInvalidToken() {
        var header = token("openid");
        when(tokens.findAccessToken(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.userInfo(header)).isInstanceOf(InvalidToken.class)
                .hasMessage("Access token has been revoked");
    }

    @Test
    void expiredTokenIsInvalidToken() throws Exception {
        var header = token("openid");
        var later = new UserInfoService(new AccessTokenVerifier(TestKeys.signingKey(), TestProperties.create(),
                Clock.fixed(NOW.plusSeconds(900), ZoneOffset.UTC)), tokens, users);

        assertThatThrownBy(() -> later.userInfo(header)).isInstanceOf(InvalidToken.class)
                .hasMessage("Access token has expired");
    }

    @Test
    void tamperedTokenIsInvalidToken() {
        var header = token("openid");
        var tampered = header.substring(0, header.length() - 4) + (header.endsWith("AAAA") ? "BBBB" : "AAAA");

        assertThatThrownBy(() -> service.userInfo(tampered)).isInstanceOf(InvalidToken.class)
                .hasMessage("Access token signature is invalid");
    }

    @Test
    void tokenWithoutOpenidScopeIsInsufficientScope() {
        var header = token("profile", "email");

        assertThatThrownBy(() -> service.userInfo(header)).isInstanceOf(InsufficientScope.class)
                .hasMessage("The openid scope is required");
        verifyNoInteractions(users);
    }

    @Test
    void deletedUserIsInvalidToken() {
        var header = token("openid");
        when(users.find("alice")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.userInfo(header)).isInstanceOf(InvalidToken.class);
    }

    @Test
    void revocationCheckAndUserLookupRunConcurrentlyOnVirtualThreads() {
        var header = token("openid");
        var bothStarted = new CountDownLatch(2);
        var threads = ConcurrentHashMap.<Thread>newKeySet();
        when(tokens.findAccessToken(any())).thenAnswer(_ -> {
            threads.add(Thread.currentThread());
            bothStarted.countDown();
            assertThat(bothStarted.await(5, TimeUnit.SECONDS)).isTrue();
            return Optional.of(new AccessTokenRecord("spa-app", "alice", Set.of("openid")));
        });
        when(users.find("alice")).thenAnswer(_ -> {
            threads.add(Thread.currentThread());
            bothStarted.countDown();
            assertThat(bothStarted.await(5, TimeUnit.SECONDS)).isTrue();
            return Optional.of(ALICE);
        });

        assertThat(service.userInfo(header).sub()).isEqualTo("alice");
        assertThat(threads).hasSize(2).allMatch(Thread::isVirtual).doesNotContain(Thread.currentThread());
        verify(users).find("alice");
    }
}
