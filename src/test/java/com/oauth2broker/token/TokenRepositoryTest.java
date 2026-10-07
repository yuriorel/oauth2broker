package com.oauth2broker.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.oauth2broker.TestProperties;
import com.oauth2broker.store.RedisJsonStore;

class TokenRepositoryTest {

    // SHA-256 of "token", hex encoded.
    private static final String TOKEN_KEY = "rt:3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0";

    private final RedisJsonStore store = mock(RedisJsonStore.class);
    private final TokenRepository repository = new TokenRepository(store, TestProperties.create());
    private final AccessTokenRecord access = new AccessTokenRecord("web-app", "alice", Set.of("openid"));
    private final RefreshTokenRecord refresh = new RefreshTokenRecord("web-app", "alice", Set.of("openid"));

    @Test
    void savesAccessTokenUnderJtiWithFifteenMinuteTtl() {
        repository.saveAccessToken("jti-1", access);

        verify(store).set("at:jti-1", access, Duration.ofMinutes(15));
    }

    @Test
    void findsAndDeletesAccessToken() {
        when(store.get("at:jti-1", AccessTokenRecord.class)).thenReturn(Optional.of(access));

        assertThat(repository.findAccessToken("jti-1")).contains(access);
        repository.deleteAccessToken("jti-1");
        verify(store).delete("at:jti-1");
    }

    @Test
    void savesRefreshTokenUnderItsHashWithThirtyDayTtl() {
        var token = repository.saveRefreshToken(refresh);

        var key = ArgumentCaptor.forClass(String.class);
        verify(store).set(key.capture(), eq(refresh), eq(Duration.ofDays(30)));
        assertThat(key.getValue()).matches("rt:[0-9a-f]{64}").doesNotContain(token);
    }

    @Test
    void looksUpRefreshTokenByHash() {
        when(store.get(TOKEN_KEY, RefreshTokenRecord.class)).thenReturn(Optional.of(refresh));
        when(store.getAndDelete(TOKEN_KEY, RefreshTokenRecord.class)).thenReturn(Optional.of(refresh));

        assertThat(repository.findRefreshToken("token")).contains(refresh);
        assertThat(repository.takeRefreshToken("token")).contains(refresh);
        repository.deleteRefreshToken("token");
        verify(store).delete(TOKEN_KEY);
    }

    @Test
    void savedRefreshTokenIsFoundAgain() {
        var token = repository.saveRefreshToken(refresh);
        var key = ArgumentCaptor.forClass(String.class);
        verify(store).set(key.capture(), any(), any(Duration.class));
        when(store.get(key.getValue(), RefreshTokenRecord.class)).thenReturn(Optional.of(refresh));

        assertThat(repository.findRefreshToken(token)).contains(refresh);
    }
}
