package com.oauth2broker.authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.oauth2broker.TestProperties;
import com.oauth2broker.store.RedisJsonStore;

class AuthorizationCodeRepositoryTest {

    private final RedisJsonStore store = mock(RedisJsonStore.class);
    private final AuthorizationCodeRepository repository =
            new AuthorizationCodeRepository(store, TestProperties.create());
    private final AuthorizationCode code = new AuthorizationCode("web-app", "http://localhost:8080/callback",
            "alice", Set.of("openid"), "n-1", "challenge", Instant.now());

    @Test
    void savesUnderNewCodeWithSixtySecondTtl() {
        var value = repository.save(code);

        assertThat(value).isNotBlank();
        verify(store).set("code:" + value, code, Duration.ofSeconds(60));
    }

    @Test
    void takeRedeemsWithGetDel() {
        when(store.getAndDelete("code:abc", AuthorizationCode.class)).thenReturn(Optional.of(code));

        assertThat(repository.take("abc")).contains(code);
        assertThat(repository.take("other")).isEmpty();
    }
}
