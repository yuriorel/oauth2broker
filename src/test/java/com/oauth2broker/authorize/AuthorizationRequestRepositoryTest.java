package com.oauth2broker.authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.oauth2broker.TestProperties;
import com.oauth2broker.store.RedisJsonStore;

class AuthorizationRequestRepositoryTest {

    private final RedisJsonStore store = mock(RedisJsonStore.class);
    private final AuthorizationRequestRepository repository =
            new AuthorizationRequestRepository(store, TestProperties.create());
    private final AuthorizationRequest request = new AuthorizationRequest("web-app",
            "http://localhost:8080/callback", Set.of("openid"), "xyz", null, "challenge");

    @Test
    void savesUnderNewIdWithTenMinuteTtl() {
        var id = repository.save(request);

        assertThat(id).isNotBlank();
        verify(store).set("authreq:" + id, request, Duration.ofMinutes(10));
        assertThat(repository.save(request)).isNotEqualTo(id);
    }

    @Test
    void findsById() {
        when(store.get("authreq:abc", AuthorizationRequest.class)).thenReturn(Optional.of(request));

        assertThat(repository.find("abc")).contains(request);
    }

    @Test
    void takeReadsAndDeletes() {
        when(store.getAndDelete("authreq:abc", AuthorizationRequest.class)).thenReturn(Optional.of(request));

        assertThat(repository.take("abc")).contains(request);
    }
}
