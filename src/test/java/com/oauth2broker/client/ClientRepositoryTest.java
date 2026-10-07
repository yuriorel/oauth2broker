package com.oauth2broker.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.oauth2broker.store.RedisJsonStore;

class ClientRepositoryTest {

    private final RedisJsonStore store = mock(RedisJsonStore.class);
    private final ClientRepository repository = new ClientRepository(store);
    private final ClientRegistration client = new ClientRegistration("spa-app", AuthMethod.NONE, null, null,
            List.of("http://localhost:8080/callback"), Set.of("openid"));

    @Test
    void savesUnderClientIdWithoutTtl() {
        repository.save(client);

        verify(store).set("client:spa-app", client);
    }

    @Test
    void findsByClientId() {
        when(store.get("client:spa-app", ClientRegistration.class)).thenReturn(Optional.of(client));

        assertThat(repository.find("spa-app")).contains(client);
    }
}
