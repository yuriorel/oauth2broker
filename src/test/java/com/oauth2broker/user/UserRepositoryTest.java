package com.oauth2broker.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.oauth2broker.store.RedisJsonStore;

class UserRepositoryTest {

    private final RedisJsonStore store = mock(RedisJsonStore.class);
    private final UserRepository repository = new UserRepository(store);
    private final User user = new User("alice", "$2a$10$hash", "Alice", "alice@example.com", true);

    @Test
    void savesUnderUsernameWithoutTtl() {
        repository.save(user);

        verify(store).set("user:alice", user);
    }

    @Test
    void findsByUsername() {
        when(store.get("user:alice", User.class)).thenReturn(Optional.of(user));

        assertThat(repository.find("alice")).contains(user);
        assertThat(repository.find("bob")).isEmpty();
    }
}
