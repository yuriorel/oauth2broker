package com.oauth2broker.user;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth2broker.store.RedisJsonStore;

@Repository
public class UserRepository {

    private static final String PREFIX = "user:";

    private final RedisJsonStore store;

    public UserRepository(RedisJsonStore store) {
        this.store = store;
    }

    public void save(User user) {
        store.set(PREFIX + user.username(), user);
    }

    public Optional<User> find(String username) {
        return store.get(PREFIX + username, User.class);
    }
}
