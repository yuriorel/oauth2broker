package com.oauth2broker.client;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth2broker.store.RedisJsonStore;

@Repository
public class ClientRepository {

    private static final String PREFIX = "client:";

    private final RedisJsonStore store;

    public ClientRepository(RedisJsonStore store) {
        this.store = store;
    }

    public void save(ClientRegistration client) {
        store.set(PREFIX + client.clientId(), client);
    }

    public Optional<ClientRegistration> find(String clientId) {
        return store.get(PREFIX + clientId, ClientRegistration.class);
    }
}
