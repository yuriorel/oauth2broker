package com.oauth2broker.authorize;

import java.time.Duration;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.store.RandomTokens;
import com.oauth2broker.store.RedisJsonStore;

@Repository
public class AuthorizationRequestRepository {

    private static final String PREFIX = "authreq:";

    private final RedisJsonStore store;
    private final Duration ttl;

    public AuthorizationRequestRepository(RedisJsonStore store, BrokerProperties properties) {
        this.store = store;
        this.ttl = properties.ttl().authorizationRequest();
    }

    /** Stores the request and returns its new id. */
    public String save(AuthorizationRequest request) {
        var id = RandomTokens.generate();
        store.set(PREFIX + id, request, ttl);
        return id;
    }

    public Optional<AuthorizationRequest> find(String id) {
        return store.get(PREFIX + id, AuthorizationRequest.class);
    }

    /** Reads and deletes the request in one step, so a sign-in completes it only once. */
    public Optional<AuthorizationRequest> take(String id) {
        return store.getAndDelete(PREFIX + id, AuthorizationRequest.class);
    }
}
