package com.oauth2broker.authorize;

import java.time.Duration;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.store.RandomTokens;
import com.oauth2broker.store.RedisJsonStore;

@Repository
public class AuthorizationCodeRepository {

    private static final String PREFIX = "code:";

    private final RedisJsonStore store;
    private final Duration ttl;

    public AuthorizationCodeRepository(RedisJsonStore store, BrokerProperties properties) {
        this.store = store;
        this.ttl = properties.ttl().authorizationCode();
    }

    /** Stores the code data and returns the new code. */
    public String save(AuthorizationCode code) {
        var value = RandomTokens.generate();
        store.set(PREFIX + value, code, ttl);
        return value;
    }

    /** Redeems the code: reads and deletes it atomically, so it works only once. */
    public Optional<AuthorizationCode> take(String code) {
        return store.getAndDelete(PREFIX + code, AuthorizationCode.class);
    }
}
