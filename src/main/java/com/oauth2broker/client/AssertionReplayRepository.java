package com.oauth2broker.client;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

/** Remembers the {@code jti} of each client assertion until it expires, so it can be used only once. */
@Repository
public class AssertionReplayRepository {

    private static final String PREFIX = "assertion:";

    private final StringRedisTemplate redis;

    public AssertionReplayRepository(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** Returns true the first time a {@code jti} is seen for the client (Redis {@code SET NX}). */
    public boolean markUsed(String clientId, String jti, Duration ttl) {
        return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(PREFIX + clientId + ":" + jti, "1", ttl));
    }
}
