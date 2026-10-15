package com.oauth2broker.client;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import com.oauth2broker.web.RequestContext;

/// Remembers the `jti` of each client assertion until it expires, so it can be used only once.
@Repository
public class AssertionReplayRepository {

    private static final Logger log = LoggerFactory.getLogger(AssertionReplayRepository.class);
    private static final String PREFIX = "assertion:";

    private final StringRedisTemplate redis;

    public AssertionReplayRepository(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /// Returns true the first time a `jti` is seen for the client (Redis `SET NX`).
    public boolean markUsed(String clientId, String jti, Duration ttl) {
        var key = PREFIX + clientId + ":" + jti;
        var first = Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, "1", ttl));
        log.debug("[{}] Redis SET NX {} ttl={} -> {}", RequestContext.id(), key, ttl, first);
        return first;
    }
}
