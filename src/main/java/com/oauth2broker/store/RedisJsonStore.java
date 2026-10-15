package com.oauth2broker.store;

import java.time.Duration;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.oauth2broker.web.RequestContext;

import tools.jackson.databind.json.JsonMapper;

/// Stores values in Redis as JSON strings. At DEBUG, every command is logged with its key, TTL and JSON value.
@Component
public class RedisJsonStore {

    private static final Logger log = LoggerFactory.getLogger(RedisJsonStore.class);

    private final StringRedisTemplate redis;
    private final JsonMapper json;

    public RedisJsonStore(StringRedisTemplate redis, JsonMapper json) {
        this.redis = redis;
        this.json = json;
    }

    public void set(String key, Object value) {
        var serialized = json.writeValueAsString(value);
        log.debug("[{}] Redis SET {} {}", RequestContext.id(), key, serialized);
        redis.opsForValue().set(key, serialized);
    }

    public void set(String key, Object value, Duration ttl) {
        var serialized = json.writeValueAsString(value);
        log.debug("[{}] Redis SET {} ttl={} {}", RequestContext.id(), key, ttl, serialized);
        redis.opsForValue().set(key, serialized, ttl);
    }

    public <T> Optional<T> get(String key, Class<T> type) {
        var value = redis.opsForValue().get(key);
        log.debug("[{}] Redis GET {} -> {}", RequestContext.id(), key, value);
        return read(value, type);
    }

    /// Atomically reads and deletes the value (Redis `GETDEL`), so it can be consumed only once.
    public <T> Optional<T> getAndDelete(String key, Class<T> type) {
        var value = redis.opsForValue().getAndDelete(key);
        log.debug("[{}] Redis GETDEL {} -> {}", RequestContext.id(), key, value);
        return read(value, type);
    }

    public void delete(String key) {
        var deleted = redis.delete(key);
        log.debug("[{}] Redis DEL {} -> {}", RequestContext.id(), key, deleted);
    }

    private <T> Optional<T> read(String value, Class<T> type) {
        return Optional.ofNullable(value).map(v -> json.readValue(v, type));
    }
}
