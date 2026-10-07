package com.oauth2broker.store;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/** Stores values in Redis as JSON strings. */
@Component
public class RedisJsonStore {

    private final StringRedisTemplate redis;
    private final JsonMapper json;

    public RedisJsonStore(StringRedisTemplate redis, JsonMapper json) {
        this.redis = redis;
        this.json = json;
    }

    public void set(String key, Object value) {
        redis.opsForValue().set(key, json.writeValueAsString(value));
    }

    public void set(String key, Object value, Duration ttl) {
        redis.opsForValue().set(key, json.writeValueAsString(value), ttl);
    }

    public <T> Optional<T> get(String key, Class<T> type) {
        return read(redis.opsForValue().get(key), type);
    }

    /** Atomically reads and deletes the value (Redis {@code GETDEL}), so it can be consumed only once. */
    public <T> Optional<T> getAndDelete(String key, Class<T> type) {
        return read(redis.opsForValue().getAndDelete(key), type);
    }

    public void delete(String key) {
        redis.delete(key);
    }

    private <T> Optional<T> read(String value, Class<T> type) {
        return Optional.ofNullable(value).map(v -> json.readValue(v, type));
    }
}
