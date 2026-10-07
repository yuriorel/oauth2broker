package com.oauth2broker.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.oauth2broker.token.AccessTokenRecord;

import tools.jackson.databind.json.JsonMapper;

class RedisJsonStoreTest {

    private static final String JSON = """
            {"clientId":"web-app","username":"alice","scope":["openid"]}""";
    private static final AccessTokenRecord RECORD = new AccessTokenRecord("web-app", "alice", Set.of("openid"));

    private StringRedisTemplate redis;
    private ValueOperations<String, String> ops;
    private RedisJsonStore store;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        store = new RedisJsonStore(redis, JsonMapper.builder().build());
    }

    @Test
    void setWritesJson() {
        store.set("k", RECORD);

        verify(ops).set("k", JSON);
    }

    @Test
    void setWithTtlWritesJsonAndTtl() {
        store.set("k", RECORD, Duration.ofSeconds(60));

        verify(ops).set("k", JSON, Duration.ofSeconds(60));
    }

    @Test
    void getReadsJson() {
        when(ops.get("k")).thenReturn(JSON);

        assertThat(store.get("k", AccessTokenRecord.class)).contains(RECORD);
    }

    @Test
    void getMissingKeyIsEmpty() {
        assertThat(store.get("k", AccessTokenRecord.class)).isEmpty();
    }

    @Test
    void getAndDeleteUsesGetDel() {
        when(ops.getAndDelete("k")).thenReturn(JSON);

        assertThat(store.getAndDelete("k", AccessTokenRecord.class)).contains(RECORD);
    }

    @Test
    void getAndDeleteMissingKeyIsEmpty() {
        assertThat(store.getAndDelete("k", AccessTokenRecord.class)).isEmpty();
    }

    @Test
    void deleteRemovesKey() {
        store.delete("k");

        verify(redis).delete("k");
    }
}
