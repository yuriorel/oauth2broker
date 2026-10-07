package com.oauth2broker.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

class RandomTokensTest {

    @Test
    void generatesUnique256BitBase64UrlValues() {
        var tokens = IntStream.range(0, 100).mapToObj(_ -> RandomTokens.generate()).collect(Collectors.toSet());

        assertThat(tokens).hasSize(100).allMatch(t -> t.matches("[A-Za-z0-9_-]{43}"));
    }
}
