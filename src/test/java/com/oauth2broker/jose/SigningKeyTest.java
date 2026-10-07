package com.oauth2broker.jose;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.oauth2broker.TestKeys;

class SigningKeyTest {

    private final SigningKey key = TestKeys.signingKey();

    @Test
    void keyIdIsTheJwkThumbprint() throws Exception {
        assertThat(key.keyId()).isEqualTo(key.jwk().computeThumbprint().toString());
        assertThat(key.jwk().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(key.jwk().getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.jwk().isPrivate()).isTrue();
    }

    @Test
    void publicJwkSetHasOnlyThePublicKey() {
        var keys = key.publicJwkSet().getKeys();

        assertThat(keys).singleElement().satisfies(jwk -> {
            assertThat(jwk.isPrivate()).isFalse();
            assertThat(jwk.getKeyID()).isEqualTo(key.keyId());
            assertThat(jwk.toJSONObject()).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi");
        });
    }

    @Test
    void toStringHidesThePrivateKey() {
        assertThat(key.toString()).isEqualTo("SigningKey[kid=" + key.keyId() + "]");
    }
}
