package com.oauth2broker.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidGrant;
import com.oauth2broker.web.OAuthException.InvalidRequest;
import com.oauth2broker.web.OAuthException.InvalidScope;
import com.oauth2broker.web.OAuthException.UnsupportedGrantType;

class OAuthExceptionTest {

    @Test
    void eachSubclassHasItsErrorCode() {
        assertThat(new InvalidRequest("x").error()).isEqualTo("invalid_request");
        assertThat(new InvalidClient("x").error()).isEqualTo("invalid_client");
        assertThat(new InvalidGrant("x").error()).isEqualTo("invalid_grant");
        assertThat(new InvalidScope("x").error()).isEqualTo("invalid_scope");
        assertThat(new UnsupportedGrantType("x").error()).isEqualTo("unsupported_grant_type");
    }

    @Test
    void descriptionKeepsOnlyCharactersAllowedByRfc6749() {
        assertThat(new InvalidRequest("say \"hi\" \\ café\n!").getMessage()).isEqualTo("say ?hi? ? caf??!");
    }
}
