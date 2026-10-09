package com.oauth2broker.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import com.oauth2broker.token.TokenRequest.AuthorizationCodeGrant;
import com.oauth2broker.token.TokenRequest.RefreshTokenGrant;
import com.oauth2broker.web.OAuthException.InvalidRequest;
import com.oauth2broker.web.OAuthException.UnsupportedGrantType;

class TokenRequestTest {

    @Test
    void parsesCodeGrant() {
        assertThat(TokenRequest.of("authorization_code", "c", "http://cb", "v", "ignored", "ignored"))
                .isEqualTo(new AuthorizationCodeGrant("c", "http://cb", "v"));
    }

    @Test
    void parsesRefreshGrant() {
        assertThat(TokenRequest.of("refresh_token", null, null, null, "rt", "openid"))
                .isEqualTo(new RefreshTokenGrant("rt", "openid"));
        assertThat(TokenRequest.of("refresh_token", null, null, null, "rt", null))
                .isEqualTo(new RefreshTokenGrant("rt", null));
    }

    @Test
    void missingParametersAreInvalidRequest() {
        assertThatThrownBy(() -> TokenRequest.of(null, "c", "r", "v", null, null))
                .isInstanceOf(InvalidRequest.class).hasMessage("grant_type is required");
        assertThatThrownBy(() -> TokenRequest.of("authorization_code", null, "r", "v", null, null))
                .isInstanceOf(InvalidRequest.class).hasMessage("code is required");
        assertThatThrownBy(() -> TokenRequest.of("authorization_code", "c", " ", "v", null, null))
                .isInstanceOf(InvalidRequest.class).hasMessage("redirect_uri is required");
        assertThatThrownBy(() -> TokenRequest.of("authorization_code", "c", "r", null, null, null))
                .isInstanceOf(InvalidRequest.class).hasMessage("code_verifier is required");
        assertThatThrownBy(() -> TokenRequest.of("refresh_token", null, null, null, null, null))
                .isInstanceOf(InvalidRequest.class).hasMessage("refresh_token is required");
    }

    @Test
    void otherGrantTypesAreUnsupported() {
        assertThatThrownBy(() -> TokenRequest.of("client_credentials", null, null, null, null, null))
                .isInstanceOf(UnsupportedGrantType.class);
    }
}
