package com.oauth2broker.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientCredentials.SecretBasic;
import com.oauth2broker.token.TokenRequest.AuthorizationCodeGrant;
import com.oauth2broker.token.TokenRequest.RefreshTokenGrant;
import com.oauth2broker.web.OAuthErrorHandler;
import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidGrant;

class TokenControllerTest {

    private final TokenService service = mock(TokenService.class);
    private final MockMvcTester mvc = MockMvcTester.create(MockMvcBuilders
            .standaloneSetup(new TokenController(service)).setControllerAdvice(new OAuthErrorHandler()).build());

    private MockMvcTester.MockMvcRequestBuilder post() {
        return mvc.post().uri("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

    @Test
    void codeGrantReturnsTokensWithNoStore() {
        when(service.token(new AuthorizationCodeGrant("c", "http://cb", "v"), new PublicClient("spa-app")))
                .thenReturn(new TokenResponse("at", "Bearer", 900, "rt", null, "openid"));

        var result = post().formField("grant_type", "authorization_code").formField("code", "c")
                .formField("redirect_uri", "http://cb").formField("code_verifier", "v")
                .formField("client_id", "spa-app").exchange();

        assertThat(result).hasStatusOk().hasHeader("Cache-Control", "no-store").bodyJson()
                .isLenientlyEqualTo("""
                        {"access_token": "at", "token_type": "Bearer", "expires_in": 900,
                         "refresh_token": "rt", "scope": "openid"}
                        """)
                .doesNotHavePath("$.id_token");
    }

    @Test
    void basicHeaderIsPassedAsSecretBasic() {
        when(service.token(new RefreshTokenGrant("rt", null), new SecretBasic("web-app", "web-app-secret")))
                .thenReturn(new TokenResponse("at", "Bearer", 900, "rt2", null, "openid"));

        assertThat(post().header("Authorization", "Basic d2ViLWFwcDp3ZWItYXBwLXNlY3JldA==")
                .formField("grant_type", "refresh_token").formField("refresh_token", "rt"))
                .hasStatusOk().bodyJson().extractingPath("$.refresh_token").isEqualTo("rt2");
    }

    @Test
    void invalidClientIs401WithWwwAuthenticate() {
        when(service.token(any(), any())).thenThrow(new InvalidClient("Client authentication failed"));

        assertThat(post().formField("grant_type", "refresh_token").formField("refresh_token", "rt")
                .formField("client_id", "x"))
                .hasStatus(401).hasHeader("WWW-Authenticate", "Basic realm=\"oauth2broker\"")
                .hasHeader("Cache-Control", "no-store")
                .bodyJson().isLenientlyEqualTo("""
                        {"error": "invalid_client", "error_description": "Client authentication failed"}
                        """);
    }

    @Test
    void grantErrorsAre400() {
        when(service.token(any(), any())).thenThrow(new InvalidGrant("Refresh token is invalid or expired"));

        assertThat(post().formField("grant_type", "refresh_token").formField("refresh_token", "rt")
                .formField("client_id", "x"))
                .hasStatus(400).bodyJson().extractingPath("$.error").isEqualTo("invalid_grant");
    }

    @Test
    void requestErrorsAre400BeforeTheServiceIsCalled() {
        assertThat(post().formField("client_id", "x")).hasStatus(400)
                .bodyJson().extractingPath("$.error").isEqualTo("invalid_request");
        assertThat(post().formField("grant_type", "password").formField("client_id", "x")).hasStatus(400)
                .bodyJson().extractingPath("$.error").isEqualTo("unsupported_grant_type");
        assertThat(post().formField("grant_type", "refresh_token").formField("refresh_token", "rt")).hasStatus(401)
                .bodyJson().extractingPath("$.error").isEqualTo("invalid_client");
    }
}
