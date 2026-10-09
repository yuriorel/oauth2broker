package com.oauth2broker.revoke;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientCredentials.SecretBasic;
import com.oauth2broker.web.OAuthErrorHandler;
import com.oauth2broker.web.OAuthException.InvalidClient;

class RevocationControllerTest {

    private final RevocationService service = mock(RevocationService.class);
    private final MockMvcTester mvc = MockMvcTester.create(MockMvcBuilders
            .standaloneSetup(new RevocationController(service)).setControllerAdvice(new OAuthErrorHandler()).build());

    private MockMvcTester.MockMvcRequestBuilder post() {
        return mvc.post().uri("/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

    @Test
    void revokesAndRespondsOkWithEmptyBody() {
        assertThat(post().header("Authorization", "Basic d2ViLWFwcDp3ZWItYXBwLXNlY3JldA==")
                .formField("token", "rt-1").formField("token_type_hint", "refresh_token"))
                .hasStatusOk().body().isEmpty();
        verify(service).revoke("rt-1", "refresh_token", new SecretBasic("web-app", "web-app-secret"));
    }

    @Test
    void publicClientIdentifiesWithClientId() {
        assertThat(post().formField("token", "at").formField("client_id", "spa-app")).hasStatusOk();
        verify(service).revoke("at", null, new PublicClient("spa-app"));
    }

    @Test
    void missingTokenIsInvalidRequest() {
        assertThat(post().formField("client_id", "spa-app")).hasStatus(400)
                .bodyJson().extractingPath("$.error").isEqualTo("invalid_request");
        verifyNoInteractions(service);
    }

    @Test
    void invalidClientIs401() {
        doThrow(new InvalidClient("Client authentication failed")).when(service).revoke(eq("at"), any(), any());

        assertThat(post().formField("token", "at").formField("client_id", "nobody")).hasStatus(401)
                .hasHeader("WWW-Authenticate", "Basic realm=\"oauth2broker\"")
                .bodyJson().extractingPath("$.error").isEqualTo("invalid_client");
        assertThat(post().formField("token", "at")).hasStatus(401);
    }
}
