package com.oauth2broker.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.oauth2broker.web.OAuthErrorHandler;
import com.oauth2broker.web.OAuthException.InsufficientScope;
import com.oauth2broker.web.OAuthException.InvalidToken;

class UserInfoControllerTest {

    private final UserInfoService service = mock(UserInfoService.class);
    private final MockMvcTester mvc = MockMvcTester.create(MockMvcBuilders
            .standaloneSetup(new UserInfoController(service)).setControllerAdvice(new OAuthErrorHandler()).build());

    @Test
    void getAndPostReturnClaimsWithoutNulls() {
        when(service.userInfo("Bearer at")).thenReturn(new UserInfo("alice", "Alice Liddell", null, null));

        for (var request : new MockMvcTester.MockMvcRequestBuilder[] {mvc.get(), mvc.post()}) {
            assertThat(request.uri("/userinfo").header("Authorization", "Bearer at"))
                    .hasStatusOk().hasHeader("Cache-Control", "no-store")
                    .bodyJson().isStrictlyEqualTo("""
                            {"sub": "alice", "name": "Alice Liddell"}
                            """);
        }
    }

    @Test
    void emailScopeSerializesEmailVerified() {
        when(service.userInfo("Bearer at")).thenReturn(new UserInfo("alice", null, "alice@example.com", true));

        assertThat(mvc.get().uri("/userinfo").header("Authorization", "Bearer at"))
                .bodyJson().extractingPath("$.email_verified").isEqualTo(true);
    }

    @Test
    void invalidTokenIs401WithBearerChallenge() {
        when(service.userInfo(null)).thenThrow(new InvalidToken("Bearer access token is required"));

        assertThat(mvc.get().uri("/userinfo")).hasStatus(401)
                .hasHeader("WWW-Authenticate", "Bearer realm=\"oauth2broker\", error=\"invalid_token\", "
                        + "error_description=\"Bearer access token is required\"")
                .bodyJson().extractingPath("$.error").isEqualTo("invalid_token");
    }

    @Test
    void insufficientScopeIs403WithBearerChallenge() {
        when(service.userInfo("Bearer at")).thenThrow(new InsufficientScope("The openid scope is required"));

        assertThat(mvc.post().uri("/userinfo").header("Authorization", "Bearer at")).hasStatus(403)
                .hasHeader("WWW-Authenticate", "Bearer realm=\"oauth2broker\", error=\"insufficient_scope\", "
                        + "error_description=\"The openid scope is required\"");
    }
}
