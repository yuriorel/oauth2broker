package com.oauth2broker.authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import com.oauth2broker.authorize.AuthorizeOutcome.ErrorPage;
import com.oauth2broker.authorize.AuthorizeOutcome.LoginPage;
import com.oauth2broker.authorize.AuthorizeOutcome.Redirect;

class AuthorizationControllerTest {

    private final AuthorizationService service = mock(AuthorizationService.class);
    private final MockMvcTester mvc = MockMvcTester.of(new AuthorizationController(service));

    @Test
    void getPassesQueryParametersAndRendersLoginPage() {
        when(service.authorize(new AuthorizeParams("code", "web-app", "http://localhost:8080/callback", "openid",
                "xyz", "n", "challenge", "S256"))).thenReturn(new LoginPage("req-1", "web-app", null, null));

        var result = mvc.get().uri("/authorize?response_type=code&client_id=web-app"
                + "&redirect_uri=http://localhost:8080/callback&scope=openid&state=xyz&nonce=n"
                + "&code_challenge=challenge&code_challenge_method=S256").exchange();

        assertThat(result).hasStatusOk().hasContentTypeCompatibleWith(MediaType.TEXT_HTML)
                .hasHeader("Cache-Control", "no-store")
                .hasHeader("Content-Security-Policy", "frame-ancestors 'none'")
                .bodyText().contains("name=\"request_id\" value=\"req-1\"", "<strong>web-app</strong>",
                        "method=\"post\" action=\"/authorize\"");
    }

    @Test
    void errorPageIsBadRequest() {
        when(service.authorize(new AuthorizeParams(null, null, null, null, null, null, null, null)))
                .thenReturn(new ErrorPage("Unknown client."));

        assertThat(mvc.get().uri("/authorize")).hasStatus(400).hasContentTypeCompatibleWith(MediaType.TEXT_HTML)
                .bodyText().contains("Unknown client.");
    }

    @Test
    void redirectIsFound() {
        var location = URI.create("http://localhost:8080/callback?error=invalid_scope&iss=x");
        when(service.authorize(new AuthorizeParams("code", "web-app", null, null, null, null, null, null)))
                .thenReturn(new Redirect(location));

        assertThat(mvc.get().uri("/authorize?response_type=code&client_id=web-app")).hasStatus(302)
                .hasHeader("Location", location.toString()).hasHeader("Cache-Control", "no-store");
    }

    @Test
    void postPassesFormFieldsAndRedirectsWithCode() {
        var location = URI.create("http://localhost:8080/callback?code=c&iss=x");
        when(service.login("req-1", "alice", "wonderland")).thenReturn(new Redirect(location));

        assertThat(mvc.post().uri("/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .formField("request_id", "req-1").formField("username", "alice").formField("password", "wonderland"))
                .hasStatus(302).hasHeader("Location", location.toString());
    }

    @Test
    void postWithWrongPasswordRendersEscapedLoginPage() {
        when(service.login("req-1", "<b>x</b>", "bad"))
                .thenReturn(new LoginPage("req-1", "web-app", "<b>x</b>", "Invalid username or password."));

        assertThat(mvc.post().uri("/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .formField("request_id", "req-1").formField("username", "<b>x</b>").formField("password", "bad"))
                .hasStatusOk().bodyText()
                .contains("value=\"&lt;b&gt;x&lt;/b&gt;\"", "Invalid username or password.")
                .doesNotContain("<b>x</b>");
    }
}
