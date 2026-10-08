package com.oauth2broker.authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.util.UriComponentsBuilder;

import com.oauth2broker.TestProperties;
import com.oauth2broker.authorize.AuthorizeOutcome.ErrorPage;
import com.oauth2broker.authorize.AuthorizeOutcome.LoginPage;
import com.oauth2broker.authorize.AuthorizeOutcome.Redirect;
import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.client.ClientRepository;
import com.oauth2broker.user.User;
import com.oauth2broker.user.UserRepository;

class AuthorizationServiceTest {

    private static final String CALLBACK = "http://localhost:8080/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
    private static final BCryptPasswordEncoder BCRYPT = new BCryptPasswordEncoder(4);

    private final ClientRepository clients = mock(ClientRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final AuthorizationRequestRepository requests = mock(AuthorizationRequestRepository.class);
    private final AuthorizationCodeRepository codes = mock(AuthorizationCodeRepository.class);
    private final AuthorizationService service = new AuthorizationService(clients, users, requests, codes, BCRYPT,
            TestProperties.create(), Clock.fixed(NOW, ZoneOffset.UTC));

    private final AuthorizationRequest pending = new AuthorizationRequest("web-app", CALLBACK,
            Set.of("openid", "profile"), "a b&c", "n-1", CHALLENGE);

    @BeforeEach
    void setUp() {
        when(clients.find("web-app")).thenReturn(Optional.of(new ClientRegistration("web-app",
                AuthMethod.CLIENT_SECRET_BASIC, "hash", null, List.of(CALLBACK), Set.of("openid", "profile", "email"))));
        when(users.find("alice")).thenReturn(Optional.of(
                new User("alice", BCRYPT.encode("wonderland"), "Alice", "alice@example.com", true)));
    }

    private static AuthorizeParams valid() {
        return new AuthorizeParams("code", "web-app", CALLBACK, "openid profile", "xyz", "n-1", CHALLENGE, "S256");
    }

    @Test
    void validRequestIsStoredAndShowsLoginPage() {
        when(requests.save(any())).thenReturn("req-1");

        var outcome = service.authorize(valid());

        assertThat(outcome).isEqualTo(new LoginPage("req-1", "web-app", null, null));
        verify(requests).save(new AuthorizationRequest("web-app", CALLBACK, Set.of("openid", "profile"), "xyz",
                "n-1", CHALLENGE));
    }

    @Test
    void stateAndNonceAreOptional() {
        when(requests.save(any())).thenReturn("req-1");

        var outcome = service.authorize(new AuthorizeParams("code", "web-app", CALLBACK, "openid", null, null,
                CHALLENGE, "S256"));

        assertThat(outcome).isInstanceOf(LoginPage.class);
    }

    @Test
    void missingClientShowsErrorPage() {
        var outcome = service.authorize(new AuthorizeParams("code", null, CALLBACK, "openid", "xyz", null,
                CHALLENGE, "S256"));

        assertThat(outcome).isEqualTo(new ErrorPage("Unknown client."));
        verifyNoInteractions(requests);
    }

    @Test
    void unknownClientShowsErrorPage() {
        when(clients.find("nope")).thenReturn(Optional.empty());

        var outcome = service.authorize(new AuthorizeParams("code", "nope", CALLBACK, "openid", "xyz", null,
                CHALLENGE, "S256"));

        assertThat(outcome).isEqualTo(new ErrorPage("Unknown client."));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {
            "null",
            "http://localhost:8080/other",
            "http://localhost:8080/callback/",
            "http://localhost:8080/callback?x=1",
            "http://evil.example/callback"})
    void redirectUriMustMatchExactlyOrErrorPageIsShown(String redirectUri) {
        var outcome = service.authorize(new AuthorizeParams("code", "web-app", redirectUri, "openid", "xyz", null,
                CHALLENGE, "S256"));

        assertThat(outcome).isEqualTo(new ErrorPage("The redirect URI is not registered for this client."));
        verifyNoInteractions(requests);
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {
            "null,  openid,         " + CHALLENGE + ", S256,  invalid_request",
            "token, openid,         " + CHALLENGE + ", S256,  unsupported_response_type",
            "code,  null,           " + CHALLENGE + ", S256,  invalid_scope",
            "code,  '  ',           " + CHALLENGE + ", S256,  invalid_scope",
            "code,  openid admin,   " + CHALLENGE + ", S256,  invalid_scope",
            "code,  openid,         null,              S256,  invalid_request",
            "code,  openid,         " + CHALLENGE + ", null,  invalid_request",
            "code,  openid,         " + CHALLENGE + ", plain, invalid_request",
            "code,  openid,         too-short,         S256,  invalid_request",
            "code,  openid,         " + CHALLENGE + "=,S256,  invalid_request"})
    void otherErrorsRedirectToClientWithStateAndIssuer(String responseType, String scope, String challenge,
                                                        String method, String error) {
        var outcome = service.authorize(new AuthorizeParams(responseType, "web-app", CALLBACK, scope, "xyz", null,
                challenge, method));

        var query = queryOf(outcome);
        assertThat(query.getFirst("error")).isEqualTo(error);
        assertThat(query.getFirst("error_description")).isNotBlank();
        assertThat(query.getFirst("state")).isEqualTo("xyz");
        assertThat(query.getFirst("iss")).isEqualTo("https%3A%2F%2Flocalhost%3A8443");
        assertThat(query).doesNotContainKey("code");
        verifyNoInteractions(requests);
    }

    @Test
    void errorRedirectLeavesOutMissingState() {
        var outcome = service.authorize(new AuthorizeParams("token", "web-app", CALLBACK, "openid", null, null,
                CHALLENGE, "S256"));

        assertThat(queryOf(outcome)).containsOnlyKeys("error", "error_description", "iss");
    }

    @Test
    void correctPasswordIssuesCodeAndRedirectsWithCodeStateAndIssuer() {
        when(requests.find("req-1")).thenReturn(Optional.of(pending));
        when(requests.take("req-1")).thenReturn(Optional.of(pending));
        when(codes.save(any())).thenReturn("code-1");

        var outcome = service.login("req-1", "alice", "wonderland");

        assertThat(outcome).isEqualTo(new Redirect(java.net.URI.create(
                CALLBACK + "?code=code-1&state=a+b%26c&iss=https%3A%2F%2Flocalhost%3A8443")));
        verify(codes).save(new AuthorizationCode("web-app", CALLBACK, "alice", Set.of("openid", "profile"), "n-1",
                CHALLENGE, NOW));
    }

    @Test
    void wrongPasswordShowsLoginPageAgainAndKeepsRequest() {
        when(requests.find("req-1")).thenReturn(Optional.of(pending));

        var outcome = service.login("req-1", "alice", "wrong");

        assertThat(outcome).isEqualTo(new LoginPage("req-1", "web-app", "alice", "Invalid username or password."));
        verify(requests, never()).take(any());
        verifyNoInteractions(codes);
    }

    @Test
    void unknownUserShowsSameErrorAsWrongPassword() {
        when(requests.find("req-1")).thenReturn(Optional.of(pending));
        when(users.find("mallory")).thenReturn(Optional.empty());

        var outcome = service.login("req-1", "mallory", "wonderland");

        assertThat(outcome).isEqualTo(new LoginPage("req-1", "web-app", "mallory", "Invalid username or password."));
        verifyNoInteractions(codes);
    }

    @Test
    void missingCredentialsShowLoginPageAgain() {
        when(requests.find("req-1")).thenReturn(Optional.of(pending));

        assertThat(service.login("req-1", null, null)).isInstanceOf(LoginPage.class);
        assertThat(service.login("req-1", "alice", null)).isInstanceOf(LoginPage.class);
        verifyNoInteractions(codes);
    }

    @Test
    void expiredOrUnknownRequestShowsErrorPage() {
        when(requests.find("gone")).thenReturn(Optional.empty());

        assertThat(service.login("gone", "alice", "wonderland")).isInstanceOf(ErrorPage.class);
        assertThat(service.login(null, "alice", "wonderland")).isInstanceOf(ErrorPage.class);
        verifyNoInteractions(codes);
    }

    @Test
    void requestCompletedConcurrentlyShowsErrorPage() {
        when(requests.find("req-1")).thenReturn(Optional.of(pending));
        when(requests.take("req-1")).thenReturn(Optional.empty());

        assertThat(service.login("req-1", "alice", "wonderland")).isInstanceOf(ErrorPage.class);
        verifyNoInteractions(codes);
    }

    private static org.springframework.util.MultiValueMap<String, String> queryOf(AuthorizeOutcome outcome) {
        assertThat(outcome).isInstanceOf(Redirect.class);
        var location = ((Redirect) outcome).location();
        assertThat(location.toString()).startsWith(CALLBACK + "?");
        return UriComponentsBuilder.fromUri(location).build().getQueryParams();
    }
}
