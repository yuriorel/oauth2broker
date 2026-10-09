package com.oauth2broker.revoke;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;
import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientAuthenticator;
import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.jose.SignedAccessToken;
import com.oauth2broker.jose.TokenSigner;
import com.oauth2broker.token.AccessTokenRecord;
import com.oauth2broker.token.RefreshTokenRecord;
import com.oauth2broker.token.TokenRepository;
import com.oauth2broker.web.OAuthException.InvalidClient;

class RevocationServiceTest {

    private final ClientAuthenticator authenticator = mock(ClientAuthenticator.class);
    private final TokenRepository tokens = mock(TokenRepository.class);
    private final RevocationService service = new RevocationService(authenticator, tokens);

    private final PublicClient spa = new PublicClient("spa-app");
    private final PublicClient web = new PublicClient("web-app");
    private final SignedAccessToken accessToken;

    RevocationServiceTest() throws Exception {
        accessToken = new TokenSigner(TestKeys.signingKey(), TestProperties.create(), Clock.systemUTC())
                .accessToken("spa-app", "alice", Set.of("openid"));
    }

    private static ClientRegistration client(String clientId) {
        return new ClientRegistration(clientId, AuthMethod.NONE, null, null, List.of(), Set.of("openid"));
    }

    @BeforeEach
    void setUp() {
        when(authenticator.authenticate(spa)).thenReturn(client("spa-app"));
        when(authenticator.authenticate(web)).thenReturn(client("web-app"));
        when(tokens.findAccessToken(anyString())).thenReturn(Optional.empty());
        when(tokens.findRefreshToken(anyString())).thenReturn(Optional.empty());
        when(tokens.findAccessToken(accessToken.jti()))
                .thenReturn(Optional.of(new AccessTokenRecord("spa-app", "alice", Set.of("openid"))));
        when(tokens.findRefreshToken("rt-1"))
                .thenReturn(Optional.of(new RefreshTokenRecord("spa-app", "alice", Set.of("openid"))));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {"null", "access_token", "refresh_token", "unknown_hint"})
    void revokesAccessTokenWithOrWithoutHint(String hint) {
        service.revoke(accessToken.value(), hint, spa);

        verify(tokens).deleteAccessToken(accessToken.jti());
        verify(tokens, never()).deleteRefreshToken(any());
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {"null", "access_token", "refresh_token", "unknown_hint"})
    void revokesRefreshTokenWithOrWithoutHint(String hint) {
        service.revoke("rt-1", hint, spa);

        verify(tokens).deleteRefreshToken("rt-1");
        verify(tokens, never()).deleteAccessToken(any());
    }

    @Test
    void refreshHintLooksUpRefreshTokenFirst() {
        service.revoke("rt-1", "refresh_token", spa);

        verify(tokens, never()).findAccessToken(any());
    }

    @Test
    void accessHintLooksUpAccessTokenFirst() {
        service.revoke(accessToken.value(), "access_token", spa);

        verify(tokens, never()).findRefreshToken(any());
    }

    @Test
    void tokenOfAnotherClientIsNotRevoked() {
        service.revoke(accessToken.value(), null, web);
        service.revoke("rt-1", null, web);

        verify(tokens, never()).deleteAccessToken(any());
        verify(tokens, never()).deleteRefreshToken(any());
    }

    @Test
    void unknownTokenIsIgnored() {
        service.revoke("unknown", null, spa);
        service.revoke("not.a.jwt", "access_token", spa);

        verify(tokens, never()).deleteAccessToken(any());
        verify(tokens, never()).deleteRefreshToken(any());
    }

    @Test
    void invalidClientIsRethrownAndNothingIsRevoked() {
        when(authenticator.authenticate(spa)).thenThrow(new InvalidClient("Client authentication failed"));

        assertThatThrownBy(() -> service.revoke("rt-1", null, spa)).isExactlyInstanceOf(InvalidClient.class);
        verify(tokens, never()).deleteRefreshToken(any());
    }
}
