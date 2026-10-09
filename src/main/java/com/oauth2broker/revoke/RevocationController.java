package com.oauth2broker.revoke;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.config.OpenApiConfig;
import com.oauth2broker.web.ErrorResponse;
import com.oauth2broker.web.OAuthException.InvalidRequest;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "Revocation", description = "Revokes access and refresh tokens (RFC 7009)")
public class RevocationController {

    private final RevocationService service;

    public RevocationController(RevocationService service) {
        this.service = service;
    }

    @PostMapping(path = "/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Token revocation",
            description = "Revokes an access or refresh token issued to the authenticated client. Responds 200 also "
                    + "when the token is unknown, expired or belongs to another client. Client authentication as "
                    + "at the token endpoint.",
            security = @SecurityRequirement(name = OpenApiConfig.CLIENT_SECRET_BASIC))
    @ApiResponse(responseCode = "200", description = "Token revoked, or nothing to revoke", content = @Content)
    @ApiResponse(responseCode = "400", description = "invalid_request",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "401", description = "invalid_client",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<Void> revoke(
            @Parameter(hidden = true)
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @Parameter(description = "The access or refresh token to revoke", required = true)
            @RequestParam(required = false) String token,
            @Parameter(description = "access_token or refresh_token; decides which lookup runs first")
            @RequestParam(name = "token_type_hint", required = false) String tokenTypeHint,
            @Parameter(description = "Client identifier: required for public clients, optional with client_assertion")
            @RequestParam(name = "client_id", required = false) String clientId,
            @Parameter(description = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer (private_key_jwt)")
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @Parameter(description = "JWT signed with the client's registered key, RS256 or ES256 (private_key_jwt)")
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        if (token == null || token.isBlank()) {
            throw new InvalidRequest("token is required");
        }
        var credentials = ClientCredentials.from(authorization, clientId, clientAssertionType, clientAssertion);
        service.revoke(token, tokenTypeHint, credentials);
        return ResponseEntity.ok().build();
    }
}
