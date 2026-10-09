package com.oauth2broker.userinfo;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oauth2broker.user.User;

/** UserInfo response (OpenID Connect Core 5.3.2). Claims outside the granted scope are left out. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserInfo(@JsonProperty("sub") String sub,
                       @JsonProperty("name") String name,
                       @JsonProperty("email") String email,
                       @JsonProperty("email_verified") Boolean emailVerified) {

    /** {@code profile} releases {@code name}; {@code email} releases {@code email} and {@code email_verified}. */
    static UserInfo of(User user, Set<String> scope) {
        var profile = scope.contains("profile");
        var email = scope.contains("email");
        return new UserInfo(user.username(), profile ? user.name() : null, email ? user.email() : null,
                email ? user.emailVerified() : null);
    }
}
