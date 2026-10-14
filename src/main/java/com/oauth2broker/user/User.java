package com.oauth2broker.user;

/// A user who signs in through the login form. The username is the `sub` claim.
public record User(String username, String passwordHash, String name, String email, boolean emailVerified) {
}
