package com.oauth2broker.store;

import java.util.List;

import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.user.User;

/** Contents of {@code seed.json}. */
record Seed(List<ClientRegistration> clients, List<User> users) {
}
