package com.oauth2broker.it;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.options.AriaRole;

/** The broker's login form, opened in its own browser context. */
final class LoginPage implements AutoCloseable {

    private static final Predicate<String> CALLBACK = url -> url.startsWith(Broker.REDIRECT_URI);

    /** Query parameters of the redirect to the callback. */
    record Callback(Map<String, String> query) {

        String code() {
            return query.get("code");
        }

        String state() {
            return query.get("state");
        }
    }

    private final BrowserContext context;
    private final Page page;
    private final Response response;

    LoginPage(Browser browser, String authorizeUrl) {
        context = browser.newContext(new Browser.NewContextOptions().setIgnoreHTTPSErrors(true));
        page = context.newPage();
        response = page.navigate(authorizeUrl);
    }

    /** HTTP status of the authorization request. */
    int status() {
        return response.status();
    }

    String text() {
        return page.locator("body").innerText();
    }

    LoginPage signIn(String username, String password) {
        page.getByLabel("Username").fill(username);
        page.getByLabel("Password").fill(password);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        return this;
    }

    String error() {
        return page.getByRole(AriaRole.ALERT).innerText();
    }

    Callback callback() {
        page.waitForURL(CALLBACK);
        var query = URI.create(page.url()).getRawQuery();
        return new Callback(Arrays.stream(query.split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(pair -> pair[0], pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8))));
    }

    @Override
    public void close() {
        context.close();
    }
}
