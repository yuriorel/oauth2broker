package com.oauth2broker.authorize;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PagesTest {

    private static final String XSS = "\"><script>alert('x')</script>";

    @Test
    void loginPageEscapesEveryValue() {
        var html = Pages.login(XSS, XSS, XSS, XSS);

        assertThat(html).doesNotContain("<script>", "'x'");
        assertThat(html.split("&quot;&gt;&lt;script&gt;alert\\(&#39;x&#39;\\)&lt;/script&gt;", -1)).hasSize(5);
    }

    @Test
    void loginPageWithoutErrorHasNoAlertAndEmptyUsername() {
        var html = Pages.login("req-1", "web-app", null, null);

        assertThat(html).startsWith("<!DOCTYPE html>").contains("name=\"username\" value=\"\"")
                .doesNotContain("role=\"alert\"").contains("width: 100%;");
    }

    @Test
    void errorPageEscapesMessage() {
        assertThat(Pages.error(XSS)).doesNotContain("<script>").contains("&lt;script&gt;");
    }
}
