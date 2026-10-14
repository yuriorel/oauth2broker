package com.oauth2broker.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.StructuredTaskScope;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class RequestIdFilterTest {

    @Test
    void bindsRequestIdForTheRequestAndItsSubtasks() throws Exception {
        var seen = new String[2];
        var servlet = new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) {
                seen[0] = RequestContext.CURRENT.get().requestId();
                try (var tasks = StructuredTaskScope.open()) {
                    var subtask = tasks.fork(() -> RequestContext.CURRENT.get().requestId());
                    Subtasks.join(tasks);
                    seen[1] = subtask.get();
                }
            }
        };
        var response = new MockHttpServletResponse();

        new RequestIdFilter().doFilter(new MockHttpServletRequest(), response, new MockFilterChain(servlet));

        assertThat(seen).containsOnly(response.getHeader(RequestIdFilter.REQUEST_ID)).doesNotContainNull();
        assertThat(RequestContext.CURRENT.isBound()).isFalse();
    }

    @Test
    void eachRequestGetsItsOwnId() throws Exception {
        var first = new MockHttpServletResponse();
        var second = new MockHttpServletResponse();
        var filter = new RequestIdFilter();

        filter.doFilter(new MockHttpServletRequest(), first, new MockFilterChain());
        filter.doFilter(new MockHttpServletRequest(), second, new MockFilterChain());

        assertThat(first.getHeader(RequestIdFilter.REQUEST_ID))
                .isNotEqualTo(second.getHeader(RequestIdFilter.REQUEST_ID));
    }
}
