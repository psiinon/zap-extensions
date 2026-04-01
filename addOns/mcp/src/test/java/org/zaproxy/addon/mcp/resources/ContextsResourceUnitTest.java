/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ContextsResource}. */
class ContextsResourceUnitTest {

    private Model model;
    private Session session;
    private ContextsResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        Model.setSingletonForTesting(model);
        resource = new ContextsResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://contexts"));
        assertThat(resource.getName(), equalTo("contexts"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoContexts() {
        given(session.getContexts()).willReturn(List.of());

        String content = resource.readContent();

        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnContextWithNameAndId() {
        Context context = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context.getId()).willReturn(1);
        given(context.getName()).willReturn("test");
        given(context.getIncludeInContextRegexs()).willReturn(List.of());
        given(context.getExcludeFromContextRegexs()).willReturn(List.of());
        given(session.getContexts()).willReturn(List.of(context));

        String content = resource.readContent();

        assertThat(
                content,
                equalTo(
                        "[{\"id\":1,\"name\":\"test\",\"includeRegexes\":[],\"excludeRegexes\":[]}]"));
    }

    @Test
    void shouldReturnIncludeAndExcludeRegexes() {
        Context context = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context.getId()).willReturn(1);
        given(context.getName()).willReturn("myContext");
        given(context.getIncludeInContextRegexs()).willReturn(List.of("http://example.com.*"));
        given(context.getExcludeFromContextRegexs()).willReturn(List.of(".*logout.*"));
        given(session.getContexts()).willReturn(List.of(context));

        String content = resource.readContent();

        assertThat(
                content,
                equalTo(
                        "[{\"id\":1,\"name\":\"myContext\","
                                + "\"includeRegexes\":[\"http://example.com.*\"],"
                                + "\"excludeRegexes\":[\".*logout.*\"]}]"));
    }

    @Test
    void shouldReturnMultipleContexts() {
        Context context1 = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context1.getId()).willReturn(1);
        given(context1.getName()).willReturn("first");
        given(context1.getIncludeInContextRegexs()).willReturn(List.of());
        given(context1.getExcludeFromContextRegexs()).willReturn(List.of());

        Context context2 = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context2.getId()).willReturn(2);
        given(context2.getName()).willReturn("second");
        given(context2.getIncludeInContextRegexs()).willReturn(List.of());
        given(context2.getExcludeFromContextRegexs()).willReturn(List.of());

        given(session.getContexts()).willReturn(List.of(context1, context2));

        String content = resource.readContent();

        assertThat(
                content,
                equalTo(
                        "[{\"id\":1,\"name\":\"first\",\"includeRegexes\":[],\"excludeRegexes\":[]},"
                                + "{\"id\":2,\"name\":\"second\",\"includeRegexes\":[],\"excludeRegexes\":[]}]"));
    }
}
