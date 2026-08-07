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
package org.zaproxy.addon.mcp.tools;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.mcp.McpTool.InputSchema;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapSendRequestTool}. */
class ZapSendRequestToolUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private ExtensionLoader extensionLoader;
    private Model model;
    private Session session;
    private ExtensionUserManagement extUserManagement;
    private AtomicReference<HttpMessage> lastSent;
    private AtomicReference<Boolean> lastFollowRedirects;
    private ZapSendRequestTool tool;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));
        extUserManagement =
                mock(ExtensionUserManagement.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(extensionLoader.getExtension(ExtensionUserManagement.class))
                .willReturn(extUserManagement);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
        Control.getSingleton().setMode(Mode.standard);

        lastSent = new AtomicReference<>();
        lastFollowRedirects = new AtomicReference<>();
        tool =
                new ZapSendRequestTool(
                        (msg, followRedirects) -> {
                            lastSent.set(msg);
                            lastFollowRedirects.set(followRedirects);
                            msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
                            msg.setResponseBody("hello");
                            msg.setTimeElapsedMillis(42);
                        });
    }

    @Test
    void shouldReturnCorrectName() {
        assertThat(tool.getName(), equalTo("zap_send_request"));
    }

    @Test
    void shouldRequireUrlInSchema() {
        InputSchema schema = tool.getInputSchema();
        assertThat(schema.required(), equalTo(List.of("url")));
        assertThat(schema.properties(), hasKey("url"));
        assertThat(schema.properties(), hasKey("method"));
        assertThat(schema.properties(), hasKey("headers"));
        assertThat(schema.properties(), hasKey("user"));
    }

    @Test
    void shouldRejectMissingUrl() {
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectEmptyUrl() {
        ToolArguments args = new ToolArguments(Map.of("url", "  "), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectInvalidBoolean() {
        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "persist", "yes"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectRequestInSafeMode() {
        Control.getSingleton().setMode(Mode.safe);
        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "persist", "false"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectOutOfScopeRequestInProtectMode() {
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(false);
        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "persist", "false"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldSendStructuredRequestAndReturnJson() throws Exception {
        ToolArguments args =
                new ToolArguments(
                        Map.of(
                                "url",
                                "https://example.com/api",
                                "method",
                                "POST",
                                "body",
                                "{\"a\":1}",
                                "persist",
                                "false",
                                "follow_redirects",
                                "true"),
                        Map.of("headers", List.of("Accept: application/json", "X-Test: 1")));

        McpToolResult result = tool.execute(args);

        assertThat(result.isError(), is(false));
        assertThat(lastFollowRedirects.get(), is(true));
        HttpMessage sent = lastSent.get();
        assertThat(sent.getRequestHeader().getMethod(), equalTo("POST"));
        assertThat(sent.getRequestHeader().getURI().toString(), equalTo("https://example.com/api"));
        assertThat(sent.getRequestHeader().getHeader("Accept"), equalTo("application/json"));
        assertThat(sent.getRequestHeader().getHeader("X-Test"), equalTo("1"));
        assertThat(sent.getRequestBody().toString(), equalTo("{\"a\":1}"));

        JsonNode json = OBJECT_MAPPER.readTree(result.text());
        assertThat(json.get("statusCode").asInt(), equalTo(200));
        assertThat(json.get("reasonPhrase").asText(), equalTo("OK"));
        assertThat(json.get("timeElapsedMillis").asInt(), equalTo(42));
        assertThat(json.get("responseBody").asText(), equalTo("hello"));
        assertThat(json.has("historyId"), is(false));
        assertThat(json.get("requestHeader").asText(), containsString("POST"));
        assertThat(json.get("responseHeader").asText(), containsString("200"));
    }

    @Test
    void shouldSendAsResolvedUser() throws Exception {
        Context context = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context.getId()).willReturn(1);
        given(context.getName()).willReturn("app");
        given(session.getContexts()).willReturn(List.of(context));
        given(session.getContext("app")).willReturn(context);

        User user = mock(User.class, withSettings().strictness(Strictness.LENIENT));
        given(user.getName()).willReturn("alice");
        ContextUserAuthManager authManager =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        given(authManager.getUsers()).willReturn(List.of(user));
        given(extUserManagement.getContextUserAuthManager(1)).willReturn(authManager);

        ToolArguments args =
                new ToolArguments(
                        Map.of(
                                "url",
                                "https://example.com/",
                                "user",
                                "alice",
                                "context",
                                "app",
                                "persist",
                                "false"),
                        Map.of());

        tool.execute(args);

        assertThat(lastSent.get().getRequestingUser(), equalTo(user));
    }

    @Test
    void shouldRejectUnknownUser() {
        Context context = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context.getId()).willReturn(1);
        given(session.getContexts()).willReturn(List.of(context));
        ContextUserAuthManager authManager =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        given(authManager.getUsers()).willReturn(List.of());
        given(extUserManagement.getContextUserAuthManager(1)).willReturn(authManager);

        ToolArguments args =
                new ToolArguments(
                        Map.of(
                                "url",
                                "https://example.com/",
                                "user",
                                "missing",
                                "persist",
                                "false"),
                        Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
        assertThat(lastSent.get(), is((HttpMessage) null));
    }

    @Test
    void shouldRejectAmbiguousUserWithoutContext() {
        Context context1 = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        Context context2 = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context1.getId()).willReturn(1);
        given(context2.getId()).willReturn(2);
        given(session.getContexts()).willReturn(List.of(context1, context2));

        User user1 = mock(User.class, withSettings().strictness(Strictness.LENIENT));
        User user2 = mock(User.class, withSettings().strictness(Strictness.LENIENT));
        given(user1.getName()).willReturn("alice");
        given(user2.getName()).willReturn("alice");
        ContextUserAuthManager authManager1 =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        ContextUserAuthManager authManager2 =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        given(authManager1.getUsers()).willReturn(List.of(user1));
        given(authManager2.getUsers()).willReturn(List.of(user2));
        given(extUserManagement.getContextUserAuthManager(1)).willReturn(authManager1);
        given(extUserManagement.getContextUserAuthManager(2)).willReturn(authManager2);

        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "user", "alice", "persist", "false"),
                        Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldDefaultMethodToGetAndNotFollowRedirects() throws Exception {
        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "persist", "false"), Map.of());

        tool.execute(args);

        assertThat(lastSent.get().getRequestHeader().getMethod(), equalTo("GET"));
        assertThat(lastFollowRedirects.get(), is(false));
        assertThat(lastSent.get().getRequestingUser(), is((User) null));
    }

    @Test
    void shouldNotSendWhenUserManagementMissing() {
        given(extensionLoader.getExtension(ExtensionUserManagement.class)).willReturn(null);
        ToolArguments args =
                new ToolArguments(
                        Map.of("url", "https://example.com/", "user", "alice", "persist", "false"),
                        Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
        assertThat(lastSent.get(), is((HttpMessage) null));
    }
}
