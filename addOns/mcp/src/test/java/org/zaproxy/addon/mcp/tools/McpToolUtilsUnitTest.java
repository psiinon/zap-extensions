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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URI;
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
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link McpToolUtils}. */
class McpToolUtilsUnitTest {

    private ExtensionLoader extensionLoader;
    private Model model;
    private Session session;
    private ExtensionUserManagement extUserManagement;

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
    }

    @Test
    void shouldRejectUriInSafeMode() throws Exception {
        Control.getSingleton().setMode(Mode.safe);
        URI uri = new URI("https://example.com/", true);

        assertThat(McpToolUtils.isValidForCurrentMode(uri), is(false));
    }

    @Test
    void shouldRejectOutOfScopeUriInProtectMode() throws Exception {
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(false);
        URI uri = new URI("https://example.com/", true);

        assertThat(McpToolUtils.isValidForCurrentMode(uri), is(false));
    }

    @Test
    void shouldAllowInScopeUriInProtectMode() throws Exception {
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(true);
        URI uri = new URI("https://example.com/", true);

        assertThat(McpToolUtils.isValidForCurrentMode(uri), is(true));
    }

    @Test
    void shouldAllowUriInStandardMode() throws Exception {
        Control.getSingleton().setMode(Mode.standard);
        URI uri = new URI("https://example.com/", true);

        assertThat(McpToolUtils.isValidForCurrentMode(uri), is(true));
    }

    @Test
    void shouldParseBooleanDefaultsAndValues() throws Exception {
        assertThat(McpToolUtils.parseBoolean(null, true, "flag"), is(true));
        assertThat(McpToolUtils.parseBoolean("  ", false, "flag"), is(false));
        assertThat(McpToolUtils.parseBoolean("true", false, "flag"), is(true));
        assertThat(McpToolUtils.parseBoolean("FALSE", true, "flag"), is(false));
    }

    @Test
    void shouldRejectInvalidBoolean() {
        assertThrows(McpToolException.class, () -> McpToolUtils.parseBoolean("yes", false, "flag"));
    }

    @Test
    void shouldRequireNonBlank() throws Exception {
        assertThat(McpToolUtils.requireNonBlank("  value  ", "name"), equalTo("value"));
        assertThrows(McpToolException.class, () -> McpToolUtils.requireNonBlank(null, "name"));
        assertThrows(McpToolException.class, () -> McpToolUtils.requireNonBlank("  ", "name"));
    }

    @Test
    void shouldOptionalTrim() {
        assertThat(McpToolUtils.optionalTrim(null), is(nullValue()));
        assertThat(McpToolUtils.optionalTrim("  "), is(nullValue()));
        assertThat(McpToolUtils.optionalTrim("  x  "), equalTo("x"));
    }

    @Test
    void shouldPutOptionalInt() throws Exception {
        Map<String, Object> params = new LinkedHashMap<>();

        McpToolUtils.putOptionalInt(params, "key", null, "name");
        assertThat(params, not(hasKey("key")));

        McpToolUtils.putOptionalInt(params, "key", "  5  ", "name");
        assertThat(params.get("key"), equalTo(5));

        assertThrows(
                McpToolException.class,
                () -> McpToolUtils.putOptionalInt(params, "key", "abc", "name"));
    }

    @Test
    void shouldResolveUserInNamedContext() throws Exception {
        Context context = mock(Context.class, withSettings().strictness(Strictness.LENIENT));
        given(context.getId()).willReturn(1);
        given(session.getContext("app")).willReturn(context);
        User user = mock(User.class, withSettings().strictness(Strictness.LENIENT));
        given(user.getName()).willReturn("alice");
        ContextUserAuthManager authManager =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        given(authManager.getUsers()).willReturn(List.of(user));
        given(extUserManagement.getContextUserAuthManager(1)).willReturn(authManager);

        assertThat(McpToolUtils.resolveUser("alice", "app"), equalTo(user));
    }

    @Test
    void shouldRejectAmbiguousUser() {
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

        McpToolException ex =
                assertThrows(McpToolException.class, () -> McpToolUtils.resolveUser("alice", null));

        assertThat(ex.getMessage(), is(notNullValue()));
    }
}
