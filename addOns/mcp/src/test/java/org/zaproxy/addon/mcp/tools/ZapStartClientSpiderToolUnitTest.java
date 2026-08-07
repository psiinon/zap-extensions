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
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
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
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapStartClientSpiderTool}. */
class ZapStartClientSpiderToolUnitTest {

    private ExtensionLoader extensionLoader;
    private Model model;
    private Session session;
    private ExtensionAutomation extAutomation;
    private ZapStartClientSpiderTool tool;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));
        extAutomation =
                mock(ExtensionAutomation.class, withSettings().strictness(Strictness.LENIENT));
        AutomationJob jobTemplate =
                mock(AutomationJob.class, withSettings().strictness(Strictness.LENIENT));
        AutomationJob job =
                mock(AutomationJob.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(extensionLoader.getExtension(ExtensionAutomation.class)).willReturn(extAutomation);
        given(extAutomation.getAutomationJob("spiderClient")).willReturn(jobTemplate);
        given(jobTemplate.newJob()).willReturn(job);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
        Control.getSingleton().setMode(Mode.standard);
        tool = new ZapStartClientSpiderTool();
    }

    @Test
    void shouldReturnCorrectNameAndSchema() {
        assertThat(tool.getName(), equalTo("zap_start_client_spider"));
        assertThat(tool.getInputSchema().properties(), hasKey("target"));
        assertThat(tool.getInputSchema().properties(), hasKey("browser_id"));
        assertThat(tool.getInputSchema().properties(), hasKey("max_duration"));
        assertThat(tool.getInputSchema().properties(), hasKey("max_crawl_depth"));
        assertThat(tool.getInputSchema().properties(), hasKey("max_children"));
        assertThat(tool.getInputSchema().required().contains("target"), is(true));
    }

    @Test
    void shouldRejectUrlTargetInSafeMode() {
        Control.getSingleton().setMode(Mode.safe);
        ToolArguments args = new ToolArguments(Map.of("target", "https://example.com/"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectOutOfScopeUrlTargetInProtectMode() {
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(false);
        ToolArguments args = new ToolArguments(Map.of("target", "https://example.com/"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldRejectInvalidIntegerParam() {
        AutomationJob job =
                mock(AutomationJob.class, withSettings().strictness(Strictness.LENIENT));
        ToolArguments args =
                new ToolArguments(
                        Map.of("target", "https://example.com/", "max_duration", "abc"), Map.of());

        McpToolException ex =
                assertThrows(McpToolException.class, () -> tool.configureJob(job, args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }
}
