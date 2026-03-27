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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapStopAjaxSpiderTool}. */
class ZapStopAjaxSpiderToolUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionAutomation extAutomation;
    private ZapStopAjaxSpiderTool tool;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAutomation =
                mock(ExtensionAutomation.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionAutomation.class)).willReturn(extAutomation);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        tool = new ZapStopAjaxSpiderTool();
    }

    @Test
    void shouldReturnCorrectNameAndInputSchema() {
        assertThat(tool.getName(), equalTo("zap_stop_ajax_spider"));
        assertThat(tool.getInputSchema(), is(notNullValue()));
        assertThat(tool.getInputSchema().properties().containsKey("scan_id"), is(true));
        assertThat(tool.getInputSchema().required().contains("scan_id"), is(true));
    }

    @Test
    void shouldThrowExceptionWhenScanIdNull() {
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolException ex =
                assertThrows(McpToolException.class, () -> tool.execute(args));
        assertThat(
                ex.getMessage(),
                containsString(
                        Constant.messages.getString(
                                "mcp.tool.stopajaxspider.error.missingscanid")));
    }

    @Test
    void shouldThrowExceptionWhenScanIdBlank() {
        ToolArguments args = new ToolArguments(Map.of("scan_id", ""), Map.of());

        McpToolException ex =
                assertThrows(McpToolException.class, () -> tool.execute(args));
        assertThat(
                ex.getMessage(),
                containsString(
                        Constant.messages.getString(
                                "mcp.tool.stopajaxspider.error.missingscanid")));
    }

    @Test
    void shouldThrowExceptionWhenScanNotFound() {
        given(extAutomation.getScanProgress("ajaxspider-1")).willReturn(-1);
        ToolArguments args = new ToolArguments(Map.of("scan_id", "ajaxspider-1"), Map.of());

        McpToolException ex =
                assertThrows(McpToolException.class, () -> tool.execute(args));
        assertThat(
                ex.getMessage(),
                containsString(
                        Constant.messages.getString(
                                "mcp.tool.stopajaxspider.error.scanidnotfound", "ajaxspider-1")));
    }

    @Test
    void shouldStopScanSuccessfully() throws McpToolException {
        given(extAutomation.getScanProgress("ajaxspider-1")).willReturn(50);
        ToolArguments args = new ToolArguments(Map.of("scan_id", "ajaxspider-1"), Map.of());

        tool.execute(args);

        verify(extAutomation).stopLongRunningJob("ajaxspider-1");
    }

    @Test
    void shouldReturnSuccessMessageOnStop() throws McpToolException {
        given(extAutomation.getScanProgress("ajaxspider-1")).willReturn(50);
        ToolArguments args = new ToolArguments(Map.of("scan_id", "ajaxspider-1"), Map.of());

        McpToolResult result = tool.execute(args);

        assertThat(
                result.text(),
                containsString(
                        Constant.messages.getString("mcp.tool.stopajaxspider.success")));
    }
}
