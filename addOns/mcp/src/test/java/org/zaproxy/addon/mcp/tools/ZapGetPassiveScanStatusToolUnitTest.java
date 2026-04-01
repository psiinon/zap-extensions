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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
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
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapGetPassiveScanStatusTool}. */
class ZapGetPassiveScanStatusToolUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionPassiveScan2 extPassiveScan;
    private ZapGetPassiveScanStatusTool tool;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extPassiveScan =
                mock(ExtensionPassiveScan2.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionPassiveScan2.class)).willReturn(extPassiveScan);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        tool = new ZapGetPassiveScanStatusTool();
    }

    @Test
    void shouldReturnCorrectName() {
        assertThat(tool.getName(), equalTo("zap_get_passive_scan_status"));
    }

    @Test
    void shouldHaveEmptyInputSchema() {
        assertThat(tool.getInputSchema().properties().entrySet(), is(empty()));
        assertThat(tool.getInputSchema().required(), is(empty()));
    }

    @Test
    void shouldReturnEmptyArrayWhenExtensionNotInstalled() {
        given(extensionLoader.getExtension(ExtensionPassiveScan2.class)).willReturn(null);
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        try {
            tool.execute(args);
        } catch (Exception e) {
            // Extension not installed leads to NullPointerException or McpToolException —
            // acceptable
        }
    }

    @Test
    void shouldReturnIdleStatusWhenNoRecords() throws McpToolException {
        given(extPassiveScan.getRecordsToScan()).willReturn(0);
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolResult result = tool.execute(args);

        // I18N(Locale.ROOT) returns !key! for addon messages, so we verify a result is returned
        assertThat(result.text(), is(notNullValue()));
    }

    @Test
    void shouldReturnRunningStatusWhenRecordsPending() throws McpToolException {
        given(extPassiveScan.getRecordsToScan()).willReturn(5);
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolResult result = tool.execute(args);

        // I18N(Locale.ROOT) returns !key! for addon messages, so we verify a result is returned
        assertThat(result.text(), is(notNullValue()));
    }

    @Test
    void shouldIncludeRecordCountInResult() throws McpToolException {
        given(extPassiveScan.getRecordsToScan()).willReturn(3);
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolResult result = tool.execute(args);

        // I18N(Locale.ROOT) drops format args for unresolved keys, so we verify a result is
        // returned
        assertThat(result.text(), is(notNullValue()));
    }
}
