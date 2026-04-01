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

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapVersionTool}. */
class ZapVersionToolUnitTest {

    private ZapVersionTool tool;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        tool = new ZapVersionTool();
    }

    @Test
    void shouldReturnCorrectName() {
        assertThat(tool.getName(), equalTo("zap_version"));
    }

    @Test
    void shouldHaveEmptyInputSchema() {
        assertThat(tool.getInputSchema().properties().entrySet(), is(empty()));
        assertThat(tool.getInputSchema().required(), is(empty()));
    }

    @Test
    void shouldReturnVersion() throws McpToolException {
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolResult result = tool.execute(args);

        assertThat(result.text(), notNullValue());
    }

    @Test
    void shouldReturnSuccessResult() throws McpToolException {
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolResult result = tool.execute(args);

        assertThat(result.isError(), is(false));
    }
}
