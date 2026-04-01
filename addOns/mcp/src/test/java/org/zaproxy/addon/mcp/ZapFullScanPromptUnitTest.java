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
package org.zaproxy.addon.mcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.prompts.ZapFullScanPrompt;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapFullScanPrompt}. */
class ZapFullScanPromptUnitTest {

    private ZapFullScanPrompt prompt;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        prompt = new ZapFullScanPrompt();
    }

    @Test
    void shouldHaveCorrectName() {
        assertThat(prompt.getName(), equalTo("zap_full_scan"));
    }

    @Test
    void shouldHaveTwoArguments() {
        List<McpPrompt.PromptArgument> arguments = prompt.getArguments();

        assertThat(arguments, hasSize(2));
        McpPrompt.PromptArgument targetArg =
                arguments.stream().filter(a -> "target".equals(a.name())).findFirst().orElseThrow();
        assertThat(targetArg.required(), equalTo(true));
        McpPrompt.PromptArgument policyArg =
                arguments.stream().filter(a -> "policy".equals(a.name())).findFirst().orElseThrow();
        assertThat(policyArg.required(), equalTo(false));
    }

    @Test
    void shouldGenerateMessageWithTargetUrl() {
        List<McpPrompt.PromptMessage> messages =
                prompt.getMessages(Map.of("target", "https://example.com"));

        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).text(), containsString("https://example.com"));
    }

    @Test
    void shouldGenerateMessageWithPolicyWhenProvided() {
        List<McpPrompt.PromptMessage> messages =
                prompt.getMessages(Map.of("target", "https://example.com", "policy", "MyPolicy"));

        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).text(), containsString("MyPolicy"));
    }

    @Test
    void shouldGenerateMessageWithActiveScanStep() {
        List<McpPrompt.PromptMessage> messages =
                prompt.getMessages(Map.of("target", "https://example.com"));

        assertThat(messages, hasSize(1));
        String text = messages.get(0).text();
        assertThat(text, containsString("zap_start_active_scan"));
        assertThat(text, containsString("zap_get_active_scan_status"));
    }
}
