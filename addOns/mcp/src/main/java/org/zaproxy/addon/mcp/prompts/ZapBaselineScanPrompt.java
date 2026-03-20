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
package org.zaproxy.addon.mcp.prompts;

import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.McpPrompt;

/** MCP prompt that guides an AI through a ZAP baseline (spider + passive) scan. */
public class ZapBaselineScanPrompt implements McpPrompt {

    @Override
    public String getName() {
        return "zap_baseline_scan";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.prompt.baselinescan.desc");
    }

    @Override
    public List<PromptArgument> getArguments() {
        return List.of(
                new PromptArgument(
                        "target",
                        Constant.messages.getString("mcp.prompt.baselinescan.arg.target"),
                        true));
    }

    @Override
    public List<PromptMessage> getMessages(Map<String, String> arguments) {
        String target = arguments.getOrDefault("target", "");
        String message =
                "Run a ZAP baseline scan against "
                        + target
                        + ". Use these steps:\n"
                        + "1. Call zap_start_spider with target="
                        + target
                        + " and wait for it to finish (poll zap_get_spider_status until progress is 100%).\n"
                        + "2. Call zap_start_ajax_spider with target="
                        + target
                        + " and wait for it to finish (poll zap_get_ajax_spider_status until it is stopped).\n"
                        + "3. Call zap_get_passive_scan_status and wait until the passive scan is idle (records to scan reaches 0).\n"
                        + "4. Call zap_generate_report with a suitable file_path and template to save a report.\n"
                        + "5. Summarise the findings.";
        return List.of(new PromptMessage("user", message));
    }
}
