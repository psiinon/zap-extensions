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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.LongRunningJob;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.model.Context;

/** MCP tool that starts the AJAX spider via an automation plan. */
public class ZapStartAjaxSpiderTool implements McpTool {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    public String getName() {
        return "zap_start_ajax_spider";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.startajaxspider.desc");
    }

    @Override
    public ObjectNode getInputSchema() {
        ObjectNode schema = OBJECT_MAPPER.createObjectNode();
        schema.put("type", "object");
        ObjectNode properties = schema.putObject("properties");
        properties
                .putObject("target")
                .put("type", "string")
                .put(
                        "description",
                        Constant.messages.getString("mcp.tool.startajaxspider.param.target"));
        schema.putArray("required").add("target");
        return schema;
    }

    @Override
    public McpToolResult execute(JsonNode arguments) throws McpToolException {
        JsonNode targetNode = arguments != null ? arguments.get("target") : null;
        if (targetNode == null || targetNode.isNull() || !targetNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.startajaxspider.error.missingtarget"));
        }

        String target = targetNode.asText().trim();
        if (target.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.startajaxspider.error.emptytarget"));
        }

        String targetFinal = target;

        String scanId = null;

        try {
            ExtensionAutomation extAutomation =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutomation.class);

            AutomationJob ajaxSpiderJob = extAutomation.getAutomationJob("spiderAjax");
            if (ajaxSpiderJob == null) {
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(
                                        "mcp.tool.startajaxspider.error.noajaxspider")));
            }
            ajaxSpiderJob = ajaxSpiderJob.newJob();

            AutomationPlan plan = new AutomationPlan();
            Session session = Model.getSingleton().getSession();
            Context context;

            if (isUrl(targetFinal)) {
                try {
                    new URI(targetFinal);
                } catch (Exception e) {
                    throw new RuntimeException(
                            new McpToolException(
                                    Constant.messages.getString(
                                            "mcp.tool.startajaxspider.error.invalidurl",
                                            targetFinal),
                                    e));
                }
                String contextName = urlToContextName(targetFinal);
                Context existing = session.getContext(contextName);
                if (existing != null) {
                    session.deleteContext(existing);
                }
                context = session.getNewContext(contextName);
                context.addIncludeInContextRegex(targetFinal + ".*");
                session.saveContext(context);
                plan.getEnv().addContext(context);
            } else {
                context = session.getContext(targetFinal);
                if (context == null) {
                    throw new RuntimeException(
                            new McpToolException(
                                    Constant.messages.getString(
                                            "mcp.tool.startajaxspider.error.contextnotfound",
                                            targetFinal)));
                }
                plan.getEnv().addContext(context);
            }
            plan.addJob(ajaxSpiderJob);

            extAutomation.registerPlan(plan);
            extAutomation.runPlanAsync(plan);

            scanId = waitForAjaxSpiderId((LongRunningJob) ajaxSpiderJob, ajaxSpiderJob);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof McpToolException mte) {
                throw mte;
            }
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.startajaxspider.error.failed", e.getMessage()),
                    e);
        }

        return McpToolResult.success(
                Constant.messages.getString("mcp.tool.startajaxspider.success", scanId));
    }

    private static String waitForAjaxSpiderId(LongRunningJob longRunningJob, AutomationJob job) {
        int maxAttempts = 50;
        int sleepMs = 200;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Thread.sleep(sleepMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(
                                        "mcp.tool.startajaxspider.error.failed", e.getMessage()),
                                e));
            }
            String id = longRunningJob.getId();
            if (id != null) {
                return id;
            }
            if (job.getStatus() == AutomationJob.Status.COMPLETED) {
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(
                                        "mcp.tool.startajaxspider.error.failed",
                                        "AJAX spider job finished without starting")));
            }
        }
        throw new RuntimeException(
                new McpToolException(
                        Constant.messages.getString(
                                "mcp.tool.startajaxspider.error.failed", "timeout")));
    }

    private static boolean isUrl(String target) {
        String t = target.toLowerCase().trim();
        return t.startsWith("http://") || t.startsWith("https://");
    }

    private static String urlToContextName(String url) {
        String result = url.trim();
        if (result.toLowerCase().startsWith("https://")) {
            result = result.substring(8);
        } else if (result.toLowerCase().startsWith("http://")) {
            result = result.substring(7);
        }
        return result.isEmpty() ? url : result;
    }
}
