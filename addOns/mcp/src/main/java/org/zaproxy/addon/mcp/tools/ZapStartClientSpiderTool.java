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

import java.util.LinkedHashMap;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.mcp.McpToolException;

/** MCP tool that starts the Client Spider via an automation plan. */
public class ZapStartClientSpiderTool extends ZapStartScanTool {

    @Override
    public String getName() {
        return "zap_start_client_spider";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.startclientspider.desc");
    }

    @Override
    protected String getMessageKeyPrefix() {
        return "mcp.tool.startclientspider";
    }

    @Override
    protected String getJobName() {
        return "spiderClient";
    }

    @Override
    protected String getJobNotAvailableErrorKey() {
        return "mcp.tool.startclientspider.error.noclientspider";
    }

    @Override
    protected void addSupplementaryProperties(Map<String, InputSchema.PropertyDef> properties) {
        properties.put(
                "browser_id",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.startclientspider.param.browserid")));
        properties.put(
                "max_duration",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString(
                                "mcp.tool.startclientspider.param.maxduration")));
        properties.put(
                "max_crawl_depth",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString(
                                "mcp.tool.startclientspider.param.maxcrawldepth")));
        properties.put(
                "max_children",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString(
                                "mcp.tool.startclientspider.param.maxchildren")));
    }

    @Override
    protected void configureJob(AutomationJob job, ToolArguments arguments)
            throws McpToolException {
        Map<String, Object> params = new LinkedHashMap<>();

        String target = McpToolUtils.optionalTrim(arguments.getString("target"));
        if (target != null
                && (target.toLowerCase().startsWith("http://")
                        || target.toLowerCase().startsWith("https://"))) {
            params.put("url", target);
        }

        String browserId = McpToolUtils.optionalTrim(arguments.getString("browser_id"));
        if (browserId != null) {
            params.put("browserId", browserId);
        }
        McpToolUtils.putOptionalInt(
                params, "maxDuration", arguments.getString("max_duration"), "max_duration");
        McpToolUtils.putOptionalInt(
                params, "maxCrawlDepth", arguments.getString("max_crawl_depth"), "max_crawl_depth");
        McpToolUtils.putOptionalInt(
                params, "maxChildren", arguments.getString("max_children"), "max_children");

        if (params.isEmpty()) {
            return;
        }

        AutomationProgress progress = new AutomationProgress();
        JobUtils.applyParamsToObject(
                params, job.getParameters(), job.getName(), new String[] {}, progress);
        if (progress.hasErrors()) {
            throw new McpToolException(progress.getErrors().get(0));
        }
    }
}
