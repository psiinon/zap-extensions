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

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.utils.ThreadUtils;

/**
 * MCP tool that sends an HTTP request through ZAP using the manual request initiator, optionally as
 * a configured context user so authentication is applied.
 */
public class ZapSendRequestTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapSendRequestTool.class);

    @FunctionalInterface
    interface RequestSender {
        void send(HttpMessage msg, boolean followRedirects) throws IOException;
    }

    private final RequestSender requestSender;

    public ZapSendRequestTool() {
        this(
                (msg, followRedirects) ->
                        new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
                                .sendAndReceive(msg, followRedirects));
    }

    ZapSendRequestTool(RequestSender requestSender) {
        this.requestSender = requestSender;
    }

    @Override
    public String getName() {
        return "zap_send_request";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.sendrequest.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "url",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.url")));
        properties.put(
                "method",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.method")));
        properties.put(
                "headers",
                InputSchema.PropertyDef.ofStringArray(
                        Constant.messages.getString("mcp.tool.sendrequest.param.headers")));
        properties.put(
                "body",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.body")));
        properties.put(
                "http_version",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.httpversion")));
        properties.put(
                "user",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.user")));
        properties.put(
                "context",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.context")));
        properties.put(
                "follow_redirects",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.followredirects")));
        properties.put(
                "persist",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.sendrequest.param.persist")));
        return new InputSchema(properties, List.of("url"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String url = McpToolUtils.requireNonBlank(arguments.getString("url"), "url");
        String method = McpToolUtils.optionalTrim(arguments.getString("method"));
        if (method == null) {
            method = "GET";
        }
        String httpVersion = McpToolUtils.optionalTrim(arguments.getString("http_version"));
        if (httpVersion == null) {
            httpVersion = HttpHeader.HTTP11;
        }
        String body = arguments.getString("body");
        boolean followRedirects =
                McpToolUtils.parseBoolean(
                        arguments.getString("follow_redirects"), false, "follow_redirects");
        boolean persist =
                McpToolUtils.parseBoolean(arguments.getString("persist"), true, "persist");
        String userName = McpToolUtils.optionalTrim(arguments.getString("user"));
        String contextName = McpToolUtils.optionalTrim(arguments.getString("context"));

        HttpMessage msg = new HttpMessage();
        for (String headerLine : arguments.getList("headers")) {
            if (headerLine == null || headerLine.isBlank()) {
                continue;
            }
            String[] parts = headerLine.split(":", 2);
            String name = parts[0].trim();
            String value = parts.length > 1 ? parts[1].trim() : "";
            if (!name.isEmpty()) {
                msg.getRequestHeader().addHeader(name, value);
            }
        }
        msg.getRequestHeader().setMethod(method);
        msg.getRequestHeader().setVersion(httpVersion);
        try {
            msg.getRequestHeader().setURI(new URI(url, true));
        } catch (URIException e) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.sendrequest.error.invalidurl", url), e);
        }

        if (StringUtils.isNotEmpty(body)) {
            msg.getRequestBody().setBody(body);
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        }

        if (!McpToolUtils.isValidForCurrentMode(msg.getRequestHeader().getURI())) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.error.mode", Control.getSingleton().getMode().name()));
        }

        if (userName != null) {
            msg.setRequestingUser(McpToolUtils.resolveUser(userName, contextName));
        }

        try {
            requestSender.send(msg, followRedirects);
        } catch (IOException e) {
            LOGGER.warn("Failed to send request to {}", url, e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.sendrequest.error.sendfailed", e.getMessage()),
                    e);
        }

        Integer historyId = null;
        if (persist) {
            historyId = persistToHistoryAndSitesTree(msg);
        }

        return McpToolResult.success(toResultJson(msg, historyId));
    }

    private static String toResultJson(HttpMessage msg, Integer historyId) {
        ObjectNode result = McpResource.OBJECT_MAPPER.createObjectNode();
        result.put("statusCode", msg.getResponseHeader().getStatusCode());
        result.put("reasonPhrase", msg.getResponseHeader().getReasonPhrase());
        result.put("timeElapsedMillis", msg.getTimeElapsedMillis());
        if (historyId != null) {
            result.put("historyId", historyId);
        }
        result.put("requestHeader", msg.getRequestHeader().toString());
        result.put("requestBody", msg.getRequestBody().toString());
        result.put("responseHeader", msg.getResponseHeader().toString());
        result.put("responseBody", msg.getResponseBody().toString());
        return result.toString();
    }

    private static Integer persistToHistoryAndSitesTree(HttpMessage msg) {
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        if (extHistory == null) {
            LOGGER.warn("ExtensionHistory not available; request was not persisted");
            return null;
        }

        HistoryReference historyRef;
        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_ZAP_USER, msg);
        } catch (Exception e) {
            LOGGER.error("Could not create history reference for sent request", e);
            return null;
        }

        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
                    });
        } catch (Exception e) {
            LOGGER.error("Could not add message to history/sites tree", e);
        }
        return historyRef.getHistoryId();
    }
}
