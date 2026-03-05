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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.utils.ThreadUtils;

/** Handles MCP JSON-RPC 2.0 requests and dispatches to the appropriate endpoint implementations. */
class McpRequestHandler {

    private static final Logger LOGGER = LogManager.getLogger(McpRequestHandler.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String PROTOCOL_VERSION = "2024-11-05";

    private final McpToolRegistry toolRegistry;
    private final McpResourceRegistry resourceRegistry;
    private final String addOnVersion;

    McpRequestHandler(
            McpToolRegistry toolRegistry,
            McpResourceRegistry resourceRegistry,
            String addOnVersion) {
        this.toolRegistry = toolRegistry;
        this.resourceRegistry = resourceRegistry;
        this.addOnVersion = addOnVersion;
    }

    String handleRequest(String requestBody) {
        try {
            JsonNode request = OBJECT_MAPPER.readTree(requestBody);
            if (!request.isObject()) {
                return errorResponse(null, -32600, "Invalid Request");
            }

            ObjectNode requestObj = (ObjectNode) request;
            String method = requestObj.has("method") ? requestObj.get("method").asText() : null;
            JsonNode id = requestObj.get("id");

            if (method == null || method.isEmpty()) {
                return errorResponse(id, -32600, "Invalid Request: method not specified");
            }

            String result;
            switch (method) {
                case "initialize":
                    result = handleInitialize(requestObj);
                    break;
                case "notifications/initialized":
                    result = handleInitialized();
                    break;
                case "ping":
                    result = handlePing(id);
                    break;
                case "tools/list":
                    result = handleToolsList(id);
                    break;
                case "tools/call":
                    result = handleToolsCall(requestObj, id);
                    break;
                case "resources/list":
                    result = handleResourcesList(id);
                    break;
                case "resources/read":
                    result = handleResourcesRead(requestObj, id);
                    break;
                default:
                    result = errorResponse(id, -32601, "Method not found: " + method);
            }

            return result;
        } catch (Exception e) {
            LOGGER.warn("Failed to handle MCP request", e);
            return errorResponse(null, -32603, "Internal error: " + e.getMessage());
        }
    }

    private String handleInitialize(ObjectNode request) {
        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.put("protocolVersion", PROTOCOL_VERSION);

        ObjectNode capabilities = result.putObject("capabilities");
        capabilities.putObject("tools").put("listChanged", true);
        capabilities.putObject("resources").put("listChanged", true);

        ObjectNode serverInfo = result.putObject("serverInfo");
        serverInfo.put("name", "ZAP MCP Server");
        serverInfo.put("version", addOnVersion);

        return jsonRpcResponse(request.get("id"), result);
    }

    private String handleInitialized() {
        return null;
    }

    private String handlePing(JsonNode id) {
        return jsonRpcResponse(id, OBJECT_MAPPER.createObjectNode());
    }

    private String handleToolsList(JsonNode id) {
        ArrayNode toolsArray = OBJECT_MAPPER.createArrayNode();

        for (McpTool tool : toolRegistry.getTools()) {
            ObjectNode toolNode = OBJECT_MAPPER.createObjectNode();
            toolNode.put("name", tool.getName());
            toolNode.put("description", tool.getDescription());
            toolNode.set("inputSchema", tool.getInputSchema());
            toolsArray.add(toolNode);
        }

        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.set("tools", toolsArray);

        return jsonRpcResponse(id, result);
    }

    private String handleToolsCall(ObjectNode request, JsonNode id) {
        JsonNode params = request.get("params");
        if (params == null || !params.isObject()) {
            return errorResponse(id, -32602, "Invalid params");
        }

        String name = params.has("name") ? params.get("name").asText() : null;
        if (name == null || name.isEmpty()) {
            return errorResponse(id, -32602, "Tool name not specified");
        }

        McpTool tool = toolRegistry.getTool(name);
        if (tool == null) {
            return errorResponse(id, -32602, "Unknown tool: " + name);
        }

        JsonNode arguments = params.has("arguments") ? params.get("arguments") : null;
        if (arguments == null) {
            arguments = OBJECT_MAPPER.createObjectNode();
        }

        McpToolResult toolResult;
        try {
            toolResult = tool.execute(arguments);
        } catch (McpToolException e) {
            toolResult = McpToolResult.error(e.getMessage());
        }

        ArrayNode contentArray = OBJECT_MAPPER.createArrayNode();
        ObjectNode textContent = OBJECT_MAPPER.createObjectNode();
        textContent.put("type", "text");
        textContent.put("text", toolResult.text());
        contentArray.add(textContent);

        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.set("content", contentArray);
        result.put("isError", toolResult.isError());

        return jsonRpcResponse(id, result);
    }

    private String handleResourcesList(JsonNode id) {
        ArrayNode resourcesArray = OBJECT_MAPPER.createArrayNode();
        for (McpResource resource : resourceRegistry.getResources()) {
            resourcesArray.add(resource.toListEntry());
        }
        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.set("resources", resourcesArray);
        return jsonRpcResponse(id, result);
    }

    private String handleResourcesRead(ObjectNode request, JsonNode id) {
        JsonNode params = request.get("params");
        if (params == null || !params.isObject()) {
            return errorResponse(id, -32602, "Invalid params");
        }

        String uri = params.has("uri") ? params.get("uri").asText() : null;
        if (uri == null || uri.isEmpty()) {
            return errorResponse(id, -32602, "Resource URI not specified");
        }

        McpResource resource = resourceRegistry.getResource(uri);
        if (resource == null) {
            return errorResponse(id, -32602, "Unknown resource: " + uri);
        }

        String content;
        try {
            StringBuilder contentHolder = new StringBuilder();
            ThreadUtils.invokeAndWaitHandled(() -> contentHolder.append(resource.readContent(uri)));
            content = contentHolder.toString();
        } catch (Exception e) {
            return errorResponse(id, -32603, "Failed to read resource: " + e.getMessage());
        }

        ArrayNode contentArray = OBJECT_MAPPER.createArrayNode();
        ObjectNode textContent = OBJECT_MAPPER.createObjectNode();
        textContent.put("uri", uri);
        textContent.put("mimeType", resource.getMimeType());
        textContent.put("text", content);
        contentArray.add(textContent);

        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.set("contents", contentArray);

        return jsonRpcResponse(id, result);
    }

    private static String jsonRpcResponse(JsonNode id, ObjectNode result) {
        ObjectNode response = OBJECT_MAPPER.createObjectNode();
        response.put("jsonrpc", "2.0");
        if (id != null) {
            response.set("id", id);
        }
        response.set("result", result);
        return response.toString();
    }

    private static String errorResponse(JsonNode id, int code, String message) {
        ObjectNode response = OBJECT_MAPPER.createObjectNode();
        response.put("jsonrpc", "2.0");
        if (id != null) {
            response.set("id", id);
        }
        ObjectNode error = response.putObject("error");
        error.put("code", code);
        error.put("message", message);
        return response.toString();
    }
}
