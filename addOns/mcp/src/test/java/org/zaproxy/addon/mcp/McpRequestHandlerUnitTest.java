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

import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.mcp.resources.HistoryEntryResource;
import org.zaproxy.addon.mcp.tools.ZapVersionTool;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link McpRequestHandler}. */
class McpRequestHandlerUnitTest {

    private McpToolRegistry toolRegistry;
    private McpResourceRegistry resourceRegistry;
    private McpPromptRegistry promptRegistry;
    private McpRequestHandler requestHandler;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        toolRegistry = new McpToolRegistry();
        resourceRegistry = new McpResourceRegistry();
        promptRegistry = new McpPromptRegistry();
        toolRegistry.registerTool(new ZapVersionTool());
        requestHandler = new McpRequestHandler(toolRegistry, resourceRegistry, promptRegistry, "");
    }

    @Test
    void shouldHandleInitialize() {
        String request =
                """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
                """;

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\","
                                + "\"capabilities\":{\"tools\":{\"listChanged\":true},\"resources\":{\"listChanged\":true},\"prompts\":{\"listChanged\":true}},"
                                + "\"serverInfo\":{\"name\":\"ZAP MCP Server\",\"version\":\"\"}}}"));
    }

    @Test
    void shouldHandlePing() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(response, equalTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    }

    @Test
    void shouldHandleToolsList() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"zap_version\","
                                + "\"description\":\"!mcp.tool.version.desc!\","
                                + "\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"required\":[]}}]}}"));
    }

    @Test
    void shouldHandleToolsCall() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"zap_version\",\"arguments\":{}}}";

        String response = requestHandler.handleRequest(request);

        // The version text is dynamic; assert the envelope structure without it.
        assertThat(response, containsString("\"isError\":false"));
        assertThat(response, containsString("\"type\":\"text\""));
    }

    @Test
    void shouldReturnErrorForInvalidJson() {
        String response = requestHandler.handleRequest("not json");

        // The Jackson parse-exception message is dynamic; assert the fixed parts.
        assertThat(response, containsString("\"code\":-32603"));
        assertThat(response, containsString("\"message\":\"Internal error:"));
    }

    @Test
    void shouldReturnErrorForMissingMethod() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32600,\"message\":\"Invalid Request: method not specified\"}}"));
    }

    @Test
    void shouldReturnErrorForUnknownMethod() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"unknown/method\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32601,\"message\":\"Method not found: unknown/method\"}}"));
    }

    @Test
    void shouldReturnErrorForUnknownTool() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"unknown_tool\",\"arguments\":{}}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32602,\"message\":\"Unknown tool: unknown_tool\"}}"));
    }

    @Test
    void shouldHandleResourcesList() {
        resourceRegistry.registerResource(new HistoryEntryResource());

        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[{\"uri\":\"zap://history/{id}\","
                                + "\"name\":\"history-entry\","
                                + "\"description\":\"!mcp.resource.historyentry.desc!\","
                                + "\"mimeType\":\"application/json\"}]}}"));
    }

    @Test
    void shouldReturnErrorForUnknownResource() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"zap://unknown\"}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32602,\"message\":\"Unknown resource: zap://unknown\"}}"));
    }

    @Test
    void shouldReturnErrorForMissingResourceUri() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32602,\"message\":\"Resource URI not specified\"}}"));
    }

    @Test
    void shouldAdvertisePromptsCapabilityInInitialize() {
        String request =
                """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
                """;

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\","
                                + "\"capabilities\":{\"tools\":{\"listChanged\":true},\"resources\":{\"listChanged\":true},\"prompts\":{\"listChanged\":true}},"
                                + "\"serverInfo\":{\"name\":\"ZAP MCP Server\",\"version\":\"\"}}}"));
    }

    @Test
    void shouldReturnIsErrorTrueForFailingTool() {
        toolRegistry.registerTool(
                new McpTool() {
                    @Override
                    public String getName() {
                        return "failing_tool";
                    }

                    @Override
                    public String getDescription() {
                        return "A tool that always fails";
                    }

                    @Override
                    public InputSchema getInputSchema() {
                        return new InputSchema(Map.of(), List.of());
                    }

                    @Override
                    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
                        throw new McpToolException("something went wrong");
                    }
                });
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"failing_tool\",\"arguments\":{}}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\","
                                + "\"text\":\"something went wrong\"}],\"isError\":true}}"));
    }

    @Test
    void shouldHandlePromptsList() {
        promptRegistry.registerPrompt(
                new McpPrompt() {
                    @Override
                    public String getName() {
                        return "test_prompt";
                    }

                    @Override
                    public String getDescription() {
                        return "A test prompt";
                    }

                    @Override
                    public List<McpPrompt.PromptArgument> getArguments() {
                        return List.of(new McpPrompt.PromptArgument("target", "The target", true));
                    }

                    @Override
                    public List<McpPrompt.PromptMessage> getMessages(
                            Map<String, String> arguments) {
                        return List.of();
                    }
                });

        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\"}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"prompts\":[{\"name\":\"test_prompt\","
                                + "\"description\":\"A test prompt\","
                                + "\"arguments\":[{\"name\":\"target\",\"description\":\"The target\",\"required\":true}]}]}}"));
    }

    @Test
    void shouldHandlePromptsGet() {
        promptRegistry.registerPrompt(
                new McpPrompt() {
                    @Override
                    public String getName() {
                        return "greet";
                    }

                    @Override
                    public String getDescription() {
                        return "A greeting prompt";
                    }

                    @Override
                    public List<McpPrompt.PromptArgument> getArguments() {
                        return List.of(new McpPrompt.PromptArgument("name", "Name to greet", true));
                    }

                    @Override
                    public List<McpPrompt.PromptMessage> getMessages(
                            Map<String, String> arguments) {
                        return List.of(
                                new McpPrompt.PromptMessage(
                                        "user", "Hello " + arguments.get("name")));
                    }
                });

        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"greet\",\"arguments\":{\"name\":\"World\"}}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"description\":\"A greeting prompt\","
                                + "\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"Hello World\"}}]}}"));
    }

    @Test
    void shouldReturnErrorForUnknownPrompt() {
        String request =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"no_such_prompt\"}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32602,\"message\":\"Unknown prompt: no_such_prompt\"}}"));
    }

    @Test
    void shouldReturnErrorForMissingPromptName() {
        String request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{}}";

        String response = requestHandler.handleRequest(request);

        assertThat(
                response,
                equalTo(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,"
                                + "\"error\":{\"code\":-32602,\"message\":\"Prompt name not specified\"}}"));
    }
}
