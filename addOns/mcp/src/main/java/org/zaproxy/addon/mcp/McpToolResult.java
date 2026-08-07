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

/**
 * The result of an MCP tool execution.
 *
 * @param text the text content to return to the client
 * @param isError whether the result indicates an error (e.g. tool execution failure)
 * @param resourceUri the URI of the embedded resource, or {@code null} if there is none
 * @param resourceMimeType the MIME type of the embedded resource, or {@code null}
 * @param resourceBlob the raw bytes of the embedded resource, or {@code null} if there is none
 */
public record McpToolResult(
        String text,
        boolean isError,
        String resourceUri,
        String resourceMimeType,
        byte[] resourceBlob) {

    /**
     * Creates a successful result with the given text.
     *
     * @param text the result text
     * @return a successful result
     */
    public static McpToolResult success(String text) {
        return new McpToolResult(text, false, null, null, null);
    }

    /**
     * Creates a successful result with the given text and an embedded binary resource, e.g. a
     * generated file returned inline instead of being written to disk.
     *
     * @param text the result text
     * @param resourceUri a URI identifying the resource (does not need to be dereferenceable)
     * @param resourceMimeType the MIME type of the resource
     * @param resourceBlob the raw bytes of the resource
     * @return a successful result
     */
    public static McpToolResult successWithBlob(
            String text, String resourceUri, String resourceMimeType, byte[] resourceBlob) {
        return new McpToolResult(text, false, resourceUri, resourceMimeType, resourceBlob);
    }

    /**
     * Creates an error result with the given message.
     *
     * @param message the error message
     * @return an error result
     */
    public static McpToolResult error(String message) {
        return new McpToolResult(message, true, null, null, null);
    }
}
