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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/** Shared helpers for MCP tool argument parsing and ZAP session lookups. */
public final class McpToolUtils {

    private McpToolUtils() {}

    /**
     * Resolves a ZAP context user by name.
     *
     * <p>If {@code contextName} is provided, the user must exist in that context. Otherwise the
     * user must exist in exactly one context.
     *
     * @param userName the user name (required)
     * @param contextName the context name, or {@code null} to search all contexts
     * @return the matching user
     * @throws McpToolException if user management is unavailable, the context/user is not found, or
     *     the user name is ambiguous
     */
    public static User resolveUser(String userName, String contextName) throws McpToolException {
        ExtensionUserManagement extUser =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
        if (extUser == null) {
            throw new McpToolException(Constant.messages.getString("mcp.tool.error.nousermgmt"));
        }

        Session session = Model.getSingleton().getSession();
        if (contextName != null) {
            Context context = session.getContext(contextName);
            if (context == null) {
                throw new McpToolException(
                        Constant.messages.getString("mcp.tool.error.contextnotfound", contextName));
            }
            User user = findUser(extUser, context.getId(), userName);
            if (user == null) {
                throw new McpToolException(
                        Constant.messages.getString(
                                "mcp.tool.error.usernotfound", userName, contextName));
            }
            return user;
        }

        List<User> matches = new ArrayList<>();
        for (Context context : session.getContexts()) {
            User user = findUser(extUser, context.getId(), userName);
            if (user != null) {
                matches.add(user);
            }
        }
        if (matches.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.error.usernotfoundany", userName));
        }
        if (matches.size() > 1) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.error.userambiguous", userName));
        }
        return matches.get(0);
    }

    private static User findUser(ExtensionUserManagement extUser, int contextId, String userName) {
        return extUser.getContextUserAuthManager(contextId).getUsers().stream()
                .filter(u -> userName.equals(u.getName()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Tells whether the given URI may be requested in the current ZAP mode.
     *
     * @param uri the request URI
     * @return {@code false} in Safe mode, or in Protect mode when the URI is out of scope;
     *     otherwise {@code true}
     */
    public static boolean isValidForCurrentMode(URI uri) {
        return switch (Control.getSingleton().getMode()) {
            case safe -> false;
            case protect -> Model.getSingleton().getSession().isInScope(uri.toString());
            default -> true;
        };
    }

    /**
     * Parses a boolean tool argument from a string.
     *
     * @param value the argument value, or {@code null}/blank to use the default
     * @param defaultValue the value when {@code value} is absent
     * @param paramName the parameter name (for error messages)
     * @return the parsed boolean
     * @throws McpToolException if {@code value} is present but not {@code "true"} or {@code
     *     "false"}
     */
    public static boolean parseBoolean(String value, boolean defaultValue, String paramName)
            throws McpToolException {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        String normalised = value.trim().toLowerCase(Locale.ROOT);
        if ("true".equals(normalised)) {
            return true;
        }
        if ("false".equals(normalised)) {
            return false;
        }
        throw new McpToolException(
                Constant.messages.getString("mcp.tool.error.invalidboolean", paramName, value));
    }

    /**
     * Requires a non-blank string argument.
     *
     * @param value the argument value
     * @param paramName the parameter name (for error messages)
     * @return the trimmed value
     * @throws McpToolException if {@code value} is {@code null} or blank
     */
    public static String requireNonBlank(String value, String paramName) throws McpToolException {
        if (value == null) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.error.missingparam", paramName));
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.error.emptyparam", paramName));
        }
        return trimmed;
    }

    /**
     * Trims an optional string argument.
     *
     * @param value the argument value
     * @return the trimmed value, or {@code null} if {@code value} is {@code null} or blank
     */
    public static String optionalTrim(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    /**
     * Parses an optional integer tool argument and puts it in the given map, keyed by {@code key},
     * if present.
     *
     * @param params the map to update
     * @param key the map key to set
     * @param value the argument value, or {@code null}/blank to leave the map unchanged
     * @param paramName the parameter name (for error messages)
     * @throws McpToolException if {@code value} is present but not a valid integer
     */
    public static void putOptionalInt(
            Map<String, Object> params, String key, String value, String paramName)
            throws McpToolException {
        String trimmed = optionalTrim(value);
        if (trimmed == null) {
            return;
        }
        try {
            params.put(key, Integer.valueOf(trimmed));
        } catch (NumberFormatException e) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.error.invalidint", paramName, value), e);
        }
    }
}
