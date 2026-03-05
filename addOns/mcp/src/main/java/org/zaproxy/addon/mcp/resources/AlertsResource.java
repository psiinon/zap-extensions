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
package org.zaproxy.addon.mcp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/** MCP resource that provides ZAP security alerts. */
public class AlertsResource implements McpResource {

    private static final String URI = "zap://alerts";
    private static final String MIME_TYPE = "application/json";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "alerts";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.alerts.desc");
    }

    @Override
    public String getMimeType() {
        return MIME_TYPE;
    }

    @Override
    public ObjectNode toListEntry() {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("uri", getUri());
        node.put("name", getName());
        node.put("description", getDescription());
        node.put("mimeType", getMimeType());
        return node;
    }

    @Override
    public String readContent() {
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return "[]";
        }

        List<Alert> alerts = extAlert.getAllAlerts();
        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (Alert alert : alerts) {
            ObjectNode node = OBJECT_MAPPER.createObjectNode();
            node.put("name", alert.getName());
            node.put("risk", alert.getRisk());
            node.put("confidence", alert.getConfidence());
            node.put("uri", alert.getUri());
            node.put("param", alert.getParam());
            node.put("attack", alert.getAttack());
            node.put("evidence", alert.getEvidence());
            node.put("pluginId", alert.getPluginId());
            if (alert.getHistoryRef() != null) {
                node.put("historyRef", "zap://history/" + alert.getHistoryRef().getHistoryId());
            }
            array.add(node);
        }
        return array.toString();
    }
}
