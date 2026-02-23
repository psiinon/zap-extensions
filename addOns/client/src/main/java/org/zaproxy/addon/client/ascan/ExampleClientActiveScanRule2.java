/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.client.ascan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.zaproxy.addon.client.internal.ClientNode;

/**
 * An example client active scan rule that logs when it is called for each node in the client map.
 * It does not raise any alerts; it is provided as a template for implementing real checks.
 */
public class ExampleClientActiveScanRule2 extends ClientActiveScanRule {

    private static final Logger LOGGER = LogManager.getLogger(ExampleClientActiveScanRule2.class);
    private static final int PLUGIN_ID = 90002;

    @Override
    protected void scanClientNode(ClientNode node, WebDriver driver) {
        String url = node.getUserObject().getUrl();
        LOGGER.info(
                "Example Client Active Scan Rule 2 called for node: {} (driver: {})", url, driver);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("client.ascan.example.name") + 2;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("client.ascan.example.desc");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("client.ascan.example.refs");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("client.ascan.example.soln");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getWascId() {
        return 0;
    }

    @Override
    public int getCweId() {
        return 0;
    }
}
