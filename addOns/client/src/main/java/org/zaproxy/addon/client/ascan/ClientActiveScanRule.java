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
package org.zaproxy.addon.client.ascan;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.zap.model.Context;

/**
 * An abstract active scan rule that operates on the Client Map instead of the Sites Tree.
 *
 * <p>Only nodes belonging to the host currently being scanned (from the scan target) are visited.
 * WebDrivers are obtained from a shared pool managed by the extension (see {@link
 * ClientActiveScanWebDriverPool}), so all client active scan rules in the same scan share the same
 * pool. For each node to scan, a WebDriver is acquired from the pool and {@link
 * #scanClientNode(ClientNode, WebDriver)} is invoked; the driver is returned to the pool
 * afterwards. Concrete implementations perform their checks in the browser using the provided
 * WebDriver.
 */
public abstract class ClientActiveScanRule extends AbstractHostPlugin {

    private static final Logger LOGGER = LogManager.getLogger(ClientActiveScanRule.class);

    @Override
    public void scan() {
        ExtensionClientIntegration extension = getExtension();
        if (extension == null) {
            LOGGER.warn("Client integration extension not loaded, skipping {} scan.", getName());
            return;
        }

        HostProcess hostProcess = getParent();
        if (hostProcess == null) {
            LOGGER.debug("No host process (parent), skipping {} scan.", getName());
            return;
        }

        ClientMap clientMap = extension.getClientMap();
        if (clientMap == null) {
            LOGGER.debug("No client map available, skipping {} scan.", getName());
            return;
        }

        ClientNode root = clientMap.getRoot();
        if (root == null || root.getChildCount() == 0) {
            LOGGER.debug("Client map is empty, skipping {} scan.", getName());
            return;
        }

        Context context = hostProcess.getContext();
        ClientActiveScanWebDriverPool pool =
                extension.getClientActiveScanPool(
                        hostProcess,
                        context,
                        msg -> {
                            try {
                                sendAndReceive(msg);
                            } catch (Exception e) {
                                LOGGER.debug("Proxy handler sendAndReceive failed", e);
                            }
                        });

        if (!pool.ensureProxy()) {
            LOGGER.warn("Could not start proxy for browser traffic, skipping {} scan.", getName());
            return;
        }

        try {
            URI baseUri = getBaseMsg().getRequestHeader().getURI();
            String targetScheme = baseUri.getScheme();
            String targetHost = baseUri.getHost();
            int targetPort = getEffectivePort(baseUri);
            scanClientMapNodes(root, false, targetScheme, targetHost, targetPort, pool);
        } catch (URIException e) {
            LOGGER.warn("Could not determine target host for client map scan: {}", e.getMessage());
        } finally {
            pool.ruleFinishedScanning(this);
        }
    }

    @Override
    public void setTimeFinished() {
        super.setTimeFinished();
        HostProcess hostProcess = getParent();
        if (hostProcess != null) {
            ExtensionClientIntegration extension = getExtension();
            if (extension != null) {
                extension.releaseClientActiveScanPool(hostProcess);
            }
        }
    }

    private ExtensionClientIntegration getExtension() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class);
    }

    private static int getEffectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        String scheme = uri.getScheme();
        if (scheme != null && scheme.equalsIgnoreCase("https")) {
            return 443;
        }
        return 80;
    }

    /**
     * Traverses the client map tree and calls {@link #scanClientNode(ClientNode, WebDriver)} for
     * each non-root, non-storage node that belongs to the host being scanned. A WebDriver is
     * acquired from the pool for each node and returned after the scan.
     */
    protected void scanClientMapNodes(
            ClientNode node,
            boolean underTargetHost,
            String targetScheme,
            String targetHost,
            int targetPort,
            ClientActiveScanWebDriverPool pool) {
        for (int i = 0; i < node.getChildCount(); i++) {
            if (isStop()) {
                LOGGER.debug("Scan rule {} stopping.", getName());
                return;
            }

            ClientNode child = node.getChildAt(i);
            if (node.isRoot()) {
                if (!child.isStorage()
                        && isNodeForHost(child, targetScheme, targetHost, targetPort)) {
                    ClientActiveScanRuleWebDriverWrapper wrapper =
                            pool.getWebDriver(this::isStop, this);
                    if (wrapper != null) {
                        try {
                            scanClientNode(child, wrapper.getDriver());
                        } finally {
                            pool.returnDriver(wrapper, this);
                        }
                    }
                    scanClientMapNodes(child, true, targetScheme, targetHost, targetPort, pool);
                }
            } else if (underTargetHost) {
                if (!child.isStorage()) {
                    ClientActiveScanRuleWebDriverWrapper wrapper =
                            pool.getWebDriver(this::isStop, this);
                    if (wrapper != null) {
                        try {
                            scanClientNode(child, wrapper.getDriver());
                        } finally {
                            pool.returnDriver(wrapper, this);
                        }
                    }
                }
                scanClientMapNodes(child, true, targetScheme, targetHost, targetPort, pool);
            }
        }
    }

    private boolean isNodeForHost(
            ClientNode node, String targetScheme, String targetHost, int targetPort) {
        String nodeUrl = node.getUserObject().getUrl();
        if (nodeUrl == null || nodeUrl.isEmpty()) {
            return false;
        }
        try {
            URI nodeUri = new URI(nodeUrl, true);
            String nodeScheme = nodeUri.getScheme();
            String nodeHost = nodeUri.getHost();
            int nodePort = getEffectivePort(nodeUri);
            return targetScheme.equalsIgnoreCase(nodeScheme)
                    && targetHost.equalsIgnoreCase(nodeHost)
                    && targetPort == nodePort;
        } catch (URIException e) {
            LOGGER.debug("Could not parse node URL for host comparison: {}", nodeUrl, e);
            return false;
        }
    }

    /**
     * Scans a single client map node in the browser. Subclasses must implement this to perform
     * their checks using the provided WebDriver.
     *
     * @param node the client map node to scan (never the root; never a storage node)
     * @param driver a WebDriver from the pool; traffic is proxied through ZAP
     */
    protected abstract void scanClientNode(ClientNode node, WebDriver driver);

    /**
     * Called when a WebDriver is no longer needed for this scan rule. This is invoked in two cases:
     * (1) when all client nodes have been scanned by this rule, for each driver in the pool that
     * this rule last used; (2) when a driver is reassigned to a different rule, before it is handed
     * to the other rule.
     *
     * <p>Subclasses may override to perform cleanup (e.g. clearing browser state, closing extra
     * tabs) specific to the rule.
     *
     * @param driver the WebDriver that is no longer needed by this rule
     */
    protected void scanComplete(WebDriver driver) {}
}
