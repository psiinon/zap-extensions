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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.TargetLocator;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;

@MockitoSettings(strictness = Strictness.LENIENT)
class ClientActiveScanRuleUnitTest
        extends ActiveScannerTestUtils<ClientActiveScanRuleUnitTest.ScanCompleteRecordingRule> {

    private static final String EXAMPLE_COM = "https://example.com/";
    private static final String EXAMPLE_PAGE1 = "https://example.com/page1/";
    private static final String EXAMPLE_PAGE2 = "https://example.com/page2/";
    private static final String OTHER_SITE = "https://other.org/";
    private static final String OTHER_SITE_STORAGE = "https://other.org/localStorage";
    private ClientMap clientMap;
    private ClientActiveScanWebDriverPool testPool;

    @Override
    protected ScanCompleteRecordingRule createScanner() {
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        if (clientMap != null) {
            org.zaproxy.zap.ZAP.getEventBus().unregisterPublisher(clientMap);
            clientMap = null;
        }

        Session session = mock(Session.class);
        given(session.getUrlParamParser(any(String.class)))
                .willReturn(new StandardParameterParser());

        ClientNode root = new ClientNode(new ClientSideDetails("Root", ""), session);
        clientMap = new ClientMap(root);

        clientMap.getOrAddNode(EXAMPLE_COM, false, false);
        clientMap.getOrAddNode(EXAMPLE_PAGE1, false, false);
        clientMap.getOrAddNode(EXAMPLE_PAGE2, false, false);
        clientMap.getOrAddNode(OTHER_SITE, false, false);
        clientMap.getOrAddNode(OTHER_SITE_STORAGE, false, true);

        // Add nodes for the host that will be scanned (test server) so the rule has something to
        // visit
        String scanHostBase = "http://localhost:" + nano.getListeningPort() + "/";
        clientMap.getOrAddNode(scanHostBase, false, false);
        clientMap.getOrAddNode(scanHostBase + "page1/", false, false);

        ExtensionClientIntegration extension =
                mock(
                        ExtensionClientIntegration.class,
                        withSettings().strictness(Strictness.LENIENT));
        given(extension.getClientMap()).willReturn(clientMap);
        ClientOptions clientOptions =
                mock(ClientOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(clientOptions.getAscanBrowserPoolSize())
                .willReturn(ClientOptions.DEFAULT_ASCAN_BROWSER_POOL_SIZE);
        given(clientOptions.getBrowserId()).willReturn(Browser.FIREFOX_HEADLESS.getId());
        given(extension.getClientParam()).willReturn(clientOptions);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class)).willReturn(extension);

        ExtensionNetwork extensionNetwork =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        Server mockServer = mock(Server.class);
        try {
            given(mockServer.start(anyInt())).willReturn(12345);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        given(extensionNetwork.createHttpProxy(anyInt(), any())).willReturn(mockServer);
        given(extensionLoader.getExtension(ExtensionNetwork.class)).willReturn(extensionNetwork);

        testPool = new TestClientActiveScanWebDriverPool(extension, null, msg -> {});
        given(extension.getClientActiveScanPool(any(), any(), any())).willReturn(testPool);
        doNothing().when(extension).releaseClientActiveScanPool(any());

        return new ScanCompleteRecordingRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionClientIntegration());
    }

    @AfterEach
    void tearDownClientMap() {
        if (clientMap != null) {
            ZAP.getEventBus().unregisterPublisher(clientMap);
        }
    }

    @Test
    void shouldAccessOnlyNodesInHostBeingScanned()
            throws HttpMalformedHeaderException, URIException {
        // Given - client map has example.com, other.org, and localhost (test server) nodes.
        // The rule is init'd with the test server message so only localhost nodes should be
        // visited.
        HttpMessage baseMsg = getHttpMessage("/");
        var requestUri = baseMsg.getRequestHeader().getURI();
        String scheme = requestUri.getScheme();
        String host = requestUri.getHost();
        int port = requestUri.getPort();
        if (port == -1) {
            port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
        }
        String scanHostBase = scheme + "://" + host + ":" + port + "/";
        Set<String> expectedUrls = Set.of(scanHostBase, scanHostBase + "page1/");
        // When
        rule.init(baseMsg, parent);
        rule.scan();
        // Then - rule must visit only nodes for the host being scanned (not example.com or
        // other.org)
        Set<String> visitedSet = new HashSet<>(rule.getVisitedNodeUrls());
        assertThat(
                "Rule should visit only nodes for the scanned host",
                visitedSet,
                hasSize(expectedUrls.size()));
        assertThat(visitedSet, containsInAnyOrder(expectedUrls.toArray(new String[0])));
    }

    @Test
    void shouldCallScanCompleteWhenRuleFinishesScanning()
            throws HttpMalformedHeaderException, URIException {
        // Given - rule that records scanComplete calls, client map with 2 nodes for scan host
        HttpMessage baseMsg = getHttpMessage("/");
        rule.init(baseMsg, parent);
        // When - rule scans all nodes and finishes
        rule.scan();
        // Then - scanComplete must be called for each driver the rule last used (1 driver with
        // pool size 1, used for 2 nodes)
        assertThat(
                "scanComplete should be called when rule finishes scanning",
                rule.getScanCompleteDrivers(),
                hasSize(1));
    }

    @Test
    void shouldCallScanCompleteWhenDriverReassignedToDifferentRule() throws IOException {
        // Given - pool with one driver, two rules that record scanComplete
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        ExtensionClientIntegration extension =
                mock(
                        ExtensionClientIntegration.class,
                        withSettings().strictness(Strictness.LENIENT));
        ClientOptions clientOptions =
                mock(ClientOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(clientOptions.getAscanBrowserPoolSize()).willReturn(1);
        given(clientOptions.getBrowserId()).willReturn(Browser.FIREFOX_HEADLESS.getId());
        given(extension.getClientParam()).willReturn(clientOptions);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class)).willReturn(extension);

        ExtensionNetwork extensionNetwork =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        Server mockServer = mock(Server.class);
        given(mockServer.start(anyInt())).willReturn(12345);
        given(extensionNetwork.createHttpProxy(anyInt(), any())).willReturn(mockServer);
        given(extensionLoader.getExtension(ExtensionNetwork.class)).willReturn(extensionNetwork);

        ClientActiveScanWebDriverPool pool =
                new TestClientActiveScanWebDriverPool(extension, null, msg -> {});
        pool.ensureProxy();

        ScanCompleteRecordingRule ruleA = new ScanCompleteRecordingRule();
        ScanCompleteRecordingRule ruleB = new ScanCompleteRecordingRule();

        // When - ruleA gets driver, returns it; ruleB gets the same driver from pool
        ClientActiveScanRuleWebDriverWrapper wrapper = pool.getWebDriver(() -> false, ruleA);
        pool.returnDriver(wrapper, ruleA);

        pool.getWebDriver(() -> false, ruleB);

        // Then - ruleA's scanComplete must have been called (driver reassigned to ruleB)
        assertThat(
                "scanComplete should be called when driver is reassigned to different rule",
                ruleA.getScanCompleteDrivers(),
                hasSize(1));
        assertThat(
                "ruleB should not have scanComplete called yet (it just received the driver)",
                ruleB.getScanCompleteDrivers(),
                hasSize(0));
    }

    /** Pool that creates mock WebDrivers for unit tests. */
    static class TestClientActiveScanWebDriverPool extends ClientActiveScanWebDriverPool {

        TestClientActiveScanWebDriverPool(
                ExtensionClientIntegration extension,
                org.zaproxy.zap.model.Context context,
                java.util.function.Consumer<org.parosproxy.paros.network.HttpMessage>
                        messageSender) {
            super(extension, context, messageSender);
        }

        @Override
        protected ClientActiveScanRuleWebDriverWrapper createWebDriver() {
            WebDriver mockDriver = mock(WebDriver.class);
            TargetLocator targetLocator =
                    mock(WebDriver.TargetLocator.class);
            org.openqa.selenium.Alert mockAlert = mock(org.openqa.selenium.Alert.class);
            given(mockDriver.switchTo()).willReturn(targetLocator);
            given(targetLocator.alert()).willReturn(mockAlert);
            return new ClientActiveScanRuleWebDriverWrapper(mockDriver, Browser.FIREFOX_HEADLESS);
        }
    }

    /** Rule that records scanComplete calls and visited node URLs. */
    static class ScanCompleteRecordingRule extends ClientActiveScanRule {

        private final List<String> visitedNodeUrls = new ArrayList<>();
        private final List<WebDriver> scanCompleteDrivers = new ArrayList<>();

        @Override
        protected void scanClientNode(ClientNode node, WebDriver driver) {
            String url = node.getUserObject().getUrl();
            if (url != null && !url.isEmpty()) {
                visitedNodeUrls.add(url);
            }
        }

        @Override
        protected void scanComplete(WebDriver driver) {
            scanCompleteDrivers.add(driver);
        }

        List<String> getVisitedNodeUrls() {
            return visitedNodeUrls;
        }

        List<WebDriver> getScanCompleteDrivers() {
            return scanCompleteDrivers;
        }

        @Override
        public int getId() {
            return 90001;
        }

        @Override
        public String getName() {
            return Constant.messages.getString("client.ascan.testrule.name");
        }

        @Override
        public String getDescription() {
            return "Test rule for unit tests.";
        }

        @Override
        public String getReference() {
            return "";
        }

        @Override
        public int getCategory() {
            return Category.INFO_GATHER;
        }

        @Override
        public String getSolution() {
            return "";
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
}
