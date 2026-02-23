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

import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.UnexpectedAlertBehaviour;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;

/**
 * Shared pool of WebDrivers (and proxy) for client active scan rules. All client active scan rules
 * in the same scan share one pool instance so that browser and proxy resources are reused.
 *
 * @see ClientActiveScanRule
 */
public class ClientActiveScanWebDriverPool {

    private static final Logger LOGGER = LogManager.getLogger(ClientActiveScanWebDriverPool.class);

    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX_HEADLESS;

    private final Object poolLock = new Object();
    private final Stack<ClientActiveScanRuleWebDriverWrapper> freeDrivers = new Stack<>();
    private final List<ClientActiveScanRuleWebDriverWrapper> takenDrivers = new ArrayList<>();

    private final ExtensionClientIntegration extension;
    private final Context context;
    private final Consumer<HttpMessage> messageSender;

    private Server proxy;
    private int proxyPort = -1;
    private Browser browser;

    /**
     * Creates a pool that uses the extension's options and the given context for proxy exclusions.
     *
     * @param extension the client integration extension (for options and browser)
     * @param context the scan context (for URL exclusions in the proxy), may be null
     * @param messageSender called to send proxy requests through ZAP (e.g. rule's sendAndReceive)
     */
    public ClientActiveScanWebDriverPool(
            ExtensionClientIntegration extension,
            Context context,
            Consumer<HttpMessage> messageSender) {
        this.extension = extension;
        this.context = context;
        this.messageSender = messageSender;
        resolveBrowser();
    }

    private void resolveBrowser() {
        if (extension != null) {
            String browserId = extension.getClientParam().getBrowserId();
            try {
                browser = Browser.getBrowserWithIdNoFailSafe(browserId);
            } catch (Exception e) {
                LOGGER.debug("Invalid browser id [{}], using default", browserId, e);
            }
        }
        if (browser == null || !isSupportedBrowser(browser)) {
            browser = DEFAULT_BROWSER;
        }
        LOGGER.debug("Client active scan WebDriver pool using browser: {}", browser);
    }

    private static boolean isSupportedBrowser(Browser b) {
        return b == Browser.FIREFOX
                || b == Browser.FIREFOX_HEADLESS
                || b == Browser.CHROME
                || b == Browser.CHROME_HEADLESS
                || b == Browser.EDGE
                || b == Browser.EDGE_HEADLESS;
    }

    private int getPoolSize() {
        return extension != null
                ? extension.getClientParam().getAscanBrowserPoolSize()
                : ClientOptions.DEFAULT_ASCAN_BROWSER_POOL_SIZE;
    }

    /**
     * Ensures the proxy is started. Must be called before acquiring drivers.
     *
     * @return true if the proxy is (or was) running
     */
    public boolean ensureProxy() {
        if (proxy != null) {
            return true;
        }
        ExtensionNetwork extNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);
        if (extNetwork == null) {
            return false;
        }
        proxy =
                extNetwork.createHttpProxy(
                        -1,
                        new HttpMessageHandler() {
                            @Override
                            public void handleMessage(
                                    HttpMessageHandlerContext ctx, HttpMessage msg) {
                                if (isExcluded(msg)) {
                                    ctx.close();
                                    return;
                                }
                                ctx.overridden();
                                try {
                                    messageSender.accept(msg);
                                } catch (Exception e) {
                                    LOGGER.debug("Proxy handler sendAndReceive failed", e);
                                }
                            }
                        });
        try {
            proxyPort = proxy.start(Server.ANY_PORT);
        } catch (IOException e) {
            LOGGER.warn("Failed to start proxy for client active scan", e);
            proxy = null;
            return false;
        }
        return true;
    }

    private boolean isExcluded(HttpMessage msg) {
        String uri = msg.getRequestHeader().getURI().toString();
        for (String regex : Model.getSingleton().getSession().getGlobalExcludeURLRegexs()) {
            if (Pattern.matches(regex, uri)) {
                return true;
            }
        }
        if (context != null && context.isExcluded(uri)) {
            return true;
        }
        return false;
    }

    /**
     * Creates a new WebDriver and wrapper. Subclasses may override to supply a mock or custom
     * driver for testing.
     */
    protected ClientActiveScanRuleWebDriverWrapper createWebDriver() {
        WebDriver webDriver =
                ExtensionSelenium.getWebDriver(
                        HttpSender.ACTIVE_SCANNER_INITIATOR,
                        browser,
                        "127.0.0.1", // TODO this is wrong
                        proxyPort,
                        capabilities ->
                                capabilities.setCapability(
                                        CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR,
                                        UnexpectedAlertBehaviour.IGNORE),
                        false);
        webDriver.manage().timeouts().pageLoadTimeout(Duration.of(30, ChronoUnit.SECONDS));
        webDriver.manage().timeouts().scriptTimeout(Duration.of(20, ChronoUnit.SECONDS));
        return new ClientActiveScanRuleWebDriverWrapper(webDriver, browser);
    }

    /**
     * Acquires a WebDriver from the pool, creating new ones up to the configured pool size. Waits
     * if all drivers are in use.
     *
     * <p>If the driver was previously used by a different rule, that rule's {@link
     * ClientActiveScanRule#scanComplete} is called before the driver is handed to the requesting
     * rule.
     *
     * @param isStop supplier that returns true when the scan has been stopped (caller should stop
     *     waiting)
     * @param rule the rule requesting the driver (used for scanComplete when driver is reassigned)
     * @return a wrapper containing the driver, or null if stopped or interrupted
     */
    public ClientActiveScanRuleWebDriverWrapper getWebDriver(
            BooleanSupplier isStop, ClientActiveScanRule rule) {
        synchronized (poolLock) {
            for (; ; ) {
                if (isStop != null && isStop.getAsBoolean()) {
                    return null;
                }
                if (!freeDrivers.isEmpty()) {
                    ClientActiveScanRuleWebDriverWrapper w = freeDrivers.pop();
                    if (w.lastUsedByRule != null && w.lastUsedByRule != rule) {
                        try {
                            w.lastUsedByRule.scanComplete(w.getDriver());
                        } catch (Exception e) {
                            LOGGER.debug(
                                    "scanComplete failed for rule {}",
                                    w.lastUsedByRule.getName(),
                                    e);
                        }
                        w.lastUsedByRule = null;
                    }
                    takenDrivers.add(w);
                    return w;
                }
                int poolSize = getPoolSize();
                if (takenDrivers.size() < poolSize) {
                    ClientActiveScanRuleWebDriverWrapper w = createWebDriver();
                    takenDrivers.add(w);
                    return w;
                }
                try {
                    poolLock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
    }

    /**
     * Returns a driver to the pool after use. Resets the driver (dismisses alert, loads
     * about:blank) before making it available again.
     *
     * @param wrapper the wrapper returned by {@link #getWebDriver}
     * @param rule the rule returning the driver (used to track which rule last used it)
     */
    public void returnDriver(
            ClientActiveScanRuleWebDriverWrapper wrapper, ClientActiveScanRule rule) {
        if (wrapper == null) {
            return;
        }
        synchronized (poolLock) {
            try {
                try {
                    wrapper.getDriver().switchTo().alert().accept();
                } catch (Exception e) {
                    // ignore
                }
                wrapper.getDriver().get("about:blank");
            } catch (Exception e) {
                LOGGER.debug("Error resetting driver before return", e);
            } finally {
                wrapper.lastUsedByRule = rule;
                if (takenDrivers.remove(wrapper)) {
                    freeDrivers.push(wrapper);
                }
                poolLock.notifyAll();
            }
        }
    }

    /**
     * Notifies the pool that a rule has finished scanning all its nodes. Calls {@link
     * ClientActiveScanRule#scanComplete} for each driver in the pool that was last used by that
     * rule.
     *
     * @param rule the rule that has finished scanning
     */
    public void ruleFinishedScanning(ClientActiveScanRule rule) {
        synchronized (poolLock) {
            for (ClientActiveScanRuleWebDriverWrapper w : freeDrivers) {
                if (w.lastUsedByRule == rule) {
                    try {
                        rule.scanComplete(w.getDriver());
                    } catch (Exception e) {
                        LOGGER.debug("scanComplete failed for rule {}", rule.getName(), e);
                    }
                    w.lastUsedByRule = null;
                }
            }
        }
    }

    /**
     * Shuts down all drivers and stops the proxy. Call when the scan using this pool has finished.
     */
    public void tidyUp() {
        synchronized (poolLock) {
            while (!freeDrivers.isEmpty()) {
                try {
                    freeDrivers.pop().getDriver().quit();
                } catch (Exception e) {
                    LOGGER.debug("Error quitting driver", e);
                }
            }
            for (ClientActiveScanRuleWebDriverWrapper w : takenDrivers) {
                try {
                    w.getDriver().quit();
                } catch (Exception e) {
                    LOGGER.debug("Error quitting taken driver", e);
                }
            }
            takenDrivers.clear();
            if (proxy != null) {
                try {
                    proxy.stop();
                } catch (IOException e) {
                    LOGGER.debug("Error stopping proxy", e);
                }
                proxy = null;
            }
            proxyPort = -1;
        }
    }
}
