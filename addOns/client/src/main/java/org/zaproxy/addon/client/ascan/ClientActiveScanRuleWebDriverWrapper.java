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

import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.extension.selenium.Browser;

/**
 * Holds a WebDriver and its browser type for use in the client active scan rule pool.
 *
 * @see ClientActiveScanRule
 */
class ClientActiveScanRuleWebDriverWrapper {

    private final WebDriver driver;
    private final Browser browser;

    /** The rule that last used this driver; used to call scanComplete when driver is reassigned. */
    ClientActiveScanRule lastUsedByRule;

    ClientActiveScanRuleWebDriverWrapper(WebDriver driver, Browser browser) {
        this.driver = driver;
        this.browser = browser;
    }

    WebDriver getDriver() {
        return driver;
    }

    Browser getBrowser() {
        return browser;
    }
}
