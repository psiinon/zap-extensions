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
package org.zaproxy.zap.extension.selenium.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.text.MessageFormat;
import java.util.ArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link CustomBrowserWebDriverProvider}. */
class CustomBrowserWebDriverProviderUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionSelenium());
    }

    @Test
    void shouldCreateProviderWithCustomBrowser() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        // When
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser);
        // Then
        assertThat(provider.getCustomBrowser(), is(equalTo(browser)));
        assertThat(provider.getId(), is(equalTo("custom.TestBrowser")));
    }

    @Test
    void shouldCreateProviderWithHeadlessFlag() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        // When
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser, true);
        // Then
        assertThat(provider.getId(), is(equalTo("custom.TestBrowser-headless")));
    }

    @Test
    void shouldCreateProviderWithoutHeadlessFlag() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        // When
        CustomBrowserWebDriverProvider provider =
                new CustomBrowserWebDriverProvider(browser, false);
        // Then
        assertThat(provider.getId(), is(equalTo("custom.TestBrowser")));
    }

    @Test
    void shouldReturnProvidedBrowser() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser);
        // When
        ProvidedBrowser providedBrowser = provider.getProvidedBrowser();
        // Then
        assertThat(providedBrowser, is(notNullValue()));
        assertThat(providedBrowser.getId(), is(equalTo("custom.TestBrowser")));
        assertThat(providedBrowser.getProviderId(), is(equalTo("custom.TestBrowser")));
    }

    @Test
    void shouldReturnBrowserNameForNonHeadlessProvider() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider =
                new CustomBrowserWebDriverProvider(browser, false);
        ProvidedBrowser providedBrowser = provider.getProvidedBrowser();
        // When
        String name = providedBrowser.getName();
        // Then
        assertThat(name, is(equalTo("TestBrowser")));
    }

    @Test
    void shouldReturnI18nHeadlessNameForHeadlessProvider() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser, true);
        ProvidedBrowser providedBrowser = provider.getProvidedBrowser();
        // When
        String name = providedBrowser.getName();
        // Then
        String expectedName =
                MessageFormat.format(
                        Constant.messages.getString("selenium.browser.headless.name"),
                        "TestBrowser",
                        Constant.messages.getString("selenium.browser.headless"));
        assertThat(name, is(equalTo(expectedName)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturnHeadlessFlagForHeadlessProvider(boolean flag) {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser, flag);
        ProvidedBrowser providedBrowser = provider.getProvidedBrowser();
        // When / Then
        assertThat(providedBrowser.isHeadless(), is(equalTo(flag)));
    }

    @Test
    void shouldReturnConfiguredStatusFromCustomBrowser() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser);
        // When / Then
        assertThat(provider.isConfigured(), is(equalTo(true)));
        assertThat(provider.getProvidedBrowser().isConfigured(), is(equalTo(true)));
    }

    @Test
    void shouldReturnConfiguredWhenBrowserHasNameAndTypeWithEmptyPaths() {
        // Custom browser with name and type is configured; empty driver/binary use defaults
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "",
                        "",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser);
        assertThat(provider.isConfigured(), is(equalTo(true)));
        assertThat(provider.getProvidedBrowser().isConfigured(), is(equalTo(true)));
    }

    @Test
    void shouldReturnNullWarnMessage() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "TestBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser);
        // When
        String message = provider.getWarnMessageFailedToStart(new RuntimeException("test"));
        // Then
        assertThat(message, is(equalTo(null)));
    }

    @Test
    void shouldUseCorrectIdFormatForHeadlessBrowser() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "MyBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.FIREFOX,
                        new ArrayList<>());
        // When
        CustomBrowserWebDriverProvider provider = new CustomBrowserWebDriverProvider(browser, true);
        // Then
        assertThat(provider.getId(), is(equalTo("custom.MyBrowser-headless")));
    }

    @Test
    void shouldUseCorrectIdFormatForNonHeadlessBrowser() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "MyBrowser",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.FIREFOX,
                        new ArrayList<>());
        // When
        CustomBrowserWebDriverProvider provider =
                new CustomBrowserWebDriverProvider(browser, false);
        // Then
        assertThat(provider.getId(), is(equalTo("custom.MyBrowser")));
    }
}
