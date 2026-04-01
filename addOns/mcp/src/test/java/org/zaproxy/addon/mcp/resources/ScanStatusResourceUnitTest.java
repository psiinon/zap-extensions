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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ScanStatusResource}. */
class ScanStatusResourceUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionAutomation extAutomation;
    private ScanStatusResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAutomation =
                mock(ExtensionAutomation.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionAutomation.class)).willReturn(extAutomation);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new ScanStatusResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://scan-status"));
        assertThat(resource.getName(), equalTo("scan-status"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoScans() {
        given(extAutomation.getAllLongRunningJobProgresses()).willReturn(Map.of());

        String content = resource.readContent();

        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnScanWithIdAndProgress() {
        given(extAutomation.getAllLongRunningJobProgresses()).willReturn(Map.of("spider-1", 75));

        String content = resource.readContent();

        assertThat(content, equalTo("[{\"id\":\"spider-1\",\"progress\":75}]"));
    }

    @Test
    void shouldReturnMultipleScans() {
        // Map.of iteration order is not guaranteed, so check for each entry's presence.
        given(extAutomation.getAllLongRunningJobProgresses())
                .willReturn(Map.of("spider-1", 100, "ascan-2", 50));

        String content = resource.readContent();

        assertThat(content, containsString("{\"id\":\"spider-1\",\"progress\":100}"));
        assertThat(content, containsString("{\"id\":\"ascan-2\",\"progress\":50}"));
    }

    @Test
    void shouldReturnScanWithFullProgress() {
        given(extAutomation.getAllLongRunningJobProgresses()).willReturn(Map.of("ascan-1", 100));

        String content = resource.readContent();

        assertThat(content, equalTo("[{\"id\":\"ascan-1\",\"progress\":100}]"));
    }
}
