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
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
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

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
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
        given(extAutomation.getAllScanProgress()).willReturn(Map.of());

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    @Test
    void shouldReturnScanWithIdAndProgress() {
        given(extAutomation.getAllScanProgress()).willReturn(Map.of("spider-1", 75));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        JsonNode node = array.get(0);
        assertThat(node.get("id").asText(), equalTo("spider-1"));
        assertThat(node.get("progress").asInt(), equalTo(75));
    }

    @Test
    void shouldReturnMultipleScans() {
        given(extAutomation.getAllScanProgress())
                .willReturn(Map.of("spider-1", 100, "ascan-2", 50));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(2));
    }

    @Test
    void shouldReturnScanWithFullProgress() {
        given(extAutomation.getAllScanProgress()).willReturn(Map.of("ascan-1", 100));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        List<String> ids = new ArrayList<>();
        List<Integer> progresses = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            ids.add(array.get(i).get("id").asText());
            progresses.add(array.get(i).get("progress").asInt());
        }
        assertThat(ids.contains("ascan-1"), equalTo(true));
        assertThat(progresses.contains(100), equalTo(true));
    }

    private static JsonNode parseJsonArray(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
