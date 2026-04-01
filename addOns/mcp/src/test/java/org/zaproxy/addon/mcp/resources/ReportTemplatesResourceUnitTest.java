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
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ReportTemplatesResource}. */
class ReportTemplatesResourceUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private ExtensionLoader extensionLoader;
    private ExtensionReports extReports;
    private ReportTemplatesResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extReports = mock(ExtensionReports.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionReports.class)).willReturn(extReports);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new ReportTemplatesResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://report-templates"));
        assertThat(resource.getName(), equalTo("report-templates"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoTemplates() {
        given(extReports.getTemplates()).willReturn(List.of());

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    @Test
    void shouldReturnTemplateWithConfigNameAndDisplayName() {
        Template template = mock(Template.class, withSettings().strictness(Strictness.LENIENT));
        given(template.getConfigName()).willReturn("traditional-html");
        given(template.getDisplayName()).willReturn("Traditional HTML");
        given(template.getExtension()).willReturn(".html");
        given(extReports.getTemplates()).willReturn(List.of(template));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        JsonNode node = array.get(0);
        assertThat(node.get("configName").asText(), equalTo("traditional-html"));
        assertThat(node.get("displayName").asText(), equalTo("Traditional HTML"));
    }

    @Test
    void shouldReturnTemplateExtension() {
        Template template = mock(Template.class, withSettings().strictness(Strictness.LENIENT));
        given(template.getConfigName()).willReturn("traditional-html");
        given(template.getDisplayName()).willReturn("Traditional HTML");
        given(template.getExtension()).willReturn(".html");
        given(extReports.getTemplates()).willReturn(List.of(template));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        assertThat(array.get(0).get("extension").asText(), equalTo(".html"));
    }

    @Test
    void shouldReturnMultipleTemplates() {
        Template template1 = mock(Template.class, withSettings().strictness(Strictness.LENIENT));
        given(template1.getConfigName()).willReturn("traditional-html");
        given(template1.getDisplayName()).willReturn("Traditional HTML");
        given(template1.getExtension()).willReturn(".html");

        Template template2 = mock(Template.class, withSettings().strictness(Strictness.LENIENT));
        given(template2.getConfigName()).willReturn("traditional-json");
        given(template2.getDisplayName()).willReturn("Traditional JSON");
        given(template2.getExtension()).willReturn(".json");

        given(extReports.getTemplates()).willReturn(List.of(template1, template2));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(2));
    }

    private static JsonNode parseJsonArray(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
