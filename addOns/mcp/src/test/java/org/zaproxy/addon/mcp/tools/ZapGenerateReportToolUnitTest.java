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
package org.zaproxy.addon.mcp.tools;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.McpTool.ToolArguments;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ZapGenerateReportTool}. */
class ZapGenerateReportToolUnitTest {

    private ExtensionReports extReports;
    private ZapGenerateReportTool tool;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extReports = mock(ExtensionReports.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionReports.class)).willReturn(extReports);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        tool = new ZapGenerateReportTool();
    }

    @Test
    void shouldRejectMissingTemplate() {
        ToolArguments args = new ToolArguments(Map.of(), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldWriteToFileWhenFilePathProvided() throws Exception {
        given(
                        extReports.generateReport(
                                anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .willReturn(new File("/tmp/report.html"));
        ToolArguments args =
                new ToolArguments(
                        Map.of("template", "traditional-html", "file_path", "/tmp/report.html"),
                        Map.of());

        McpToolResult result = tool.execute(args);

        assertThat(result.isError(), is(false));
        assertThat(result.resourceBlob(), is(nullValue()));
        verify(extReports).generateReport("traditional-html", "/tmp/report.html", "", "", false);
    }

    @Test
    void shouldRejectUnknownTemplateWhenFilePathOmitted() {
        given(extReports.getTemplateByConfigName("nope")).willReturn(null);
        ToolArguments args = new ToolArguments(Map.of("template", "nope"), Map.of());

        McpToolException ex = assertThrows(McpToolException.class, () -> tool.execute(args));

        assertThat(ex.getMessage(), is(notNullValue()));
    }

    @Test
    void shouldReturnZipBlobWhenFilePathOmitted() throws Exception {
        Template template = mock(Template.class, withSettings().strictness(Strictness.LENIENT));
        given(template.getExtension()).willReturn("html");
        given(extReports.getTemplateByConfigName("traditional-html")).willReturn(template);

        String reportContent = "<html>report</html>";
        given(
                        extReports.generateReport(
                                anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .willAnswer(
                        invocation -> {
                            String reportFilename = invocation.getArgument(1);
                            Path reportPath = Path.of(reportFilename);
                            Files.writeString(reportPath, reportContent, StandardCharsets.UTF_8);
                            return reportPath.toFile();
                        });
        ToolArguments args = new ToolArguments(Map.of("template", "traditional-html"), Map.of());

        McpToolResult result = tool.execute(args);

        assertThat(result.isError(), is(false));
        assertThat(result.resourceMimeType(), equalTo("application/zip"));
        assertThat(result.resourceBlob(), is(notNullValue()));

        Map<String, String> entries = readZipEntries(result.resourceBlob());
        assertThat(entries, is(Map.of("report.html", reportContent)));
    }

    private static Map<String, String> readZipEntries(byte[] zipBytes) throws Exception {
        Map<String, String> entries = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                entries.put(
                        entry.getName(), new String(zip.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return entries;
    }
}
