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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.Template;

/** MCP tool that generates a ZAP report. */
public class ZapGenerateReportTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapGenerateReportTool.class);

    @Override
    public String getName() {
        return "zap_generate_report";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.generatereport.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "file_path",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.filepath")));
        properties.put(
                "template",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.template")));
        properties.put(
                "title",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.title")));
        return new InputSchema(properties, List.of("template"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        ExtensionReports extReports =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionReports.class);

        String template = arguments.getString("template");
        if (template == null || template.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.generatereport.error.missingtemplate"));
        }
        template = template.trim();

        String title = arguments.getString("title");
        title = title == null ? "" : title.trim();

        String filePath = McpToolUtils.optionalTrim(arguments.getString("file_path"));
        if (filePath != null) {
            return generateToFile(extReports, template, title, filePath);
        }
        return generateAsZip(extReports, template, title);
    }

    private McpToolResult generateToFile(
            ExtensionReports extReports, String template, String title, String filePath)
            throws McpToolException {
        try {
            File report = extReports.generateReport(template, filePath, title, "", false);
            return McpToolResult.success(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.success", report.getAbsolutePath()));
        } catch (IOException e) {
            // Likely to be a file problem
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.failed", e.getMessage()));
        } catch (IllegalArgumentException e) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.unknowntemplate", template));
        } catch (Exception e) {
            LOGGER.error("Failed to generate report", e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.failed",
                            Constant.messages.getString("mcp.tool.error.unknown")));
        }
    }

    /**
     * Generates the report to a temporary directory and returns the whole thing (report file plus
     * any accompanying resources, e.g. CSS/images) zipped up as an embedded resource, since there
     * is nowhere on disk that would be meaningful to a remote MCP client.
     */
    private McpToolResult generateAsZip(ExtensionReports extReports, String template, String title)
            throws McpToolException {
        Template reportTemplate = extReports.getTemplateByConfigName(template);
        if (reportTemplate == null) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.unknowntemplate", template));
        }

        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("zap-report-");
            Path reportFile = tempDir.resolve("report." + reportTemplate.getExtension());

            extReports.generateReport(template, reportFile.toString(), title, "", false);

            byte[] zipBytes = zipDirectory(tempDir);
            return McpToolResult.successWithBlob(
                    Constant.messages.getString("mcp.tool.generatereport.success.zip"),
                    "zap-report:///" + template + ".zip",
                    "application/zip",
                    zipBytes);
        } catch (IOException e) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.failed", e.getMessage()));
        } catch (Exception e) {
            LOGGER.error("Failed to generate report", e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.failed",
                            Constant.messages.getString("mcp.tool.error.unknown")));
        } finally {
            deleteRecursively(tempDir);
        }
    }

    private static byte[] zipDirectory(Path dir) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(byteStream);
                Stream<Path> paths = Files.walk(dir)) {
            for (Path path : (Iterable<Path>) paths.filter(Files::isRegularFile)::iterator) {
                String entryName = dir.relativize(path).toString().replace(File.separatorChar, '/');
                zip.putNextEntry(new ZipEntry(entryName));
                Files.copy(path, zip);
                zip.closeEntry();
            }
        }
        return byteStream.toByteArray();
    }

    private static void deleteRecursively(Path dir) {
        if (dir == null) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder())
                    .forEach(
                            path -> {
                                try {
                                    Files.deleteIfExists(path);
                                } catch (IOException e) {
                                    LOGGER.debug("Failed to delete {}", path, e);
                                }
                            });
        } catch (IOException e) {
            LOGGER.debug("Failed to clean up temp report directory {}", dir, e);
        }
    }
}
