/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.testutils.TestUtils;

class PruneJobUnitTest extends TestUtils {
    private ExtensionExim extExim;

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setUp() {
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extExim = mock(ExtensionExim.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionExim.class)).willReturn(extExim);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        PruneJob job = new PruneJob();

        // Then
        assertThat(job.getType(), is(equalTo("prune")));
        assertThat(job.getName(), is(equalTo("prune")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.AFTER_EXPLORE)));
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        PruneJob job = new PruneJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.get("fileName"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String fileName = "C:\\Users\\ZAPBot\\Documents\\test file.har";
        String yamlStr = "parameters:\n" + "  fileName: " + fileName;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PruneJob job = new PruneJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getFileName(), is(equalTo(fileName)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidFile() {
        // Given
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        String yamlStr = "parameters:\n" + "  fileName: 'Invalid file path'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PruneJob job = new PruneJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors(),
                contains(
                        allOf(
                                startsWith("Job prune Read 0 node(s) from "),
                                containsString(
                                        ", deleted 0 node(s), and failed with Exception loading file, for more details see the log file: Invalid file path ("))));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
