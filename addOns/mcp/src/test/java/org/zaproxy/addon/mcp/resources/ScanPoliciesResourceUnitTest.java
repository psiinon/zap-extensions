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

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ScanPoliciesResource}. */
class ScanPoliciesResourceUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionActiveScan extActiveScan;
    private PolicyManager policyManager;
    private ScanPoliciesResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extActiveScan =
                mock(ExtensionActiveScan.class, withSettings().strictness(Strictness.LENIENT));
        policyManager = mock(PolicyManager.class, withSettings().strictness(Strictness.LENIENT));
        given(extActiveScan.getPolicyManager()).willReturn(policyManager);
        given(extensionLoader.getExtension(ExtensionActiveScan.class)).willReturn(extActiveScan);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new ScanPoliciesResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://scan-policies"));
        assertThat(resource.getName(), equalTo("scan-policies"));
    }

    @Test
    void shouldReturnEmptyArrayWhenExtensionNotInstalled() {
        given(extensionLoader.getExtension(ExtensionActiveScan.class)).willReturn(null);

        String content = resource.readContent();

        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoPolicies() {
        given(policyManager.getAllPolicyNames()).willReturn(List.of());

        String content = resource.readContent();

        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnPolicyNames() {
        given(policyManager.getAllPolicyNames()).willReturn(List.of("Default Policy", "Light"));

        String content = resource.readContent();

        assertThat(content, equalTo("[{\"name\":\"Default Policy\"},{\"name\":\"Light\"}]"));
    }

    @Test
    void shouldReturnMultiplePolicies() {
        given(policyManager.getAllPolicyNames())
                .willReturn(List.of("Default Policy", "Light", "Heavy"));

        String content = resource.readContent();

        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"Default Policy\"},{\"name\":\"Light\"},{\"name\":\"Heavy\"}]"));
    }
}
