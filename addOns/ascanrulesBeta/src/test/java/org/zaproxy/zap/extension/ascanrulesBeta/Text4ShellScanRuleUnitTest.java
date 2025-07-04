/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

class Text4ShellScanRuleUnitTest extends ActiveScannerTest<Text4ShellScanRule> {

    private ExtensionOast extensionOast;

    @Override
    protected Text4ShellScanRule createScanner() {
        return new Text4ShellScanRule();
    }

    @BeforeEach
    void init() throws Exception {
        nano.addHandler(new Log4ShellServerHandler("/abc"));
        HttpMessage httpMessageToTest = getHttpMessage("/abc?test=123");

        extensionOast = mock(ExtensionOast.class);
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class))
                .thenReturn(extensionOast);

        rule.init(httpMessageToTest, parent);
    }

    @Test
    void shouldTargetJavaApps() {
        // Given
        TechSet techSet = techSet(Tech.JAVA);
        // Then
        assertThat(rule.targets(techSet), is(equalTo(true)));
    }

    @Test
    void shouldSendHttpMessageForEachPayload() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any())).thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(Text4ShellScanRule.ATTACK_PATTERN_COUNT));
    }

    @Test
    void shouldSendAllPayloadsEvenInCaseOfIoException() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any()))
                .thenReturn("PAYLOAD1")
                .thenThrow(IOException.class)
                .thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(Text4ShellScanRule.ATTACK_PATTERN_COUNT - 1));
    }

    @Test
    void shouldStopSendingPayloadsOnNonIoException() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any()))
                .thenReturn("PAYLOAD1")
                .thenThrow(NullPointerException.class)
                .thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(1));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(117)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(11)));

        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(ExtensionOast.OAST_ALERT_TAG_KEY), is(equalTo(true)));
        assertThat(tags.containsKey(Text4ShellScanRule.CVE), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getValue())));
        assertThat(
                tags.get(ExtensionOast.OAST_ALERT_TAG_KEY),
                is(equalTo(ExtensionOast.OAST_ALERT_TAG_VALUE)));
    }

    private static class Log4ShellServerHandler extends NanoServerHandler {
        public Log4ShellServerHandler(String path) {
            super(path);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, "Text4Shell");
        }
    }
}
