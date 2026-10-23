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
package org.zaproxy.addon.authhelpertest.multistep;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpLayout;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpMode;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for {@link MultiStepAuthConfigPage}. */
class MultiStepAuthConfigPageUnitTest {

    private MultiStepAuthDir dir;
    private MultiStepAuthConfigPage page;

    @BeforeEach
    void setUp() {
        dir =
                new MultiStepAuthDir(
                        new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class)),
                        "multi-step-auth");
        page = (MultiStepAuthConfigPage) dir.getPage("config");
    }

    private static HttpMessage request(String method, String query) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                method + " http://localhost/auth/multi-step-auth/config" + query + " HTTP/1.1");
        return msg;
    }

    private static HttpMessage get(String query) throws Exception {
        return request("GET", query);
    }

    private static HttpMessage post(String query) throws Exception {
        return request("POST", query);
    }

    @Test
    void shouldReturnCurrentConfigWithoutParameters() throws Exception {
        HttpMessage msg = post("");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
        assertThat(msg.getResponseBody().toString(), containsString("\"totp\":\"off\""));
        assertThat(dir.isTotpEnabled(), is(false));
    }

    @Test
    void shouldNotChangeConfigOnGet() throws Exception {
        dir.configureTotp(TotpMode.SECRET, TotpLayout.DIGITS, null, null, null);
        HttpMessage msg = get("?totp=off");

        page.handleMessage(null, msg);

        assertThat(dir.getTotpMode(), is(TotpMode.SECRET));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
        assertThat(msg.getResponseBody().toString(), containsString("\"totp\":\"secret\""));
    }

    @Test
    void shouldNotChangeConfigWithoutConfirmation() throws Exception {
        dir.configureTotp(TotpMode.SECRET, TotpLayout.DIGITS, null, null, null);

        page.handleMessage(null, post("?totp=off"));
        page.handleMessage(null, post("?totp=off&confirm=no"));

        assertThat(dir.getTotpMode(), is(TotpMode.SECRET));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
    }

    @Test
    void shouldConfigureFromFormParameters() throws Exception {
        HttpMessage msg = post("");
        msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
        msg.setRequestBody("totp=fixed&code=2468&layout=digits&confirm=yes");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

        page.handleMessage(null, msg);

        assertThat(dir.getTotpMode(), is(TotpMode.FIXED));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
        assertThat(dir.isValidTotpCode("2468"), is(true));
    }

    @Test
    void shouldConfigureFixedCode() throws Exception {
        HttpMessage msg = post("?totp=fixed&code=9999&layout=digits&confirm=yes");

        page.handleMessage(null, msg);

        assertThat(dir.getTotpMode(), is(TotpMode.FIXED));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
        assertThat(dir.isValidTotpCode("9999"), is(true));
        assertThat(msg.getResponseBody().toString(), containsString("\"digits\":4"));
    }

    @Test
    void shouldConfigureSecret() throws Exception {
        HttpMessage msg = post("?totp=secret&secret=ABCDEFGH&digits=8&confirm=yes");

        page.handleMessage(null, msg);

        assertThat(dir.getTotpMode(), is(TotpMode.SECRET));
        assertThat(dir.getTotpLayout(), is(TotpLayout.SINGLE));
        assertThat(dir.getTotpDigits(), is(equalTo(8)));
        assertThat(msg.getResponseBody().toString(), containsString("\"secret\":\"ABCDEFGH\""));
    }

    @Test
    void shouldIgnoreInvalidValues() throws Exception {
        HttpMessage msg = post("?totp=bogus&layout=bogus&digits=abc&confirm=yes");

        page.handleMessage(null, msg);

        assertThat(dir.getTotpMode(), is(TotpMode.OFF));
        assertThat(dir.getTotpLayout(), is(TotpLayout.SINGLE));
    }

    @Test
    void shouldTurnOff() throws Exception {
        dir.configureTotp(TotpMode.SECRET, TotpLayout.DIGITS, null, null, null);

        page.handleMessage(null, post("?totp=off&confirm=yes"));

        assertThat(dir.isTotpEnabled(), is(false));
    }
}
