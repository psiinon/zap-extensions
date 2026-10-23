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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpMode;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for {@link MultiStepAuthTotpVerifyPage}. */
class MultiStepAuthTotpVerifyPageUnitTest {

    private MultiStepAuthDir dir;
    private MultiStepAuthTotpVerifyPage page;

    @BeforeEach
    void setUp() {
        dir =
                new MultiStepAuthDir(
                        new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class)),
                        "multi-step-auth");
        dir.configureTotp(TotpMode.FIXED, null, "1234", null, null);
        page = (MultiStepAuthTotpVerifyPage) dir.getPage("verify");
    }

    private static HttpMessage post(String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "POST http://localhost/auth/multi-step-auth/verify HTTP/1.1\r\n"
                        + "Content-Type: application/x-www-form-urlencoded");
        msg.setRequestBody(body);
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        return msg;
    }

    @Test
    void shouldIssueSessionForValidCode() throws Exception {
        String pending = dir.createPendingToken("test@test.com");
        HttpMessage msg = post("pending=" + pending + "&code=1234");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(msg.getResponseHeader().getHeader(HttpHeader.LOCATION), is(equalTo("home")));
        String cookie = msg.getResponseHeader().getHeader(HttpHeader.SET_COOKIE);
        assertThat(cookie, is(notNullValue()));
        assertThat(cookie, startsWith("session="));
        assertThat(dir.getUser(cookie.substring("session=".length())), is("test@test.com"));
        assertThat(dir.getPendingUser(pending), is(nullValue()));
    }

    @Test
    void shouldRedirectToLoginForInvalidCode() throws Exception {
        String pending = dir.createPendingToken("test@test.com");
        HttpMessage msg = post("pending=" + pending + "&code=0000");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(
                msg.getResponseHeader().getHeader(HttpHeader.LOCATION), is(equalTo("index.html")));
        assertThat(msg.getResponseHeader().getHeader(HttpHeader.SET_COOKIE), is(nullValue()));
        assertThat(dir.getPendingUser(pending), is(nullValue()));
    }

    @Test
    void shouldRedirectToLoginForUnknownPendingToken() throws Exception {
        HttpMessage msg = post("pending=unknown&code=1234");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(
                msg.getResponseHeader().getHeader(HttpHeader.LOCATION), is(equalTo("index.html")));
    }
}
