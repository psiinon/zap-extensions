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
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpLayout;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpMode;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for {@link MultiStepAuthTotpPage}. */
class MultiStepAuthTotpPageUnitTest {

    private static final Path TEMPLATE =
            Path.of("src/main/zapHomeFiles/addOnData/dev/server/auth/multi-step-auth/totp.html");

    private MultiStepAuthDir dir;
    private MultiStepAuthTotpPage page;

    @BeforeEach
    void setUp() throws Exception {
        TestProxyServer server = mock(TestProxyServer.class);
        given(server.getTextFile(any(), eq("totp.html"))).willReturn(Files.readString(TEMPLATE));
        dir =
                new MultiStepAuthDir(
                        new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class)),
                        "multi-step-auth");
        page =
                new MultiStepAuthTotpPage(server) {
                    @Override
                    public MultiStepAuthDir getParent() {
                        return dir;
                    }
                };
    }

    private static HttpMessage get(String query) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://localhost/auth/multi-step-auth/totp" + query + " HTTP/1.1");
        return msg;
    }

    @Test
    void shouldRedirectToLoginWithoutValidPendingToken() throws Exception {
        dir.configureTotp(TotpMode.FIXED, null, null, null, null);
        HttpMessage msg = get("?pending=unknown");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(
                msg.getResponseHeader().getHeader(HttpHeader.LOCATION), is(equalTo("index.html")));
    }

    @Test
    void shouldRedirectToLoginWhenTotpIsOff() throws Exception {
        String pending = dir.createPendingToken("test@test.com");
        HttpMessage msg = get("?pending=" + pending);

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
    }

    @Test
    void shouldRenderSingleCodeField() throws Exception {
        dir.configureTotp(TotpMode.SECRET, TotpLayout.SINGLE, null, null, 6);
        String pending = dir.createPendingToken("test@test.com");
        HttpMessage msg = get("?pending=" + pending);

        page.handleMessage(null, msg);

        String body = msg.getResponseBody().toString();
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
        assertThat(body, containsString("test@test.com"));
        assertThat(body, containsString("name=\"pending\" value=\"" + pending + "\""));
        assertThat(body, containsString("<input id=\"code\" name=\"code\" type=\"text\""));
        assertThat(body, containsString("maxlength=\"6\""));
        assertThat(body, not(containsString("id=\"digits\"")));
    }

    @Test
    void shouldRenderOneFieldPerDigit() throws Exception {
        dir.configureTotp(TotpMode.FIXED, TotpLayout.DIGITS, "1234", null, null);
        String pending = dir.createPendingToken("test@test.com");
        HttpMessage msg = get("?pending=" + pending);

        page.handleMessage(null, msg);

        String body = msg.getResponseBody().toString();
        assertThat(body, containsString("<div id=\"digits\">"));
        assertThat(count(body, "class=\"digit\" maxlength=\"1\""), is(equalTo(4)));
        assertThat(body, containsString("<input type=\"hidden\" id=\"code\" name=\"code\">"));
        // The digit fields must not have ids or names, so ZAP has to select them structurally.
        assertThat(body, not(containsString("id=\"code1\"")));
    }

    private static int count(String text, String substring) {
        Matcher matcher = Pattern.compile(Pattern.quote(substring)).matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }
}
