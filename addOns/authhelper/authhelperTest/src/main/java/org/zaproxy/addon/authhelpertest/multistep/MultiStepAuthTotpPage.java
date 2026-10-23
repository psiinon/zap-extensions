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

import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpLayout;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Serves the TOTP page (step 4), with either a single code field or one field per digit depending
 * on the configured layout. The per digit fields have neither {@code id} nor {@code name}, as is
 * common in real apps, so ZAP must select them structurally.
 */
public class MultiStepAuthTotpPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(MultiStepAuthTotpPage.class);

    static final String PARAM_PENDING = "pending";

    public MultiStepAuthTotpPage(TestProxyServer server) {
        super(server, "totp");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String pending = getUrlParameter(msg, PARAM_PENDING);
        String user = getParent().getPendingUser(pending);
        if (user == null || !getParent().isTotpEnabled()) {
            LOGGER.debug("TOTP page request with no valid pending token, redirecting to login");
            DevUtils.setRedirect(msg, "index.html");
            return;
        }

        String body = this.getServer().getTextFile(this.getParent(), "totp.html");
        body = body.replace("<!-- USER -->", user);
        body = body.replace("<!-- PENDING -->", pending);
        body = body.replace("<!-- CODE_INPUTS -->", createCodeInputs());
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private String createCodeInputs() {
        int digits = getParent().getTotpDigits();
        if (getParent().getTotpLayout() == TotpLayout.DIGITS) {
            return "<div id=\"digits\">"
                    + IntStream.range(0, digits)
                            .mapToObj(
                                    i ->
                                            "<input type=\"text\" class=\"digit\" maxlength=\"1\""
                                                    + " inputmode=\"numeric\""
                                                    + " autocomplete=\"one-time-code\">")
                            .collect(Collectors.joining())
                    + "</div><input type=\"hidden\" id=\"code\" name=\"code\">";
        }
        return "<input id=\"code\" name=\"code\" type=\"text\" inputmode=\"numeric\""
                + " autocomplete=\"one-time-code\" maxlength=\""
                + digits
                + "\">";
    }

    private static String getUrlParameter(HttpMessage msg, String name) {
        return msg.getUrlParams().stream()
                .filter(p -> p.getName().equals(name))
                .findFirst()
                .map(HtmlParameter::getValue)
                .orElse(null);
    }

    @Override
    public MultiStepAuthDir getParent() {
        return (MultiStepAuthDir) super.getParent();
    }
}
