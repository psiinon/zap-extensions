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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Validates the TOTP code submitted from the TOTP page and issues the session token on success. The
 * pending token is consumed either way, so a wrong code sends the user back to the start.
 */
public class MultiStepAuthTotpVerifyPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(MultiStepAuthTotpVerifyPage.class);

    static final String PARAM_CODE = "code";

    public MultiStepAuthTotpVerifyPage(TestProxyServer server) {
        super(server, "verify");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String user =
                getParent()
                        .consumePendingToken(
                                getFormParameter(msg, MultiStepAuthTotpPage.PARAM_PENDING));
        String code = getFormParameter(msg, PARAM_CODE);
        boolean codeValid = user != null && getParent().isValidTotpCode(code);
        LOGGER.debug("TOTP attempt: user={} codeOk={}", user, codeValid);

        if (codeValid) {
            String token = getParent().getToken(user);
            DevUtils.setRedirect(msg, "home");
            msg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + token);
        } else {
            DevUtils.setRedirect(msg, "index.html");
        }
    }

    @Override
    public MultiStepAuthDir getParent() {
        return (MultiStepAuthDir) super.getParent();
    }
}
