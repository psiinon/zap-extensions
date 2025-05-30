/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.dev.auth.simpleJsonBearerDiffCookies;

import java.net.HttpCookie;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SimpleJsonBearerDiffCookiesVerificationPage extends TestPage {

    private static final Logger LOGGER =
            LogManager.getLogger(SimpleJsonBearerDiffCookiesVerificationPage.class);

    private static final String BEARER_PREFIX = "Bearer ";

    private SimpleJsonBearerDiffCookiesDir parentDir;

    public SimpleJsonBearerDiffCookiesVerificationPage(
            TestProxyServer server, SimpleJsonBearerDiffCookiesDir parentDir) {
        super(server, "user");
        this.parentDir = parentDir;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String token = msg.getRequestHeader().getHeader("x-auth-token");
        if (token != null && token.startsWith(BEARER_PREFIX)) {
            token = token.substring(BEARER_PREFIX.length());
        } else {
            token = null;
        }
        String lbcookie = null;
        String corscookie = null;
        List<HttpCookie> cookieList = msg.getRequestHeader().getHttpCookies();
        for (HttpCookie hc : cookieList) {
            if ("ANOLB".equals(hc.getName())) {
                lbcookie = hc.getValue();
            } else if ("ANOCORS".equals(hc.getName())) {
                corscookie = hc.getValue();
            }
        }
        String user = getParent().getUser(token);
        LOGGER.debug("Token: {} user: {}", token, user);

        JSONObject response = new JSONObject();
        String status = TestProxyServer.STATUS_FORBIDDEN;
        if (lbcookie == null) {
            response.put("result", "FAIL (no LB cookie)");
        } else if (!parentDir.isValidCookie(user, lbcookie)) {
            response.put("result", "FAIL (bad LB cookie)");
        } else if (corscookie == null) {
            response.put("result", "FAIL (no CORS cookie)");
        } else if (!parentDir.isValidCookie(user, corscookie)) {
            response.put("result", "FAIL (bad CORS cookie)");
        } else if (user != null) {
            response.put("result", "OK");
            response.put("user", user);
            status = TestProxyServer.STATUS_OK;
        } else {
            response.put("result", "FAIL");
        }
        this.getServer().setJsonResponse(status, response, msg);
    }

    @Override
    public SimpleJsonBearerDiffCookiesDir getParent() {
        return (SimpleJsonBearerDiffCookiesDir) super.getParent();
    }
}
