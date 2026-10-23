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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpLayout;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpMode;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Configures the TOTP step of the multi-step login, so that tests can run against the same app in
 * different modes. The configuration is changed with a POST, with the parameters in the URL or the
 * body, a GET just returns it. Either way the current configuration is returned as JSON, for
 * example:
 *
 * <pre>{@code
 * POST config?totp=off&confirm=yes
 * POST config?totp=fixed&code=1234&layout=single&confirm=yes
 * POST config?totp=secret&secret=JBSWY3DPEHPK3PXP&digits=6&layout=digits&confirm=yes
 * }</pre>
 *
 * Parameters not provided keep their defaults, {@code totp=off} resets everything. Only a POST with
 * {@code confirm=yes} changes the configuration, so that neither the GETs of spiders, or of browser
 * extensions which re-request the URLs already seen, nor crawlers submitting the form of {@code
 * config.html} with its default values ({@code confirm=no}) change it behind the back of a test.
 */
public class MultiStepAuthConfigPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(MultiStepAuthConfigPage.class);

    static final String PARAM_TOTP = "totp";
    static final String PARAM_LAYOUT = "layout";
    static final String PARAM_CODE = "code";
    static final String PARAM_SECRET = "secret";
    static final String PARAM_DIGITS = "digits";
    static final String PARAM_CONFIRM = "confirm";
    static final String CONFIRM_VALUE = "yes";

    public MultiStepAuthConfigPage(TestProxyServer server) {
        super(server, "config");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (HttpRequestHeader.POST.equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            Map<String, String> params = new HashMap<>();
            Stream.concat(msg.getUrlParams().stream(), msg.getFormParams().stream())
                    .forEach(p -> params.put(p.getName(), p.getValue()));
            if (!CONFIRM_VALUE.equals(params.get(PARAM_CONFIRM))) {
                LOGGER.debug("Ignoring TOTP configuration request without confirmation.");
            } else if (params.containsKey(PARAM_TOTP)) {
                getParent()
                        .configureTotp(
                                toEnum(TotpMode.class, params.get(PARAM_TOTP), TotpMode.OFF),
                                toEnum(
                                        TotpLayout.class,
                                        params.get(PARAM_LAYOUT),
                                        TotpLayout.SINGLE),
                                params.get(PARAM_CODE),
                                params.get(PARAM_SECRET),
                                toInteger(params.get(PARAM_DIGITS)));
                LOGGER.info("TOTP configured: {}", getParent().getTotpConfig());
            }
        }
        getServer().setJsonResponse(getParent().getTotpConfig(), msg);
    }

    private static <E extends Enum<E>> E toEnum(Class<E> type, String value, E defaultValue) {
        if (StringUtils.isEmpty(value)) {
            return defaultValue;
        }
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            LOGGER.debug("Ignoring invalid value {} for {}", value, type.getSimpleName());
            return defaultValue;
        }
    }

    private static Integer toInteger(String value) {
        if (StringUtils.isEmpty(value)) {
            return null;
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public MultiStepAuthDir getParent() {
        return (MultiStepAuthDir) super.getParent();
    }
}
