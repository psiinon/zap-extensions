/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledOpenRedirect}
 */
public class UserControlledOpenRedirectScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final Logger LOGGER =
            LogManager.getLogger(UserControlledOpenRedirectScanRule.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.usercontrolledopenredirect.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.MOVED_PERMANENTLY
                || msg.getResponseHeader().getStatusCode() == HttpStatusCode.FOUND) {
            if (msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION) != null) {
                Set<HtmlParameter> params = new TreeSet<>(msg.getUrlParams());
                params.addAll(msg.getFormParams());

                if (!params.isEmpty()) {
                    checkUserControllableLocationHeaderValue(
                            msg,
                            id,
                            params,
                            msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION));
                }
            }
        }
    }

    private void checkUserControllableLocationHeaderValue(
            HttpMessage msg, int id, Set<HtmlParameter> params, String responseLocation) {
        if (responseLocation.length() == 0) {
            return;
        }

        String requestDomain = null;
        try {
            requestDomain = msg.getRequestHeader().getURI().getAuthority();
        } catch (URIException ex) {
            LOGGER.warn(
                    "Unable to get authority from URI : {}. Ignoring and moving ahead with the scanning OpenRedirect",
                    msg.getRequestHeader().getURI(),
                    ex);
        }

        String domain = null;

        // if contains protocol/domain name separator
        if (responseLocation.indexOf("://") > 0) {
            URL responseURL;
            try {
                responseURL = new URL(responseLocation);
            } catch (MalformedURLException e) {
                return;
            }

            // get domain name
            domain = responseURL.getAuthority();
        }

        if (requestDomain != null && requestDomain.equalsIgnoreCase(domain)) {
            return;
        }

        for (HtmlParameter param : params) {
            String paramValue = param.getValue();

            if (paramValue == null || paramValue.length() == 0) {
                continue;
            }

            if (paramValue.equalsIgnoreCase(domain)
                    || (responseLocation.indexOf("://") > 0
                            && paramValue.indexOf(responseLocation) >= 0)) {
                buildAlert(msg, param.getName(), paramValue, responseLocation).raise();
            }
        }
    }

    private AlertBuilder buildAlert(
            HttpMessage msg, String paramName, String paramValue, String responseLocation) {
        return newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setParam(paramName)
                .setOtherInfo(getExtraInfoMessage(msg, paramName, paramValue, responseLocation))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setCweId(601) // CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
                .setWascId(38); // WASC-38: URL Redirector Abuse
    }

    @Override
    public int getPluginId() {
        return 10028;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private static String getExtraInfoMessage(
            HttpMessage msg, String paramName, String paramValue, String responseLocation) {
        StringBuilder extraInfoSB = new StringBuilder();
        if ("GET".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            extraInfoSB.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.get"));
        } else if ("POST".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
            extraInfoSB.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.post"));
        }

        extraInfoSB.append(
                Constant.messages.getString(
                        MESSAGE_PREFIX + "extrainfo.common",
                        msg.getRequestHeader().getURI().toString(),
                        paramName,
                        paramValue,
                        responseLocation));

        return extraInfoSB.toString();
    }

    @Override
    public List<Alert> getExampleAlerts() {
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setMethod(HttpRequestHeader.GET);
        try {
            msg.getRequestHeader().setURI(new URI("https://example.com/transact", false));
        } catch (URIException | NullPointerException e) {
            // ignore
        }

        return List.of(buildAlert(msg, "place", "evil.com", "http://evil.com").build());
    }
}
