/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement
 * ('Expression Language Injection')
 *
 * <p>http://cwe.mitre.org/data/definitions/917.html
 *
 * @author yhawke (2014)
 */
public class ExpressionLanguageInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    // Logger object
    private static final Logger LOGGER =
            LogManager.getLogger(ExpressionLanguageInjectionScanRule.class);

    private static final int MAX_NUM_TRIES = 1000;
    private static final int DEVIATION_VALUE = 999999;
    private static final int MEAN_VALUE = 100000;
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final Random RAND = new Random();

    @Override
    public int getId() {
        return 90025;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.elinjection.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.elinjection.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.elinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.elinjection.refs");
    }

    @Override
    public int getCweId() {
        return 917;
    }

    @Override
    public int getWascId() {
        // There's not a real classification for this
        // so we consider the general "Improper Input Handling" class
        // http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling
        return 20;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public void init() {
        // do nothing
    }

    /**
     * Scan for Expression Language Injection Vulnerabilities
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {

        String originalContent = getBaseMsg().getResponseBody().toString();
        String addedString;
        int bignum1;
        int bignum2;
        int tries = 0;

        do {
            bignum1 = MEAN_VALUE + (int) (RAND.nextFloat() * (DEVIATION_VALUE - MEAN_VALUE + 1));
            bignum2 = MEAN_VALUE + (int) (RAND.nextFloat() * (DEVIATION_VALUE - MEAN_VALUE + 1));
            addedString = String.valueOf(bignum1 + bignum2);
            tries++;

        } while (originalContent.contains(addedString) && (tries < MAX_NUM_TRIES));

        // Build the evil payload ${100146+99273}
        String payload = "${" + bignum1 + "+" + bignum2 + "}";

        try {
            // Set the expression value
            setParameter(msg, paramName, payload);
            try {
                // Send the request and retrieve the response
                sendAndReceive(msg);
            } catch (URIException | UnknownHostException | IllegalArgumentException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg.getRequestHeader().getURI());
                return;
            }
            // Check if the resulting content contains the executed addition
            if (msg.getResponseBody().toString().contains(addedString)) {
                // We Found IT!
                // First do logging
                LOGGER.debug(
                        "[Expression Language Injection Found] on parameter [{}]  with payload [{}]",
                        paramName,
                        payload);

                createAlert(paramName, payload, addedString).setMessage(msg).raise();
            }

        } catch (IOException ex) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOGGER.error(
                    "Expression Language Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                    paramName,
                    payload,
                    ex);
        }
    }

    private AlertBuilder createAlert(String paramName, String attack, String evidence) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(paramName)
                .setAttack(attack)
                .setEvidence(evidence);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("foo", "${719117+853088}", "1572205").build());
    }
}
