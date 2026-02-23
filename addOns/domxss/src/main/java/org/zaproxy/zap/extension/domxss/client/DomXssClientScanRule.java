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
package org.zaproxy.zap.extension.domxss.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ascan.ClientActiveScanRule;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.domxss.DomAlertInfo;
import org.zaproxy.zap.extension.domxss.DomXssScanLogic;
import org.zaproxy.zap.utils.Stats;

/**
 * Client active scan rule that performs DOM XSS checks on URLs discovered in the client map. Uses
 * the same attack vectors and detection logic as {@link
 * org.zaproxy.zap.extension.domxss.DomXssScanRule} but operates on browser-discovered content via
 * the shared WebDriver pool.
 */
public class DomXssClientScanRule extends ClientActiveScanRule {

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");

    private static final int UNLIKELY_INT = DomXssScanLogic.UNLIKELY_INT;
    private static final String PAYLOAD_0 = "<PAYLOAD_0>";
    private static final String PAYLOAD_1 = "<PAYLOAD_1>";

    // Same attack strings as DomXssScanRule (in order of effectiveness)
    private static final String[] ATTACK_STRINGS = {
        "#jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert("
                + UNLIKELY_INT
                + ") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("
                + UNLIKELY_INT
                + ")//>\\x3e",
        "#javascript:alert(" + UNLIKELY_INT + ")",
        "?name=abc#<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>",
        "#alert(" + UNLIKELY_INT + ")",
        "?name=<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>",
        "#<script>alert(" + UNLIKELY_INT + ")</script>",
        "#<img src=\"random.gif\" onerror=alert(" + UNLIKELY_INT + ")>",
        "#abc#<script>alert(" + UNLIKELY_INT + ")</script>",
        "#abc#<img src='random.gif' onerror=alert(" + UNLIKELY_INT + ")",
    };

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_CLNT_01_DOM_XSS));
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return 40030; // TODO original is 40026
    }

    @Override
    public String getName() {
        return Constant.messages.getString("domxss.client.name") + " client"; // TODO
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.BROWSER;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public AttackStrength[] getAttackStrengthsSupported() {
        return new AttackStrength[] {
            AttackStrength.LOW, AttackStrength.MEDIUM, AttackStrength.HIGH, AttackStrength.INSANE
        };
    }

    @Override
    public AlertThreshold[] getAlertThresholdsSupported() {
        return new AlertThreshold[] {AlertThreshold.LOW, AlertThreshold.MEDIUM};
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Collections.singletonList(buildAlert().build());
    }

    @Override
    protected void scanClientNode(ClientNode node, WebDriver driver) {
        String nodeUrl = node.getUserObject().getUrl();
        if (nodeUrl == null || nodeUrl.isEmpty()) {
            return;
        }

        Stats.incCounter("domxss.scan.count");

        int numberOfAttackStrings;
        switch (getAttackStrength()) {
            case LOW:
                numberOfAttackStrings = 1;
                break;
            case MEDIUM:
            default:
                numberOfAttackStrings = 3;
                break;
            case HIGH:
                numberOfAttackStrings = 6;
                break;
            case INSANE:
                numberOfAttackStrings = ATTACK_STRINGS.length;
                break;
        }

        for (int i = 0; i < numberOfAttackStrings; i++) {
            if (isStop()) {
                return;
            }
            String attackVector = ATTACK_STRINGS[i];
            List<String> steps = new ArrayList<>();
            DomAlertInfo result =
                    DomXssScanLogic.scan(
                            driver, attackVector, nodeUrl + attackVector, this::isStop, steps);

            if (result != null) {
                raiseAlert(result, steps, "");
                if (!Plugin.AlertThreshold.LOW.equals(getAlertThreshold())) {
                    break;
                }
            }
        }
    }

    private void raiseAlert(DomAlertInfo result, List<String> steps, String processedAttackVector) {
        StringBuilder otherInfo = new StringBuilder();
        otherInfo.append(Constant.messages.getString("domxss.step.intro")).append('\n');
        steps.replaceAll(e -> e.replace(result.getAttack(), PAYLOAD_0));
        if (steps.stream().anyMatch(e -> e.contains(PAYLOAD_0))) {
            otherInfo
                    .append(
                            Constant.messages.getString(
                                    "domxss.step.payload", PAYLOAD_0, result.getAttack()))
                    .append('\n');
        }
        if (!processedAttackVector.isEmpty()) {
            steps.replaceAll(e -> e.replace(processedAttackVector, PAYLOAD_1));
            if (steps.stream().anyMatch(e -> e.contains(PAYLOAD_1))) {
                otherInfo
                        .append(
                                Constant.messages.getString(
                                        "domxss.step.payload", PAYLOAD_1, processedAttackVector))
                        .append('\n');
            }
        }
        steps.forEach(e -> otherInfo.append(e).append('\n'));

        HttpMessage msg = getBaseMsg();
        buildAlert()
                .setUri(result.getUrl())
                .setAttack(result.getAttack())
                .setOtherInfo(otherInfo.toString())
                .setMessage(msg)
                .raise();
    }

    private AlertBuilder buildAlert() {
        return newAlert().setConfidence(Alert.CONFIDENCE_HIGH);
    }
}
