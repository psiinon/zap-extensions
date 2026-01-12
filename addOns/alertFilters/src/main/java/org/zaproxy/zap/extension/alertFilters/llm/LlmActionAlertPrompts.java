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
package org.zaproxy.zap.extension.alertFilters.llm;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;

public class LlmActionAlertPrompts {

    private static final String ALERT_REVIEW_MAIN =
            """
            The alert title is: {{title}}

            The alert is described as follows: {{description}}

            """;

    private static final String ALERT_REVIEW_EVIDENCE =
            """
            As evidence, the HTTP message contains:
            ---
            {{evidence}}
            ---
            """;
    private static final String ALERT_REVIEW_NO_EVIDENCE =
            """
            There is no evidence in the alert, which is usual for missing security controls.
            ---
            """;
    private static final String ALERT_REVIEW_OTHER_INFO =
            """
            As alert other info contains:
            ---
            {{other}}
            ---
            """;

    public static String getAlertPrompt(Alert alert) {
    	StringBuilder sb = new StringBuilder();
    	sb.append(ALERT_REVIEW_MAIN
                .replace("{{title}}", alert.getName())
                .replace("{{description}}", alert.getDescription()));
    	
    	if (StringUtils.isNotBlank(alert.getEvidence())) {
        	sb.append(ALERT_REVIEW_EVIDENCE
                    .replace("{{evidence}}", alert.getEvidence()));
    	} else {
        	sb.append(ALERT_REVIEW_NO_EVIDENCE);
    	}
        if (StringUtils.isNotBlank(alert.getOtherInfo())) {
            sb.append(ALERT_REVIEW_OTHER_INFO.replace(
                        "{{other}}", alert.getOtherInfo()));
        }
    	
    	return sb.toString();
    }
    }
