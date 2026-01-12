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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.utils.Stats;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.request.ResponseFormatType;

public class LlmActionExplainAlert {

    private ExtensionLlm extLlm;

    private static final String ALERT_EXPLAIN_PROMPT =
            """
            Your task is to explain the following finding from ZAP (Zed Attack Proxy) to a developer who
            has been tasked with reviewing and fixing this problem.

            The alert title is: {{title}}

            The alert is described as follows: {{description}}

            As evidence, the HTTP message contains:
            ---
            {{evidence}}
            ---
            """;

    private static final String ALERT_REVIEW_OTHER_INFO =
            """
            As alert other info contains:
            ---
            {{other}}
            ---
            """;

    private static final String ALERT_REVIEW_GOAL =
            "Provide a detailed explanation of the alert, including guidance for fixing the problem.\n";

    public LlmActionExplainAlert(ExtensionLlm extLlm) {
        this.extLlm = extLlm;
    }

    public void reviewAlert(Alert alert)
            throws JsonMappingException,
                    JsonProcessingException,
                    HttpMalformedHeaderException,
                    DatabaseException {
        ResponseFormat responseFormat =
                ResponseFormat.builder()
                        .type(ResponseFormatType.TEXT)
                        .build();

        UserMessage userMessage =
                UserMessage.from(
                        ALERT_EXPLAIN_PROMPT
                                        .replace("{{title}}", alert.getName())
                                        .replace("{{description}}", alert.getDescription())
                                        .replace("{{evidence}}", alert.getEvidence())
                                + (StringUtils.isNotBlank(alert.getOtherInfo())
                                        ? ALERT_REVIEW_OTHER_INFO.replace(
                                                "{{other}}", alert.getOtherInfo())
                                        : "")
                                + ALERT_REVIEW_GOAL);

        ChatRequest chatRequest =
                ChatRequest.builder().responseFormat(responseFormat).messages(userMessage).build();

        LlmCommunicationService commsService =
                extLlm.getCommunicationService(
                        "ALERT_REVIEW",
                        Constant.messages.getString("alertFilters.llm.reviewalert.output.tab"));

        commsService.switchToOutputTab();
        commsService.chat(chatRequest);
        Stats.incCounter("stats.llm.alertexplain.result");
    }
}
