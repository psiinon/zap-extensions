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
package org.zaproxy.addon.llm.services;

import dev.langchain4j.model.chat.listener.ChatModelErrorContext;
import dev.langchain4j.model.chat.listener.ChatModelRequestContext;
import dev.langchain4j.model.chat.listener.ChatModelResponseContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.ui.LlmChatPanel;

/** A response handler that writes request/response output to the LLM Chat panel. */
public class LlmChatPanelResponseHandler implements FocusableChatModelListener {

    private static final Logger LOGGER = LogManager.getLogger(LlmChatPanelResponseHandler.class);

    private final LlmChatPanel chatPanel;
    private final boolean appendResponse;

    public LlmChatPanelResponseHandler(LlmChatPanel chatPanel) {
        this(chatPanel, true);
    }

    public LlmChatPanelResponseHandler(LlmChatPanel chatPanel, boolean appendResponse) {
        this.chatPanel = chatPanel;
        this.appendResponse = appendResponse;
    }

    @Override
    public void onRequest(ChatModelRequestContext requestContext) {
        if (chatPanel != null) {
            chatPanel.setProcessing(true);
            chatPanel.appendOutput(
                    Constant.messages.getString("llm.chat.panel.prefix.zap"),
                    requestContext.chatRequest().messages().get(0).toString());
        }
    }

    @Override
    public void onResponse(ChatModelResponseContext responseContext) {
        LOGGER.info("Token usage = {} ", responseContext.chatResponse().tokenUsage());
        if (chatPanel != null) {
            if (appendResponse) {
                chatPanel.appendOutput(
                        Constant.messages.getString("llm.chat.panel.prefix.assistant"),
                        responseContext.chatResponse().aiMessage().text());
            }
            chatPanel.setProcessing(false);
        }
    }

    @Override
    public void onError(ChatModelErrorContext errorContext) {
        LOGGER.error("LLM Error : {} ", errorContext.error().getMessage());
        if (chatPanel != null) {
            chatPanel.appendOutput(
                    Constant.messages.getString("llm.chat.panel.prefix.assistant"),
                    errorContext.error().getMessage());
            chatPanel.setProcessing(false);
            chatPanel.switchToPanel();
        }

        throw new RuntimeException(
                String.format("LLM Error : %s", errorContext.error().getMessage()));
    }

    @Override
    public void setFocus() {
        if (chatPanel != null) {
            chatPanel.switchToPanel();
        }
    }
}
