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
package org.zaproxy.addon.llm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.llm.services.LlmChatPanelResponseHandler;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmAppendAlertMenu;
import org.zaproxy.addon.llm.ui.LlmAppendHttpMessageMenu;
import org.zaproxy.addon.llm.ui.LlmChatPanel;
import org.zaproxy.addon.llm.ui.LlmOptionsPanel;
import org.zaproxy.addon.llm.ui.LlmSelectorButton;

/**
 * An extension for ZAP that enables researchers to leverage Large Language Models (LLMs) to augment
 * the functionalities of ZAP.
 */
public class ExtensionLlm extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlm";

    protected static final String PREFIX = "llm";

    private LlmOptions options;
    private LlmOptions prevOptions;
    private LlmChatPanel llmChatPanel;
    private Map<String, LlmCommunicationService> commsServices =
            Collections.synchronizedMap(new HashMap<>());

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

    public ExtensionLlm() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        options = new LlmOptions();
        prevOptions = new LlmOptions();
        extensionHook.addOptionsParamSet(options);

        extensionHook.addOptionsChangedListener(
                new OptionsChangedListener() {

                    @Override
                    public void optionsChanged(OptionsParam optionsParam) {
                        if (options.hasCommsChanged(prevOptions)) {
                            optionsReset();
                        }
                    }
                });

        if (hasView()) {
            llmChatPanel = new LlmChatPanel(this);
            extensionHook.getHookView().addOptionPanel(new LlmOptionsPanel());
            extensionHook
                    .getHookView()
                    .addMainToolBarComponent(new LlmSelectorButton(this, options));
            extensionHook.getHookView().addWorkPanel(llmChatPanel);
            extensionHook.getHookMenu().addPopupMenuItem(new LlmAppendAlertMenu(llmChatPanel));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString("llm.menu.append.request.title"),
                                    true,
                                    false));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString("llm.menu.append.response.title"),
                                    false,
                                    true));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new LlmAppendHttpMessageMenu(
                                    llmChatPanel,
                                    Constant.messages.getString(
                                            "llm.menu.append.requestresponse.title"),
                                    true,
                                    true));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    public boolean isConfigured() {
        return options != null && options.isCommsConfigured();
    }

    public String getCommsIssue() {
        return options != null ? options.getCommsIssue() : "";
    }

    /**
     * Only for testing purposes.
     *
     * @return the options
     */
    protected LlmOptions getOptions() {
        return this.options;
    }

    @Override
    public void optionsLoaded() {
        this.prevOptions = this.options.clone();
    }

    private void optionsReset() {
        commsServices.clear();
        prevOptions = options.clone();
    }

    public LlmCommunicationService getCommunicationService(String commsKey, String outputTabName) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(
                commsKey,
                k ->
                        new LlmCommunicationService(
                                options.getDefaultProviderConfig(),
                                options.getDefaultModelName(),
                                outputTabName));
    }

    /** Switches focus to the LLM Chat panel. */
    public void switchToLlmChatPanel() {
        if (llmChatPanel != null) {
            llmChatPanel.switchToPanel();
        }
    }

    /**
     * Executes a chat request, displaying the request and response in the LLM Chat panel. Returns
     * null if not configured or if the chat panel is not available.
     *
     * @param commsKey the key to identify the service (e.g. for caching)
     * @param chatRequest the chat request to send
     * @return the chat response, or null if the service is not available
     */
    public ChatResponse executeChatRequestForPanel(String commsKey, ChatRequest chatRequest) {
        return executeChatRequestForPanel(commsKey, chatRequest, true);
    }

    /**
     * Executes a chat request, optionally displaying the response in the LLM Chat panel. Returns
     * null if not configured or if the chat panel is not available.
     *
     * @param commsKey the key to identify the service (e.g. for caching)
     * @param chatRequest the chat request to send
     * @param appendResponseToPanel whether to append the raw response to the panel
     * @return the chat response, or null if the service is not available
     */
    public ChatResponse executeChatRequestForPanel(
            String commsKey, ChatRequest chatRequest, boolean appendResponseToPanel) {
        LlmCommunicationService service =
                getCommunicationServiceForChatPanel(commsKey, appendResponseToPanel);
        if (service == null) {
            return null;
        }
        ChatResponse response = service.chat(chatRequest);
        service.switchToOutputTab();
        return response;
    }

    /** Appends a message to the LLM Chat panel. */
    public void appendToChatPanel(String message) {
        if (llmChatPanel != null) {
            llmChatPanel.appendOutput(
                    Constant.messages.getString("llm.chat.panel.prefix.assistant"), message);
        }
    }

    /**
     * Parses the JSON text from a chat response into the specified type.
     *
     * @param response the chat response
     * @param clazz the type to parse into
     * @return the parsed object
     */
    public <T> T parseChatResponse(ChatResponse response, Class<T> clazz)
            throws JsonMappingException, JsonProcessingException {
        return LlmCommunicationService.mapResponse(response, clazz);
    }

    /**
     * Returns a communication service that displays request/response in the LLM Chat panel. Returns
     * null if not configured or if the chat panel is not available.
     *
     * @param commsKey the key to identify the service (e.g. for caching)
     * @return the communication service, or null
     */
    public LlmCommunicationService getCommunicationServiceForChatPanel(String commsKey) {
        return getCommunicationServiceForChatPanel(commsKey, true);
    }

    /**
     * Returns a communication service that displays request/response in the LLM Chat panel. Returns
     * null if not configured or if the chat panel is not available.
     *
     * @param commsKey the key to identify the service (e.g. for caching)
     * @param appendResponseToPanel whether to append the raw response to the panel
     * @return the communication service, or null
     */
    public LlmCommunicationService getCommunicationServiceForChatPanel(
            String commsKey, boolean appendResponseToPanel) {
        if (!isConfigured() || llmChatPanel == null) {
            return null;
        }
        String cacheKey = commsKey + (appendResponseToPanel ? "" : ".no_append");
        return commsServices.computeIfAbsent(
                cacheKey,
                k ->
                        new LlmCommunicationService(
                                options.getDefaultProviderConfig(),
                                options.getDefaultModelName(),
                                new LlmChatPanelResponseHandler(
                                        llmChatPanel, appendResponseToPanel)));
    }

    public void setDefaultProvider(String name, String modelName) {
        if (name == null) {
            return;
        }

        String providerName = name;
        if (LlmProvider.NONE.toString().equals(providerName)) {
            providerName = "";
            modelName = "";
        }

        if (providerName.equals(options.getDefaultProviderName())
                && modelName.equals(options.getDefaultModelName())) {
            return;
        }

        options.setDefaultProviderName(providerName);
        options.setDefaultModelName(modelName);
        this.optionsReset();

        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save LLM default provider selection:", e);
        }
    }
}
