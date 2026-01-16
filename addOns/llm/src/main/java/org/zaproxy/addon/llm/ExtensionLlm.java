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

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmAppendAlertMenu;
import org.zaproxy.addon.llm.ui.LlmAppendHttpMessageMenu;
import org.zaproxy.addon.llm.ui.LlmChatPanel;
import org.zaproxy.addon.llm.ui.LlmOptionsPanel;

/**
 * An extension for ZAP that enables researchers to leverage Large Language Models (LLMs) to augment
 * the functionalities of ZAP.
 */
public class ExtensionLlm extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

    public static final String NAME = "ExtensionLlm";

    protected static final String PREFIX = "llm";

    private static final String TOOLBAR_ICON_RESOURCE =
            "/org/zaproxy/addon/llm/resources/agent.png";
    private static final String TOOLBAR_ICON_FALLBACK = "/resource/icon/16/041.png";

    private LlmChatPanel llmChatPanel;
    private LlmOptions options;
    private LlmOptions prevOptions;
    private Map<String, LlmCommunicationService> commsServices =
            Collections.synchronizedMap(new HashMap<>());
    private JButton providerSelectorButton;

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
                            commsServices.clear();
                            prevOptions = options.clone();
                        }
                    }
                });

        if (hasView()) {
            LlmChatPanel llmChatPanel = new LlmChatPanel(this);
            extensionHook.getHookView().addOptionPanel(new LlmOptionsPanel());
            extensionHook.getHookView().addMainToolBarComponent(getProviderSelectorButton());
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

    public LlmCommunicationService getCommunicationService(String commsKey, String outputTabName) {
        if (!isConfigured()) {
            return null;
        }
        return commsServices.computeIfAbsent(
                commsKey, k -> new LlmCommunicationService(options, outputTabName));
    }

    private JButton getProviderSelectorButton() {
        if (providerSelectorButton == null) {
            providerSelectorButton = new JButton();
            ImageIcon icon = getImageIcon(TOOLBAR_ICON_RESOURCE);
            if (icon == null) {
                icon = getImageIcon(TOOLBAR_ICON_FALLBACK);
            }
            if (icon != null) {
                providerSelectorButton.setIcon(icon);
            }
            providerSelectorButton.setToolTipText(
                    Constant.messages.getString("llm.toolbar.button.tooltip"));
            providerSelectorButton.addActionListener(
                    e -> showProvidersPopup(providerSelectorButton));
        }
        return providerSelectorButton;
    }

    private void showProvidersPopup(JButton invoker) {
        JPopupMenu menu = buildProvidersMenu();
        menu.show(invoker, 0, invoker.getHeight());
    }

    private JPopupMenu buildProvidersMenu() {
        JPopupMenu menu = new JPopupMenu();
        List<LlmProviderConfig> configs = options.getProviderConfigs();
        if (configs.isEmpty()) {
            JMenuItem empty =
                    new JMenuItem(
                            Constant.messages.getString("llm.toolbar.providers.none"));
            empty.setEnabled(false);
            menu.add(empty);
            return menu;
        }

        String defaultName = options.getDefaultProviderName();
        String defaultModel = options.getDefaultModelName();
        ButtonGroup group = new ButtonGroup();
        for (LlmProviderConfig config : configs) {
            String name = config.getName();
            List<String> models = config.getModels();
            if (models.isEmpty()) {
                addProviderModelItem(
                        menu,
                        group,
                        name,
                        "",
                        name.equals(defaultName) && defaultModel.isEmpty());
                continue;
            }
            for (String model : models) {
                boolean isDefault =
                        name.equals(defaultName) && model.equals(defaultModel);
                addProviderModelItem(menu, group, name, model, isDefault);
            }
        }
        return menu;
    }

    private void addProviderModelItem(
            JPopupMenu menu,
            ButtonGroup group,
            String providerName,
            String modelName,
            boolean isDefault) {
        String label = providerName;
        if (!modelName.isEmpty()) {
            label += " - " + modelName;
        } else {
            label += " - " + Constant.messages.getString("llm.toolbar.model.empty");
        }
        if (isDefault) {
            label += Constant.messages.getString("llm.toolbar.default.suffix");
        }

        JRadioButtonMenuItem item = new JRadioButtonMenuItem(label, isDefault);
        item.addActionListener(e -> setDefaultProvider(providerName, modelName));
        group.add(item);
        menu.add(item);
    }

    private void setDefaultProvider(String name, String modelName) {
        if (name == null) {
            return;
        }

        if (name.equals(options.getDefaultProviderName())
                && modelName.equals(options.getDefaultModelName())) {
            return;
        }

        options.setDefaultProviderName(name);
        options.setDefaultModelName(modelName);
        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save LLM default provider selection:", e);
        }

        if (options.hasCommsChanged(prevOptions)) {
            commsServices.clear();
            prevOptions = options.clone();
        }
    }

    private static ImageIcon getImageIcon(String resourceName) {
        URL icon = ExtensionLlm.class.getResource(resourceName);
        if (icon == null) {
            return null;
        }
        return new ImageIcon(icon);
    }
    
    private LlmChatPanel getLlmChatPanel() {
        if (llmChatPanel == null) {
            llmChatPanel = new LlmChatPanel(this);
        }
        return llmChatPanel;
    }
}
