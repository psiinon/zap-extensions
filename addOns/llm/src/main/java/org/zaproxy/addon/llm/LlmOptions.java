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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class LlmOptions extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 2;

    private static final String BASE_KEY = "llm";

    public static final String MODEL_PROVIDER_PROPERTY = BASE_KEY + ".modelprovider";
    public static final String APIKEY_PROPERTY = BASE_KEY + ".apikey";
    public static final String ENDPOINT_PROPERTY = BASE_KEY + ".endpoint";
    public static final String MODEL_NAME_PROPERTY = BASE_KEY + ".modelname";

    private static final String PROVIDERS_BASE_KEY = BASE_KEY + ".providers";
    private static final String ALL_PROVIDERS_KEY = PROVIDERS_BASE_KEY + ".provider";
    private static final String DEFAULT_PROVIDER_PROPERTY = PROVIDERS_BASE_KEY + ".default";
    private static final String PROVIDER_NAME_KEY = "name";
    private static final String PROVIDER_TYPE_KEY = "type";
    private static final String PROVIDER_APIKEY_KEY = "apikey";
    private static final String PROVIDER_ENDPOINT_KEY = "endpoint";
    private static final String PROVIDER_MODEL_NAME_KEY = "modelname";

    private static final String DEFAULT_PROVIDER_NAME = "Default";

    private List<LlmProviderConfig> providerConfigs = new ArrayList<>();
    private String defaultProviderName;

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected void parseImpl() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_PROVIDERS_KEY);
        List<LlmProviderConfig> configs = new ArrayList<>(fields.size());
        Set<String> names = new HashSet<>();
        for (HierarchicalConfiguration sub : fields) {
            String name = StringUtils.trimToEmpty(sub.getString(PROVIDER_NAME_KEY, ""));
            if (name.isEmpty() || !names.add(name)) {
                continue;
            }

            LlmProvider provider = LlmProvider.NONE;
            try {
                provider =
                        LlmProvider.valueOf(
                                sub.getString(PROVIDER_TYPE_KEY, LlmProvider.NONE.name()));
            } catch (IllegalArgumentException e) {
                provider = LlmProvider.NONE;
            }
            String apiKey = sub.getString(PROVIDER_APIKEY_KEY, "");
            String endpoint = sub.getString(PROVIDER_ENDPOINT_KEY, "");
            String modelName = sub.getString(PROVIDER_MODEL_NAME_KEY, "");

            configs.add(new LlmProviderConfig(name, provider, apiKey, endpoint, modelName));
        }
        this.providerConfigs = configs;
        defaultProviderName = getString(DEFAULT_PROVIDER_PROPERTY, "");
        normalizeDefaultProviderName();
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        if (fileVersion < 2) {
            migrateLegacyConfig();
        }
    }

    private void migrateLegacyConfig() {
        HierarchicalConfiguration config = (HierarchicalConfiguration) getConfig();
        if (config.getKeys(ALL_PROVIDERS_KEY).hasNext()) {
            return;
        }

        LlmProvider legacyProvider = getEnum(MODEL_PROVIDER_PROPERTY, LlmProvider.NONE);
        String legacyApiKey = getString(APIKEY_PROPERTY, "");
        String legacyEndpoint = getString(ENDPOINT_PROPERTY, "");
        String legacyModelName = getString(MODEL_NAME_PROPERTY, "");

        if (legacyProvider != LlmProvider.NONE
                || StringUtils.isNotBlank(legacyApiKey)
                || StringUtils.isNotBlank(legacyEndpoint)
                || StringUtils.isNotBlank(legacyModelName)) {
            String elementBaseKey = ALL_PROVIDERS_KEY + "(0).";
            config.setProperty(elementBaseKey + PROVIDER_NAME_KEY, DEFAULT_PROVIDER_NAME);
            config.setProperty(elementBaseKey + PROVIDER_TYPE_KEY, legacyProvider.name());
            config.setProperty(elementBaseKey + PROVIDER_APIKEY_KEY, legacyApiKey);
            config.setProperty(elementBaseKey + PROVIDER_ENDPOINT_KEY, legacyEndpoint);
            config.setProperty(elementBaseKey + PROVIDER_MODEL_NAME_KEY, legacyModelName);
            config.setProperty(DEFAULT_PROVIDER_PROPERTY, DEFAULT_PROVIDER_NAME);
        }

        config.clearProperty(MODEL_PROVIDER_PROPERTY);
        config.clearProperty(APIKEY_PROPERTY);
        config.clearProperty(ENDPOINT_PROPERTY);
        config.clearProperty(MODEL_NAME_PROPERTY);
    }

    public String getApiKey() {
        LlmProviderConfig config = getDefaultProviderConfig();
        return config != null ? config.getApiKey() : "";
    }

    public void setApiKey(String apiKey) {
        LlmProviderConfig config = getOrCreateDefaultProviderConfig();
        config.setApiKey(apiKey);
        persistProviderConfigs();
    }

    public String getEndpoint() {
        LlmProviderConfig config = getDefaultProviderConfig();
        return config != null ? config.getEndpoint() : "";
    }

    public void setEndpoint(String endpoint) {
        LlmProviderConfig config = getOrCreateDefaultProviderConfig();
        config.setEndpoint(endpoint);
        persistProviderConfigs();
    }

    public String getModelName() {
        LlmProviderConfig config = getDefaultProviderConfig();
        return config != null ? config.getModelName() : "";
    }

    public void setModelName(String modelName) {
        LlmProviderConfig config = getOrCreateDefaultProviderConfig();
        config.setModelName(modelName);
        persistProviderConfigs();
    }

    public LlmProvider getModelProvider() {
        LlmProviderConfig config = getDefaultProviderConfig();
        return config != null ? config.getProvider() : LlmProvider.NONE;
    }

    public void setModelProvider(LlmProvider modelProvider) {
        LlmProviderConfig config = getOrCreateDefaultProviderConfig();
        config.setProvider(modelProvider);
        persistProviderConfigs();
    }

    public boolean hasCommsChanged(LlmOptions options) {
        return !Objects.equals(this.providerConfigs, options.providerConfigs)
                || !Objects.equals(this.defaultProviderName, options.defaultProviderName);
    }

    public boolean isCommsConfigured() {
        LlmProviderConfig config = getDefaultProviderConfig();
        if (config == null || LlmProvider.NONE.equals(config.getProvider())) {
            return false;
        }
        return !config.getProvider().supportsEndpoint()
                || !StringUtils.isBlank(config.getEndpoint());
    }

    public String getCommsIssue() {
        LlmProviderConfig config = getDefaultProviderConfig();
        if (config == null || LlmProvider.NONE.equals(config.getProvider())) {
            return Constant.messages.getString("llm.error.provider");
        }
        if (config.getProvider().supportsEndpoint() && StringUtils.isBlank(config.getEndpoint())) {
            return Constant.messages.getString("llm.error.endpoint");
        }
        return null;
    }

    public List<LlmProviderConfig> getProviderConfigs() {
        List<LlmProviderConfig> configs = new ArrayList<>(providerConfigs.size());
        for (LlmProviderConfig config : providerConfigs) {
            configs.add(new LlmProviderConfig(config));
        }
        return configs;
    }

    public void setProviderConfigs(List<LlmProviderConfig> providerConfigs) {
        Objects.requireNonNull(providerConfigs);
        this.providerConfigs = new ArrayList<>(providerConfigs.size());
        for (LlmProviderConfig config : providerConfigs) {
            this.providerConfigs.add(new LlmProviderConfig(config));
        }
        normalizeDefaultProviderName();
        persistProviderConfigs();
    }

    public LlmProviderConfig getProviderConfig(String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        for (LlmProviderConfig config : providerConfigs) {
            if (name.equals(config.getName())) {
                return new LlmProviderConfig(config);
            }
        }
        return null;
    }

    public LlmProviderConfig getDefaultProviderConfig() {
        LlmProviderConfig config = getDefaultProviderConfigInternal();
        return config != null ? new LlmProviderConfig(config) : null;
    }

    private LlmProviderConfig getOrCreateDefaultProviderConfig() {
        LlmProviderConfig config = getDefaultProviderConfigInternal();
        if (config != null) {
            return config;
        }
        LlmProviderConfig created =
                new LlmProviderConfig(DEFAULT_PROVIDER_NAME, LlmProvider.NONE, "", "", "");
        providerConfigs.add(created);
        defaultProviderName = created.getName();
        return created;
    }

    private void persistProviderConfigs() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_PROVIDERS_KEY);

        for (int i = 0, size = providerConfigs.size(); i < size; ++i) {
            String elementBaseKey = ALL_PROVIDERS_KEY + "(" + i + ").";
            LlmProviderConfig config = providerConfigs.get(i);
            getConfig().setProperty(elementBaseKey + PROVIDER_NAME_KEY, config.getName());
            getConfig()
                    .setProperty(elementBaseKey + PROVIDER_TYPE_KEY, config.getProvider().name());
            getConfig().setProperty(elementBaseKey + PROVIDER_APIKEY_KEY, config.getApiKey());
            getConfig().setProperty(elementBaseKey + PROVIDER_ENDPOINT_KEY, config.getEndpoint());
            getConfig()
                    .setProperty(elementBaseKey + PROVIDER_MODEL_NAME_KEY, config.getModelName());
        }

        getConfig().setProperty(DEFAULT_PROVIDER_PROPERTY, defaultProviderName);
    }

    public String getDefaultProviderName() {
        return defaultProviderName;
    }

    public void setDefaultProviderName(String defaultProviderName) {
        this.defaultProviderName = StringUtils.trimToEmpty(defaultProviderName);
        normalizeDefaultProviderName();
        getConfig().setProperty(DEFAULT_PROVIDER_PROPERTY, this.defaultProviderName);
    }

    private LlmProviderConfig getDefaultProviderConfigInternal() {
        if (providerConfigs.isEmpty()) {
            return null;
        }
        if (!StringUtils.isBlank(defaultProviderName)) {
            for (LlmProviderConfig config : providerConfigs) {
                if (defaultProviderName.equals(config.getName())) {
                    return config;
                }
            }
        }
        return providerConfigs.get(0);
    }

    private void normalizeDefaultProviderName() {
        if (providerConfigs.isEmpty()) {
            defaultProviderName = "";
            return;
        }
        for (LlmProviderConfig config : providerConfigs) {
            if (config.getName().equals(defaultProviderName)) {
                return;
            }
        }
        defaultProviderName = providerConfigs.get(0).getName();
    }

    @Override
    public LlmOptions clone() {
        LlmOptions clone = (LlmOptions) super.clone();
        clone.providerConfigs = getProviderConfigs();
        clone.defaultProviderName = defaultProviderName;
        return clone;
    }
}
