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
package org.zaproxy.addon.llm;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.zaproxy.zap.utils.EnableableInterface;

@Getter
@Setter
@EqualsAndHashCode
public class LlmProviderConfig implements EnableableInterface {

    private String name;
    private LlmProvider provider;
    private String apiKey;
    private String endpoint;
    private String modelName;
    private boolean enabled = true;

    public LlmProviderConfig(
            String name, LlmProvider provider, String apiKey, String endpoint, String modelName) {
        this.name = name;
        this.provider = provider;
        this.apiKey = apiKey;
        this.endpoint = endpoint;
        this.modelName = modelName;
    }

    public LlmProviderConfig(LlmProviderConfig other) {
        this(other.name, other.provider, other.apiKey, other.endpoint, other.modelName);
        this.enabled = other.enabled;
    }
}
