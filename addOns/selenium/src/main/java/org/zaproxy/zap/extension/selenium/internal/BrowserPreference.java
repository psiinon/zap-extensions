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
package org.zaproxy.zap.extension.selenium.internal;

import java.util.Objects;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.zaproxy.zap.utils.EnableableInterface;

/**
 * A browser preference (key-value pair with enabled state), e.g. for Chrome prefs or Firefox
 * about:config-style preferences.
 */
@Getter
@EqualsAndHashCode
public class BrowserPreference implements EnableableInterface {

    @Setter private boolean enabled;

    private String name;
    private String value;

    public BrowserPreference(String name, String value, boolean enabled) {
        this.enabled = enabled;
        setName(name);
        setValue(value);
    }

    public BrowserPreference(BrowserPreference other) {
        this(other.name, other.value, other.enabled);
    }

    public void setName(String name) {
        this.name = Objects.requireNonNull(name).trim();
    }

    public void setValue(String value) {
        this.value = value != null ? value : "";
    }
}
