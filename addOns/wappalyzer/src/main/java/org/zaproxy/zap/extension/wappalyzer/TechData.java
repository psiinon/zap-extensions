/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TechData {

    private Map<String, String> categories = new HashMap<>();
    private List<Application> applications = Collections.synchronizedList(new ArrayList<>());

    public void addCategory(String key, String value) {
        this.categories.put(key, value);
    }

    public void addApplication(Application application) {
        this.applications.add(application);
    }

    public Map<String, String> getCategories() {
        return categories;
    }

    public List<Application> getApplications() {
        return applications;
    }
}
