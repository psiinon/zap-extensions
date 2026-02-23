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

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.client.ExtensionClientIntegration;

/**
 * Sub-extension that provides DOM XSS scanning for client-side (browser) discovered content.
 * Depends on the Client add-on to access the client map and shared WebDriver pool.
 */
public class ExtensionDomXssClient extends ExtensionAdaptor {

    public static final String NAME = "ExtensionDomXssClient";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private DomXssClientScanRule scanRule;

    public ExtensionDomXssClient() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
        scanRule = new DomXssClientScanRule();
        scanRule.setStatus(getAddOn().getStatus());
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (scanRule != null) {
            PluginFactory.loadedPlugin(scanRule);
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("domxss.client.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (scanRule != null) {
            PluginFactory.unloadedPlugin(scanRule);
        }
    }
}
