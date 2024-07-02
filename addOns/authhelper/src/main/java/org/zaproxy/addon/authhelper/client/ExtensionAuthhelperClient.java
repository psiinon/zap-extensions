/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.client;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;

public class ExtensionAuthhelperClient extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAuthhelperClient";

    /* TODO why does this fail? */
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAjax.class);
    /*  */

    protected static final ClientScriptBasedAuthenticationMethodType CLIENT_SCRIPT_BASED_AUTH_TYPE =
            new ClientScriptBasedAuthenticationMethodType();

    private ClientScriptBasedAuthHandler authHandler;

    public ExtensionAuthhelperClient() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAjax extAjax =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
        authHandler = new ClientScriptBasedAuthHandler();
        extAjax.addAuthenticationHandler(authHandler);
    }

    @Override
    public void optionsLoaded() {
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        System.out.println("SBSB ExtAuthhelperClient optionsLoaded " + extAuth); // TODO
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().add(CLIENT_SCRIPT_BASED_AUTH_TYPE);
            System.out.println("SBSB loaded client script based auth type"); // TODO
        }
    }

    @Override
    public void unload() {
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().remove(CLIENT_SCRIPT_BASED_AUTH_TYPE);
        }
        /*
        AuthUtils.disableBrowserAuthentication();
        BrowserBasedAuthenticationMethodType.stopProxies();
        AuthUtils.clean();
         */
        ExtensionAjax extAjax =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
        // extAjax.removeAuthenticationHandler(authHandler);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authhelper.spiderajax.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authhelper.spiderajax.name");
    }
}
