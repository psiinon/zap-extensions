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

import java.io.IOException;

import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.client.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.extension.spiderAjax.AuthenticationHandler;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestActionFailException;
import org.zaproxy.zest.core.v1.ZestAssertFailException;
import org.zaproxy.zest.core.v1.ZestAssignFailException;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestInvalidCommonTestException;
import org.zaproxy.zest.impl.ZestBasicRunner;

public class ClientScriptBasedAuthHandler implements AuthenticationHandler {

	private BrowserHook browserHook;
	private static ZestBasicRunner zestRunner;

    @Override
    public boolean enableAuthentication(User user) {
        Context context = user.getContext();
        if (context.getAuthenticationMethod()
                instanceof ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod) {

			if (browserHook != null) {
                throw new IllegalStateException("BrowserHook already enabled");
            }
            browserHook = new AuthenticationBrowserHook(context, user);

            AuthUtils.getExtension(ExtensionSelenium.class).registerBrowserHook(browserHook);

            return true;
        }
        return false;
    }

    @Override
    public boolean disableAuthentication(User user) {
        if (browserHook != null) {
        	AuthUtils.getExtension(ExtensionSelenium.class).deregisterBrowserHook(browserHook);
            browserHook = null;
            return true;
        }
        return false;
    }
    
    private static ZestBasicRunner getZestRunner() {
    	if (zestRunner == null) {
    		zestRunner = new ZestBasicRunner();
            // Always proxy via ZAP
            ServerInfo serverInfo = AuthUtils.getExtension(ExtensionNetwork.class).getMainProxyServerInfo();
            zestRunner.setProxy(serverInfo.getAddress(), serverInfo.getPort());

    	}
    	return zestRunner;
    }
    
    static class AuthenticationBrowserHook implements BrowserHook {

        private ClientScriptBasedAuthenticationMethod csaMethod;
        private UsernamePasswordAuthenticationCredentials userCreds;
        private Context context;

        /*
        AuthenticationBrowserHook(Context context, String userName) {
            this(context, getUser(context, userName));
        }
        */

        AuthenticationBrowserHook(Context context, User user) {
            this.context = context;
            AuthenticationMethod method = context.getAuthenticationMethod();
            if (!(method instanceof ClientScriptBasedAuthenticationMethod)) {
                throw new IllegalStateException("Unsupported method " + method.getType().getName());
            }
            csaMethod = (ClientScriptBasedAuthenticationMethod) method;

            AuthenticationCredentials creds = user.getAuthenticationCredentials();
            if (!(creds instanceof UsernamePasswordAuthenticationCredentials)) {
            	/* dont need this? Or just optional for param substitution
                throw new IllegalStateException(
                        "Unsupported user credentials type " + creds.getClass().getCanonicalName());
                        */
            }
            // userCreds = (UsernamePasswordAuthenticationCredentials) creds;
        }

        @Override
        public void browserLaunched(SeleniumScriptUtils ssutils) {
            // TODO Instantiate and call BasicZestRunner?
        	ZestBasicRunner runner = getZestRunner();
        	runner.setWebDriver(ssutils.getWebDriver());
        	try {
        		// TODO need Zest script!
				runner.run(csaMethod.getZestScript(), null);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	/*
            LOGGER.debug(
                    "AuthenticationBrowserHook - authenticating as {}", userCreds.getUsername());
            AuthUtils.authenticateAsUser(
                    ssutils.getWebDriver(),
                    context,
                    bbaMethod.getLoginPageUrl(),
                    userCreds.getUsername(),
                    userCreds.getPassword(),
                    bbaMethod.getLoginPageWait());
        */
        }
        
    }

}
