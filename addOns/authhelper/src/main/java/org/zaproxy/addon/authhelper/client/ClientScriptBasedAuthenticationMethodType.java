/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXComboBox;
import org.jdesktop.swingx.decorator.FontHighlighter;
import org.jdesktop.swingx.renderer.DefaultListRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.SessionManagementRequestDetails;
import org.zaproxy.addon.authhelper.SessionToken;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationIndicatorsPanel;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestAuthenticationRunner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.EncodingUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.DynamicFieldsPanel;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zest.core.v1.ZestScript;

public class ClientScriptBasedAuthenticationMethodType extends ScriptBasedAuthenticationMethodType {

    public static final int METHOD_IDENTIFIER = 8; // TODO check its ok

    private static final Logger LOGGER =
            LogManager.getLogger(ClientScriptBasedAuthenticationMethodType.class);

    private ExtensionScript extensionScript;

    private HttpMessageHandler handler;
    private HttpMessage authMsg;
    private HttpMessage fallbackMsg;
    private int firstHrefId;


    public ClientScriptBasedAuthenticationMethodType() {}

    private HttpMessageHandler getHandler (Context context) {
    	if (handler == null) {
            handler =
                    new HttpMessageHandler() {

                        @Override
                        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
                            if (ctx.isFromClient()) {
                                return;
                            }

                            AuthenticationHelper.addAuthMessageToHistory(msg);

                            if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())
                                    && context.isIncluded(
                                            msg.getRequestHeader().getURI().toString())) {
                                // Record the last in scope POST as a fallback
                                fallbackMsg = msg;
                            }

                            SessionManagementRequestDetails smReqDetails = null;
                            Map<String, SessionToken> sessionTokens =
                                    AuthUtils.getResponseSessionTokens(msg);
                            if (!sessionTokens.isEmpty()) {
                                authMsg = msg;
                                smReqDetails =
                                        new SessionManagementRequestDetails(
                                                authMsg,
                                                new ArrayList<>(sessionTokens.values()),
                                                Alert.CONFIDENCE_HIGH);
                            } else {
                                Set<SessionToken> reqSessionTokens =
                                        AuthUtils.getRequestSessionTokens(msg);
                                if (!reqSessionTokens.isEmpty()) {
                                    // The request has at least one auth token we missed - try
                                    // to find one of them
                                    for (SessionToken st : reqSessionTokens) {
                                        smReqDetails =
                                                AuthUtils.findSessionTokenSource(
                                                        st.getValue(), firstHrefId);
                                        if (smReqDetails != null) {
                                            authMsg = smReqDetails.getMsg();
                                            LOGGER.debug(
                                                    "Session token found in href {}",
                                                    authMsg.getHistoryRef().getHistoryId());
                                            break;
                                        }
                                    }
                                }

                                if (authMsg != null && View.isInitialised()) {
                                    String hrefId = "?";
                                    if (msg.getHistoryRef() != null) {
                                        hrefId = "" + msg.getHistoryRef().getHistoryId();
                                    }
                                    AuthUtils.logUserMessage(
                                            Level.INFO,
                                            Constant.messages.getString(
                                                    "authhelper.auth.method.browser.output.sessionid",
                                                    hrefId));
                                }
                            }
                            if (firstHrefId == 0 && msg.getHistoryRef() != null) {
                                firstHrefId = msg.getHistoryRef().getHistoryId();
                            }
                        }
                    };

    		
    	}
    	return handler;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.clientscript.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public ClientScriptBasedAuthenticationMethod createAuthenticationMethod(int contextId) {
        return new ClientScriptBasedAuthenticationMethod();
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new ClientScriptBasedAuthenticationMethodOptionsPanel();
    }

    public class ClientScriptBasedAuthenticationMethod extends ScriptBasedAuthenticationMethod {
        private ScriptWrapper script;

        private String[] credentialsParamNames;

        private Map<String, String> paramValues;

        /**
         * Load a script and fills in the method's filled according to the values specified by the
         * script.
         *
         * <p>If the method already had a loaded script and a set of values for the parameters, it
         * tries to provide new values for the new parameters if they match any previous parameter
         * names.
         *
         * @param scriptW the script wrapper
         * @throws IllegalArgumentException if an error occurs while loading the script.
         */
        @Override
        public void loadScript(ScriptWrapper scriptW) {
            AuthenticationScript script = getScriptInterfaceV2(scriptW);
            if (script == null) {
                script = getScriptInterface(scriptW);
            }
            if (script == null) {
                LOGGER.warn(
                        "The script {} does not properly implement the Authentication Script interface.",
                        scriptW.getName());
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.interface",
                                scriptW.getName()));
            }

            try {
                if (script instanceof AuthenticationScriptV2) {
                    AuthenticationScriptV2 scriptV2 = (AuthenticationScriptV2) script;
                    setLoggedInIndicatorPattern(scriptV2.getLoggedInIndicator());
                    setLoggedOutIndicatorPattern(scriptV2.getLoggedOutIndicator());
                }
                String[] requiredParams = script.getRequiredParamsNames();
                String[] optionalParams = script.getOptionalParamsNames();
                this.credentialsParamNames = script.getCredentialsParamsNames();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Loaded authentication script - required parameters: {} - optional parameters: {}",
                            Arrays.toString(requiredParams),
                            Arrays.toString(optionalParams));
                }
                // If there's an already loaded script, make sure we save its values and _try_
                // to use them
                Map<String, String> oldValues =
                        this.paramValues != null
                                ? this.paramValues
                                : Collections.<String, String>emptyMap();
                this.paramValues = new HashMap<>(requiredParams.length + optionalParams.length);
                for (String param : requiredParams)
                    this.paramValues.put(param, oldValues.get(param));
                for (String param : optionalParams)
                    this.paramValues.put(param, oldValues.get(param));

                this.script = scriptW;
                LOGGER.info(
                        "Successfully loaded new script for ClientScriptBasedAuthentication: {}",
                        this);
            } catch (Exception e) {
                LOGGER.error("Error while loading authentication script", e);
                getScriptsExtension().handleScriptException(this.script, e);
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.loading",
                                e.getMessage()));
            }
            
        }

        @Override
        public String toString() {
            return "ClientScriptBasedAuthenticationMethod [script="
                    + script
                    + ", paramValues="
                    + paramValues
                    + ", credentialsParamNames="
                    + Arrays.toString(credentialsParamNames)
                    + "]";
        }

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public AuthenticationMethod duplicate() {
            ClientScriptBasedAuthenticationMethod method =
                    new ClientScriptBasedAuthenticationMethod();
            method.script = script;
            method.paramValues = this.paramValues != null ? new HashMap<>(this.paramValues) : null;
            method.credentialsParamNames = this.credentialsParamNames;
            return method;
        }

        @Override
        public boolean validateCreationOfAuthenticationCredentials() {
            if (credentialsParamNames != null) {
                return true;
            }

            if (View.isInitialised()) {
                View.getSingleton()
                        .showMessageDialog(
                                Constant.messages.getString(
                                        "authentication.method.script.dialog.error.text.notLoaded"));
            }

            return false;
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return new GenericAuthenticationCredentials(this.credentialsParamNames);
        }

        @Override
        public AuthenticationMethodType getType() {
            return new ClientScriptBasedAuthenticationMethodType();
        }
        
        public ScriptWrapper getScriptWrapper() {
        	return this.script;
        }

        public ZestScript getZestScript() {
            AuthenticationScript authScript = getScriptInterfaceV2(this.script);
            if (authScript == null) {
                authScript = getScriptInterface(this.script);
            }

            if (authScript == null) {
            	LOGGER.debug("Failed to get ZestScript - no suitable interface");
                return null;
            }

            if (authScript instanceof ZestAuthenticationRunner) {
            	ZestAuthenticationRunner zestScript = (ZestAuthenticationRunner)authScript;
            	return zestScript.getScript().getZestScript();
            }
            // TODO this ok?
        	LOGGER.debug("Failed to get ZestScript - authScript on right type {}", authScript.getClass().getCanonicalName());
            return null;

        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {
            // type check
            if (!(credentials instanceof GenericAuthenticationCredentials)) {
                user.getAuthenticationState()
                        .setLastAuthFailure("Credentials not GenericAuthenticationCredentials");
                throw new UnsupportedAuthenticationCredentialsException(
                        "Script based Authentication method only supports "
                                + GenericAuthenticationCredentials.class.getSimpleName()
                                + ". Received: "
                                + credentials.getClass());
            }
            GenericAuthenticationCredentials cred = (GenericAuthenticationCredentials) credentials;

            // Call the script to get an authenticated message from which we can then extract the
            // session
            AuthenticationScript authScript = getScriptInterfaceV2(this.script);
            if (authScript == null) {
                authScript = getScriptInterface(this.script);
            }

            if (authScript == null) {
                return null;
            }
            LOGGER.info("SBSB script class: " + authScript.getClass().getCanonicalName());
            ExtensionScript.recordScriptCalledStats(this.script);

            try {
                if (authScript instanceof AuthenticationScriptV2) {
                    AuthenticationScriptV2 scriptV2 = (AuthenticationScriptV2) authScript;
                    setLoggedInIndicatorPattern(scriptV2.getLoggedInIndicator());
                    setLoggedOutIndicatorPattern(scriptV2.getLoggedOutIndicator());
                }
                
                if (authScript instanceof ZestAuthenticationRunner) {
                	ZestAuthenticationRunner zestScript = (ZestAuthenticationRunner)authScript;
                	zestScript.registerHandler(getHandler(user.getContext()));
                } else {
                	// TODO fail in some way?
                }
                
                authScript.authenticate(
                        new AuthenticationHelper(
                                getHttpSender(), sessionManagementMethod, user),
                        this.paramValues,
                        cred);
            } catch (Exception e) {
                // Catch Exception instead of ScriptException and IOException because script engine
                // implementations
                // might throw other exceptions on script errors (e.g.
                // jdk.nashorn.internal.runtime.ECMAException)
                user.getAuthenticationState()
                        .setLastAuthFailure(
                                "Error running authentication script " + e.getMessage());
                LOGGER.error(
                        "An error occurred while trying to authenticate using the Authentication Script: {}",
                        this.script.getName(),
                        e);
                getScriptsExtension().handleScriptException(this.script, e);
                return null;
            }
            
            // Wait until the authentication request is identified
            for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
                if (authMsg != null) {
                    break;
                }
                AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
            }

            if (authMsg != null) {
                // Update the session as it may have changed
                WebSession session = sessionManagementMethod.extractWebSession(authMsg);
                user.setAuthenticatedSession(session);

                if (this.isAuthenticated(authMsg, user, true)) {
                    // Let the user know it worked
                    AuthenticationHelper.notifyOutputAuthSuccessful(authMsg);
                    user.getAuthenticationState().setLastAuthFailure("");
                } else {
                    // Let the user know it failed
                    AuthenticationHelper.notifyOutputAuthFailure(authMsg);
                }
                return session;
            }

            // We don't expect this to work, but it will prevent some NPEs
            return sessionManagementMethod.extractWebSession(fallbackMsg);
        }

        /* TODO
        @Override
        public ApiResponse getApiResponseRepresentation() {
            Map<String, String> values = new HashMap<>();
            values.put("methodName", API_METHOD_NAME);
            values.put("scriptName", script.getName());
            values.putAll(paramValues);
            return new AuthMethodApiResponseRepresentation<>(values);
        }
        */

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {
            AuthenticationHelper.replaceUserDataInRequest(
                    msg, wrapKeys(this.paramValues), NULL_ENCODER);
        }
    }

    private static Map<String, String> wrapKeys(Map<String, String> kvPairs) {
        Map<String, String> map = new HashMap<>();
        for (Entry<String, String> kv : kvPairs.entrySet()) {
            map.put(
                    AuthenticationMethod.TOKEN_PREFIX
                            + kv.getKey()
                            + AuthenticationMethod.TOKEN_POSTFIX,
                    kv.getValue());
        }
        return map;
    }

    @SuppressWarnings("serial")
    public class ClientScriptBasedAuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 7812841049435409987L;

        private final String SCRIPT_NAME_LABEL =
                Constant.messages.getString("authentication.method.script.field.label.scriptName");
        private final String LABEL_NOT_LOADED =
                Constant.messages.getString("authentication.method.script.field.label.notLoaded");
        private JXComboBox scriptsComboBox;
        private JButton loadScriptButton;

        private ClientScriptBasedAuthenticationMethod method;
        private AuthenticationIndicatorsPanel indicatorsPanel;

        private ScriptWrapper loadedScript;

        private JPanel dynamicContentPanel;

        private DynamicFieldsPanel dynamicFieldsPanel;

        private String[] loadedCredentialParams;

        public ClientScriptBasedAuthenticationMethodOptionsPanel() {
            super();
            initialize();
        }

        private void initialize() {
            this.setLayout(new GridBagLayout());

            this.add(new JLabel(SCRIPT_NAME_LABEL), LayoutHelper.getGBC(0, 0, 1, 0.0d, 0.0d));

            scriptsComboBox = new JXComboBox();
            scriptsComboBox.addHighlighter(
                    new FontHighlighter(
                            (renderer, adapter) -> loadedScript == adapter.getValue(),
                            scriptsComboBox.getFont().deriveFont(Font.BOLD)));
            scriptsComboBox.setRenderer(
                    new DefaultListRenderer(
                            sw -> {
                                if (sw == null) {
                                    return null;
                                }

                                String name = ((ScriptWrapper) sw).getName();
                                if (loadedScript == sw) {
                                    return Constant.messages.getString(
                                            "authentication.method.script.loaded", name);
                                }
                                return name;
                            }));
            this.add(this.scriptsComboBox, LayoutHelper.getGBC(1, 0, 1, 1.0d, 0.0d));

            this.loadScriptButton =
                    new JButton(
                            Constant.messages.getString(
                                    "authentication.method.script.load.button"));
            this.add(this.loadScriptButton, LayoutHelper.getGBC(2, 0, 1, 0.0d, 0.0d));
            this.loadScriptButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            loadScript((ScriptWrapper) scriptsComboBox.getSelectedItem(), true);
                        }
                    });

            // Make sure the 'Load' button is disabled when nothing is selected
            this.loadScriptButton.setEnabled(false);
            this.scriptsComboBox.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            loadScriptButton.setEnabled(scriptsComboBox.getSelectedIndex() >= 0);
                        }
                    });

            this.dynamicContentPanel = new JPanel(new BorderLayout());
            this.add(this.dynamicContentPanel, LayoutHelper.getGBC(0, 1, 3, 1.0d, 0.0d));
            this.dynamicContentPanel.add(new ZapHtmlLabel(LABEL_NOT_LOADED));
        }

        @Override
        public void validateFields() throws IllegalStateException {
            if (this.loadedScript == null) {
                this.scriptsComboBox.requestFocusInWindow();
                throw new IllegalStateException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.notLoadedNorConfigured"));
            }
            this.dynamicFieldsPanel.validateFields();
        }

        @Override
        public void saveMethod() {
            this.method.script = (ScriptWrapper) this.scriptsComboBox.getSelectedItem();
            // This method will also be called when switching panels to save a temporary state so
            // the state of the authentication method might not be valid
            if (this.dynamicFieldsPanel != null)
                this.method.paramValues = this.dynamicFieldsPanel.getFieldValues();
            else this.method.paramValues = Collections.emptyMap();
            if (this.loadedScript != null)
                this.method.credentialsParamNames = this.loadedCredentialParams;
        }

        @Override
        @SuppressWarnings("unchecked")
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            this.method = (ClientScriptBasedAuthenticationMethod) method;

            // Make sure the list of scripts is refreshed with just Zest scripts
            List<ScriptWrapper> scripts =
                    getScriptsExtension().getScripts(SCRIPT_TYPE_AUTH).stream()
                            .filter(sc -> sc.getEngineName().contains("Zest"))
                            .toList();
            DefaultComboBoxModel<ScriptWrapper> model =
                    new DefaultComboBoxModel<>(scripts.toArray(new ScriptWrapper[scripts.size()]));
            this.scriptsComboBox.setModel(model);
            this.scriptsComboBox.setSelectedItem(this.method.script);
            this.loadScriptButton.setEnabled(this.method.script != null);

            // Load the selected script, if any
            if (this.method.script != null) {
                loadScript(this.method.script, false);
                if (this.dynamicFieldsPanel != null)
                    this.dynamicFieldsPanel.bindFieldValues(this.method.paramValues);
            }
        }

        @Override
        public void bindMethod(
                AuthenticationMethod method, AuthenticationIndicatorsPanel indicatorsPanel)
                throws UnsupportedAuthenticationMethodException {
            this.indicatorsPanel = indicatorsPanel;
            bindMethod(method);
        }

        @Override
        public AuthenticationMethod getMethod() {
            return this.method;
        }

        private void loadScript(ScriptWrapper scriptW, boolean adaptOldValues) {
            AuthenticationScript script = getScriptInterfaceV2(scriptW);
            if (script == null) {
                script = getScriptInterface(scriptW);
            }

            if (script == null) {
                LOGGER.warn(
                        "The script {} does not properly implement the Authentication Script interface.",
                        scriptW.getName());
                warnAndResetPanel(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.interface",
                                scriptW.getName()));
                return;
            }

            try {
                if (script instanceof AuthenticationScriptV2) {
                    AuthenticationScriptV2 scriptV2 = (AuthenticationScriptV2) script;
                    String toolTip =
                            Constant.messages.getString(
                                    "authentication.method.script.dialog.loggedInOutIndicatorsInScript.toolTip");
                    String loggedInIndicator = scriptV2.getLoggedInIndicator();
                    this.method.setLoggedInIndicatorPattern(loggedInIndicator);
                    this.indicatorsPanel.setLoggedInIndicatorPattern(loggedInIndicator);
                    this.indicatorsPanel.setLoggedInIndicatorEnabled(false);
                    this.indicatorsPanel.setLoggedInIndicatorToolTip(toolTip);

                    String loggedOutIndicator = scriptV2.getLoggedOutIndicator();
                    this.method.setLoggedOutIndicatorPattern(loggedOutIndicator);
                    this.indicatorsPanel.setLoggedOutIndicatorPattern(loggedOutIndicator);
                    this.indicatorsPanel.setLoggedOutIndicatorEnabled(false);
                    this.indicatorsPanel.setLoggedOutIndicatorToolTip(toolTip);
                } else {
                    this.indicatorsPanel.setLoggedInIndicatorEnabled(true);
                    this.indicatorsPanel.setLoggedInIndicatorToolTip(null);
                    this.indicatorsPanel.setLoggedOutIndicatorEnabled(true);
                    this.indicatorsPanel.setLoggedOutIndicatorToolTip(null);
                }
                String[] requiredParams = script.getRequiredParamsNames();
                String[] optionalParams = script.getOptionalParamsNames();
                this.loadedCredentialParams = script.getCredentialsParamsNames();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Loaded authentication script - required parameters: {} - optional parameters: {}",
                            Arrays.toString(requiredParams),
                            Arrays.toString(optionalParams));
                }
                // If there's an already loaded script, make sure we save its values and _try_
                // to place them in the new panel
                Map<String, String> oldValues = null;
                if (adaptOldValues && dynamicFieldsPanel != null) {
                    oldValues = dynamicFieldsPanel.getFieldValues();
                    LOGGER.debug("Trying to adapt old values: {}", oldValues);
                }

                this.dynamicFieldsPanel = new DynamicFieldsPanel(requiredParams, optionalParams);
                this.loadedScript = scriptW;
                if (adaptOldValues && oldValues != null)
                    this.dynamicFieldsPanel.bindFieldValues(oldValues);

                this.dynamicContentPanel.removeAll();
                this.dynamicContentPanel.add(dynamicFieldsPanel, BorderLayout.CENTER);
                this.dynamicContentPanel.revalidate();

            } catch (Exception e) {
                getScriptsExtension().handleScriptException(scriptW, e);
                LOGGER.error("Error while calling authentication script", e);
                warnAndResetPanel(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.loading",
                                ExceptionUtils.getRootCauseMessage(e)));
            }
        }

        private void warnAndResetPanel(String errorMessage) {
            JOptionPane.showMessageDialog(
                    this,
                    errorMessage,
                    Constant.messages.getString("authentication.method.script.dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
            this.loadedScript = null;
            this.scriptsComboBox.setSelectedItem(null);
            this.dynamicFieldsPanel = null;
            this.dynamicContentPanel.removeAll();
            this.dynamicContentPanel.add(new JLabel(LABEL_NOT_LOADED), BorderLayout.CENTER);
            this.dynamicContentPanel.revalidate();
        }
    }

    private ExtensionScript getScriptsExtension() {
        if (extensionScript == null)
            extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        return extensionScript;
    }

    private AuthenticationScript getScriptInterface(ScriptWrapper script) {
        try {
            return getScriptsExtension().getInterface(script, AuthenticationScript.class);
        } catch (Exception e) {
            getScriptsExtension()
                    .handleFailedScriptInterface(
                            script,
                            Constant.messages.getString(
                                    "authentication.method.script.dialog.error.text.interface",
                                    script.getName()));
        }
        return null;
    }

    private AuthenticationScriptV2 getScriptInterfaceV2(ScriptWrapper script) {
        try {
            AuthenticationScriptV2 authScript =
                    getScriptsExtension().getInterface(script, AuthenticationScriptV2.class);
            if (authScript == null) {
                LOGGER.debug(
                        "Script '{}' is not a AuthenticationScriptV2 interface.", script::getName);
                return null;
            }

            // Some ScriptEngines do not verify if all Interface Methods are contained in the
            // script.
            // So we must invoke them to ensure that they are defined in the loaded script!
            // Otherwise some ScriptEngines loads successfully AuthenticationScriptV2 without the
            // methods
            // getLoggedInIndicator() / getLoggedOutIndicator().
            // Though it should fallback to interface AuthenticationScript.
            authScript.getLoggedInIndicator();
            authScript.getLoggedOutIndicator();
            return authScript;
        } catch (Exception ignore) {
            // The interface is optional, the AuthenticationScript will be checked after this one.
            LOGGER.debug(
                    "Script '{}' is not a AuthenticationScriptV2 interface!",
                    script.getName(),
                    ignore);
        }
        return null;
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Client script based authentication type only supports: "
                            + ClientScriptBasedAuthenticationMethod.class.getName());
        }
        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        config.setProperty(CONTEXT_CONFIG_AUTH_SCRIPT_NAME, method.script.getName());
        config.setProperty(
                CONTEXT_CONFIG_AUTH_SCRIPT_PARAMS, EncodingUtils.mapToString(method.paramValues));
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Client script based authentication type only supports: "
                            + ClientScriptBasedAuthenticationMethod.class.getName());
        }
        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        this.loadMethod(
                method,
                objListToStrList(config.getList(CONTEXT_CONFIG_AUTH_SCRIPT_NAME)),
                objListToStrList(config.getList(CONTEXT_CONFIG_AUTH_SCRIPT_PARAMS)));
    }

    private List<String> objListToStrList(List<Object> oList) {
        List<String> sList = new ArrayList<>(oList.size());
        for (Object o : oList) {
            sList.add(o.toString());
        }
        return sList;
    }
}

