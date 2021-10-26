/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AuthenticationData;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ContextDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.context.tab.context",
        "automation.dialog.context.tab.include",
        "automation.dialog.context.tab.exclude",
        "automation.dialog.context.tab.auth"
    };

    private static final String TITLE = "automation.dialog.context.title";
    private static final String NAME_PARAM = "automation.dialog.context.name";
    private static final String URLS_PARAM = "automation.dialog.context.urls";
    private static final String INCLUDE_PARAM = "automation.dialog.context.include";
    private static final String EXCLUDE_PARAM = "automation.dialog.context.exclude";
    private static final String AUTH_METHOD_PARAM = "automation.dialog.context.auth.method";
    private static final String AUTH_HOSTNAME_PARAM = "automation.dialog.context.auth.hostname";
    private static final String AUTH_PORT_PARAM = "automation.dialog.context.auth.port";
    private static final String AUTH_REALM_PARAM = "automation.dialog.context.auth.realm";

    private boolean isNew = false;
    private EnvironmentDialog envDialog;
    private ContextWrapper.Data context;
    private DefaultComboBoxModel<AuthMethod> authMethodCombo;
    private String currentModelKey;
    private JPanel authParams;

    private ZapTextField hostnameField;
    private ZapTextField realmField;
    private ZapPortNumberSpinner portField;

    public ContextDialog(EnvironmentDialog owner) {
        this(owner, null);
    }

    public ContextDialog(EnvironmentDialog owner, ContextWrapper.Data context) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(400, 300), TAB_LABELS);
        this.envDialog = owner;
        if (context == null) {
            context = new ContextWrapper.Data();
            this.isNew = true;
        }
        this.context = context;

        this.addTextField(0, NAME_PARAM, context.getName());
        this.addMultilineField(0, URLS_PARAM, StringUtils.join(context.getUrls().toArray()));

        this.addMultilineField(1, INCLUDE_PARAM, listToString(context.getIncludePaths()));

        this.addMultilineField(2, EXCLUDE_PARAM, listToString(context.getExcludePaths()));

        // Authentication tab
        authMethodCombo = new DefaultComboBoxModel<>();
        AuthenticationData.validMethods.forEach(
                st -> authMethodCombo.addElement(new AuthMethod(st)));
        this.addComboField(3, AUTH_METHOD_PARAM, authMethodCombo);

        getHostnameField()
                .setText(
                        JobUtils.unBox(
                                context.getAuthentication()
                                        .getParameters()
                                        .get(AuthenticationData.PARAM_HOSTNAME),
                                ""));
        getRealmField()
                .setText(
                        JobUtils.unBox(
                                context.getAuthentication()
                                        .getParameters()
                                        .get(AuthenticationData.PARAM_REALM),
                                ""));
        getPortField()
                .setValue(
                        JobUtils.unBox(
                                context.getAuthentication()
                                        .getParameters()
                                        .get(AuthenticationData.PARAM_PORT),
                                80));

        authParams = new JPanel(new GridBagLayout());
        this.addCustomComponent(3, authParams);
        this.addPadding(3);

        this.addFieldListener(
                AUTH_METHOD_PARAM,
                e -> {
                    String key = ((AuthMethod) authMethodCombo.getSelectedItem()).getKey();
                    if (key == null) {
                        return;
                    }
                    if (!key.equals(currentModelKey)) {
                        // Method changed - replace all of the parameter fields...
                        authParams.removeAll();
                        int indexy = 0;
                        switch (key) {
                            case AuthenticationData.METHOD_HTTP:
                                addParamComponent(
                                        authParams,
                                        AUTH_HOSTNAME_PARAM,
                                        getHostnameField(),
                                        ++indexy);
                                addParamComponent(
                                        authParams, AUTH_REALM_PARAM, getRealmField(), ++indexy);
                                addParamComponent(
                                        authParams, AUTH_PORT_PARAM, getPortField(), ++indexy);
                                break;
                            case AuthenticationData.METHOD_MANUAL:
                            default:
                                // Nothing to add
                                break;
                        }
                        currentModelKey = key;
                    }
                });
        authMethodCombo.setSelectedItem(new AuthMethod(context.getAuthentication().getMethod()));
    }

    private ZapTextField getHostnameField() {
        if (hostnameField == null) {
            hostnameField = new ZapTextField();
        }
        return hostnameField;
    }

    private ZapTextField getRealmField() {
        if (realmField == null) {
            realmField = new ZapTextField();
        }
        return realmField;
    }

    private ZapPortNumberSpinner getPortField() {
        if (portField == null) {
            portField = new ZapPortNumberSpinner(0);
        }
        return portField;
    }

    private void addParamComponent(JPanel panel, String labelkey, Component component, int indexy) {
        JLabel label = new JLabel(Constant.messages.getString(labelkey));
        label.setLabelFor(component);
        label.setVerticalAlignment(SwingConstants.TOP);
        panel.add(
                label,
                LayoutHelper.getGBC(
                        0, indexy, 1, 0, 1, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                component,
                LayoutHelper.getGBC(
                        1, indexy, 1, 1.0D, 1, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
    }

    private String listToString(List<String> list) {
        if (list != null) {
            return StringUtils.join(list, "\n");
        }
        return "";
    }

    private List<String> stringParamToList(String param) {
        // Return a list of the trimmed and non empty strings
        return Arrays.asList(this.getStringValue(param).split("\n")).stream()
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .collect(Collectors.toList());
    }

    @Override
    public void save() {
        this.context.setName(this.getStringValue(NAME_PARAM).trim());
        this.context.setUrls(stringParamToList(URLS_PARAM));
        this.context.setIncludePaths(stringParamToList(INCLUDE_PARAM));
        this.context.setExcludePaths(stringParamToList(EXCLUDE_PARAM));
        String authMethod = ((AuthMethod) authMethodCombo.getSelectedItem()).getKey();
        if (!authMethod.isEmpty()) {
            this.context.getAuthentication().setMethod(authMethod);
            context.getAuthentication()
                    .addParameter(
                            AuthenticationData.PARAM_HOSTNAME, this.getHostnameField().getText());
            context.getAuthentication()
                    .addParameter(AuthenticationData.PARAM_REALM, this.getRealmField().getText());
        }
        if (this.isNew) {
            envDialog.addContext(context);
        }
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(NAME_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.context.error.badname");
        }
        List<String> urls = stringParamToList(URLS_PARAM);
        if (urls.isEmpty()) {
            return Constant.messages.getString("automation.dialog.context.error.nourls");
        }
        for (String str : urls) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    new URI(str, true);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.badurl", str);
                }
            }
        }
        for (String str : stringParamToList(INCLUDE_PARAM)) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    Pattern.compile(str);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.incregex", str);
                }
            }
        }
        for (String str : stringParamToList(EXCLUDE_PARAM)) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    Pattern.compile(str);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.excregex", str);
                }
            }
        }
        return null;
    }

    private static class AuthMethod {
        private String key;

        public AuthMethod(String key) {
            this.key = key;
        }

        @Override
        public String toString() {
            if (key == null) {
                return "";
            }
            return Constant.messages.getString(
                    "automation.dialog.context.auth.method." + key.toLowerCase(Locale.ROOT));
        }

        public String getKey() {
            return key;
        }
    }
}
