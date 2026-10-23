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
package org.zaproxy.addon.authhelper.internal;

import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.internal.TotpSupport.TotpData;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

/**
 * A panel with the TOTP fields: secret (or fixed code), period, digits and algorithm.
 *
 * <p>The algorithms offered are the ones supported by the add-on, see {@link TotpAlgorithms}.
 */
@SuppressWarnings("serial")
public class TotpFieldsPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private static final int DEFAULT_PERIOD = 30;
    private static final int DEFAULT_DIGITS = 6;

    private final ZapTextField secretField;
    private final ZapNumberSpinner periodSpinner;
    private final ZapNumberSpinner digitsSpinner;
    private final JComboBox<String> algorithmComboBox;

    public TotpFieldsPanel() {
        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);

        secretField = new ZapTextField(25);
        secretField.setToolTipText(
                Constant.messages.getString("authhelper.totp.fields.secret.tooltip"));
        JLabel secretLabel = createLabel("totpsecret", secretField);
        periodSpinner = new ZapNumberSpinner(1, DEFAULT_PERIOD, Integer.MAX_VALUE);
        JLabel periodLabel = createLabel("totpperiod", periodSpinner);
        digitsSpinner = new ZapNumberSpinner(1, DEFAULT_DIGITS, Integer.MAX_VALUE);
        JLabel digitsLabel = createLabel("totpdigits", digitsSpinner);
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        TotpAlgorithms.getSupported().forEach(model::addElement);
        algorithmComboBox = new JComboBox<>(model);
        JLabel algorithmLabel = createLabel("totpalgorithm", algorithmComboBox);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(secretLabel)
                                        .addComponent(periodLabel)
                                        .addComponent(digitsLabel)
                                        .addComponent(algorithmLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(secretField)
                                        .addComponent(periodSpinner)
                                        .addComponent(digitsSpinner)
                                        .addComponent(algorithmComboBox)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(secretLabel)
                                        .addComponent(secretField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(periodLabel)
                                        .addComponent(periodSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(digitsLabel)
                                        .addComponent(digitsSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(algorithmLabel)
                                        .addComponent(algorithmComboBox)));
    }

    private static JLabel createLabel(String key, JComponent field) {
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.field." + key));
        label.setLabelFor(field);
        return label;
    }

    /**
     * Tells whether a secret (or fixed code) was provided.
     *
     * @return {@code true} if a secret was provided, {@code false} otherwise.
     */
    public boolean hasSecret() {
        return StringUtils.isNotBlank(secretField.getText());
    }

    /**
     * Gets the TOTP data from the fields.
     *
     * @return the TOTP data.
     */
    public TotpData getTotpData() {
        return new TotpData(
                secretField.getText().trim(),
                periodSpinner.getValue(),
                digitsSpinner.getValue(),
                (String) algorithmComboBox.getSelectedItem());
    }

    /** Resets the fields to their default values. */
    public void reset() {
        secretField.setText("");
        secretField.discardAllEdits();
        periodSpinner.setValue(DEFAULT_PERIOD);
        digitsSpinner.setValue(DEFAULT_DIGITS);
        algorithmComboBox.setSelectedIndex(0);
    }
}
