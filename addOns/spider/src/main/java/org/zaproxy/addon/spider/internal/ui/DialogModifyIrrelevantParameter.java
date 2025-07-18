/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.spider.internal.ui;

import java.awt.Dialog;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.spider.internal.IrrelevantParameter;

class DialogModifyIrrelevantParameter extends DialogAddIrrelevantParameter {

    private static final long serialVersionUID = -4031122965844883255L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("spider.options.irrelevantparameter.modify.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("spider.options.irrelevantparameter.modify.button.confirm");

    protected DialogModifyIrrelevantParameter(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    public void setIrrelevantParameter(IrrelevantParameter irrelevantParameter) {
        this.irrelevantParameter = irrelevantParameter;
    }

    @Override
    protected void init() {
        getNameTextField().setText(irrelevantParameter.getName());
        getNameTextField().discardAllEdits();

        getRegexCheckBox().setSelected(irrelevantParameter.isRegex());

        getEnabledCheckBox().setSelected(irrelevantParameter.isEnabled());
    }
}
