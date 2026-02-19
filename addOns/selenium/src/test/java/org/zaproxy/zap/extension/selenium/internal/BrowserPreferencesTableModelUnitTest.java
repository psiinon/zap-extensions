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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link BrowserPreferencesTableModel}. */
class BrowserPreferencesTableModelUnitTest {

    @BeforeAll
    static void setUpAll() {
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldCreateCopyOfCollectionAndValues() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        List<BrowserPreference> preferences = new ArrayList<>();
        BrowserPreference original = new BrowserPreference("name", "value", false);
        preferences.add(original);
        // When
        model.setPreferences(preferences);
        model.setAllEnabled(true);
        preferences.clear();
        // Then
        assertThat(original.isEnabled(), is(equalTo(false)));
        assertThat(model.getElements(), hasSize(1));
        assertThat(model.getElements().get(0).isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldSetEnabledStateOfPreference() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        model.setPreferences(
                List.of(
                        new BrowserPreference("n1", "v1", false),
                        new BrowserPreference("n2", "v2", false)));
        // When
        model.setValueAt(true, 1, 0);
        // Then
        assertThat(model.getElements().get(0).isEnabled(), is(equalTo(false)));
        assertThat(model.getElements().get(1).isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldGetEnabledStateFromPreference() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        model.setPreferences(
                List.of(
                        new BrowserPreference("n1", "v1", true),
                        new BrowserPreference("n2", "v2", false)));
        // When
        Object enabled = model.getValueAt(0, 0);
        // Then
        assertThat(enabled, is(equalTo(true)));
    }

    @Test
    void shouldGetName() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        model.setPreferences(
                List.of(
                        new BrowserPreference("n1", "v1", false),
                        new BrowserPreference("n2", "v2", false)));
        // When
        Object name = model.getValueAt(1, 1);
        // Then
        assertThat(name, is(equalTo("n2")));
    }

    @Test
    void shouldGetValue() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        model.setPreferences(
                List.of(
                        new BrowserPreference("n1", "v1", false),
                        new BrowserPreference("n2", "v2", false)));
        // When
        Object value = model.getValueAt(1, 2);
        // Then
        assertThat(value, is(equalTo("v2")));
    }

    @Test
    void shouldGetPreferencesAsString() {
        // Given
        BrowserPreferencesTableModel model = new BrowserPreferencesTableModel();
        model.setPreferences(
                List.of(
                        new BrowserPreference("nameA", "valA", true),
                        new BrowserPreference("nameB", "valB", false),
                        new BrowserPreference("nameC", "valC", true)));
        // When
        String summary = model.getPreferencesAsString();
        // Then
        assertThat(summary, is(equalTo("nameA=valA, nameC=valC")));
    }
}
