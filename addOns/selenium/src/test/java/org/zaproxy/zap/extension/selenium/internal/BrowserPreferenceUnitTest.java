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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Unit test for {@link BrowserPreference}. */
class BrowserPreferenceUnitTest {

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        String name = "pref.name";
        String value = "prefValue";
        boolean enabled = false;
        // When
        BrowserPreference preference = new BrowserPreference(name, value, enabled);
        // Then
        assertThat(preference.getName(), is(equalTo(name)));
        assertThat(preference.getValue(), is(equalTo(value)));
        assertThat(preference.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldCreateWithNullValueAsEmptyString() {
        // Given
        String name = "pref.name";
        // When
        BrowserPreference preference = new BrowserPreference(name, null, true);
        // Then
        assertThat(preference.getValue(), is(equalTo("")));
    }

    @Test
    void shouldThrowWhenCreatingWithNullName() {
        // Given
        String name = null;
        String value = "val";
        boolean enabled = false;
        // When / Then
        assertThrows(NullPointerException.class, () -> new BrowserPreference(name, value, enabled));
    }

    @Test
    void shouldCreateWithOtherInstance() {
        // Given
        String name = "pref.name";
        String value = "value";
        boolean enabled = false;
        BrowserPreference other = new BrowserPreference(name, value, enabled);
        // When
        BrowserPreference preference = new BrowserPreference(other);
        // Then
        assertThat(preference.getName(), is(equalTo(name)));
        assertThat(preference.getValue(), is(equalTo(value)));
        assertThat(preference.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldThrowWhenCreatingWithNullOtherInstance() {
        // Given
        BrowserPreference other = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new BrowserPreference(other));
    }

    @Test
    void shouldSetEnabledState() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", true);
        // When
        preference.setEnabled(false);
        // Then
        assertThat(preference.isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldSetName() {
        // Given
        BrowserPreference preference = new BrowserPreference("old", "value", true);
        String name = "new.name";
        // When
        preference.setName(name);
        // Then
        assertThat(preference.getName(), is(equalTo(name)));
    }

    @Test
    void shouldSetNameTrimmed() {
        // Given
        BrowserPreference preference = new BrowserPreference("old", "value", true);
        String name = "  new.name  ";
        // When
        preference.setName(name);
        // Then
        assertThat(preference.getName(), is(equalTo("new.name")));
    }

    @Test
    void shouldThrowWhenSettingNullName() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", true);
        // When / Then
        assertThrows(NullPointerException.class, () -> preference.setName(null));
    }

    @Test
    void shouldSetValue() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "old", true);
        String value = "newValue";
        // When
        preference.setValue(value);
        // Then
        assertThat(preference.getValue(), is(equalTo(value)));
    }

    @Test
    void shouldSetNullValueAsEmptyString() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "old", true);
        // When
        preference.setValue(null);
        // Then
        assertThat(preference.getValue(), is(equalTo("")));
    }

    @Test
    void shouldProduceConsistentHashCodes() {
        // Given
        BrowserPreference preference = new BrowserPreference("a", "b", false);
        // When
        int hashCode1 = preference.hashCode();
        int hashCode2 = preference.hashCode();
        // Then
        assertThat(hashCode1, is(equalTo(hashCode2)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", false);
        // When
        boolean equals = preference.equals(preference);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    static Stream<Arguments> constructorArgsProvider() {
        return Stream.of(
                arguments("pref.name", "value1", false), arguments("other.pref", "value2", true));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldBeEqualToDifferentPreferenceWithSameContents(
            String name, String value, boolean enabled) {
        // Given
        BrowserPreference preference = new BrowserPreference(name, value, enabled);
        BrowserPreference other = new BrowserPreference(name, value, enabled);
        // When
        boolean equals = preference.equals(other);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", false);
        // When
        boolean equals = preference.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToNonPreference() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", false);
        // When
        boolean equals = preference.equals("name");
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @ParameterizedTest
    @MethodSource("constructorArgsProvider")
    void shouldNotBeEqualToPreferenceWithDifferentName(String name, String value, boolean enabled) {
        // Given
        BrowserPreference preference = new BrowserPreference(name, value, enabled);
        BrowserPreference other = new BrowserPreference("different.name", value, enabled);
        // When
        boolean equals = preference.equals(other);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPreferenceWithDifferentValue() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value1", true);
        BrowserPreference other = new BrowserPreference("name", "value2", true);
        // When
        boolean equals = preference.equals(other);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPreferenceWithDifferentEnabled() {
        // Given
        BrowserPreference preference = new BrowserPreference("name", "value", true);
        BrowserPreference other = new BrowserPreference("name", "value", false);
        // When
        boolean equals = preference.equals(other);
        // Then
        assertThat(equals, is(equalTo(false)));
    }
}
