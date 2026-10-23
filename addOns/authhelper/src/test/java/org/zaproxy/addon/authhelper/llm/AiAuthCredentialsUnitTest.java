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
package org.zaproxy.addon.authhelper.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

/** Unit test for {@link AiAuthCredentials}. */
class AiAuthCredentialsUnitTest {

    private static final String USERNAME = "realUser";
    private static final String PASSWORD = "realS3cret";
    private static final String TOTP_CODE = "483920";

    private static final AiAuthCredentials CREDS = new AiAuthCredentials(USERNAME, PASSWORD, null);
    private static final AiAuthCredentials TOTP_CREDS =
            new AiAuthCredentials(USERNAME, PASSWORD, TOTP_CODE);

    private static AiAuthInputElement element(String type, String value) {
        return element(type, value, null);
    }

    private static AiAuthInputElement element(String type, String value, Integer maxLength) {
        return new AiAuthInputElement(
                "input",
                type,
                "id",
                "name",
                "label",
                "placeholder",
                value,
                null,
                true,
                maxLength,
                null,
                null,
                "#id");
    }

    @Nested
    class Placeholders {

        @ParameterizedTest
        @NullAndEmptySource
        void shouldNotHaveTotpWithoutCode(String code) {
            var creds = new AiAuthCredentials(USERNAME, PASSWORD, code);

            assertThat(creds.hasTotp(), is(false));
            assertThat(creds.totpDigits(), is(nullValue()));
            assertThat(creds.toPlaceholders(), not(hasKey("totp")));
            assertThat(creds.toPlaceholders(), hasEntry("username", "{{username}}"));
            assertThat(creds.toPlaceholders(), hasEntry("password", "{{password}}"));
        }

        @Test
        void shouldHaveTotpWithCode() {
            assertThat(TOTP_CREDS.hasTotp(), is(true));
            assertThat(TOTP_CREDS.totpDigits(), is(equalTo(6)));
            assertThat(TOTP_CREDS.toPlaceholders(), hasEntry("totp", "{{totp}}"));
        }
    }

    @Nested
    class Substitute {

        @Test
        void shouldReturnNullForNull() {
            assertThat(TOTP_CREDS.substitute(null), is(nullValue()));
        }

        @Test
        void shouldSubstituteUsernameAndPassword() {
            assertThat(CREDS.substitute("{{username}}"), is(equalTo(USERNAME)));
            assertThat(CREDS.substitute("{{password}}"), is(equalTo(PASSWORD)));
            assertThat(CREDS.substitute("Project1"), is(equalTo("Project1")));
        }

        @Test
        void shouldSubstituteWholeTotpCode() {
            assertThat(TOTP_CREDS.substitute("{{totp}}"), is(equalTo(TOTP_CODE)));
        }

        @Test
        void shouldSubstituteTotpDigits() {
            assertThat(TOTP_CREDS.substitute("{{totp1}}"), is(equalTo("4")));
            assertThat(TOTP_CREDS.substitute("{{totp6}}"), is(equalTo("0")));
            assertThat(TOTP_CREDS.substitute("{{totp2}}{{totp3}}"), is(equalTo("83")));
        }

        @Test
        void shouldFailTotpDigitOutOfRange() {
            var e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> TOTP_CREDS.substitute("{{totp7}}"));
            assertThat(e.getMessage(), containsString("6 digits"));
            assertThrows(IllegalArgumentException.class, () -> TOTP_CREDS.substitute("{{totp0}}"));
        }

        @Test
        void shouldFailTotpWhenNotConfigured() {
            var e =
                    assertThrows(
                            IllegalArgumentException.class, () -> CREDS.substitute("{{totp}}"));
            assertThat(e.getMessage(), containsString("no TOTP data"));
            assertThrows(IllegalArgumentException.class, () -> CREDS.substitute("{{totp1}}"));
        }
    }

    @Nested
    class Mask {

        @Test
        void shouldMaskFilledPasswordTypeField() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("password", PASSWORD)));

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldNotMaskEmptyPasswordTypeField() {
            // An empty password field must stay empty, so the LLM can tell it still needs filling
            // in rather than believing it already contains a (masked) value.
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("password", "")));

            assertThat(masked.get(0).value(), is(equalTo("")));
        }

        @Test
        void shouldMaskTextFieldValueEqualToRealUsername() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("text", USERNAME)));

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.USERNAME_PLACEHOLDER)));
        }

        @Test
        void shouldMaskTextFieldValueEqualToRealPassword() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("text", PASSWORD)));

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldNotMaskUnrelatedFieldValues() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("text", "Project1")));

            assertThat(masked.get(0).value(), is(equalTo("Project1")));
        }

        @Test
        void shouldNotMaskNullValues() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("text", null)));

            assertThat(masked.get(0).value(), nullValue());
        }

        @Test
        void shouldMaskWholeTotpCode() {
            List<AiAuthInputElement> masked = TOTP_CREDS.mask(List.of(element("text", TOTP_CODE)));

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.TOTP_PLACEHOLDER)));
        }

        @Test
        void shouldNotMaskTotpCodeWhenNotConfigured() {
            List<AiAuthInputElement> masked = CREDS.mask(List.of(element("text", TOTP_CODE)));

            assertThat(masked.get(0).value(), is(equalTo(TOTP_CODE)));
        }

        @Test
        void shouldMaskTotpDigitInSingleCharacterInput() {
            List<AiAuthInputElement> masked =
                    TOTP_CREDS.mask(List.of(element("text", "8", 1), element("text", "0", 1)));

            assertThat(masked.get(0).value(), is(equalTo("{{totp2}}")));
            assertThat(masked.get(1).value(), is(equalTo("{{totp6}}")));
        }

        @Test
        void shouldNotMaskSingleCharacterNotInTotpCode() {
            List<AiAuthInputElement> masked = TOTP_CREDS.mask(List.of(element("text", "7", 1)));

            assertThat(masked.get(0).value(), is(equalTo("7")));
        }

        @Test
        void shouldNotMaskSingleCharacterInNonSingleCharacterInput() {
            List<AiAuthInputElement> masked = TOTP_CREDS.mask(List.of(element("text", "8")));

            assertThat(masked.get(0).value(), is(equalTo("8")));
        }
    }
}
