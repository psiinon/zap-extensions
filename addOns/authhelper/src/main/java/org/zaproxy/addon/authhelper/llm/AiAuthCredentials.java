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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * The real credential values for one turn of the AI authentication loop, along with the logic to
 * substitute them into action values and to mask them in page elements.
 *
 * <p>The TOTP code is resolved once per turn so that all digits typed in that turn come from the
 * same code; it's {@code null} when the user has no TOTP data configured.
 */
record AiAuthCredentials(String username, String password, String totpCode) {

    /**
     * Returns the credentials map to send to the LLM, with placeholders instead of real values.
     *
     * @return the placeholder credentials map.
     */
    Map<String, String> toPlaceholders() {
        Map<String, String> creds = new LinkedHashMap<>();
        creds.put("username", AiAuthTurnPayload.USERNAME_PLACEHOLDER);
        creds.put("password", AiAuthTurnPayload.PASSWORD_PLACEHOLDER);
        if (hasTotp()) {
            creds.put(AiAuthTurnPayload.TOTP_CREDENTIAL, AiAuthTurnPayload.TOTP_PLACEHOLDER);
        }
        return creds;
    }

    boolean hasTotp() {
        return totpCode != null && !totpCode.isEmpty();
    }

    /**
     * Returns the number of digits of the TOTP code, or {@code null} if no TOTP is configured.
     *
     * @return the number of digits, or {@code null}.
     */
    Integer totpDigits() {
        return hasTotp() ? totpCode.length() : null;
    }

    /**
     * Replaces the credential placeholders in the given action value with the real values.
     *
     * @param value the action value, possibly containing placeholders.
     * @return the value with real credentials.
     * @throws IllegalArgumentException if a TOTP placeholder is used but no TOTP is configured, or
     *     a digit placeholder is out of range for the current code.
     */
    String substitute(String value) {
        if (value == null) {
            return null;
        }
        String result =
                value.replace(AiAuthTurnPayload.USERNAME_PLACEHOLDER, username)
                        .replace(AiAuthTurnPayload.PASSWORD_PLACEHOLDER, password);
        if (!result.contains("{{totp")) {
            return result;
        }
        if (!hasTotp()) {
            throw new IllegalArgumentException(
                    "A TOTP placeholder was used but no TOTP data is configured for the user.");
        }
        result = result.replace(AiAuthTurnPayload.TOTP_PLACEHOLDER, totpCode);
        Matcher matcher = AiAuthTurnPayload.TOTP_DIGIT_PLACEHOLDER.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            int position = Integer.parseInt(matcher.group(1));
            if (position < 1 || position > totpCode.length()) {
                throw new IllegalArgumentException(
                        "The TOTP code has "
                                + totpCode.length()
                                + " digits but "
                                + matcher.group()
                                + " was requested.");
            }
            matcher.appendReplacement(
                    sb, Matcher.quoteReplacement(String.valueOf(totpCode.charAt(position - 1))));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Replaces any real credential value found in extracted page elements with its placeholder
     * token, so a value typed via {@code SEND_KEYS} is never read back off the DOM and sent to the
     * LLM on a later turn. Leaves genuinely empty fields untouched, so the LLM can still tell that
     * they haven't been filled in yet.
     *
     * @param elements the extracted elements.
     * @return the elements with credential values masked.
     */
    List<AiAuthInputElement> mask(List<AiAuthInputElement> elements) {
        return elements.stream().map(this::mask).toList();
    }

    private AiAuthInputElement mask(AiAuthInputElement element) {
        String value = element.value();
        if (value == null || value.isEmpty()) {
            return element;
        }
        if ("password".equals(element.type()) || value.equals(password)) {
            return element.withValue(AiAuthTurnPayload.PASSWORD_PLACEHOLDER);
        }
        if (value.equals(username)) {
            return element.withValue(AiAuthTurnPayload.USERNAME_PLACEHOLDER);
        }
        if (hasTotp()) {
            if (value.equals(totpCode)) {
                return element.withValue(AiAuthTurnPayload.TOTP_PLACEHOLDER);
            }
            if (element.isSingleCharacterInput() && value.length() == 1) {
                int position = totpCode.indexOf(value);
                if (position >= 0) {
                    return element.withValue(AiAuthTurnPayload.totpDigitPlaceholder(position + 1));
                }
            }
        }
        return element;
    }
}
