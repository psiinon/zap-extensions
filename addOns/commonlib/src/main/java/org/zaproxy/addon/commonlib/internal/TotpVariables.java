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
package org.zaproxy.addon.commonlib.internal;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.zaproxy.zap.authentication.AuthenticationCredentials;

/**
 * Resolves the TOTP variables referenced by authentication scripts.
 *
 * <p>A script references the whole code with the {@value #NAME} variable (e.g. {@code {{TOTP}}})
 * and each digit of the code with {@value #DIGIT_NAME_PREFIX}{@code <position>} (e.g. {@code
 * {{TOTP_1}}}), for pages that use one input per digit. The code is (re)generated when the whole
 * code or the first digit is referenced and reused for the following digits, so that all digits
 * typed come from the same code even if the TOTP period rolls over midway.
 *
 * <p>Meant to be used by the Zest authentication runners before running a statement:
 *
 * <pre>{@code
 * totpVariables.getVariables(sendKeys.getValue(), credentials).forEach(this::setVariable);
 * }</pre>
 */
public class TotpVariables {

    /** The name of the variable with the whole TOTP code. */
    public static final String NAME = "TOTP";

    /** The prefix of the variables with each digit of the TOTP code, followed by the position. */
    public static final String DIGIT_NAME_PREFIX = NAME + "_";

    private static final Pattern VARIABLE_NAME = Pattern.compile(NAME + "(?:_\\d+)?");

    private final String wholeCode;
    private final String firstDigit;
    private final Pattern reference;

    private String currentCode;

    /**
     * Constructs the variables resolver for the given variable tokens.
     *
     * @param tokenStart the token that starts a variable reference, e.g. <code>{{</code>.
     * @param tokenEnd the token that ends a variable reference, e.g. <code>}}</code>.
     */
    public TotpVariables(String tokenStart, String tokenEnd) {
        wholeCode = tokenStart + NAME + tokenEnd;
        firstDigit = tokenStart + DIGIT_NAME_PREFIX + "1" + tokenEnd;
        reference =
                Pattern.compile(
                        Pattern.quote(tokenStart) + NAME + "(?:_\\d+)?" + Pattern.quote(tokenEnd));
    }

    /**
     * Tells whether or not the given name is one of the TOTP variables, {@value #NAME} or {@value
     * #DIGIT_NAME_PREFIX}{@code <position>}.
     *
     * <p>Allows the authentication runners to recognise the TOTP variables declared as parameters
     * of a script (so that it can be run manually), which are set when running the statements.
     *
     * @param name the name of the variable, might be {@code null}.
     * @return {@code true} if it is a TOTP variable, {@code false} otherwise.
     */
    public static boolean isVariable(String name) {
        return name != null && VARIABLE_NAME.matcher(name).matches();
    }

    /**
     * Gets the TOTP variables that should be set before running a statement with the given value.
     *
     * @param value the value of the statement, might be {@code null}.
     * @param credentials the credentials of the user, from where the TOTP code is obtained.
     * @return the variables (name to value) to set, empty if the value does not reference the TOTP
     *     variables or no code could be obtained.
     */
    public Map<String, String> getVariables(String value, AuthenticationCredentials credentials) {
        if (value == null || !reference.matcher(value).find()) {
            return Map.of();
        }

        if (currentCode == null || value.contains(wholeCode) || value.contains(firstDigit)) {
            currentCode = TotpSupport.getCode(credentials);
        }
        if (currentCode == null) {
            return Map.of();
        }

        Map<String, String> variables = new LinkedHashMap<>();
        variables.put(NAME, currentCode);
        for (int i = 0; i < currentCode.length(); i++) {
            variables.put(DIGIT_NAME_PREFIX + (i + 1), String.valueOf(currentCode.charAt(i)));
        }
        return variables;
    }
}
