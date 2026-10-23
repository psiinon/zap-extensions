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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The payload sent to the LLM at the start of each turn. Describes the current page state and the
 * outcomes of any actions taken in the previous turn.
 *
 * <p>Credentials are passed as placeholder tokens ({@link #USERNAME_PLACEHOLDER}, {@link
 * #PASSWORD_PLACEHOLDER}, {@link #TOTP_PLACEHOLDER} and {@link #totpDigitPlaceholder(int)}) so that
 * real credentials are never transmitted to the LLM. The caller must substitute the real values
 * when executing the actions.
 *
 * <p>The {@code totp} credential and {@code totpDigits} are only present when the user has TOTP
 * data configured.
 *
 * <p>Example first-turn payload:
 *
 * <pre>{@code
 * {
 *   "step": 1,
 *   "url": "http://localhost:8080/auth/multi-step-auth/",
 *   "pageTitle": "Login",
 *   "inputElements": [
 *     { "tag": "input", "type": "email", "id": "user",   "name": "user",   "label": "Username:", "placeholder": "", "value": "", "options": null, "visible": true },
 *     { "tag": "select","type": null,    "id": "domain", "name": "domain", "label": "Domain:",   "placeholder": "", "value": "", "options": ["alpha.example.com","beta.example.com","Project1","Project2"], "visible": true }
 *   ],
 *   "previousActions": [],
 *   "completedActions": [],
 *   "credentials": { "username": "{{username}}", "password": "{{password}}", "totp": "{{totp}}" },
 *   "userHint": "The domain pulldown needs to be set to Project1",
 *   "totpDigits": 6
 * }
 * }</pre>
 */
public record AiAuthTurnPayload(
        @JsonProperty("step") int step,
        @JsonProperty("url") String url,
        @JsonProperty("pageTitle") String pageTitle,
        @JsonProperty("inputElements") List<AiAuthInputElement> inputElements,
        @JsonProperty("previousActions") List<AiAuthActionResult> previousActions,
        @JsonProperty("completedActions") List<AiAuthActionResult> completedActions,
        @JsonProperty("credentials") Map<String, String> credentials,
        @JsonProperty("userHint") String userHint,
        @JsonProperty("visibleText") String visibleText,
        @JsonInclude(Include.NON_NULL) @JsonProperty("totpDigits") Integer totpDigits) {

    /** Placeholder token used in the credentials map for the username. */
    public static final String USERNAME_PLACEHOLDER = "{{username}}";

    /** Placeholder token used in the credentials map for the password. */
    public static final String PASSWORD_PLACEHOLDER = "{{password}}";

    /** Placeholder token used in the credentials map for the whole TOTP code. */
    public static final String TOTP_PLACEHOLDER = "{{totp}}";

    /** Key of the TOTP code in the credentials map. */
    public static final String TOTP_CREDENTIAL = "totp";

    /**
     * Matches a single TOTP digit placeholder, e.g. {@code {{totp1}}}; group 1 is the 1-based digit
     * position.
     */
    public static final Pattern TOTP_DIGIT_PLACEHOLDER = Pattern.compile("\\{\\{totp(\\d+)\\}\\}");

    /**
     * Returns the placeholder for a single digit of the TOTP code.
     *
     * @param position the 1-based position of the digit.
     * @return the placeholder, e.g. {@code {{totp1}}}.
     */
    public static String totpDigitPlaceholder(int position) {
        return "{{totp" + position + "}}";
    }
}
