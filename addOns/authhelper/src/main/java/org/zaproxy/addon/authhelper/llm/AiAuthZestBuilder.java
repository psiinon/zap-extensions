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

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementScrollTo;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

/**
 * Builds a Zest browser authentication script from a list of recorded AI-driven auth actions.
 *
 * <p>The generated script can be registered with {@link ExtensionZest} and used by {@code
 * ClientScriptBasedAuthenticationMethodType} to replay the authentication flow.
 *
 * <p>The LLM credential placeholders are converted to the Zest variables understood by the
 * authentication runners: {@code {{username}}} and {@code {{password}}} are kept as is, {@code
 * {{totp}}} becomes {@code {{TOTP}}} and {@code {{totpN}}} becomes {@code {{TOTP_N}}}, all of which
 * are resolved from the user's credentials each time the script runs. They are also declared as
 * parameters of the script, so that it can be run manually with the values provided.
 */
class AiAuthZestBuilder {

    private static final Logger LOGGER = LogManager.getLogger(AiAuthZestBuilder.class);

    /** Window-handle name used by Zest for client (browser) sessions. */
    private static final String WINDOW_HANDLE = "windowHandle1";

    /**
     * Zest element-selector type string for CSS selectors.
     *
     * @see org.zaproxy.zest.core.v1.ZestScript (getBy method)
     */
    private static final String SELECTOR_TYPE = "cssSelector";

    /** Zest variable set by the authentication runners with the whole TOTP code. */
    static final String TOTP_VARIABLE = "{{TOTP}}";

    /** Prefix of the Zest variables set by the authentication runners with each TOTP digit. */
    static final String TOTP_DIGIT_VARIABLE_PREFIX = "{{TOTP_";

    /** Matches the TOTP variables in a Zest value, the name is the first group. */
    private static final Pattern TOTP_VARIABLE_PATTERN =
            Pattern.compile("\\{\\{(TOTP(?:_\\d+)?)\\}\\}");

    /** Orders the TOTP variable names: {@code TOTP, TOTP_1, ..., TOTP_9, TOTP_10}. */
    private static final Comparator<String> TOTP_VARIABLE_ORDER =
            Comparator.comparingInt(String::length).thenComparing(Comparator.naturalOrder());

    private AiAuthZestBuilder() {}

    /**
     * Converts the LLM credential placeholders in the given value to Zest variables.
     *
     * @param value the recorded action value, might be {@code null}.
     * @return the value to use in the Zest statement.
     */
    static String toZestValue(String value) {
        if (value == null || !value.contains("{{totp")) {
            return value;
        }
        return AiAuthTurnPayload.TOTP_DIGIT_PLACEHOLDER
                .matcher(value.replace(AiAuthTurnPayload.TOTP_PLACEHOLDER, TOTP_VARIABLE))
                .replaceAll(TOTP_DIGIT_VARIABLE_PREFIX + "$1}}");
    }

    /**
     * Builds a {@link ZestScriptWrapper} from recorded browser actions.
     *
     * @param scriptName name to assign the script
     * @param loginUrl URL navigated to at the start of the flow
     * @param browserId ZAP browser ID (e.g. {@code "firefox-headless"}, {@code "chrome"})
     * @param actions successfully-executed actions from the AI auth loop
     * @param extZest the Zest extension (must not be null)
     * @param extScript the Script extension (must not be null)
     * @return a ready-to-register Zest script wrapper
     */
    static ZestScriptWrapper build(
            String scriptName,
            String loginUrl,
            String browserId,
            List<AiAuthActionResult> actions,
            ExtensionZest extZest,
            ExtensionScript extScript) {

        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(scriptName);
        sw.setEngine(extZest.getZestEngineWrapper());
        sw.setEngineName("Mozilla Zest");
        sw.setType(extScript.getScriptType(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH));

        ZestScriptWrapper zsw = new ZestScriptWrapper(sw);
        configureZestScript(zsw.getZestScript(), scriptName, loginUrl, browserId, actions);

        LOGGER.debug(
                "Built Zest auth script '{}' with {} statements",
                scriptName,
                zsw.getZestScript().getStatements().size());
        return zsw;
    }

    /**
     * Builds a standalone {@link ZestScript} from recorded browser actions. Package-private for
     * unit testing (no ZAP infrastructure required).
     */
    static ZestScript buildZestScript(
            String scriptName,
            String loginUrl,
            String browserId,
            List<AiAuthActionResult> actions) {
        ZestScript zs = new ZestScript();
        configureZestScript(zs, scriptName, loginUrl, browserId, actions);
        return zs;
    }

    private static void configureZestScript(
            ZestScript zs,
            String scriptName,
            String loginUrl,
            String browserId,
            List<AiAuthActionResult> actions) {
        zs.setTitle(scriptName);

        boolean headless = browserId != null && browserId.endsWith("-headless");
        String browserName =
                headless
                        ? browserId.substring(0, browserId.length() - "-headless".length())
                        : (browserId != null ? browserId : "firefox");

        zs.getParameters().addVariable("username", "");
        zs.getParameters().addVariable("password", "");
        zs.setOptions(Map.of(ZestScript.STATEMENT_DELAY_MS, "1000"));

        zs.add(new ZestClientLaunch(WINDOW_HANDLE, browserName, loginUrl, headless));

        List<AiAuthActionResult> replayable =
                actions.stream().filter(a -> a.success() && a.usedSelector() != null).toList();
        replayable.forEach(action -> addStep(zs, action));
        getTotpVariables(replayable).forEach(name -> zs.getParameters().addVariable(name, ""));
    }

    /** The names of the TOTP variables typed by the given actions, in order. */
    private static List<String> getTotpVariables(List<AiAuthActionResult> actions) {
        return actions.stream()
                .filter(a -> a.type() == AiAuthActionType.SEND_KEYS && a.value() != null)
                .flatMap(a -> TOTP_VARIABLE_PATTERN.matcher(toZestValue(a.value())).results())
                .map(m -> m.group(1))
                .distinct()
                .sorted(TOTP_VARIABLE_ORDER)
                .toList();
    }

    private static void addStep(ZestScript zs, AiAuthActionResult action) {
        switch (action.type()) {
            case SEND_KEYS -> {
                zs.add(
                        new ZestClientElementScrollTo(
                                WINDOW_HANDLE, SELECTOR_TYPE, action.usedSelector()));
                zs.add(
                        new ZestClientElementClear(
                                WINDOW_HANDLE, SELECTOR_TYPE, action.usedSelector()));
                zs.add(
                        new ZestClientElementSendKeys(
                                WINDOW_HANDLE,
                                SELECTOR_TYPE,
                                action.usedSelector(),
                                toZestValue(action.value())));
            }
            case CLICK -> {
                zs.add(
                        new ZestClientElementScrollTo(
                                WINDOW_HANDLE, SELECTOR_TYPE, action.usedSelector()));
                zs.add(
                        new ZestClientElementClick(
                                WINDOW_HANDLE, SELECTOR_TYPE, action.usedSelector()));
            }
            case SELECT -> {
                // Zest has no native select-by-visible-text step; sendKeys works for basic
                // <select> elements in most browsers.
                zs.add(
                        new ZestClientElementScrollTo(
                                WINDOW_HANDLE, SELECTOR_TYPE, action.usedSelector()));
                zs.add(
                        new ZestClientElementSendKeys(
                                WINDOW_HANDLE,
                                SELECTOR_TYPE,
                                action.usedSelector(),
                                action.value()));
            }
            case WAIT -> {
                long ms = 0;
                try {
                    ms = Long.parseLong(action.value()) * 1000L;
                } catch (Exception ignored) {
                }
                zs.add(new ZestActionSleep(ms));
            }
            default -> LOGGER.debug("Skipping unhandled action type: {}", action.type());
        }
    }
}
