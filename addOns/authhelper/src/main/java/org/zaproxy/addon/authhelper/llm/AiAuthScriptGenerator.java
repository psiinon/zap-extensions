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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;

/**
 * Drives an iterative browser-based authentication flow using an LLM.
 *
 * <p>Each turn:
 *
 * <ol>
 *   <li>Extract the current page state (URL, title, visible form elements) via JavaScript.
 *   <li>Serialise the state into an {@link AiAuthTurnPayload} and send it to the LLM.
 *   <li>Deserialise the {@link AiAuthResponse} and execute any returned actions.
 *   <li>Repeat until the LLM returns a terminal state or {@link #MAX_TURNS} is reached.
 * </ol>
 *
 * <p>Credentials are passed to the LLM as placeholder tokens ({@link
 * AiAuthTurnPayload#USERNAME_PLACEHOLDER}, {@link AiAuthTurnPayload#PASSWORD_PLACEHOLDER}, {@link
 * AiAuthTurnPayload#TOTP_PLACEHOLDER} and the per digit {@link
 * AiAuthTurnPayload#totpDigitPlaceholder(int)}). Real values are substituted just before executing
 * each action so they are never sent to the LLM, see {@link AiAuthCredentials}.
 */
public class AiAuthScriptGenerator {

    private static final Logger LOGGER = LogManager.getLogger(AiAuthScriptGenerator.class);

    static final int MAX_TURNS = 10;
    static final long PAGE_SETTLE_MS = 1500;
    static final int MAX_WAIT_SECONDS = 30;

    /**
     * JavaScript that extracts all interactive form elements from the current page and returns them
     * as a JSON string. Using a JSON string avoids Selenium's type-coercion of nested maps.
     */
    // Selenium executeScript requires a top-level `return` to capture the result value.
    // An IIFE without a top-level return causes the driver to see `undefined` and return null.
    static final String PAGE_TEXT_JS =
            """
            var parts = [];
            document.querySelectorAll('h1, h2, h3, p, a, label, span').forEach(function(el) {
              try {
                if (el.offsetParent !== null && !el.hidden) {
                  var t = el.textContent.trim().replace(/\\s+/g, ' ');
                  if (t) parts.push(t);
                }
              } catch(e) {}
            });
            var text = parts.join(' | ');
            return text.length > 500 ? text.substring(0, 500) + '...' : text;
            """;

    static final String PAGE_ELEMENTS_JS =
            """
            var els = [];
            function cssPath(el) {
              if (el.id) return '#' + CSS.escape(el.id);
              var parts = [];
              var cur = el;
              while (cur && cur.nodeType === 1) {
                if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
                var tag = cur.tagName.toLowerCase();
                if (tag === 'html') break;
                var sel = tag;
                var parent = cur.parentElement;
                if (parent && tag !== 'body') {
                  var sibs = Array.prototype.filter.call(parent.children, function(c) {
                    return c.tagName === cur.tagName;
                  });
                  if (sibs.length > 1) sel += ':nth-of-type(' + (sibs.indexOf(cur) + 1) + ')';
                }
                parts.unshift(sel);
                if (tag === 'body') break;
                cur = parent;
              }
              return parts.join(' > ');
            }
            document.querySelectorAll('input, select, textarea, button').forEach(function(el) {
              var label = null;
              if (el.type === 'hidden' || el.offsetParent === null || el.hidden) {
                return;
              }
              try {
                if (el.id) {
                  var lbl = document.querySelector('label[for="' + el.id + '"]');
                  if (lbl) label = lbl.textContent.trim();
                }
                if (!label) {
                  var parent = el.closest('label');
                  if (parent) {
                    var clone = parent.cloneNode(true);
                    clone.querySelectorAll('input,select,textarea,button').forEach(function(c){c.remove();});
                    label = clone.textContent.trim() || null;
                  }
                }
              } catch(e) {}
              var opts = null;
              if (el.tagName === 'SELECT') {
                opts = Array.from(el.options).map(function(o) { return o.text.trim(); });
              }
              var maxLength = parseInt(el.getAttribute('maxlength'), 10);
              var path = null;
              try { path = cssPath(el); } catch(e) {}
              els.push({
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || null,
                id: el.id || null,
                name: el.name || null,
                label: label,
                placeholder: el.placeholder || null,
                value: el.value || null,
                options: opts,
                visible: el.offsetParent !== null && !el.hidden,
                maxLength: isNaN(maxLength) || maxLength < 0 ? null : maxLength,
                inputMode: el.getAttribute('inputmode') || null,
                autocomplete: el.getAttribute('autocomplete') || null,
                cssPath: path
              });
            });
            return JSON.stringify(els);
            """;

    private static final String SYSTEM_PROMPT =
            """
            You are a browser automation agent whose sole job is to complete a web authentication flow.

            You will receive a JSON object with these fields:
              step            - the current turn number (starts at 1)
              url             - the current page URL
              pageTitle       - the page <title>
              inputElements   - an array of visible form elements on the page; each has:
                                  tag, type, id, name, label, placeholder, value, options, visible,
                                  maxLength, inputMode, autocomplete, cssPath
              previousActions - the actions you requested last turn and whether each succeeded
              completedActions - all the actions successfully performed since the start of the flow,
                                in order, including those of earlier turns
              credentials     - {"username":"{{username}}","password":"{{password}}"} plus
                                "totp":"{{totp}}" when the user has a TOTP (authenticator app)
                                second factor configured
              totpDigits      - the number of digits in the TOTP code, only present when
                                credentials has "totp"
              visibleText     - visible headings, labels and link text on the page (first 500 chars)
              userHint        - optional free-text guidance from the human operator

            You must respond with ONLY a valid JSON object matching this schema (no markdown, no code fences):
            {
              "state": "IN_PROGRESS" | "SUCCESS" | "FAILURE" | "MFA_REQUIRED" | "CAPTCHA_DETECTED",
              "reasoning": "<one sentence explaining what you observe and what you will do>",
              "actions": [
                {
                  "type": "CLICK" | "SEND_KEYS" | "SELECT" | "WAIT",
                  "selectors": ["#most-stable", ".fallback", "button[name=\\"submit\\"]"],
                  "value": "<text to type, option to select, or seconds as a string for WAIT; null for CLICK>"
                }
              ],
              "successIndicator": {
                "type": "URL_PATTERN" | "ELEMENT_APPEARS" | "ELEMENT_DISAPPEARS",
                "value": "<substring of expected URL, or CSS selector>"
              }
            }

            Rules:
            - For a username/email field use value "{{username}}". For a password field use "{{password}}".
              Never invent or guess real credential values, and never put a credential into a field
              whose own type/label/id/name does not match that credential (e.g. never send the
              password value to a field that is for the username/email, or vice versa).
            - Before including a CLICK on a submit/next/continue/login button, first inspect every
              element in inputElements: for every visible text/email/password input or select whose
              "value" is currently empty, add a SEND_KEYS or SELECT action for it in the SAME turn's
              "actions" array, ordered before the CLICK. Only click once all empty fields relevant to
              this step have been filled.
            - selectors[0] MUST be built only from attribute values that are actually present (non-null)
              on that element in inputElements: use "#<id>" when "id" is non-null, otherwise
              "[name='<name>']" when "name" is non-null, otherwise the element's "cssPath" exactly as
              given. Never fabricate a selector using an attribute (id, name, etc.) that is null for
              that element. Additional selectors, if any, are fallbacks ordered from most- to
              least-specific.
            - TOTP / one-time codes: when credentials has "totp" and the page asks for a verification,
              one-time, authenticator or 2FA code, fill it in this turn and continue - do NOT report
              MFA_REQUIRED. Never type the password into a code field or the code into the password
              field.
                * One code field: SEND_KEYS with value "{{totp}}".
                * One box per digit (several inputs with maxLength 1, often inputMode "numeric" or
                  autocomplete "one-time-code", and their count equals totpDigits): add one SEND_KEYS
                  per box in page order with values "{{totp1}}", "{{totp2}}", ... "{{totpN}}" where N
                  is totpDigits, then CLICK the verify/continue button in the same turn.
              Never guess or invent a code. A previous "{{totp}}" that was rejected means the field or
              the flow was wrong, not the code; do not retry the identical actions.
            - Set state MFA_REQUIRED only when a second factor is requested that cannot be completed:
              there is no "totp" in credentials, or the factor is not a code entry (push
              notification, SMS/email code, security key).
            - "actions" must be [] and "successIndicator" must be non-null when state is SUCCESS.
            - "actions" must be [] and "successIndicator" must be null for all other terminal states.
            - Set state SUCCESS only when you are confident the browser shows a post-login page
              (URL changed away from the login page, a greeting is visible, a dashboard loaded, etc.).
              A page that greets the user, says they are logged in, or offers a log out / sign out
              link IS the post-login page: report SUCCESS with no actions. Never click a log out /
              sign out / log off element, that would undo the login.
            - Set state FAILURE if credentials are rejected or a dead end is reached.
            - Compare this turn's url, inputElements and visibleText with the previous turn's. If they
              are unchanged even though previousActions reported success, that action did not actually
              advance the flow — do not repeat the exact same action again; instead reconsider whether
              a required field was left empty or a different selector/action is needed.
            - If a previousActions entry failed with a reason mentioning "No element matched selectors",
              fix that action's selectors (prefer "#<id>" from the current inputElements) on this turn.
              Do not respond to a selector-matching failure by changing field values instead.
            - Follow any instructions in the userHint field — they describe non-obvious steps
              (e.g. "set the domain dropdown to Project1") that are required for login to succeed.
            - You have no memory of earlier turns: completedActions is the record of what you have
              already done. Treat an instruction of the userHint as done once completedActions shows
              it (e.g. a SELECT of "Project1"), do not try to repeat it, and do not keep the flow
              IN_PROGRESS for something already completed.
            - Respond with JSON only. Do not wrap the response in a code block.
            """;

    private final AiAssistedAuthenticationMethod config;
    private final LlmCommunicationService llm;
    private final ObjectMapper mapper;
    private final LlmChatTabPanel chatTab;
    private final List<AiAuthActionResult> successfulActions = new ArrayList<>();
    private final List<TurnStart> turnStarts = new ArrayList<>();
    private final Supplier<String> totpCodeSupplier;

    /** The state of the page at the start of a turn and how many actions were recorded by then. */
    private record TurnStart(int step, String pageState, int recordedActions) {}

    public AiAuthScriptGenerator(
            AiAssistedAuthenticationMethod config,
            LlmCommunicationService llm,
            LlmChatTabPanel chatTab) {
        this(config, llm, chatTab, null);
    }

    /**
     * Constructs the generator with a source of TOTP codes.
     *
     * @param config the method configuration.
     * @param llm the LLM service.
     * @param chatTab the chat tab to log to, might be {@code null}.
     * @param totpCodeSupplier supplies the current TOTP code of the user, or {@code null} when the
     *     user has no TOTP data; the supplier itself might be {@code null}.
     */
    public AiAuthScriptGenerator(
            AiAssistedAuthenticationMethod config,
            LlmCommunicationService llm,
            LlmChatTabPanel chatTab,
            Supplier<String> totpCodeSupplier) {
        this.config = config;
        this.llm = llm;
        this.mapper = new ObjectMapper();
        this.chatTab = chatTab;
        this.totpCodeSupplier = totpCodeSupplier;
    }

    /**
     * Runs the iterative authentication loop.
     *
     * @param wd an already-open WebDriver instance; navigation and closure are the caller's
     *     responsibility
     * @param username the real username to substitute for {@link
     *     AiAuthTurnPayload#USERNAME_PLACEHOLDER}
     * @param password the real password to substitute for {@link
     *     AiAuthTurnPayload#PASSWORD_PLACEHOLDER}
     * @return the final result, which may be success or any terminal failure state
     */
    public AiAuthResult run(WebDriver wd, String username, String password) {
        LOGGER.info("Starting AI auth loop for URL: {}", config.getLoginPageUrl());
        wd.get(config.getLoginPageUrl());
        waitSeconds(config.getLoginPageWait());

        List<AiAuthActionResult> previousActions = new ArrayList<>();

        for (int step = 1; step <= MAX_TURNS; step++) {
            AiAuthCredentials credentials = createCredentials(username, password);
            List<AiAuthInputElement> elements = credentials.mask(extractPageElements(wd));
            String currentUrl = wd.getCurrentUrl();
            String pageTitle = wd.getTitle();
            String visibleText = extractVisibleText(wd);
            LOGGER.debug("Turn {}: url={}, elements={}", step, currentUrl, elements.size());

            logTurnContext(step, currentUrl, pageTitle, elements, visibleText, credentials);
            discardActionsIfPageSeen(step, getPageState(currentUrl, elements));

            AiAuthTurnPayload payload =
                    new AiAuthTurnPayload(
                            step,
                            currentUrl,
                            pageTitle,
                            elements,
                            previousActions,
                            getSuccessfulActions(),
                            credentials.toPlaceholders(),
                            config.getHint(),
                            visibleText,
                            credentials.totpDigits());

            AiAuthResponse response = askLlm(payload);
            if (response == null) {
                AiAuthResult failure =
                        AiAuthResult.failure(
                                Constant.messages.getString(
                                        "authhelper.auth.method.ai.chat.error.no.response", step));
                logFinalResult(failure);
                return failure;
            }

            LOGGER.info(
                    "Turn {}: state={}, reasoning={}",
                    step,
                    response.state(),
                    response.reasoning());
            logLlmResponse(response);

            if (response.isTerminal()) {
                boolean success = response.state() == AiAuthState.SUCCESS;
                LOGGER.info("AI auth loop finished: success={}", success);
                if (response.state() == AiAuthState.MFA_REQUIRED && !credentials.hasTotp()) {
                    reportLlmError(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.mfa.nototp"));
                }
                AiAuthResult result =
                        new AiAuthResult(
                                success,
                                response.state(),
                                response.reasoning(),
                                response.successIndicator());
                if (success) {
                    logFinalResult(result);
                }
                return result;
            }

            // The LLM might have taken a while to answer, so type a fresh TOTP code.
            AiAuthCredentials actionCredentials =
                    credentials.hasTotp() ? createCredentials(username, password) : credentials;
            previousActions = new ArrayList<>();
            for (AiAuthAction action :
                    response.actions() != null ? response.actions() : List.<AiAuthAction>of()) {
                AiAuthActionResult result = executeAction(wd, action, actionCredentials);
                LOGGER.debug(
                        "Action {}: selector={}, success={}",
                        action.type(),
                        result.usedSelector(),
                        result.success());
                if (result.success()) {
                    successfulActions.add(result);
                }
                previousActions.add(result);
            }

            waitMillis(PAGE_SETTLE_MS);
        }

        AiAuthResult maxTurns =
                AiAuthResult.failure(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.max.turns", MAX_TURNS));
        logFinalResult(maxTurns);
        return maxTurns;
    }

    /**
     * Returns the successfully-executed actions which led to the current page, in order, for Zest
     * script generation.
     */
    List<AiAuthActionResult> getSuccessfulActions() {
        return Collections.unmodifiableList(successfulActions);
    }

    /** The URL and the visible elements identify the state of the page. */
    private static String getPageState(String url, List<AiAuthInputElement> elements) {
        return elements.stream()
                .filter(AiAuthInputElement::visible)
                .map(e -> String.join("|", e.tag(), e.type(), e.id(), e.name(), e.cssPath()))
                .collect(Collectors.joining(";", url + "\n", ""));
    }

    /**
     * Discards the actions recorded since the flow was last at the same page state, as the flow
     * went back on itself (for example the login page shown again after a rejected code), the
     * actions which do work are the ones recorded from now on.
     */
    private void discardActionsIfPageSeen(int step, String pageState) {
        for (int i = 0; i < turnStarts.size(); i++) {
            TurnStart seen = turnStarts.get(i);
            if (!seen.pageState().equals(pageState)) {
                continue;
            }
            int discarded = successfulActions.size() - seen.recordedActions();
            if (discarded > 0) {
                LOGGER.info(
                        "Turn {}: the page is back to the state of turn {}, discarding {} recorded action(s)",
                        step,
                        seen.step(),
                        discarded);
                if (chatTab != null) {
                    chatTab.appendToOutput(
                            LlmChatTabPanel.USER_LABEL,
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.discarded",
                                    seen.step(),
                                    discarded));
                }
                successfulActions.subList(seen.recordedActions(), successfulActions.size()).clear();
            }
            turnStarts.subList(i, turnStarts.size()).clear();
            break;
        }
        turnStarts.add(new TurnStart(step, pageState, successfulActions.size()));
    }

    /**
     * Creates the credentials, resolving the TOTP code (if any) once so that all the digits typed
     * come from the same code. Called at the start of a turn and again before typing, so the code
     * is fresh.
     */
    AiAuthCredentials createCredentials(String username, String password) {
        String totpCode = null;
        if (totpCodeSupplier != null) {
            try {
                totpCode = totpCodeSupplier.get();
            } catch (Exception e) {
                LOGGER.warn("Failed to obtain the TOTP code: {}", e.getMessage());
            }
        }
        return new AiAuthCredentials(username, password, totpCode);
    }

    // ─── Page extraction ──────────────────────────────────────────────────────

    List<AiAuthInputElement> extractPageElements(WebDriver wd) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) wd;
            String json = (String) js.executeScript(PAGE_ELEMENTS_JS);
            return mapper.readValue(json, new TypeReference<List<AiAuthInputElement>>() {});
        } catch (Exception e) {
            LOGGER.warn("Failed to extract page elements: {}", e.getMessage());
            return List.of();
        }
    }

    String extractVisibleText(WebDriver wd) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) wd;
            String text = (String) js.executeScript(PAGE_TEXT_JS);
            return text != null ? text : "";
        } catch (Exception e) {
            LOGGER.debug("Failed to extract visible text: {}", e.getMessage());
            return "";
        }
    }

    // ─── LLM turn ─────────────────────────────────────────────────────────────

    AiAuthResponse askLlm(AiAuthTurnPayload payload) {
        ChatResponse response;
        try {
            String payloadJson = mapper.writeValueAsString(payload);
            ChatRequest request =
                    ChatRequest.builder()
                            .messages(
                                    SystemMessage.from(SYSTEM_PROMPT),
                                    UserMessage.from(payloadJson))
                            .responseFormat(ResponseFormat.JSON)
                            .build();
            // Each turn is self-contained, the history would just use up the context window.
            response = llm.chatWithoutMemory(request);
        } catch (Exception e) {
            LOGGER.error("LLM call failed: {}", e.getMessage(), e);
            reportLlmError(
                    Constant.messages.getString(
                            "authhelper.auth.method.ai.chat.error.call.failed", e.getMessage()));
            return null;
        }

        if (chatTab != null) {
            chatTab.addTokenUsage(response.tokenUsage());
        }

        try {
            return LlmCommunicationService.mapResponse(response, AiAuthResponse.class);
        } catch (Exception e) {
            String rawResponse = response.aiMessage() != null ? response.aiMessage().text() : null;
            LOGGER.error("Failed to parse LLM response: {}", rawResponse, e);
            reportLlmError(
                    Constant.messages.getString(
                            "authhelper.auth.method.ai.chat.error.unparseable", rawResponse));
            return null;
        }
    }

    private void reportLlmError(String message) {
        if (chatTab != null) {
            chatTab.appendToOutput(LlmChatTabPanel.ERROR_LABEL, message);
        }
    }

    // ─── Action execution ─────────────────────────────────────────────────────

    AiAuthActionResult executeAction(
            WebDriver wd, AiAuthAction action, AiAuthCredentials credentials) {
        AiAuthActionType type = action.type();

        if (type == AiAuthActionType.WAIT) {
            try {
                int seconds = Integer.parseInt(action.value());
                if (seconds < 0 || seconds > MAX_WAIT_SECONDS) {
                    return AiAuthActionResult.failed(
                            type,
                            "WAIT value out of range [0, "
                                    + MAX_WAIT_SECONDS
                                    + "]: "
                                    + action.value());
                }
                waitSeconds(seconds);
                return AiAuthActionResult.ok(type, "wait", action.value());
            } catch (Exception e) {
                return AiAuthActionResult.failed(type, "Invalid WAIT value: " + action.value());
            }
        }

        SelectorMatch match = resolveSelector(wd, action.selectors());
        if (match == null) {
            return AiAuthActionResult.failed(
                    type, "No element matched selectors: " + action.selectors());
        }
        WebElement element = match.element();
        String usedSelector = match.selector();

        return switch (type) {
            case CLICK -> {
                if (isLogoutElement(element)) {
                    yield AiAuthActionResult.failed(
                            type,
                            "Refused to click "
                                    + usedSelector
                                    + ", it logs out and would undo the login. If the page shows that"
                                    + " the user is logged in report SUCCESS instead.");
                }
                try {
                    element.click();
                    yield AiAuthActionResult.ok(type, usedSelector, null);
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            case SEND_KEYS -> {
                try {
                    String value = credentials.substitute(action.value());
                    element.clear();
                    element.sendKeys(value);
                    yield AiAuthActionResult.ok(type, usedSelector, action.value());
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            case SELECT -> {
                try {
                    new Select(element).selectByVisibleText(action.value());
                    yield AiAuthActionResult.ok(type, usedSelector, action.value());
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            default -> AiAuthActionResult.failed(type, "Unhandled action type: " + type);
        };
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /** Matches the text and attributes of elements that log out, e.g. "Log out" or "#signout". */
    private static final Pattern LOGOUT =
            Pattern.compile("(?i)\\b(?:log|sign)[\\s_-]*(?:out|off)\\b");

    /**
     * Tells whether or not the given element logs out, which an LLM might click when it fails to
     * recognise the post-login page, undoing the login.
     */
    static boolean isLogoutElement(WebElement element) {
        return Stream.of(
                        element.getText(),
                        element.getAttribute("id"),
                        element.getAttribute("name"),
                        element.getAttribute("value"),
                        element.getAttribute("href"))
                .filter(Objects::nonNull)
                .anyMatch(text -> LOGOUT.matcher(text).find());
    }

    /** A selector that matched an element, paired with the element it matched. */
    private record SelectorMatch(String selector, WebElement element) {}

    private SelectorMatch resolveSelector(WebDriver wd, List<String> selectors) {
        if (selectors == null) return null;
        for (String selector : selectors) {
            try {
                List<WebElement> found = wd.findElements(By.cssSelector(selector));
                if (!found.isEmpty()) {
                    return new SelectorMatch(selector, found.get(0));
                }
            } catch (Exception e) {
                LOGGER.trace("Selector '{}' failed: {}", selector, e.getMessage());
            }
        }
        return null;
    }

    // ─── Chat-tab logging ─────────────────────────────────────────────────────

    private void logTurnContext(
            int step,
            String url,
            String pageTitle,
            List<AiAuthInputElement> elements,
            String visibleText,
            AiAuthCredentials credentials) {
        if (chatTab == null) return;
        long visible = elements.stream().filter(AiAuthInputElement::visible).count();
        StringBuilder msg = new StringBuilder();
        msg.append(Constant.messages.getString("authhelper.auth.method.ai.chat.turn", step, url));
        msg.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.page", pageTitle));
        msg.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.elements",
                                visible,
                                elements.size()));
        if (visibleText != null && !visibleText.isBlank()) {
            msg.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.text", visibleText));
        }
        if (credentials.hasTotp()) {
            msg.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.totp",
                                    credentials.totpDigits()));
        }
        msg.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.completed",
                                successfulActions.size()));
        chatTab.appendToOutput(LlmChatTabPanel.USER_LABEL, msg.toString());
    }

    private void logLlmResponse(AiAuthResponse response) {
        if (chatTab == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append(
                Constant.messages.getString(
                        "authhelper.auth.method.ai.chat.state", response.state()));
        sb.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.reasoning", response.reasoning()));
        if (response.actions() != null && !response.actions().isEmpty()) {
            sb.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.actions.header"));
            int n = 1;
            for (AiAuthAction action : response.actions()) {
                sb.append("\n  ")
                        .append(
                                Constant.messages.getString(
                                        "authhelper.auth.method.ai.chat.action.item",
                                        n++,
                                        action.type()));
                if (action.selectors() != null && !action.selectors().isEmpty()) {
                    sb.append(" ").append(action.selectors().get(0));
                }
                if (action.value() != null) {
                    sb.append(" → ").append(action.value());
                }
            }
        }
        if (response.successIndicator() != null) {
            sb.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.success.indicator",
                                    response.successIndicator().type(),
                                    response.successIndicator().value()));
        }
        chatTab.appendToOutput(LlmChatTabPanel.ASSISTANT_LABEL, sb.toString());
    }

    private void logFinalResult(AiAuthResult result) {
        if (chatTab == null) return;
        String resultWord =
                Constant.messages.getString(
                        result.success()
                                ? "authhelper.auth.method.ai.chat.result.succeeded"
                                : "authhelper.auth.method.ai.chat.result.failed");
        String msg =
                Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.result.header",
                                resultWord,
                                result.finalState())
                        + "\n"
                        + result.reasoning();
        chatTab.appendToOutput(
                result.success() ? LlmChatTabPanel.ASSISTANT_LABEL : LlmChatTabPanel.ERROR_LABEL,
                msg);
    }

    private void waitSeconds(int seconds) {
        waitMillis((long) seconds * 1000);
    }

    private void waitMillis(long ms) {
        if (ms <= 0) return;
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
