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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.utils.I18N;

class AiAuthScriptGeneratorUnitTest {

    private static final String USERNAME = "realUser";
    private static final String PASSWORD = "realS3cret";
    private static final String TOTP_CODE = "483920";
    private static final AiAuthCredentials CREDS = new AiAuthCredentials(USERNAME, PASSWORD, null);
    private static final AiAuthCredentials TOTP_CREDS =
            new AiAuthCredentials(USERNAME, PASSWORD, TOTP_CODE);

    private AiAssistedAuthenticationMethod config;
    private LlmCommunicationService llm;
    private AiAuthScriptGenerator generator;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
    }

    @BeforeEach
    void setUp() {
        config = new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
        config.setLoginPageUrl("http://localhost/login");
        llm = mock(LlmCommunicationService.class);
        generator = new AiAuthScriptGenerator(config, llm, null);
    }

    /**
     * Stubs {@code llm.chatWithoutMemory(...)} to return a response whose {@code
     * aiMessage().text()} is json.
     */
    private void stubLlmResponse(String json) throws Exception {
        stubLlmResponses(json);
    }

    /** Stubs {@code llm.chatWithoutMemory(...)} to return the given responses, one per turn. */
    private void stubLlmResponses(String... jsons) throws Exception {
        ChatResponse[] responses =
                Stream.of(jsons)
                        .map(
                                json -> {
                                    ChatResponse response = mock(ChatResponse.class);
                                    AiMessage aiMessage = mock(AiMessage.class);
                                    given(response.aiMessage()).willReturn(aiMessage);
                                    given(aiMessage.text()).willReturn(json);
                                    return response;
                                })
                        .toArray(ChatResponse[]::new);
        given(llm.chatWithoutMemory(any(ChatRequest.class)))
                .willReturn(responses[0], Arrays.copyOfRange(responses, 1, responses.length));
    }

    private static String sendKeysTurn(String selector, String value) {
        return """
                { "state": "IN_PROGRESS", "reasoning": "fill", "successIndicator": null,
                  "actions": [ { "type": "SEND_KEYS", "selectors": ["%s"], "value": "%s" } ] }
                """
                .formatted(selector, value);
    }

    private static final String SUCCESS_TURN =
            """
            { "state": "SUCCESS", "reasoning": "Logged in", "actions": [],
              "successIndicator": { "type": "URL_PATTERN", "value": "home" } }
            """;

    @Nested
    class ExecuteAction {

        private TestWebDriver wd;
        private WebElement webElement;

        @BeforeEach
        void setUpDriver() {
            wd = mock(TestWebDriver.class);
            webElement = mock(WebElement.class);
        }

        @Test
        void shouldClickResolvedElement() {
            when(wd.findElements(By.cssSelector("#submit"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.CLICK, List.of("#submit"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            verify(webElement).click();
            assertThat(result.success(), is(true));
            assertThat(result.usedSelector(), is(equalTo("#submit")));
        }

        @ParameterizedTest
        @ValueSource(strings = {"Log out", "Logout", "Sign-out", "log_off", "/auth/logout?x=1"})
        void shouldRefuseToClickLogoutElement(String text) {
            when(wd.findElements(By.cssSelector("#link"))).thenReturn(List.of(webElement));
            when(webElement.getAttribute("href")).thenReturn(text);
            AiAuthAction action = new AiAuthAction(AiAuthActionType.CLICK, List.of("#link"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            verify(webElement, never()).click();
            assertThat(result.success(), is(false));
            assertThat(result.error(), containsString("report SUCCESS"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"Login", "Sign in", "Log in to Project1", "#logo", "/checkout"})
        void shouldClickElementNotLoggingOut(String text) {
            when(wd.findElements(By.cssSelector("#btn"))).thenReturn(List.of(webElement));
            when(webElement.getText()).thenReturn(text);
            AiAuthAction action = new AiAuthAction(AiAuthActionType.CLICK, List.of("#btn"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            verify(webElement).click();
            assertThat(result.success(), is(true));
        }

        @Test
        void shouldFailWhenNoElementMatchesAnySelector() {
            when(wd.findElements(By.cssSelector("#missing"))).thenReturn(List.of());
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.CLICK, List.of("#missing"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldSendRealCredentialButKeepPlaceholderInResult() {
            when(wd.findElements(By.cssSelector("#password"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#password"),
                            AiAuthTurnPayload.PASSWORD_PLACEHOLDER);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            verify(webElement).sendKeys(PASSWORD);
            assertThat(result.success(), is(true));
            assertThat(result.value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldSendWholeTotpCode() {
            when(wd.findElements(By.cssSelector("#code"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#code"),
                            AiAuthTurnPayload.TOTP_PLACEHOLDER);

            AiAuthActionResult result = generator.executeAction(wd, action, TOTP_CREDS);

            verify(webElement).sendKeys(TOTP_CODE);
            assertThat(result.success(), is(true));
            assertThat(result.value(), is(equalTo(AiAuthTurnPayload.TOTP_PLACEHOLDER)));
        }

        @Test
        void shouldSendSingleTotpDigit() {
            when(wd.findElements(By.cssSelector("#d3"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#d3"),
                            AiAuthTurnPayload.totpDigitPlaceholder(3));

            AiAuthActionResult result = generator.executeAction(wd, action, TOTP_CREDS);

            verify(webElement).sendKeys("3");
            assertThat(result.success(), is(true));
            assertThat(result.value(), is(equalTo("{{totp3}}")));
        }

        @Test
        void shouldFailTotpDigitOutOfRange() {
            when(wd.findElements(By.cssSelector("#d7"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#d7"),
                            AiAuthTurnPayload.totpDigitPlaceholder(7));

            AiAuthActionResult result = generator.executeAction(wd, action, TOTP_CREDS);

            verify(webElement, never()).sendKeys(any(CharSequence.class));
            assertThat(result.success(), is(false));
            assertThat(result.error(), containsString("6 digits"));
        }

        @Test
        void shouldFailTotpWhenNotConfigured() {
            when(wd.findElements(By.cssSelector("#code"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#code"),
                            AiAuthTurnPayload.TOTP_PLACEHOLDER);

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            verify(webElement, never()).sendKeys(any(CharSequence.class));
            assertThat(result.success(), is(false));
            assertThat(result.error(), containsString("no TOTP data"));
        }

        @Test
        void shouldFailSelectWhenOptionNotFound() {
            when(wd.findElements(By.cssSelector("#domain"))).thenReturn(List.of(webElement));
            when(webElement.getTagName()).thenReturn("select");
            when(webElement.getAttribute("multiple")).thenReturn(null);
            when(webElement.findElements(any())).thenReturn(List.of());
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.SELECT, List.of("#domain"), "Project1");

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldWaitForGivenSeconds() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "0");

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(true));
        }

        @Test
        void shouldFailOnInvalidWaitValue() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "not-a-number");

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldWaitForMaxAllowedSeconds() {
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT,
                            null,
                            String.valueOf(AiAuthScriptGenerator.MAX_WAIT_SECONDS));

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(true));
        }

        @Test
        void shouldFailWhenWaitExceedsMaxAllowedSeconds() {
            // A model-controlled WAIT value must be bounded, otherwise a response like
            // Integer.MAX_VALUE would block the auth worker thread for decades.
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT,
                            null,
                            String.valueOf(AiAuthScriptGenerator.MAX_WAIT_SECONDS + 1));

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldFailWhenWaitIsExtremelyLarge() {
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT, null, String.valueOf(Integer.MAX_VALUE));

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldFailWhenWaitIsNegative() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "-1");

            AiAuthActionResult result = generator.executeAction(wd, action, CREDS);

            assertThat(result.success(), is(false));
        }
    }

    @Nested
    class Run {

        private TestWebDriver wd;

        @BeforeEach
        void setUpDriver() {
            wd = mock(TestWebDriver.class);
            when(wd.executeScript(AiAuthScriptGenerator.PAGE_ELEMENTS_JS)).thenReturn("[]");
            when(wd.executeScript(AiAuthScriptGenerator.PAGE_TEXT_JS)).thenReturn("");
            when(wd.getCurrentUrl()).thenReturn("http://localhost/login");
            when(wd.getTitle()).thenReturn("Login");
        }

        @Test
        void shouldNotSendTotpToLlmWhenNotConfigured() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "FAILURE", "reasoning": "stop", "actions": [],
                      "successIndicator": null }
                    """);

            generator.run(wd, USERNAME, PASSWORD);

            String payload = capturedPayload();
            assertThat(payload, not(containsString("totp")));
        }

        @Test
        void shouldSendTotpPlaceholderAndDigitsToLlmWhenConfigured() throws Exception {
            AiAuthScriptGenerator withTotp =
                    new AiAuthScriptGenerator(config, llm, null, () -> TOTP_CODE);
            stubLlmResponse(
                    """
                    { "state": "FAILURE", "reasoning": "stop", "actions": [],
                      "successIndicator": null }
                    """);

            withTotp.run(wd, USERNAME, PASSWORD);

            String payload = capturedPayload();
            assertThat(payload, containsString("\"totp\":\"{{totp}}\""));
            assertThat(payload, containsString("\"totpDigits\":6"));
            assertThat(payload, not(containsString(TOTP_CODE)));
        }

        @Test
        void shouldReportMissingTotpWhenMfaRequired() throws Exception {
            given(Constant.messages.getString("authhelper.auth.method.ai.chat.mfa.nototp"))
                    .willReturn("No TOTP");
            LlmChatTabPanel chatTab = mock(LlmChatTabPanel.class);
            AiAuthScriptGenerator withChatTab = new AiAuthScriptGenerator(config, llm, chatTab);
            stubLlmResponse(
                    """
                    { "state": "MFA_REQUIRED", "reasoning": "code needed", "actions": [],
                      "successIndicator": null }
                    """);

            AiAuthResult result = withChatTab.run(wd, USERNAME, PASSWORD);

            assertThat(result.finalState(), is(AiAuthState.MFA_REQUIRED));
            verify(chatTab).appendToOutput(eq(LlmChatTabPanel.ERROR_LABEL), eq("No TOTP"));
        }

        private String capturedPayload() throws Exception {
            ArgumentCaptor<ChatRequest> captor = ArgumentCaptor.forClass(ChatRequest.class);
            verify(llm).chatWithoutMemory(captor.capture());
            return ((UserMessage) captor.getValue().messages().get(1)).singleText();
        }

        @Test
        void shouldReturnFailureWhenLlmReturnsNoParseableResponse() throws Exception {
            given(llm.chatWithoutMemory(any(ChatRequest.class)))
                    .willThrow(new RuntimeException("boom"));

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldReportRawResponseToChatTabWhenNotParseable() throws Exception {
            given(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.error.unparseable",
                                    "this is not json"))
                    .willReturn("Unparseable LLM response: this is not json");
            LlmChatTabPanel chatTab = mock(LlmChatTabPanel.class);
            AiAuthScriptGenerator withChatTab = new AiAuthScriptGenerator(config, llm, chatTab);
            stubLlmResponse("this is not json");

            withChatTab.run(wd, USERNAME, PASSWORD);

            verify(chatTab)
                    .appendToOutput(
                            eq(LlmChatTabPanel.ERROR_LABEL),
                            eq("Unparseable LLM response: this is not json"));
        }

        @Test
        void shouldNotThrowWhenLlmReturnsNullActionsForInProgressState() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "IN_PROGRESS", "reasoning": "thinking", "actions": null,
                      "successIndicator": null }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            // Every turn repeats the same IN_PROGRESS/null-actions response, so the loop should
            // run out its MAX_TURNS budget rather than throwing a NullPointerException.
            assertThat(result.success(), is(false));
        }

        @Test
        void shouldReturnSuccessOnTerminalSuccessState() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "SUCCESS", "reasoning": "Logged in", "actions": [],
                      "successIndicator": { "type": "URL_PATTERN", "value": "home" } }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(true));
            assertThat(result.finalState(), is(AiAuthState.SUCCESS));
        }

        @Test
        void shouldRecordActionsOnDifferentPages() throws Exception {
            when(wd.getCurrentUrl())
                    .thenReturn(
                            "http://localhost/login",
                            "http://localhost/password",
                            "http://localhost/home");
            when(wd.findElements(any(By.class))).thenReturn(List.of(mock(WebElement.class)));
            stubLlmResponses(
                    sendKeysTurn("#user", "{{username}}"),
                    sendKeysTurn("#password", "{{password}}"),
                    SUCCESS_TURN);

            generator.run(wd, USERNAME, PASSWORD);

            assertThat(
                    generator.getSuccessfulActions().stream()
                            .map(AiAuthActionResult::usedSelector)
                            .toList(),
                    contains("#user", "#password"));
        }

        @Test
        void shouldSendActionsCompletedInEarlierTurns() throws Exception {
            when(wd.getCurrentUrl())
                    .thenReturn(
                            "http://localhost/login",
                            "http://localhost/password",
                            "http://localhost/home");
            when(wd.findElements(any(By.class))).thenReturn(List.of(mock(WebElement.class)));
            stubLlmResponses(
                    sendKeysTurn("#user", "{{username}}"),
                    sendKeysTurn("#password", "{{password}}"),
                    SUCCESS_TURN);

            generator.run(wd, USERNAME, PASSWORD);

            ArgumentCaptor<ChatRequest> captor = ArgumentCaptor.forClass(ChatRequest.class);
            verify(llm, times(3)).chatWithoutMemory(captor.capture());
            String lastPayload =
                    ((UserMessage) captor.getAllValues().get(2).messages().get(1)).singleText();
            assertThat(
                    lastPayload,
                    containsString(
                            "\"completedActions\":[{\"type\":\"SEND_KEYS\",\"usedSelector\":\"#user\","));
            assertThat(lastPayload, containsString("\"usedSelector\":\"#password\""));
            assertThat(
                    lastPayload,
                    containsString(
                            "\"previousActions\":[{\"type\":\"SEND_KEYS\",\"usedSelector\":\"#password\","));
        }

        @Test
        void shouldDiscardActionsRecordedBeforePageWasShownAgain() throws Exception {
            when(wd.getCurrentUrl())
                    .thenReturn(
                            "http://localhost/login",
                            "http://localhost/code",
                            "http://localhost/login",
                            "http://localhost/code",
                            "http://localhost/home");
            when(wd.findElements(any(By.class))).thenReturn(List.of(mock(WebElement.class)));
            stubLlmResponses(
                    sendKeysTurn("#user", "{{username}}"),
                    sendKeysTurn("#code", "{{totp}}"),
                    sendKeysTurn("#user2", "{{username}}"),
                    sendKeysTurn("#code2", "{{totp}}"),
                    SUCCESS_TURN);
            LlmChatTabPanel chatTab = mock(LlmChatTabPanel.class);
            given(Constant.messages.getString("authhelper.auth.method.ai.chat.discarded", 1, 2))
                    .willReturn("Discarded");
            generator = new AiAuthScriptGenerator(config, llm, chatTab, () -> TOTP_CODE);

            generator.run(wd, USERNAME, PASSWORD);

            assertThat(
                    generator.getSuccessfulActions().stream()
                            .map(AiAuthActionResult::usedSelector)
                            .toList(),
                    contains("#user2", "#code2"));
            verify(chatTab).appendToOutput(eq(LlmChatTabPanel.USER_LABEL), eq("Discarded"));
        }

        @Test
        void shouldTypeTotpCodeObtainedAfterLlmResponse() throws Exception {
            WebElement codeField = mock(WebElement.class);
            when(wd.findElements(By.cssSelector("#code"))).thenReturn(List.of(codeField));
            stubLlmResponses(sendKeysTurn("#code", "{{totp}}"), SUCCESS_TURN);
            Iterator<String> codes = List.of("111111", "222222", "333333").iterator();
            generator = new AiAuthScriptGenerator(config, llm, null, codes::next);

            generator.run(wd, USERNAME, PASSWORD);

            verify(codeField).sendKeys("222222");
        }

        @Test
        void shouldReturnFailureAfterMaxTurnsWhenStuckInProgress() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "IN_PROGRESS", "reasoning": "still working", "actions": [],
                      "successIndicator": null }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
            assertThat(result.finalState(), is(AiAuthState.FAILURE));
        }
    }

    /** A WebDriver that also implements JavascriptExecutor, as ZAP's browsers always are. */
    private interface TestWebDriver extends WebDriver, JavascriptExecutor {}
}
