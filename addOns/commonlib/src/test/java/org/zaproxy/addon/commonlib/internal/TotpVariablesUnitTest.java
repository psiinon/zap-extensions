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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.commonlib.internal.TotpSupport.TotpData;
import org.zaproxy.addon.commonlib.internal.TotpSupport.TotpGenerator;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

/** Unit test for {@link TotpVariables}. */
class TotpVariablesUnitTest {

    private AtomicInteger generations;
    private UsernamePasswordAuthenticationCredentials credentials;
    private TotpVariables variables;

    @BeforeEach
    void setUp() {
        generations = new AtomicInteger();
        TotpSupport.setTotpGenerator(
                new TotpGenerator() {

                    @Override
                    public String generate(TotpData data, Instant when) {
                        return "12345" + generations.incrementAndGet();
                    }

                    @Override
                    public List<String> getSupportedAlgorithms() {
                        return List.of("SHA1");
                    }
                });

        credentials = TotpSupport.createUsernamePasswordAuthenticationCredentials();
        TotpSupport.setTotpData(new TotpData("secret", 30, 6, "SHA1"), credentials);
        variables = new TotpVariables("{{", "}}");
    }

    @AfterAll
    static void cleanUp() {
        TotpSupport.setTotpGenerator(null);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"{{username}}", "TOTP", "{{TOTPX}}", "{{TOTP_}}", "[[TOTP]]"})
    void shouldNotResolveVariablesForNonTotpValues(String value) {
        Map<String, String> vars = variables.getVariables(value, credentials);

        assertThat(vars, is(anEmptyMap()));
        assertThat(generations.get(), is(0));
    }

    @Test
    void shouldResolveWholeCodeAndDigits() {
        Map<String, String> vars = variables.getVariables("{{TOTP}}", credentials);

        assertThat(vars, is(aMapWithSize(7)));
        assertThat(vars, hasEntry("TOTP", "123451"));
        assertThat(vars, hasEntry("TOTP_1", "1"));
        assertThat(vars, hasEntry("TOTP_5", "5"));
        assertThat(vars, hasEntry("TOTP_6", "1"));
    }

    @Test
    void shouldGenerateOnFirstDigitAndReuseForFollowingDigits() {
        variables.getVariables("{{TOTP_1}}", credentials);
        Map<String, String> second = variables.getVariables("{{TOTP_2}}", credentials);
        Map<String, String> sixth = variables.getVariables("{{TOTP_6}}", credentials);

        assertThat(generations.get(), is(1));
        assertThat(second, hasEntry("TOTP", "123451"));
        assertThat(sixth, hasEntry("TOTP_6", "1"));
    }

    @Test
    void shouldRegenerateOnWholeCodeOrFirstDigit() {
        variables.getVariables("{{TOTP}}", credentials);
        variables.getVariables("{{TOTP}}", credentials);
        Map<String, String> vars = variables.getVariables("{{TOTP_1}}", credentials);

        assertThat(generations.get(), is(3));
        assertThat(vars, hasEntry("TOTP", "123453"));
    }

    @Test
    void shouldGenerateOnLaterDigitWhenNoCodeYet() {
        Map<String, String> vars = variables.getVariables("{{TOTP_3}}", credentials);

        assertThat(generations.get(), is(1));
        assertThat(vars, hasEntry("TOTP_3", "3"));
    }

    @Test
    void shouldResolveWithOtherTokens() {
        TotpVariables other = new TotpVariables("<<", ">>");

        Map<String, String> vars = other.getVariables("<<TOTP_2>>", credentials);

        assertThat(vars, hasEntry("TOTP_2", "2"));
        assertThat(other.getVariables("{{TOTP}}", credentials), is(anEmptyMap()));
    }

    @Test
    void shouldNotResolveVariablesWithoutTotpData() {
        UsernamePasswordAuthenticationCredentials noTotp =
                new UsernamePasswordAuthenticationCredentials("user", "pass");

        Map<String, String> vars = variables.getVariables("{{TOTP}}", noTotp);

        assertThat(vars, is(anEmptyMap()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TOTP", "TOTP_1", "TOTP_10"})
    void shouldBeVariable(String name) {
        assertThat(TotpVariables.isVariable(name), is(true));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"totp", "TOTP_", "TOTP_x", "{{TOTP}}", "username", "OTP"})
    void shouldNotBeVariable(String name) {
        assertThat(TotpVariables.isVariable(name), is(false));
    }
}
