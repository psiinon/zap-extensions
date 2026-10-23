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
package org.zaproxy.addon.authhelpertest.multistep;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;

import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.authhelper.internal.TotpAlgorithms;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpLayout;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir.TotpMode;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for the TOTP configuration of {@link MultiStepAuthDir}. */
class MultiStepAuthDirUnitTest {

    private MultiStepAuthDir dir;

    @BeforeEach
    void setUp() {
        dir =
                new MultiStepAuthDir(
                        new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class)),
                        "multi-step-auth");
    }

    @Test
    void shouldHaveTotpOffByDefault() {
        assertThat(dir.isTotpEnabled(), is(false));
        assertThat(dir.getTotpMode(), is(TotpMode.OFF));
        assertThat(dir.getTotpLayout(), is(TotpLayout.SINGLE));
        assertThat(dir.isValidTotpCode(MultiStepAuthDir.DEFAULT_FIXED_CODE), is(false));
        assertThat(dir.getTotpConfig().getString("totp"), is(equalTo("off")));
    }

    @Test
    void shouldUseDefaultsWhenConfiguredWithNulls() {
        dir.configureTotp(TotpMode.FIXED, null, null, null, null);

        assertThat(dir.isTotpEnabled(), is(true));
        assertThat(dir.getTotpLayout(), is(TotpLayout.SINGLE));
        assertThat(dir.getTotpDigits(), is(equalTo(MultiStepAuthDir.DEFAULT_FIXED_CODE.length())));
        assertThat(dir.isValidTotpCode(MultiStepAuthDir.DEFAULT_FIXED_CODE), is(true));
        assertThat(dir.getTotpConfig().getString("secret"), is(MultiStepAuthDir.DEFAULT_SECRET));
    }

    @Test
    void shouldValidateConfiguredFixedCode() {
        dir.configureTotp(TotpMode.FIXED, TotpLayout.DIGITS, "987654", null, null);

        assertThat(dir.getTotpDigits(), is(equalTo(6)));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
        assertThat(dir.isValidTotpCode("987654"), is(true));
        assertThat(dir.isValidTotpCode("1234"), is(false));
    }

    @Test
    void shouldValidateCodeGeneratedFromSecret() {
        dir.configureTotp(TotpMode.SECRET, null, null, null, null);
        String code =
                TotpAlgorithms.generate(
                        MultiStepAuthDir.DEFAULT_SECRET, 30, 6, "SHA1", Instant.now());

        assertThat(dir.getTotpDigits(), is(equalTo(6)));
        assertThat(dir.isValidTotpCode(code), is(true));
    }

    @Test
    void shouldAcceptCodesFromAdjacentPeriods() {
        dir.configureTotp(TotpMode.SECRET, null, null, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 8);

        String previous =
                TotpAlgorithms.generate(
                        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                        30,
                        8,
                        "SHA1",
                        Instant.now().minusSeconds(30));
        String next =
                TotpAlgorithms.generate(
                        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                        30,
                        8,
                        "SHA1",
                        Instant.now().plusSeconds(30));
        String old =
                TotpAlgorithms.generate(
                        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                        30,
                        8,
                        "SHA1",
                        Instant.now().minusSeconds(90));

        assertThat(dir.getTotpDigits(), is(equalTo(8)));
        assertThat(dir.isValidTotpCode(previous), is(true));
        assertThat(dir.isValidTotpCode(next), is(true));
        assertThat(dir.isValidTotpCode(old), is(false));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"abc", "12345"})
    void shouldRejectInvalidCodes(String code) {
        dir.configureTotp(TotpMode.FIXED, null, "1234", null, null);

        assertThat(dir.isValidTotpCode(code), is(false));
    }

    @Test
    void shouldCreateAndConsumePendingTokens() {
        String token = dir.createPendingToken("test@test.com");

        assertThat(dir.getPendingUser(token), is(equalTo("test@test.com")));
        assertThat(dir.consumePendingToken(token), is(equalTo("test@test.com")));
        assertThat(dir.getPendingUser(token), is(nullValue()));
        assertThat(dir.consumePendingToken(token), is(nullValue()));
        assertThat(dir.consumePendingToken(null), is(nullValue()));
    }

    @Test
    void shouldClearPendingTokensWhenReconfigured() {
        String token = dir.createPendingToken("test@test.com");

        dir.configureTotp(TotpMode.FIXED, null, null, null, null);

        assertThat(dir.getPendingUser(token), is(nullValue()));
    }

    @Test
    void shouldKeepTotpConfigurationButClearPendingTokensOnReset() {
        dir.configureTotp(TotpMode.SECRET, TotpLayout.DIGITS, null, null, null);
        String token = dir.createPendingToken("test@test.com");

        dir.reset();

        assertThat(dir.isTotpEnabled(), is(true));
        assertThat(dir.getTotpLayout(), is(TotpLayout.DIGITS));
        assertThat(dir.getPendingUser(token), is(nullValue()));
    }
}
