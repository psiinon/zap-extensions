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

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.addon.authhelper.internal.TotpAlgorithms;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A multi-step login flow where the user must select a domain on the first page, a department on
 * the second page, and enter their password on the third page. Login only succeeds when the correct
 * domain ("Project1") is selected, making it a good test case for AI-assisted authentication where
 * ZAP needs a user-supplied hint to know which domain to choose.
 *
 * <p>Optionally, a fourth step asks for a TOTP code, which is enabled and configured through the
 * {@code config} page (see {@link MultiStepAuthConfigPage}): the code can be a fixed one or
 * generated from a shared secret, and entered in a single field or in one field per digit.
 */
public class MultiStepAuthDir extends TestAuthDirectory {

    public static final String REQUIRED_DOMAIN = "Project1";

    /** The default fixed TOTP code. */
    public static final String DEFAULT_FIXED_CODE = "1234";

    /** The default shared secret, base32 encoded. */
    public static final String DEFAULT_SECRET = "JBSWY3DPEHPK3PXP";

    /** The default number of digits of codes generated from the shared secret. */
    public static final int DEFAULT_DIGITS = 6;

    private static final int PERIOD = 30;
    private static final String ALGORITHM = "SHA1";

    /** How the TOTP step validates the code. */
    public enum TotpMode {
        /** No TOTP step. */
        OFF,
        /** The code must be equal to the configured fixed code. */
        FIXED,
        /** The code is generated from the configured shared secret. */
        SECRET
    }

    /** How the TOTP code is entered. */
    public enum TotpLayout {
        /** One field for the whole code. */
        SINGLE,
        /** One field per digit. */
        DIGITS
    }

    private volatile TotpMode totpMode = TotpMode.OFF;
    private volatile TotpLayout totpLayout = TotpLayout.SINGLE;
    private volatile String fixedCode = DEFAULT_FIXED_CODE;
    private volatile String secret = DEFAULT_SECRET;
    private volatile int digits = DEFAULT_DIGITS;

    /** Tokens of users that provided valid credentials but still have to provide the TOTP code. */
    private final Map<String, String> pendingTokens = state(new ConcurrentHashMap<>());

    public MultiStepAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new MultiStepAuthStep2Page(server));
        this.addPage(new MultiStepAuthPasswordPage(server));
        this.addPage(new MultiStepAuthLoginPage(server));
        this.addPage(new MultiStepAuthTotpPage(server));
        this.addPage(new MultiStepAuthTotpVerifyPage(server));
        this.addPage(new MultiStepAuthConfigPage(server));
        this.addPage(new MultiStepAuthHomePage(server));
        this.addPage(new MultiStepAuthVerificationPage(server));
        // The TOTP configuration is a setting, not state, so that it survives a session change
        // (for example when running a plan from the GUI) and the app can be tested manually.
    }

    /**
     * Configures the TOTP step.
     *
     * @param mode the mode, {@link TotpMode#OFF} disables the step and resets the other settings.
     * @param layout the layout, {@code null} for the default ({@link TotpLayout#SINGLE}).
     * @param fixedCode the fixed code, {@code null} or empty for the default.
     * @param secret the shared secret, {@code null} or empty for the default.
     * @param digits the number of digits of generated codes, {@code null} for the default.
     */
    public void configureTotp(
            TotpMode mode, TotpLayout layout, String fixedCode, String secret, Integer digits) {
        this.totpMode = mode == null ? TotpMode.OFF : mode;
        this.totpLayout = layout == null ? TotpLayout.SINGLE : layout;
        this.fixedCode = StringUtils.defaultIfEmpty(fixedCode, DEFAULT_FIXED_CODE);
        this.secret = StringUtils.defaultIfEmpty(secret, DEFAULT_SECRET);
        this.digits = digits == null || digits <= 0 ? DEFAULT_DIGITS : digits;
        pendingTokens.clear();
    }

    public boolean isTotpEnabled() {
        return totpMode != TotpMode.OFF;
    }

    public TotpMode getTotpMode() {
        return totpMode;
    }

    public TotpLayout getTotpLayout() {
        return totpLayout;
    }

    /**
     * Gets the number of digits the TOTP code has, so the TOTP page can show one field per digit.
     *
     * @return the number of digits.
     */
    public int getTotpDigits() {
        return totpMode == TotpMode.FIXED ? fixedCode.length() : digits;
    }

    /**
     * Tells whether the given code is valid for the current TOTP configuration. Codes generated
     * from the secret are accepted for the current period and the ones immediately before and after
     * it, to allow for the time it takes to type the code.
     *
     * @param code the code to check.
     * @return {@code true} if valid, {@code false} otherwise.
     */
    public boolean isValidTotpCode(String code) {
        if (StringUtils.isEmpty(code)) {
            return false;
        }
        return switch (totpMode) {
            case OFF -> false;
            case FIXED -> fixedCode.equals(code);
            case SECRET ->
                    IntStream.rangeClosed(-1, 1)
                            .mapToObj(
                                    i ->
                                            TotpAlgorithms.generate(
                                                    secret,
                                                    PERIOD,
                                                    digits,
                                                    ALGORITHM,
                                                    Instant.now()
                                                            .plus(Duration.ofSeconds(i * PERIOD))))
                            .anyMatch(code::equals);
        };
    }

    /**
     * Creates a token for a user that provided valid credentials and still has to provide the TOTP
     * code.
     *
     * @param username the name of the user.
     * @return the token.
     */
    public String createPendingToken(String username) {
        String token = RandomStringUtils.secure().nextAlphanumeric(32);
        pendingTokens.put(token, username);
        return token;
    }

    /**
     * Consumes the given pending token, which is no longer valid afterwards.
     *
     * @param token the token.
     * @return the name of the user, or {@code null} if the token is not valid.
     */
    public String consumePendingToken(String token) {
        return token == null ? null : pendingTokens.remove(token);
    }

    /**
     * Gets the name of the user of the given pending token, without consuming it.
     *
     * @param token the token.
     * @return the name of the user, or {@code null} if the token is not valid.
     */
    public String getPendingUser(String token) {
        return token == null ? null : pendingTokens.get(token);
    }

    /**
     * Gets the current TOTP configuration as JSON, with the secret as it is needed by ZAP.
     *
     * @return the configuration.
     */
    public JSONObject getTotpConfig() {
        JSONObject json = new JSONObject();
        json.put("totp", totpMode.name().toLowerCase(Locale.ROOT));
        json.put("layout", totpLayout.name().toLowerCase(Locale.ROOT));
        json.put("code", fixedCode);
        json.put("secret", secret);
        json.put("digits", getTotpDigits());
        return json;
    }
}
