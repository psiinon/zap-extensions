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
package org.zaproxy.addon.authhelper.internal;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * The TOTP algorithms supported by the add-on.
 *
 * <p>Besides the standard HMAC algorithms this includes {@link #FIXED}, for applications that
 * accept a static code (e.g. {@code 1234} in test/demo apps): the "secret" is then the code itself
 * and is returned as is.
 */
public final class TotpAlgorithms {

    /** The pseudo-algorithm whose "secret" is the (fixed) code to use. */
    public static final String FIXED = "FIXED";

    private static final List<String> SUPPORTED =
            Stream.concat(Stream.of(HMACAlgorithm.values()).map(Enum::name), Stream.of(FIXED))
                    .toList();

    private TotpAlgorithms() {}

    /**
     * Gets the names of the supported algorithms.
     *
     * @return the supported algorithms.
     */
    public static List<String> getSupported() {
        return SUPPORTED;
    }

    /**
     * Tells whether the given algorithm is supported.
     *
     * @param algorithm the name of the algorithm.
     * @return {@code true} if supported, {@code false} otherwise.
     */
    public static boolean isSupported(String algorithm) {
        return SUPPORTED.contains(algorithm);
    }

    /**
     * Tells whether the given algorithm is the {@link #FIXED} one.
     *
     * @param algorithm the name of the algorithm.
     * @return {@code true} if fixed, {@code false} otherwise.
     */
    public static boolean isFixed(String algorithm) {
        return FIXED.equals(algorithm);
    }

    /**
     * Generates the code for the given TOTP data.
     *
     * @param secret the shared secret, or the code itself for {@link #FIXED}.
     * @param period the period, in seconds.
     * @param digits the number of digits of the code.
     * @param algorithm the algorithm.
     * @param when the instant for which to generate the code.
     * @return the code.
     * @throws IllegalArgumentException if the algorithm is not supported or the data is not valid.
     */
    public static String generate(
            String secret, int period, int digits, String algorithm, Instant when) {
        if (isFixed(algorithm)) {
            return secret;
        }
        return new TOTPGenerator.Builder(secret)
                .withHOTPGenerator(
                        builder ->
                                builder.withAlgorithm(HMACAlgorithm.valueOf(algorithm))
                                        .withPasswordLength(digits))
                .withPeriod(Duration.ofSeconds(period))
                .build()
                .at(when);
    }
}
