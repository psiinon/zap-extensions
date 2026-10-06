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

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;

/** Works out how long an OAuth2 access token is valid for, from a token endpoint response. */
public final class OAuth2TokenLifetime {

    private static final String EXPIRES_IN = "expires_in";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String JWT_EXP = "exp";

    private OAuth2TokenLifetime() {}

    /**
     * Gets the lifetime of the access token in the given token response.
     *
     * <p>The {@code expires_in} field is used if present, otherwise the {@code exp} claim of the
     * access token, if that is a JWT. The JWT is only decoded, it is not validated, as the value is
     * just a hint for when to refresh.
     *
     * @param tokenResponse the (normalised) JSON token response.
     * @param clock the clock to compare a JWT expiry against.
     * @return the remaining lifetime, empty if it is unknown or not positive.
     */
    public static Optional<Duration> fromResponse(JSONObject tokenResponse, Clock clock) {
        return positive(expiresIn(tokenResponse))
                .or(() -> positive(jwtLifetime(tokenResponse.optString(ACCESS_TOKEN), clock)));
    }

    private static Optional<Duration> positive(Optional<Duration> lifetime) {
        return lifetime.filter(l -> l.isPositive());
    }

    private static Optional<Duration> expiresIn(JSONObject tokenResponse) {
        Object value = tokenResponse.opt(EXPIRES_IN);
        if (value instanceof Number number) {
            return Optional.of(Duration.ofSeconds(number.longValue()));
        }
        if (value instanceof String str && StringUtils.isNumeric(str.trim())) {
            try {
                return Optional.of(Duration.ofSeconds(Long.parseLong(str.trim())));
            } catch (NumberFormatException e) {
                // Too big, ignore.
            }
        }
        return Optional.empty();
    }

    private static Optional<Duration> jwtLifetime(String accessToken, Clock clock) {
        String[] parts = accessToken.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            JSONObject claims =
                    JSONObject.fromObject(
                            new String(
                                    Base64.getUrlDecoder().decode(parts[1]),
                                    StandardCharsets.UTF_8));
            if (claims.opt(JWT_EXP) instanceof Number exp) {
                return Optional.of(
                        Duration.between(clock.instant(), Instant.ofEpochSecond(exp.longValue())));
            }
        } catch (RuntimeException e) {
            // Not a JWT, or not one we can read.
        }
        return Optional.empty();
    }
}
