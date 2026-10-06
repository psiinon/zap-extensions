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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link OAuth2TokenLifetime}. */
class OAuth2TokenLifetimeUnitTest {

    private static final Instant NOW = Instant.ofEpochSecond(1_800_000_000L);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void shouldUseNumericExpiresIn() {
        // Given
        JSONObject response = JSONObject.fromObject("{\"access_token\":\"a\",\"expires_in\":3600}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.of(Duration.ofHours(1)))));
    }

    @Test
    void shouldUseStringExpiresIn() {
        // Given
        JSONObject response =
                JSONObject.fromObject("{\"access_token\":\"a\",\"expires_in\":\" 300 \"}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.of(Duration.ofMinutes(5)))));
    }

    @Test
    void shouldPreferExpiresInOverJwtExp() {
        // Given
        JSONObject response =
                JSONObject.fromObject(
                        "{\"access_token\":\""
                                + jwt("{\"exp\":" + (NOW.getEpochSecond() + 60) + "}")
                                + "\",\"expires_in\":120}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.of(Duration.ofSeconds(120)))));
    }

    @Test
    void shouldFallBackToJwtExpWithoutExpiresIn() {
        // Given
        JSONObject response =
                JSONObject.fromObject(
                        "{\"access_token\":\""
                                + jwt("{\"exp\":" + (NOW.getEpochSecond() + 90) + "}")
                                + "\"}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.of(Duration.ofSeconds(90)))));
    }

    @Test
    void shouldFallBackToJwtExpWhenExpiresInNotUsable() {
        // Given
        JSONObject response =
                JSONObject.fromObject(
                        "{\"expires_in\":0,\"access_token\":\""
                                + jwt("{\"exp\":" + (NOW.getEpochSecond() + 90) + "}")
                                + "\"}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.of(Duration.ofSeconds(90)))));
    }

    @Test
    void shouldIgnoreExpiredJwt() {
        // Given
        JSONObject response =
                JSONObject.fromObject(
                        "{\"access_token\":\""
                                + jwt("{\"exp\":" + (NOW.getEpochSecond() - 1) + "}")
                                + "\"}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.empty())));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"access_token\":\"opaque\"}",
                "{\"access_token\":\"a.b.c\"}",
                "{\"access_token\":\"a.!!!.c\"}",
                "{\"access_token\":\"opaque\",\"expires_in\":0}",
                "{\"access_token\":\"opaque\",\"expires_in\":-5}",
                "{\"access_token\":\"opaque\",\"expires_in\":\"soon\"}",
                "{\"access_token\":\"opaque\",\"expires_in\":\"\"}",
                "{\"access_token\":\"opaque\",\"expires_in\":null}",
                "{\"access_token\":\"opaque\",\"expires_in\":\"99999999999999999999999\"}",
                "{}"
            })
    void shouldHaveNoLifetimeWhenUnknownOrNotUsable(String response) {
        // Given
        JSONObject json = JSONObject.fromObject(response);
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(json, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.empty())));
    }

    @Test
    void shouldHaveNoLifetimeForJwtWithoutNumericExp() {
        // Given
        JSONObject response =
                JSONObject.fromObject(
                        "{\"access_token\":\"" + jwt("{\"exp\":\"tomorrow\"}") + "\"}");
        // When
        Optional<Duration> lifetime = OAuth2TokenLifetime.fromResponse(response, CLOCK);
        // Then
        assertThat(lifetime, is(equalTo(Optional.empty())));
    }

    private static String jwt(String claims) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + encoder.encodeToString(claims.getBytes(StandardCharsets.UTF_8))
                + ".sig";
    }
}
