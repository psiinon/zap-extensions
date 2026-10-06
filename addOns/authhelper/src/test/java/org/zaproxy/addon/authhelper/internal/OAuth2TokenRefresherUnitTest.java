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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.RefreshAction;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.RefreshResult;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.UserKey;
import org.zaproxy.zap.users.User;

/** Unit test for {@link OAuth2TokenRefresher}. */
class OAuth2TokenRefresherUnitTest {

    private static final UserKey KEY = new UserKey(1, 2);
    private static final Duration LIFETIME = Duration.ofHours(1);

    private ScheduledExecutorService executor;
    private final List<Runnable> tasks = new ArrayList<>();
    private final List<Long> delaysMillis = new ArrayList<>();
    private final List<ScheduledFuture<?>> futures = new ArrayList<>();
    private TestClock clock;
    private OAuth2TokenRefresher refresher;

    @BeforeEach
    void setUp() {
        executor = mock(ScheduledExecutorService.class);
        given(executor.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class)))
                .willAnswer(
                        invocation -> {
                            tasks.add(invocation.getArgument(0));
                            long delay = invocation.getArgument(1);
                            TimeUnit unit = invocation.getArgument(2);
                            delaysMillis.add(unit.toMillis(delay));
                            ScheduledFuture<?> future = mock(ScheduledFuture.class);
                            futures.add(future);
                            return future;
                        });
        clock = new TestClock();
        refresher = new OAuth2TokenRefresher(executor, clock);
    }

    @ParameterizedTest
    @CsvSource({
        "3600, 3570", // Capped margin.
        "100, 80", // 20% margin.
        "10, 8",
        "5, 5", // Minimum delay.
        "2, 5",
        "864000, 86400" // Maximum delay.
    })
    void shouldComputeRefreshDelay(long lifetimeSeconds, long expectedSeconds) {
        // Given
        Duration lifetime = Duration.ofSeconds(lifetimeSeconds);
        // When
        Duration delay = OAuth2TokenRefresher.refreshDelay(lifetime);
        // Then
        assertThat(delay, is(equalTo(Duration.ofSeconds(expectedSeconds))));
    }

    @ParameterizedTest
    @CsvSource({"60, 300", "150, 300", "151, 302", "3600, 7200"})
    void shouldComputeIdleThreshold(long lifetimeSeconds, long expectedSeconds) {
        // Given
        Duration lifetime = Duration.ofSeconds(lifetimeSeconds);
        // When
        Duration threshold = OAuth2TokenRefresher.idleThreshold(lifetime);
        // Then
        assertThat(threshold, is(equalTo(Duration.ofSeconds(expectedSeconds))));
    }

    @Test
    void shouldScheduleRefreshAheadOfExpiry() {
        // Given
        TestAction action = new TestAction();
        // When
        refresher.schedule(KEY, LIFETIME, action);
        // Then
        assertThat(delaysMillis, contains(Duration.ofSeconds(3570).toMillis()));
        assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
        assertThat(action.refreshes, is(equalTo(0)));
    }

    @Test
    void shouldRefreshWhenDue() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofSeconds(3570));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(1)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
    }

    @Test
    void shouldKeepGoingWhenRefreshSchedulesNextRefresh() {
        // Given
        TestAction action = new TestAction();
        action.onRefresh = () -> refresher.schedule(KEY, LIFETIME, action);
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofSeconds(3570));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(1)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
        assertThat(tasks, hasSize(2));
        // The replaced entry's pending future is cancelled, without interrupting.
        verify(futures.get(0)).cancel(false);
    }

    @Test
    void shouldNotRefreshWhenNoLongerValid() {
        // Given
        TestAction action = new TestAction();
        action.valid = false;
        refresher.schedule(KEY, LIFETIME, action);
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
    }

    @Test
    void shouldNotRefreshWhenIdle() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofHours(2).plusSeconds(1));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
        assertThat(action.gaveUp, is(equalTo(false)));
    }

    @Test
    void shouldRefreshWhenNotIdleDueToRequestsAsUser() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofHours(1));
        refresher.onHttpRequestSend(requestAs(KEY), HttpSender.ACTIVE_SCANNER_INITIATOR, null);
        clock.advance(Duration.ofHours(1));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(1)));
    }

    @Test
    void shouldNotCountAuthenticationRequestsAsUse() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofHours(1));
        refresher.onHttpRequestSend(requestAs(KEY), HttpSender.AUTHENTICATION_INITIATOR, null);
        refresher.onHttpRequestSend(
                requestAs(KEY), HttpSender.AUTHENTICATION_HELPER_INITIATOR, null);
        clock.advance(Duration.ofHours(1).plusSeconds(1));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
    }

    @Test
    void shouldNotCountRequestsAsOtherUsersOrNoUserAsUse() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        clock.advance(Duration.ofHours(1));
        refresher.onHttpRequestSend(
                requestAs(new UserKey(1, 3)), HttpSender.ACTIVE_SCANNER_INITIATOR, null);
        refresher.onHttpRequestSend(new HttpMessage(), HttpSender.ACTIVE_SCANNER_INITIATOR, null);
        clock.advance(Duration.ofHours(1).plusSeconds(1));
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
    }

    @Test
    void shouldRetryFailedRefreshWithBackoffThenGiveUp() {
        // Given
        TestAction action = new TestAction();
        action.refreshResult = RefreshResult.RETRY;
        refresher.schedule(KEY, LIFETIME, action);

        // When / Then
        for (int i = 0; i < 3; i++) {
            tasks.get(i).run();
            assertThat(action.refreshes, is(equalTo(i + 1)));
            assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
            assertThat(action.gaveUp, is(equalTo(false)));
        }
        assertThat(delaysMillis.subList(1, 4), contains(10_000L, 30_000L, 90_000L));

        tasks.get(3).run();
        assertThat(action.refreshes, is(equalTo(4)));
        assertThat(action.gaveUp, is(equalTo(true)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
        assertThat(tasks, hasSize(4));
    }

    @Test
    void shouldGiveUpStraightAwayWhenRefreshResultIsGiveUp() {
        // Given
        TestAction action = new TestAction();
        action.refreshResult = RefreshResult.GIVE_UP;
        refresher.schedule(KEY, LIFETIME, action);

        // When
        tasks.get(0).run();

        // Then
        assertThat(action.refreshes, is(equalTo(1)));
        assertThat(action.gaveUp, is(equalTo(true)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
        assertThat(tasks, hasSize(1));
    }

    @Test
    void shouldTreatExceptionAsFailedRefresh() {
        // Given
        TestAction action = new TestAction();
        action.onRefresh =
                () -> {
                    throw new IllegalStateException("test");
                };
        refresher.schedule(KEY, LIFETIME, action);
        // When
        tasks.get(0).run();
        // Then
        assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
        assertThat(tasks, hasSize(2));
        assertThat(delaysMillis.get(1), is(equalTo(10_000L)));
    }

    @Test
    void shouldStopRetryingOnceSuperseded() {
        // Given
        TestAction action = new TestAction();
        action.refreshResult = RefreshResult.RETRY;
        refresher.schedule(KEY, LIFETIME, action);
        tasks.get(0).run();
        TestAction newAction = new TestAction();
        refresher.schedule(KEY, LIFETIME, newAction);
        // When
        tasks.get(1).run();
        // Then
        assertThat(action.refreshes, is(equalTo(1)));
        assertThat(newAction.refreshes, is(equalTo(0)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
    }

    @Test
    void shouldNotRunSupersededRefresh() {
        // Given
        TestAction action = new TestAction();
        TestAction newAction = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        refresher.schedule(KEY, LIFETIME, newAction);
        // When
        tasks.get(0).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
        assertThat(newAction.refreshes, is(equalTo(0)));
        verify(futures.get(0)).cancel(false);
    }

    @Test
    void shouldCancelRefresh() {
        // Given
        TestAction action = new TestAction();
        refresher.schedule(KEY, LIFETIME, action);
        // When
        refresher.cancel(KEY);
        tasks.get(0).run();
        // Then
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
        assertThat(action.refreshes, is(equalTo(0)));
        verify(futures.get(0)).cancel(false);
    }

    @Test
    void shouldCancelAllRefreshes() {
        // Given
        refresher.schedule(KEY, LIFETIME, new TestAction());
        refresher.schedule(new UserKey(1, 3), LIFETIME, new TestAction());
        // When
        refresher.cancelAll();
        // Then
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
        assertThat(refresher.isScheduled(new UserKey(1, 3)), is(equalTo(false)));
        verify(futures.get(0)).cancel(false);
        verify(futures.get(1)).cancel(false);
    }

    @Test
    void shouldKeepUsersSeparate() {
        // Given
        TestAction action = new TestAction();
        TestAction otherAction = new TestAction();
        UserKey otherKey = new UserKey(1, 3);
        refresher.schedule(KEY, LIFETIME, action);
        refresher.schedule(otherKey, LIFETIME, otherAction);
        // When
        tasks.get(1).run();
        // Then
        assertThat(action.refreshes, is(equalTo(0)));
        assertThat(otherAction.refreshes, is(equalTo(1)));
        assertThat(refresher.isScheduled(KEY), is(equalTo(true)));
    }

    @Test
    void shouldShutdownExecutor() {
        // Given
        refresher.schedule(KEY, LIFETIME, new TestAction());
        // When
        refresher.shutdown();
        // Then
        verify(executor).shutdownNow();
        assertThat(refresher.isScheduled(KEY), is(equalTo(false)));
    }

    @Test
    void shouldNotKeepRefreshWhenExecutorRejectsIt() {
        // Given
        ScheduledExecutorService rejecting = mock(ScheduledExecutorService.class);
        given(rejecting.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class)))
                .willThrow(new RejectedExecutionException());
        OAuth2TokenRefresher shutdownRefresher = new OAuth2TokenRefresher(rejecting, clock);
        // When
        shutdownRefresher.schedule(KEY, LIFETIME, new TestAction());
        // Then
        assertThat(shutdownRefresher.isScheduled(KEY), is(equalTo(false)));
    }

    @Test
    void shouldIgnoreRequestsWhenNothingScheduled() {
        // Given
        HttpMessage msg = mock(HttpMessage.class);
        // When
        refresher.onHttpRequestSend(msg, HttpSender.ACTIVE_SCANNER_INITIATOR, null);
        // Then
        verify(msg, never()).getRequestingUser();
    }

    private static HttpMessage requestAs(UserKey key) {
        User user = mock(User.class);
        given(user.getContextId()).willReturn(key.contextId());
        given(user.getId()).willReturn(key.userId());
        HttpMessage msg = new HttpMessage();
        msg.setRequestingUser(user);
        return msg;
    }

    private static class TestAction implements RefreshAction {

        boolean valid = true;
        RefreshResult refreshResult = RefreshResult.REFRESHED;
        Runnable onRefresh = () -> {};
        int refreshes;
        boolean gaveUp;

        @Override
        public boolean isValid() {
            return valid;
        }

        @Override
        public RefreshResult refresh() {
            refreshes++;
            onRefresh.run();
            return refreshResult;
        }

        @Override
        public void onGiveUp() {
            gaveUp = true;
        }
    }

    private static class TestClock extends Clock {

        private Instant now = Instant.ofEpochSecond(1_800_000_000L);

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
