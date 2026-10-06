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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

/**
 * Refreshes the OAuth2 tokens of users ahead of their expiry, for as long as the users are in use.
 *
 * <p>Each user has at most one pending refresh. It is (re)scheduled with {@link #schedule} every
 * time tokens are obtained, so a successful refresh keeps itself going. A user stops being
 * refreshed when:
 *
 * <ul>
 *   <li>the {@link RefreshAction} says it is no longer valid, for example the user was removed;
 *   <li>no requests were sent as the user for a while, see {@link #idleThreshold};
 *   <li>the refresh failed in a way that retrying will not fix, or failed repeatedly;
 *   <li>it is cancelled or the refresher shut down.
 * </ul>
 *
 * <p>Idle users are not refreshed so that tokens are not requested forever after a scan finishes.
 * Reactive re-authentication still takes care of any later use of the user.
 */
public class OAuth2TokenRefresher implements HttpSenderListener {

    private static final Logger LOGGER = LogManager.getLogger(OAuth2TokenRefresher.class);

    static final Duration MAX_MARGIN = Duration.ofSeconds(30);
    static final Duration MIN_DELAY = Duration.ofSeconds(5);
    static final Duration MAX_DELAY = Duration.ofHours(24);
    static final Duration MIN_IDLE_THRESHOLD = Duration.ofMinutes(5);

    /** The time to wait before each retry of a failed refresh, giving up after the last one. */
    static final List<Duration> RETRY_BACKOFFS =
            List.of(Duration.ofSeconds(10), Duration.ofSeconds(30), Duration.ofSeconds(90));

    /** Identifies a user, in a context. */
    public record UserKey(int contextId, int userId) {

        public static UserKey of(User user) {
            return new UserKey(user.getContextId(), user.getId());
        }
    }

    /** What to do for a user, when it is time to refresh. */
    public interface RefreshAction {

        /**
         * Tells if the refresh is still wanted, for example the user still exists and still uses
         * the same authentication method.
         *
         * @return {@code true} if the refresh should go ahead.
         */
        boolean isValid();

        /**
         * Refreshes the user's tokens. Obtaining new tokens is expected to {@link #schedule
         * schedule} the next refresh.
         *
         * @return the result of the refresh.
         */
        RefreshResult refresh();

        /** Called once the refresh failed and will not be tried again. */
        void onGiveUp();
    }

    /** The result of a refresh. */
    public enum RefreshResult {
        /** The tokens were refreshed. */
        REFRESHED,
        /** The refresh failed, but might work if tried again, for example a server error. */
        RETRY,
        /** The refresh failed, and trying again will not help, for example it was rejected. */
        GIVE_UP
    }

    private final ScheduledExecutorService executor;
    private final Clock clock;
    private final Map<UserKey, Entry> entries = new ConcurrentHashMap<>();

    public OAuth2TokenRefresher() {
        this(createExecutor(), Clock.systemUTC());
    }

    OAuth2TokenRefresher(ScheduledExecutorService executor, Clock clock) {
        this.executor = executor;
        this.clock = clock;
    }

    private static ScheduledExecutorService createExecutor() {
        ScheduledThreadPoolExecutor executor =
                new ScheduledThreadPoolExecutor(
                        1,
                        runnable -> {
                            Thread thread = new Thread(runnable, "ZAP-OAuth2-Token-Refresher");
                            thread.setDaemon(true);
                            return thread;
                        });
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }

    /**
     * Gets how long to wait before refreshing tokens that are valid for the given time.
     *
     * <p>The refresh is done a little before the expiry, 20% of the lifetime up to 30 seconds, but
     * never sooner than 5 seconds (to avoid tight loops if the IdP gives tiny lifetimes) nor later
     * than 24 hours.
     *
     * @param lifetime how long the tokens are valid for.
     * @return the delay.
     */
    static Duration refreshDelay(Duration lifetime) {
        Duration margin = lifetime.dividedBy(5);
        if (margin.compareTo(MAX_MARGIN) > 0) {
            margin = MAX_MARGIN;
        }
        Duration delay = lifetime.minus(margin);
        if (delay.compareTo(MIN_DELAY) < 0) {
            return MIN_DELAY;
        }
        return delay.compareTo(MAX_DELAY) > 0 ? MAX_DELAY : delay;
    }

    /**
     * Gets how long a user can go without being used, before no longer being refreshed.
     *
     * <p>That is two token lifetimes, as a user not used for that long is clearly abandoned, but at
     * least 5 minutes.
     *
     * @param lifetime how long the tokens are valid for.
     * @return the threshold.
     */
    static Duration idleThreshold(Duration lifetime) {
        Duration threshold = lifetime.multipliedBy(2);
        return threshold.compareTo(MIN_IDLE_THRESHOLD) < 0 ? MIN_IDLE_THRESHOLD : threshold;
    }

    /**
     * Schedules the refresh of the user's tokens, replacing any pending one. The user counts as
     * just used.
     *
     * @param key the user.
     * @param lifetime how long the new tokens are valid for.
     * @param action what to do when it is time to refresh.
     */
    public void schedule(UserKey key, Duration lifetime, RefreshAction action) {
        Entry entry = new Entry(lifetime, action, clock.instant());
        Entry previous = entries.put(key, entry);
        if (previous != null) {
            previous.cancel();
        }
        Duration delay = refreshDelay(lifetime);
        LOGGER.debug("Scheduling OAuth2 token refresh for {} in {}", key, delay);
        if (!submit(key, entry, 0, delay)) {
            entries.remove(key, entry);
        }
    }

    /**
     * Cancels the pending refresh of the user, if any.
     *
     * @param key the user.
     */
    public void cancel(UserKey key) {
        Entry entry = entries.remove(key);
        if (entry != null) {
            entry.cancel();
        }
    }

    /** Cancels the pending refresh of all users. */
    public void cancelAll() {
        entries.keySet().forEach(this::cancel);
    }

    /** Cancels all refreshes and releases the resources, no more refreshes can be scheduled. */
    public void shutdown() {
        executor.shutdownNow();
        entries.clear();
    }

    boolean isScheduled(UserKey key) {
        return entries.containsKey(key);
    }

    private boolean submit(UserKey key, Entry entry, int attempt, Duration delay) {
        try {
            entry.future =
                    executor.schedule(
                            () -> run(key, entry, attempt),
                            delay.toMillis(),
                            TimeUnit.MILLISECONDS);
            return true;
        } catch (RejectedExecutionException e) {
            LOGGER.debug("Unable to schedule OAuth2 token refresh, shutting down?");
            return false;
        }
    }

    private void run(UserKey key, Entry entry, int attempt) {
        if (entries.get(key) != entry) {
            // Superseded or cancelled.
            return;
        }

        RefreshResult result = RefreshResult.RETRY;
        try {
            if (!entry.action.isValid()) {
                LOGGER.debug("OAuth2 token refresh for {} no longer valid, stopping", key);
                entries.remove(key, entry);
                return;
            }
            if (isIdle(entry)) {
                LOGGER.debug("OAuth2 user {} not used recently, no longer refreshing", key);
                entries.remove(key, entry);
                return;
            }
            result = entry.action.refresh();
        } catch (Exception e) {
            LOGGER.warn("Failed to refresh OAuth2 tokens for {}: {}", key, e.getMessage());
            LOGGER.debug(e, e);
        }

        if (result == RefreshResult.REFRESHED) {
            // A new refresh was scheduled, replacing this entry, if the tokens have an expiry.
            entries.remove(key, entry);
            return;
        }

        if (result == RefreshResult.RETRY && attempt < RETRY_BACKOFFS.size()) {
            Duration backoff = RETRY_BACKOFFS.get(attempt);
            LOGGER.debug("OAuth2 token refresh for {} failed, retrying in {}", key, backoff);
            if (!submit(key, entry, attempt + 1, backoff)) {
                entries.remove(key, entry);
            }
            return;
        }

        LOGGER.warn(
                "Giving up refreshing OAuth2 tokens for {}{}",
                key,
                result == RefreshResult.GIVE_UP ? ", it was rejected" : "");
        entries.remove(key, entry);
        try {
            entry.action.onGiveUp();
        } catch (Exception e) {
            LOGGER.debug(e, e);
        }
    }

    private boolean isIdle(Entry entry) {
        return Duration.between(entry.lastUsed, clock.instant())
                        .compareTo(idleThreshold(entry.lifetime))
                > 0;
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        if (entries.isEmpty()
                || initiator == HttpSender.AUTHENTICATION_INITIATOR
                || initiator == HttpSender.AUTHENTICATION_HELPER_INITIATOR) {
            // Authenticating, including refreshing, is not using the user.
            return;
        }
        User user = msg.getRequestingUser();
        if (user == null) {
            return;
        }
        Entry entry = entries.get(UserKey.of(user));
        if (entry != null) {
            entry.lastUsed = clock.instant();
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        // Nothing to do.
    }

    private static final class Entry {

        private final Duration lifetime;
        private final RefreshAction action;
        private volatile Instant lastUsed;
        private volatile ScheduledFuture<?> future;

        Entry(Duration lifetime, RefreshAction action, Instant lastUsed) {
            this.lifetime = lifetime;
            this.action = action;
            this.lastUsed = lastUsed;
        }

        void cancel() {
            ScheduledFuture<?> pending = future;
            if (pending != null) {
                // Do not interrupt, it might be the running refresh replacing itself.
                pending.cancel(false);
            }
        }
    }
}
