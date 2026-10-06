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
package org.zaproxy.addon.authhelper;

import java.awt.BorderLayout;
import java.awt.GridBagLayout;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.internal.ExtraParamsPanel;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenLifetime;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.RefreshAction;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.RefreshResult;
import org.zaproxy.addon.authhelper.internal.OAuth2TokenRefresher.UserKey;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AbstractCredentialsOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.authentication.AuthenticationAPI;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.extension.users.UsersAPI;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.EncodingUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.DynamicFieldsPanel;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * An {@link AuthenticationMethodType} that obtains an OAuth2 access (and optionally refresh) token
 * directly from a token endpoint, using one of the non-interactive grant types ({@code
 * client_credentials}, {@code password} or {@code refresh_token}).
 *
 * <p>The token endpoint's JSON response is normalized and then fed into the configured {@link
 * SessionManagementMethod}, so the access/refresh token become available for header templating
 * (e.g. {@code Authorization: Bearer \{%json:access_token%\}}).
 */
public class OAuth2AuthenticationMethodType extends AuthenticationMethodType {

    /**
     * Stat for each time a user's tokens were refreshed, ahead of their expiry, with the refresh
     * token.
     */
    public static final String REFRESH_SUCCESS_STATS = "stats.auth.oauth2.refresh.success";

    /**
     * Stat for each time a user's tokens could not be refreshed, ahead of their expiry, with the
     * refresh token (none, or rejected) and the user was authenticated again instead.
     */
    public static final String REFRESH_FALLBACK_STATS = "stats.auth.oauth2.refresh.fallback";

    /** Stat for each time refreshing a user's tokens, ahead of their expiry, was given up on. */
    public static final String REFRESH_GIVE_UP_STATS = "stats.auth.oauth2.refresh.giveup";

    private static final int METHOD_IDENTIFIER = 9;

    private static final String API_METHOD_NAME = "oauth2Authentication";
    private static final String ACTION_SET_CREDENTIALS = "oauth2AuthenticationCredentials";

    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    public static final String CLIENT_AUTH_BASIC = "client_secret_basic";
    public static final String CLIENT_AUTH_POST = "client_secret_post";
    public static final String CLIENT_AUTH_NONE = "none";

    private static final String DEFAULT_ACCESS_TOKEN_FIELD = "access_token";
    private static final String DEFAULT_REFRESH_TOKEN_FIELD = "refresh_token";

    private static final String CREDENTIAL_PARAM_USERNAME = "username";
    private static final String CREDENTIAL_PARAM_PASSWORD = "password";
    private static final String[] CREDENTIAL_PARAM_NAMES = {
        CREDENTIAL_PARAM_USERNAME, CREDENTIAL_PARAM_PASSWORD
    };

    /**
     * Key used to store the refresh token captured automatically from a successful {@code
     * client_credentials}/{@code password} grant response, so it can be reused (and kept up to date
     * across rotations) on subsequent authentications without any user configuration.
     */
    private static final String CREDENTIAL_PARAM_REFRESH_TOKEN = "refreshToken";

    private static final String CONTEXT_CONFIG_AUTH_OAUTH2 =
            AuthenticationMethod.CONTEXT_CONFIG_AUTH + ".oauth2";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_GRANT_TYPE =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".granttype";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_TOKEN_ENDPOINT =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".tokenendpoint";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_ID =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".clientid";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_SECRET =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".clientsecret";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_AUTH_METHOD =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".clientauthmethod";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_SCOPE =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".scope";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_ACCESS_TOKEN_FIELD =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".accesstokenfield";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_REFRESH_TOKEN_FIELD =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".refreshtokenfield";
    private static final String CONTEXT_CONFIG_AUTH_OAUTH2_EXTRA_PARAM =
            CONTEXT_CONFIG_AUTH_OAUTH2 + ".extraparams.param";

    /* API related constants. */
    private static final String PARAM_GRANT_TYPE = "grantType";
    private static final String PARAM_TOKEN_ENDPOINT = "tokenEndpoint";
    private static final String PARAM_CLIENT_ID = "clientId";
    private static final String PARAM_CLIENT_SECRET = "clientSecret";
    private static final String PARAM_CLIENT_AUTH_METHOD = "clientAuthMethod";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_ACCESS_TOKEN_FIELD = "accessTokenField";
    private static final String PARAM_REFRESH_TOKEN_FIELD = "refreshTokenField";
    private static final String PARAM_EXTRA_TOKEN_PARAMS = "extraTokenParams";

    private static final Logger LOGGER = LogManager.getLogger(OAuth2AuthenticationMethodType.class);

    private static volatile OAuth2TokenRefresher tokenRefresher;

    /**
     * Sets the refresher used to refresh the tokens of users ahead of their expiry.
     *
     * @param refresher the refresher, or {@code null} to not refresh ahead of expiry.
     */
    static void setTokenRefresher(OAuth2TokenRefresher refresher) {
        tokenRefresher = refresher;
    }

    public class OAuth2AuthenticationMethod extends AuthenticationMethod {

        private String grantType = GRANT_TYPE_CLIENT_CREDENTIALS;
        private String tokenEndpoint;
        private String clientId;
        private String clientSecret;
        private String clientAuthMethod = CLIENT_AUTH_BASIC;
        private String scope;
        private String accessTokenField = DEFAULT_ACCESS_TOKEN_FIELD;
        private String refreshTokenField = DEFAULT_REFRESH_TOKEN_FIELD;
        private Map<String, String> extraTokenParams = new LinkedHashMap<>();
        private boolean diagnostics;

        private HttpSender httpSender;

        /**
         * When the access token of each user expires, by user ID. Transient, so not copied or
         * persisted.
         */
        private final Map<Integer, Instant> tokenExpiries = new ConcurrentHashMap<>();

        /**
         * The IDs of the users whose current tokens were obtained with a refresh token. If those
         * are rejected then using the refresh token again is not expected to help. Transient, so
         * not copied or persisted.
         */
        private final Set<Integer> usersWithRefreshedTokens = ConcurrentHashMap.newKeySet();

        /**
         * The IDs of the users for which the token endpoint rejected (with a client error, 4xx) the
         * last attempt to get tokens with the configured grant, trying again is not expected to
         * help. Transient, so not copied or persisted.
         */
        private final Set<Integer> usersRejectedByTokenEndpoint = ConcurrentHashMap.newKeySet();

        public OAuth2AuthenticationMethod() {}

        public OAuth2AuthenticationMethod(OAuth2AuthenticationMethod method) {
            this.grantType = method.grantType;
            this.tokenEndpoint = method.tokenEndpoint;
            this.clientId = method.clientId;
            this.clientSecret = method.clientSecret;
            this.clientAuthMethod = method.clientAuthMethod;
            this.scope = method.scope;
            this.accessTokenField = method.accessTokenField;
            this.refreshTokenField = method.refreshTokenField;
            this.extraTokenParams = new LinkedHashMap<>(method.extraTokenParams);
            this.diagnostics = method.diagnostics;
        }

        @Override
        public boolean isConfigured() {
            return StringUtils.isNotEmpty(grantType) && StringUtils.isNotEmpty(tokenEndpoint);
        }

        @Override
        protected AuthenticationMethod duplicate() {
            return new OAuth2AuthenticationMethod(this);
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return new GenericAuthenticationCredentials(CREDENTIAL_PARAM_NAMES);
        }

        @Override
        public AuthenticationMethodType getType() {
            return new OAuth2AuthenticationMethodType();
        }

        public String getGrantType() {
            return grantType;
        }

        public void setGrantType(String grantType) {
            if (!StringUtils.isEmpty(grantType)) {
                this.grantType = grantType;
            }
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientAuthMethod() {
            return clientAuthMethod;
        }

        public void setClientAuthMethod(String clientAuthMethod) {
            if (!StringUtils.isEmpty(clientAuthMethod)) {
                this.clientAuthMethod = clientAuthMethod;
            }
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getAccessTokenField() {
            return accessTokenField;
        }

        public void setAccessTokenField(String accessTokenField) {
            if (!StringUtils.isEmpty(accessTokenField)) {
                this.accessTokenField = accessTokenField;
            }
        }

        public String getRefreshTokenField() {
            return refreshTokenField;
        }

        public void setRefreshTokenField(String refreshTokenField) {
            if (!StringUtils.isEmpty(refreshTokenField)) {
                this.refreshTokenField = refreshTokenField;
            }
        }

        public Map<String, String> getExtraTokenParams() {
            return extraTokenParams;
        }

        public void setExtraTokenParams(Map<String, String> extraTokenParams) {
            this.extraTokenParams =
                    extraTokenParams == null ? new LinkedHashMap<>() : extraTokenParams;
        }

        public boolean isDiagnostics() {
            return diagnostics;
        }

        public void setDiagnostics(boolean diagnostics) {
            this.diagnostics = diagnostics;
        }

        private synchronized HttpSender getHttpSender() {
            if (httpSender == null) {
                httpSender = new HttpSender(HttpSender.AUTHENTICATION_INITIATOR);
            }
            return httpSender;
        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {

            if (!(credentials instanceof GenericAuthenticationCredentials cred)) {
                user.getAuthenticationState()
                        .setLastAuthFailure("Credentials not GenericAuthenticationCredentials");
                throw new UnsupportedAuthenticationCredentialsException(
                        "OAuth2 authentication method only supports "
                                + GenericAuthenticationCredentials.class.getSimpleName()
                                + ". Received: "
                                + credentials.getClass());
            }

            // Serialised per user, as refresh tokens might be rotated by the IdP, in which case
            // each one can only be used once.
            synchronized (cred) {
                // Authenticating, instead of refreshing ahead of the expiry, is done when the user
                // was found not to be authenticated, if the tokens are from a refresh token then
                // using it again is not expected to help, so the configured grant is used.
                WebSession session =
                        authenticate(cred, user, !usersWithRefreshedTokens.contains(user.getId()));
                if (session == null) {
                    cancelRefresh(user);
                }
                return session;
            }
        }

        private WebSession authenticate(
                GenericAuthenticationCredentials cred, User user, boolean tryRefreshToken) {
            try (AuthenticationDiagnostics diags =
                    new AuthenticationDiagnostics(
                            diagnostics, getName(), user.getContext().getName(), user.getName())) {

                if (!isConfigured()) {
                    LOGGER.warn(
                            "OAuth2 method not fully configured, cannot authenticate user: {}",
                            user.getName());
                    user.getAuthenticationState()
                            .setLastAuthFailure("OAuth2 method not fully configured");
                    diags.recordErrorStep(null);
                    return null;
                }

                AuthUtils.resolveAutoDetectSessionManagement(
                        user.getContext(), "Authorization", "Bearer {%json:access_token%}");
                AuthUtils.resolveAutoDetectVerification(
                        this, "\\Q 200 OK\\E", "\\Q 401 Unauthorized\\E");

                usersRejectedByTokenEndpoint.remove(user.getId());
                HttpMessage msg = tryRefreshToken ? attemptRefreshGrant(cred, diags, user) : null;
                boolean refreshed = msg != null;

                if (msg == null) {
                    msg = attemptGrant(grantType, cred, null, diags, user);
                    if (msg == null) {
                        return null;
                    }
                    if (!isSuccessfulTokenResponse(msg)) {
                        if (isClientError(msg)) {
                            usersRejectedByTokenEndpoint.add(user.getId());
                        }
                        user.getAuthenticationState()
                                .setLastAuthFailure(
                                        "OAuth2 token endpoint did not return a valid access"
                                                + " token");
                        AuthenticationHelper.notifyOutputAuthFailure(msg);
                        diags.recordStep(
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.unauthenticated"));
                        return null;
                    }
                }

                WebSession session = applyTokenResponse(msg, cred, user, refreshed);

                if (this.isAuthenticated(msg, user, true)) {
                    AuthenticationHelper.notifyOutputAuthSuccessful(msg);
                    user.getAuthenticationState().setLastAuthFailure("");
                    diags.recordStep(
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.authenticated"));
                    scheduleRefresh(user);
                    return session;
                }

                user.getAuthenticationState()
                        .setLastAuthFailure("OAuth2 authentication verification failed");
                user.setAuthenticatedSession(null);
                AuthenticationHelper.notifyOutputAuthFailure(msg);
                diags.recordStep(
                        Constant.messages.getString(
                                "authhelper.auth.method.diags.steps.unauthenticated"));
                return null;
            }
        }

        /**
         * Gets when the user's current access token expires, as reported by the token endpoint
         * ({@code expires_in}) or by the token itself (JWT {@code exp} claim).
         *
         * @param user the user.
         * @return the expiry, empty if it is not known.
         */
        Optional<Instant> getTokenExpiry(User user) {
            return Optional.ofNullable(tokenExpiries.get(user.getId()));
        }

        /**
         * Refreshes the user's tokens using the cached refresh token, without verifying the
         * resulting session and without falling back to the configured grant. The user's current
         * session is left untouched if the refresh fails.
         *
         * @param user the user to refresh the session of.
         * @return {@code true} if the tokens were refreshed and the user's session updated, {@code
         *     false} otherwise.
         */
        boolean refreshSession(User user) {
            if (!(user.getAuthenticationCredentials()
                    instanceof GenericAuthenticationCredentials cred)) {
                return false;
            }
            synchronized (cred) {
                HttpMessage msg = attemptRefreshGrant(cred, null, user);
                if (msg == null) {
                    return false;
                }
                applyTokenResponse(msg, cred, user, true);
                scheduleRefresh(user);
                return true;
            }
        }

        /**
         * Schedules the refresh of the user's tokens, ahead of their expiry, if the expiry is known
         * and the refresher is available.
         */
        private void scheduleRefresh(User user) {
            OAuth2TokenRefresher refresher = tokenRefresher;
            if (refresher == null) {
                return;
            }
            UserKey key = UserKey.of(user);
            Duration lifetime =
                    getTokenExpiry(user)
                            .map(expiry -> Duration.between(Instant.now(), expiry))
                            .orElse(Duration.ZERO);
            if (lifetime.isPositive()) {
                refresher.schedule(key, lifetime, new TokenRefreshAction(key));
            } else {
                refresher.cancel(key);
            }
        }

        private void incStat(String stat) {
            try {
                Stats.incCounter(SessionStructure.getHostName(new URI(tokenEndpoint, true)), stat);
            } catch (URIException e) {
                LOGGER.debug("Unable to record stat {}: {}", stat, e.getMessage());
            }
        }

        private void cancelRefresh(User user) {
            OAuth2TokenRefresher refresher = tokenRefresher;
            if (refresher != null) {
                refresher.cancel(UserKey.of(user));
            }
        }

        /**
         * The refresh of a user's tokens, when they are about to expire. Refreshes using the
         * refresh token, falling back to authenticating again if that is not possible.
         */
        private final class TokenRefreshAction implements RefreshAction {

            private final UserKey key;

            TokenRefreshAction(UserKey key) {
                this.key = key;
            }

            private User findUser() {
                ExtensionUserManagement extUser =
                        AuthUtils.getExtension(ExtensionUserManagement.class);
                if (extUser == null) {
                    return null;
                }
                ContextUserAuthManager userManager =
                        extUser.getContextUserAuthManager(key.contextId());
                return userManager == null ? null : userManager.getUserById(key.userId());
            }

            @Override
            public boolean isValid() {
                User user = findUser();
                return user != null
                        && user.getContext().getAuthenticationMethod()
                                == OAuth2AuthenticationMethod.this;
            }

            @Override
            public RefreshResult refresh() {
                User user = findUser();
                if (user == null
                        || !(user.getAuthenticationCredentials()
                                instanceof GenericAuthenticationCredentials cred)) {
                    return RefreshResult.GIVE_UP;
                }
                if (refreshSession(user)) {
                    incStat(REFRESH_SUCCESS_STATS);
                    return RefreshResult.REFRESHED;
                }
                incStat(REFRESH_FALLBACK_STATS);
                // Not cancelling the refresh on failure, it might be retried. The refresh token was
                // not used, or just rejected, no point in trying it again.
                synchronized (cred) {
                    if (authenticate(cred, user, false) != null) {
                        return RefreshResult.REFRESHED;
                    }
                    // If the token endpoint rejected the request then trying again will not help,
                    // for example the credentials are wrong, which could lock the account.
                    return usersRejectedByTokenEndpoint.contains(user.getId())
                            ? RefreshResult.GIVE_UP
                            : RefreshResult.RETRY;
                }
            }

            @Override
            public void onGiveUp() {
                incStat(REFRESH_GIVE_UP_STATS);
                User user = findUser();
                if (user != null) {
                    user.getAuthenticationState()
                            .setLastAuthFailure("OAuth2 token refresh failed repeatedly");
                }
            }
        }

        /**
         * Requests new tokens using the cached refresh token, if there is one.
         *
         * @return the token response, or {@code null} if there is no cached refresh token or the
         *     refresh did not succeed.
         */
        private HttpMessage attemptRefreshGrant(
                GenericAuthenticationCredentials cred, AuthenticationDiagnostics diags, User user) {
            String cachedRefreshToken = cred.getParam(CREDENTIAL_PARAM_REFRESH_TOKEN);
            if (StringUtils.isEmpty(cachedRefreshToken)) {
                return null;
            }
            HttpMessage msg =
                    attemptGrant(GRANT_TYPE_REFRESH_TOKEN, cred, cachedRefreshToken, diags, user);
            if (msg == null) {
                return null;
            }
            if (isSuccessfulTokenResponse(msg)) {
                return msg;
            }
            if (isClientError(msg)) {
                // It was rejected, so there is no point in using it again.
                cred.setParam(CREDENTIAL_PARAM_REFRESH_TOKEN, "");
            }
            return null;
        }

        private static boolean isClientError(HttpMessage msg) {
            int status = msg.getResponseHeader().getStatusCode();
            return status >= 400 && status < 500;
        }

        /**
         * Captures the tokens from a successful token response and sets the resulting session as
         * the user's authenticated session.
         *
         * @param fromRefresh {@code true} if the tokens were obtained with a refresh token.
         */
        private WebSession applyTokenResponse(
                HttpMessage msg,
                GenericAuthenticationCredentials cred,
                User user,
                boolean fromRefresh) {
            captureTokens(msg, cred, user);
            WebSession session =
                    user.getContext().getSessionManagementMethod().extractWebSession(msg);
            user.setAuthenticatedSession(session);
            if (fromRefresh) {
                usersWithRefreshedTokens.add(user.getId());
            } else {
                usersWithRefreshedTokens.remove(user.getId());
            }
            return session;
        }

        /**
         * Performs a single token request for the given grant type, recording diagnostics and
         * authentication-state failures along the way.
         *
         * @return the (already history-recorded and normalized) response message, or {@code null}
         *     if the request could not be prepared or sent.
         */
        private HttpMessage attemptGrant(
                String effectiveGrantType,
                GenericAuthenticationCredentials cred,
                String refreshTokenOverride,
                AuthenticationDiagnostics diags,
                User user) {
            HttpMessage msg;
            try {
                msg = prepareTokenRequest(effectiveGrantType, cred, refreshTokenOverride);
            } catch (Exception e) {
                LOGGER.error(
                        "Unable to prepare OAuth2 token request for token endpoint '{}': {}",
                        tokenEndpoint,
                        e.getMessage(),
                        e);
                user.getAuthenticationState()
                        .setLastAuthFailure(
                                "Unable to prepare OAuth2 token request for token endpoint '"
                                        + tokenEndpoint
                                        + "': "
                                        + e.getMessage());
                recordErrorStep(diags);
                return null;
            }

            try {
                getHttpSender().sendAndReceive(msg);
            } catch (IOException e) {
                LOGGER.error("Unable to send OAuth2 token request: {}", e.getMessage());
                user.getAuthenticationState()
                        .setLastAuthFailure(
                                "Unable to send OAuth2 token request: " + e.getMessage());
                recordErrorStep(diags);
                return null;
            }
            AuthenticationHelper.addAuthMessageToHistory(msg);

            normalizeTokenResponse(msg);
            return msg;
        }

        private static void recordErrorStep(AuthenticationDiagnostics diags) {
            if (diags != null) {
                diags.recordErrorStep(null);
            }
        }

        private boolean isSuccessfulTokenResponse(HttpMessage msg) {
            if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                return false;
            }
            try {
                JSONObject json = JSONObject.fromObject(msg.getResponseBody().toString());
                return json.has("access_token") && !json.has("error");
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * Captures the {@code refresh_token} from a successful token response (if present) and
         * stores it internally so it can be reused on subsequent authentications (kept up to date
         * across rotations), without any user configuration.
         */
        private void captureTokens(
                HttpMessage msg, GenericAuthenticationCredentials cred, User user) {
            try {
                JSONObject json = JSONObject.fromObject(msg.getResponseBody().toString());
                captureIfPresent(json, "refresh_token", cred, CREDENTIAL_PARAM_REFRESH_TOKEN);
                OAuth2TokenLifetime.fromResponse(json, Clock.systemUTC())
                        .ifPresentOrElse(
                                lifetime ->
                                        tokenExpiries.put(
                                                user.getId(), Instant.now().plus(lifetime)),
                                () -> tokenExpiries.remove(user.getId()));
            } catch (Exception e) {
                LOGGER.debug("Unable to capture OAuth2 tokens: {}", e.getMessage());
            }
        }

        private void captureIfPresent(
                JSONObject json,
                String fieldName,
                GenericAuthenticationCredentials cred,
                String credentialParamName) {
            if (json.has(fieldName)) {
                String value = json.getString(fieldName);
                if (StringUtils.isNotEmpty(value)) {
                    cred.setParam(credentialParamName, value);
                }
            }
        }

        private HttpMessage prepareTokenRequest(
                String effectiveGrantType,
                GenericAuthenticationCredentials cred,
                String refreshTokenOverride)
                throws Exception {
            Map<String, String> bodyParams = new LinkedHashMap<>();
            bodyParams.putAll(extraTokenParams);

            bodyParams.put("grant_type", effectiveGrantType);

            if (GRANT_TYPE_PASSWORD.equals(effectiveGrantType)) {
                bodyParams.put(CREDENTIAL_PARAM_USERNAME, cred.getParam(CREDENTIAL_PARAM_USERNAME));
                bodyParams.put(CREDENTIAL_PARAM_PASSWORD, cred.getParam(CREDENTIAL_PARAM_PASSWORD));
            } else if (GRANT_TYPE_REFRESH_TOKEN.equals(effectiveGrantType)) {
                bodyParams.put("refresh_token", refreshTokenOverride);
            }

            if (StringUtils.isNotEmpty(scope)) {
                bodyParams.put("scope", scope);
            }

            String authHeaderValue = applyClientAuthentication(bodyParams);

            HttpMessage msg = new HttpMessage();
            msg.setRequestHeader(
                    new HttpRequestHeader(
                            HttpRequestHeader.POST,
                            new URI(tokenEndpoint, true),
                            HttpHeader.HTTP11));
            msg.getRequestHeader()
                    .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
            if (authHeaderValue != null) {
                msg.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, authHeaderValue);
            }
            msg.getRequestBody().setBody(encodeFormBody(bodyParams));
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            return msg;
        }

        /**
         * Applies this method's configured client authentication to a token request: for {@link
         * #CLIENT_AUTH_POST}/{@link #CLIENT_AUTH_NONE} this adds {@code client_id}/{@code
         * client_secret} to {@code bodyParams}; otherwise (the default, {@link #CLIENT_AUTH_BASIC})
         * it returns the {@code Authorization: Basic ...} header value to set on the request
         * instead.
         *
         * @return the {@code Authorization} header value to set, or {@code null} if client
         *     authentication was folded into {@code bodyParams} instead (or there's no client ID).
         */
        private String applyClientAuthentication(Map<String, String> bodyParams) {
            if (StringUtils.isEmpty(clientId)) {
                return null;
            }
            if (CLIENT_AUTH_POST.equals(clientAuthMethod)) {
                bodyParams.put("client_id", clientId);
                if (StringUtils.isNotEmpty(clientSecret)) {
                    bodyParams.put("client_secret", clientSecret);
                }
                return null;
            } else if (CLIENT_AUTH_BASIC.equals(clientAuthMethod)) {
                return "Basic "
                        + Base64.getEncoder()
                                .encodeToString(
                                        (URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                                                        + ":"
                                                        + URLEncoder.encode(
                                                                StringUtils.defaultString(
                                                                        clientSecret),
                                                                StandardCharsets.UTF_8))
                                                .getBytes(StandardCharsets.UTF_8));
            } else if (CLIENT_AUTH_NONE.equals(clientAuthMethod)) {
                bodyParams.put("client_id", clientId);
                return null;
            }
            return null;
        }

        private String encodeFormBody(Map<String, String> params) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : params.entrySet()) {
                if (entry.getValue() == null) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                        .append('=')
                        .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
            return sb.toString();
        }

        /**
         * Rewrites the token response so that the access/refresh token are always available under
         * the canonical {@code access_token}/{@code refresh_token} JSON keys, regardless of the
         * field names actually used by the IdP, so that session management templating can always
         * rely on {@code \{%json:access_token%\}}/{@code \{%json:refresh_token%\}}.
         */
        private void normalizeTokenResponse(HttpMessage msg) {
            if (DEFAULT_ACCESS_TOKEN_FIELD.equals(accessTokenField)
                    && DEFAULT_REFRESH_TOKEN_FIELD.equals(refreshTokenField)) {
                return;
            }
            try {
                JSONObject json = JSONObject.fromObject(msg.getResponseBody().toString());
                copyIfPresent(json, accessTokenField, DEFAULT_ACCESS_TOKEN_FIELD);
                copyIfPresent(json, refreshTokenField, DEFAULT_REFRESH_TOKEN_FIELD);
                msg.getResponseBody().setBody(json.toString());
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            } catch (Exception e) {
                LOGGER.debug(
                        "Unable to normalize OAuth2 token response as JSON: {}", e.getMessage());
            }
        }

        private void copyIfPresent(JSONObject json, String fieldName, String canonicalName) {
            if (!canonicalName.equals(fieldName)
                    && json.has(fieldName)
                    && !json.has(canonicalName)) {
                json.put(canonicalName, json.get(fieldName));
            }
        }

        @Override
        public ApiResponse getApiResponseRepresentation() {
            Map<String, Object> values = new HashMap<>();
            values.put(PARAM_GRANT_TYPE, grantType);
            values.put(PARAM_TOKEN_ENDPOINT, tokenEndpoint);
            values.put(PARAM_CLIENT_ID, clientId);
            values.put(PARAM_CLIENT_AUTH_METHOD, clientAuthMethod);
            values.put(PARAM_SCOPE, scope);
            values.put(PARAM_ACCESS_TOKEN_FIELD, accessTokenField);
            values.put(PARAM_REFRESH_TOKEN_FIELD, refreshTokenField);
            values.put(PARAM_EXTRA_TOKEN_PARAMS, extraTokenParams);
            return new AuthMethodApiResponseRepresentation<>(values);
        }

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {
            user.processMessageToMatchAuthenticatedSession(msg);
        }
    }

    @Override
    public OAuth2AuthenticationMethod createAuthenticationMethod(int contextId) {
        return new OAuth2AuthenticationMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.oauth2.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new OAuth2AuthenticationMethodOptionsPanel();
    }

    @Override
    public boolean hasOptionsPanel() {
        return true;
    }

    @Override
    public AbstractCredentialsOptionsPanel<? extends AuthenticationCredentials>
            buildCredentialsOptionsPanel(
                    AuthenticationCredentials credentials, Context uiSharedContext) {
        return new OAuth2CredentialsOptionsPanel((GenericAuthenticationCredentials) credentials);
    }

    @Override
    public boolean hasCredentialsOptionsPanel() {
        return true;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod method) {
        return method instanceof OAuth2AuthenticationMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {}

    @Override
    public AuthenticationMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        OAuth2AuthenticationMethod method = createAuthenticationMethod(contextId);
        Map<String, String> map =
                EncodingUtils.stringToMap(
                        session.getContextDataString(
                                contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""));

        method.setGrantType(map.get(PARAM_GRANT_TYPE));
        method.setTokenEndpoint(map.get(PARAM_TOKEN_ENDPOINT));
        method.setClientId(map.get(PARAM_CLIENT_ID));
        method.setClientSecret(map.get(PARAM_CLIENT_SECRET));
        method.setClientAuthMethod(map.get(PARAM_CLIENT_AUTH_METHOD));
        method.setScope(map.get(PARAM_SCOPE));
        method.setAccessTokenField(map.get(PARAM_ACCESS_TOKEN_FIELD));
        method.setRefreshTokenField(map.get(PARAM_REFRESH_TOKEN_FIELD));
        method.setExtraTokenParams(extractExtraParams(map));

        return method;
    }

    private static final String EXTRA_PARAM_PREFIX = "extra:";

    private static Map<String, String> extractExtraParams(Map<String, String> map) {
        Map<String, String> extraParams = new LinkedHashMap<>();
        map.forEach(
                (key, value) -> {
                    if (key.startsWith(EXTRA_PARAM_PREFIX)) {
                        extraParams.put(key.substring(EXTRA_PARAM_PREFIX.length()), value);
                    }
                });
        return extraParams;
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authMethod)
            throws DatabaseException {
        if (!(authMethod instanceof OAuth2AuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "OAuth2 authentication type only supports: "
                            + OAuth2AuthenticationMethod.class);
        }

        OAuth2AuthenticationMethod method = (OAuth2AuthenticationMethod) authMethod;
        Map<String, String> map = new LinkedHashMap<>();
        map.put(PARAM_GRANT_TYPE, method.grantType);
        map.put(PARAM_TOKEN_ENDPOINT, method.tokenEndpoint);
        map.put(PARAM_CLIENT_ID, method.clientId);
        map.put(PARAM_CLIENT_SECRET, method.clientSecret);
        map.put(PARAM_CLIENT_AUTH_METHOD, method.clientAuthMethod);
        map.put(PARAM_SCOPE, method.scope);
        map.put(PARAM_ACCESS_TOKEN_FIELD, method.accessTokenField);
        map.put(PARAM_REFRESH_TOKEN_FIELD, method.refreshTokenField);
        method.extraTokenParams.forEach((k, v) -> map.put(EXTRA_PARAM_PREFIX + k, v));

        session.setContextData(
                contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, EncodingUtils.mapToString(map));
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof OAuth2AuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "OAuth2 authentication type only supports: "
                            + OAuth2AuthenticationMethod.class);
        }

        OAuth2AuthenticationMethod method = (OAuth2AuthenticationMethod) authMethod;
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_GRANT_TYPE, method.grantType);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_TOKEN_ENDPOINT, method.tokenEndpoint);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_ID, method.clientId);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_SECRET, method.clientSecret);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_AUTH_METHOD, method.clientAuthMethod);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_SCOPE, method.scope);
        config.setProperty(CONTEXT_CONFIG_AUTH_OAUTH2_ACCESS_TOKEN_FIELD, method.accessTokenField);
        config.setProperty(
                CONTEXT_CONFIG_AUTH_OAUTH2_REFRESH_TOKEN_FIELD, method.refreshTokenField);

        config.setProperty(
                CONTEXT_CONFIG_AUTH_OAUTH2_EXTRA_PARAM,
                EncodingUtils.mapToString(method.extraTokenParams));
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof OAuth2AuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "OAuth2 authentication type only supports: "
                            + OAuth2AuthenticationMethod.class);
        }

        OAuth2AuthenticationMethod method = (OAuth2AuthenticationMethod) authMethod;
        try {
            method.setGrantType(config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_GRANT_TYPE));
            method.setTokenEndpoint(config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_TOKEN_ENDPOINT));
            method.setClientId(config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_ID));
            method.setClientSecret(config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_SECRET));
            method.setClientAuthMethod(
                    config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_CLIENT_AUTH_METHOD));
            method.setScope(config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_SCOPE));
            method.setAccessTokenField(
                    config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_ACCESS_TOKEN_FIELD));
            method.setRefreshTokenField(
                    config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_REFRESH_TOKEN_FIELD));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }

        try {
            method.setExtraTokenParams(
                    EncodingUtils.stringToMap(
                            config.getString(CONTEXT_CONFIG_AUTH_OAUTH2_EXTRA_PARAM, "")));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    @Override
    public GenericAuthenticationCredentials createAuthenticationCredentials() {
        return new GenericAuthenticationCredentials(CREDENTIAL_PARAM_NAMES);
    }

    @Override
    public Class<GenericAuthenticationCredentials> getAuthenticationCredentialsType() {
        return GenericAuthenticationCredentials.class;
    }

    private static Map<String, String> parseKeyValueLines(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (StringUtils.isEmpty(text)) {
            return map;
        }
        for (String line : text.split("\n")) {
            int colonIndex = line.indexOf(":");
            if (colonIndex > 0) {
                map.put(
                        line.substring(0, colonIndex).trim(),
                        line.substring(colonIndex + 1).trim());
            }
        }
        return map;
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        String[] mandatoryParamNames = new String[] {PARAM_GRANT_TYPE, PARAM_TOKEN_ENDPOINT};
        String[] optionalParamNames =
                new String[] {
                    PARAM_CLIENT_ID,
                    PARAM_CLIENT_SECRET,
                    PARAM_CLIENT_AUTH_METHOD,
                    PARAM_SCOPE,
                    PARAM_ACCESS_TOKEN_FIELD,
                    PARAM_REFRESH_TOKEN_FIELD,
                    PARAM_EXTRA_TOKEN_PARAMS
                };
        return new ApiDynamicActionImplementor(
                API_METHOD_NAME, mandatoryParamNames, optionalParamNames) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, AuthenticationAPI.PARAM_CONTEXT_ID);

                OAuth2AuthenticationMethod method = createAuthenticationMethod(context.getId());
                try {
                    method.setGrantType(ApiUtils.getNonEmptyStringParam(params, PARAM_GRANT_TYPE));
                    method.setTokenEndpoint(
                            ApiUtils.getNonEmptyStringParam(params, PARAM_TOKEN_ENDPOINT));
                    method.setClientId(ApiUtils.getOptionalStringParam(params, PARAM_CLIENT_ID));
                    method.setClientSecret(
                            ApiUtils.getOptionalStringParam(params, PARAM_CLIENT_SECRET));

                    String clientAuthMethod =
                            ApiUtils.getOptionalStringParam(params, PARAM_CLIENT_AUTH_METHOD);
                    if (!StringUtils.isEmpty(clientAuthMethod)) {
                        method.setClientAuthMethod(clientAuthMethod);
                    }

                    method.setScope(ApiUtils.getOptionalStringParam(params, PARAM_SCOPE));

                    String accessTokenField =
                            ApiUtils.getOptionalStringParam(params, PARAM_ACCESS_TOKEN_FIELD);
                    if (!StringUtils.isEmpty(accessTokenField)) {
                        method.setAccessTokenField(accessTokenField);
                    }

                    String refreshTokenField =
                            ApiUtils.getOptionalStringParam(params, PARAM_REFRESH_TOKEN_FIELD);
                    if (!StringUtils.isEmpty(refreshTokenField)) {
                        method.setRefreshTokenField(refreshTokenField);
                    }

                    method.setExtraTokenParams(
                            parseKeyValueLines(
                                    ApiUtils.getOptionalStringParam(
                                            params, PARAM_EXTRA_TOKEN_PARAMS)));
                } catch (ApiException e) {
                    throw e;
                } catch (Exception e) {
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
                }

                context.setAuthenticationMethod(method);
            }
        };
    }

    @Override
    public ApiDynamicActionImplementor getSetCredentialsForUserApiAction() {
        return new ApiDynamicActionImplementor(
                ACTION_SET_CREDENTIALS, null, List.of(CREDENTIAL_PARAM_NAMES)) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context = ApiUtils.getContextByParamId(params, UsersAPI.PARAM_CONTEXT_ID);
                int userId = ApiUtils.getIntParam(params, UsersAPI.PARAM_USER_ID);
                if (!isTypeForMethod(context.getAuthenticationMethod())) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "User's credentials should match authentication method type of the"
                                    + " context: "
                                    + context.getAuthenticationMethod().getType().getName());
                }

                ExtensionUserManagement extensionUserManagement =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionUserManagement.class);
                User user =
                        extensionUserManagement
                                .getContextUserAuthManager(context.getId())
                                .getUserById(userId);
                if (user == null) {
                    throw new ApiException(
                            ApiException.Type.USER_NOT_FOUND, UsersAPI.PARAM_USER_ID);
                }

                GenericAuthenticationCredentials credentials =
                        (GenericAuthenticationCredentials)
                                context.getAuthenticationMethod().createAuthenticationCredentials();
                for (String paramName : CREDENTIAL_PARAM_NAMES) {
                    String value = ApiUtils.getOptionalStringParam(params, paramName);
                    if (!StringUtils.isEmpty(value)) {
                        credentials.setParam(paramName, value);
                    }
                }
                user.setAuthenticationCredentials(credentials);
            }
        };
    }

    /** The Options Panel used for configuring an {@link OAuth2AuthenticationMethod}. */
    @SuppressWarnings("serial")
    protected class OAuth2AuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 1L;
        private OAuth2AuthenticationMethod authenticationMethod;

        private JComboBox<String> grantTypeCombo;
        private ZapTextField tokenEndpointField;
        private ZapTextField clientIdField;
        private JPasswordField clientSecretField;
        private JComboBox<String> clientAuthMethodCombo;
        private ZapTextField scopeField;
        private ZapTextField accessTokenFieldField;
        private ZapTextField refreshTokenFieldField;
        private ExtraParamsPanel extraParamsPanel;
        private JCheckBox diagnosticsCheckBox;

        public OAuth2AuthenticationMethodOptionsPanel() {
            this.setLayout(new GridBagLayout());

            int y = 0;

            grantTypeCombo =
                    new JComboBox<>(
                            new String[] {GRANT_TYPE_CLIENT_CREDENTIALS, GRANT_TYPE_PASSWORD});
            addRow("authhelper.auth.method.oauth2.label.grantType", grantTypeCombo, y++);

            tokenEndpointField = new ZapTextField();
            addRow("authhelper.auth.method.oauth2.label.tokenEndpoint", tokenEndpointField, y++);

            clientIdField = new ZapTextField();
            addRow("authhelper.auth.method.oauth2.label.clientId", clientIdField, y++);

            clientSecretField = new JPasswordField();
            addRow("authhelper.auth.method.oauth2.label.clientSecret", clientSecretField, y++);

            clientAuthMethodCombo =
                    new JComboBox<>(
                            new String[] {CLIENT_AUTH_BASIC, CLIENT_AUTH_POST, CLIENT_AUTH_NONE});
            addRow(
                    "authhelper.auth.method.oauth2.label.clientAuthMethod",
                    clientAuthMethodCombo,
                    y++);

            scopeField = new ZapTextField();
            addRow("authhelper.auth.method.oauth2.label.scope", scopeField, y++);

            accessTokenFieldField = new ZapTextField();
            addRow(
                    "authhelper.auth.method.oauth2.label.accessTokenField",
                    accessTokenFieldField,
                    y++);

            refreshTokenFieldField = new ZapTextField();
            addRow(
                    "authhelper.auth.method.oauth2.label.refreshTokenField",
                    refreshTokenFieldField,
                    y++);

            extraParamsPanel = new ExtraParamsPanel(View.getSingleton().getSessionDialog());
            this.add(extraParamsPanel.getPanel(), LayoutHelper.getGBC(0, y++, 2, 1.0d, 0.0d));

            diagnosticsCheckBox = new JCheckBox();
            addRow("authhelper.auth.method.oauth2.label.diagnostics", diagnosticsCheckBox, y++);
        }

        private void addRow(String labelKey, JComponent field, int y) {
            JLabel label = new JLabel(Constant.messages.getString(labelKey));
            label.setLabelFor(field);
            this.add(label, LayoutHelper.getGBC(0, y, 1, 0.0d, 0.0d));
            this.add(field, LayoutHelper.getGBC(1, y, 1, 1.0d, 0.0d));
        }

        @Override
        public void validateFields() throws IllegalStateException {
            if (StringUtils.isEmpty(tokenEndpointField.getText())) {
                tokenEndpointField.requestFocusInWindow();
                throw new IllegalStateException(
                        Constant.messages.getString(
                                "authhelper.auth.method.oauth2.dialog.error.tokenEndpoint"));
            }
        }

        @Override
        public void saveMethod() {
            getMethod().setGrantType((String) grantTypeCombo.getSelectedItem());
            getMethod().setTokenEndpoint(tokenEndpointField.getText());
            getMethod().setClientId(clientIdField.getText());
            getMethod().setClientSecret(new String(clientSecretField.getPassword()));
            getMethod().setClientAuthMethod((String) clientAuthMethodCombo.getSelectedItem());
            getMethod().setScope(scopeField.getText());
            getMethod().setAccessTokenField(accessTokenFieldField.getText());
            getMethod().setRefreshTokenField(refreshTokenFieldField.getText());
            getMethod().setExtraTokenParams(extraParamsPanel.getParams());
            getMethod().setDiagnostics(diagnosticsCheckBox.isSelected());
        }

        @Override
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            this.authenticationMethod = (OAuth2AuthenticationMethod) method;
            grantTypeCombo.setSelectedItem(authenticationMethod.getGrantType());
            tokenEndpointField.setText(authenticationMethod.getTokenEndpoint());
            clientIdField.setText(authenticationMethod.getClientId());
            clientSecretField.setText(authenticationMethod.getClientSecret());
            clientAuthMethodCombo.setSelectedItem(authenticationMethod.getClientAuthMethod());
            scopeField.setText(authenticationMethod.getScope());
            accessTokenFieldField.setText(authenticationMethod.getAccessTokenField());
            refreshTokenFieldField.setText(authenticationMethod.getRefreshTokenField());
            extraParamsPanel.setParams(authenticationMethod.getExtraTokenParams());
            diagnosticsCheckBox.setSelected(authenticationMethod.isDiagnostics());
        }

        @Override
        public OAuth2AuthenticationMethod getMethod() {
            return this.authenticationMethod;
        }
    }

    /** The Options Panel used for configuring the credentials of an {@link User}. */
    @SuppressWarnings("serial")
    protected static class OAuth2CredentialsOptionsPanel
            extends AbstractCredentialsOptionsPanel<GenericAuthenticationCredentials> {

        private static final long serialVersionUID = 1L;
        private final DynamicFieldsPanel fieldsPanel;

        public OAuth2CredentialsOptionsPanel(GenericAuthenticationCredentials credentials) {
            super(credentials);
            this.setLayout(new BorderLayout());

            fieldsPanel = new DynamicFieldsPanel(new String[0], CREDENTIAL_PARAM_NAMES);
            Map<String, String> values = new HashMap<>();
            for (String paramName : CREDENTIAL_PARAM_NAMES) {
                values.put(paramName, credentials.getParam(paramName));
            }
            fieldsPanel.bindFieldValues(values);
            add(fieldsPanel);
        }

        @Override
        public boolean validateFields() {
            try {
                fieldsPanel.validateFields();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                        this,
                        e.getMessage(),
                        Constant.messages.getString("authentication.method.fb.dialog.error.title"),
                        JOptionPane.WARNING_MESSAGE);
                return false;
            }
            return true;
        }

        @Override
        public void saveCredentials() {
            Map<String, String> values = fieldsPanel.getFieldValues();
            values.forEach(credentials::setParam);
        }
    }

    /*
     * Copied from org.zaproxy.zap.authentication.AuthenticationMethod
     */
    static class AuthMethodApiResponseRepresentation<T> extends ApiResponseSet<T> {

        public AuthMethodApiResponseRepresentation(Map<String, T> values) {
            super("method", values);
        }

        @Override
        public JSON toJSON() {
            JSONObject response = new JSONObject();
            response.put(getName(), super.toJSON());
            return response;
        }
    }
}
