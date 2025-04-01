/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.apache.commons.text.StringEscapeUtils.escapeXml10;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/** Unit test for {@link SqlInjectionScanRule}. */
class SqlInjectionScanRuleUnitTest extends ActiveScannerTest<SqlInjectionScanRule> {

    static final String[] ALL_SQL_ERRORS = {
        "You have an error in your SQL syntax",
        "com.mysql.jdbc.exceptions",
        "org.gjt.mm.mysql",
        "ODBC driver does not support",
        "The used SELECT statements have a different number of columns",
        "You have an error in your SQL syntax",
        "The used SELECT statements have a different number of columns",
        "com.microsoft.sqlserver.jdbc",
        "com.microsoft.jdbc",
        "com.inet.tds",
        "com.microsoft.sqlserver.jdbc",
        "com.ashna.jturbo",
        "weblogic.jdbc.mssqlserver",
        "[Microsoft]",
        "[SQLServer]",
        "[SQLServer 2000 Driver for JDBC]",
        "net.sourceforge.jtds.jdbc",
        "80040e14",
        "800a0bcd",
        "80040e57",
        "ODBC driver does not support",
        "All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists",
        "All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists",
        "oracle.jdbc",
        "SQLSTATE[HY",
        "ORA-00933",
        "ORA-06512",
        "SQL command not properly ended",
        "ORA-00942",
        "ORA-29257",
        "ORA-00932",
        "query block has incorrect number of result columns",
        "ORA-01789",
        "org.postgresql.util.PSQLException",
        "org.postgresql",
        "each UNION query must have the same number of columns",
        "com.sybase.jdbc",
        "net.sourceforge.jtds.jdbc",
    };

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 24;
            case INSANE:
                return recommendMax + 7;
        }
    }

    @Override
    protected SqlInjectionScanRule createScanner() {
        return new SqlInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(89)));
        assertThat(wasc, is(equalTo(19)));
        assertThat(tags.size(), is(equalTo(10)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getValue())));
    }

    @Test
    void shouldTargetDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetOracleDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Oracle);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetJustNoSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldTargetNoSqlPlusMsSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.MsSQL, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechs() {
        // Given
        TechSet techSet = techSet(techsOf(Tech.Db));
        techSet.exclude(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechsWithNonBuiltInTechInstances() {
        // Given
        TechSet techSet = techSet(new Tech(new Tech("Db"), "SomeDb"));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonDbTechs() {
        // Given
        TechSet techSet = techSetWithout(techsOf(Tech.Db));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.SUM, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessfulAndIsReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.SUM,
                        true,
                        ExpressionBasedHandler.Expression.SUM.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.MULT, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessfulAndReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.MULT,
                        true,
                        ExpressionBasedHandler.Expression.MULT.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    static final List<Function<String, String>> ENCODING_FUNCTIONS =
            List.of(
                    SqlInjectionScanRule::getURLEncode,
                    SqlInjectionScanRule::getHTMLEncode,
                    s -> SqlInjectionScanRule.getHTMLEncode(SqlInjectionScanRule.getURLEncode(s)),
                    StringEscapeUtils::escapeXml10,
                    s -> s // Make sure to test for no encoding as well
                    );

    static Stream<Function<String, String>> reflectionEncodings() {
        return ENCODING_FUNCTIONS.stream();
    }

    @Nested
    class BooleanBasedSqlInjection {

        @Test
        void shouldAlertAndTrueMatchesAndFalseDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse("different response"))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldAlertAndTrueMatchesAndFalseMatchesOrTrueDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String ORTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse("normal response"))
                            .whenParamValueIs(ORTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldNotAlertAndTrueMatchesAndFalseMatchesOrTrueMatches() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String orTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(orTrueValue)
                            .thenReturnHtml("normal response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertAndTrueDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.zap.extension.ascanrules.SqlInjectionScanRuleUnitTest#reflectionEncodings")
        void shouldAlertEncodedPayloadReflected(Function<String, String> encodingFunction)
                throws Exception {
            String param = "param";
            String normalValue = "<a>%test"; // Includes characters that will be encoded
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue)))
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue))
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldAlertValueReflectedMultipleTimesAndWithDifferentEncodings() throws Exception {
            // Given
            String param = "param";
            String normalValue = "<a>%test"; // Includes characters that will be encoded
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(escapeXml10(andTrueValue), 4))
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(
                                                    AbstractPlugin.getURLEncode(andFalseValue), 2)
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldNotAlertResponseIsSameForAllParameterOriginalParameterIsAlwaysInResponse()
                throws Exception {
            // Given
            String param = "param";
            String normalValue = "normal";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String ORTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue) + normalValue)
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(constructReflectedResponse(andTrueValue) + normalValue)
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse(andFalseValue) + normalValue)
                            .whenParamValueIs(ORTrueValue)
                            .thenReturnHtml(constructReflectedResponse(ORTrueValue) + normalValue)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        private UrlParamValueHandler getLikeTestHandler(String normalValue) {
            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            String param = "param";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LIKE;
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LIKE_SAFE;
            return UrlParamValueHandler.builder()
                    .targetParam(param)
                    .whenParamValueIs(normalValue)
                    .thenReturnHtml(constructReflectedResponse(normalValue))
                    .whenParamValueIs(andTrueValue)
                    .thenReturnHtml(constructReflectedResponse(andTrueValue))
                    .whenParamValueIs(andFalseValue)
                    .thenReturnHtml(constructReflectedResponse("different from normal and ANDTrue"))
                    .build();
        }

        @Test
        void shouldNotAlertLikeAttacksStrengthMedium() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.MEDIUM);
            String normalValue = "payload";
            nano.addHandler(getLikeTestHandler(normalValue));
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlertLikeAttacksStrengthHigh() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.HIGH);
            String param = "param";
            String normalValue = "payload";

            nano.addHandler(getLikeTestHandler(normalValue));
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(
                    actual.getAttack(), is(equalTo(normalValue + SqlInjectionScanRule.SQL_LIKE)));
        }

        /** Build a short response that contains the payload reflected in some text */
        private String constructReflectedResponse(String payload) {
            return constructReflectedResponse(payload, 1);
        }

        private String constructReflectedResponse(String payload, int reflectionCount) {
            return "foo " + StringUtils.repeat(payload, reflectionCount) + " foo ";
        }

        @Test
        void shouldAlertByBodyComparisonIgnoringXmlEscapedPayload() throws Exception {
            // Given
            String param = "topic";
            String normalPayload = "cats";
            String attackPayload = "cats' AND '1'='1' -- ";
            String verificationPayload = "cats' AND '1'='2' -- ";
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalPayload)
                            .thenReturnHtml(normalPayload + ": A")
                            .whenParamValueIs(attackPayload)
                            .thenReturnHtml(escapeXml10(attackPayload + ": A"))
                            .whenParamValueIs(verificationPayload)
                            .thenReturnHtml(escapeXml10(verificationPayload + ": "))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?topic=" + normalPayload), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(attackPayload)));
        }
    }

    @Nested
    class ErrorBasedSqlInjection {

        static List<String> allSqlErrors() {
            return Arrays.asList(ALL_SQL_ERRORS);
        }

        @ParameterizedTest
        @MethodSource("allSqlErrors")
        void shouldAlertEmptyPrefix(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String emptyPrefixErrorValue = SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(emptyPrefixErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
        }

        @ParameterizedTest
        @MethodSource("allSqlErrors")
        void shouldAlertOriginalParamPrefix(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
        }

        @Test
        void shouldNotAlertNonSqlMessage() throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("Not a SQL error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlertGenericRdbmsErrorOnLowThreshold() throws Exception {
            // Given
            rule.setAlertThreshold(AlertThreshold.LOW);
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("java.sql.SQLException")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }
    }

    @Nested
    class UnionBasedSqlInjection {

        private UrlParamValueHandler serverWithRdbmsError() {
            String param = "param";
            String normalValue = "test";
            String unionValueString =
                    normalValue
                            + SqlInjectionScanRule.SQL_UNION_SELECT
                            + SqlInjectionScanRule.SQL_ONE_LINE_COMMENT;

            return UrlParamValueHandler.builder()
                    .targetParam(param)
                    .whenParamValueIs(param)
                    .thenReturnHtml(normalValue)
                    .whenParamValueIs(unionValueString)
                    .thenReturnHtml("You have an error in your SQL syntax")
                    .build();
        }

        @Test
        void shouldAlertRdbmsErrorMessage() throws Exception {
            // Given
            nano.addHandler(serverWithRdbmsError());
            rule.init(getHttpMessage("/?param=test"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }

        @Test
        void shouldNotRunStrengthLow() throws Exception {
            // Given
            nano.addHandler(serverWithRdbmsError());
            rule.setAttackStrength(AttackStrength.LOW);
            rule.init(getHttpMessage("/?param=test"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertNonErrorMessageResponse() throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String unionValueString =
                    normalValue
                            + SqlInjectionScanRule.SQL_UNION_SELECT
                            + SqlInjectionScanRule.SQL_ONE_LINE_COMMENT;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(unionValueString)
                            .thenReturnHtml("This is not a sql error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    @Nested
    class FiveHundredErrors {

        private Response error500Response() {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.INTERNAL_ERROR,
                    NanoHTTPD.MIME_HTML,
                    "500 error handling request");
        }

        @Test
        void shouldAlertIf500OnSingleQuote() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            String value = getFirstParamValue(session, param);
                            if (StringUtils.countMatches(value, "'") == 1) {
                                return error500Response();
                            }
                            String response = "<html><body></body></html>";
                            return newFixedLengthResponse(response);
                        }
                    });

            rule.init(getHttpMessage("/?" + param + "=test"), parent);
            // When
            rule.scan();
            // Then
            assertThat(httpMessagesSent, hasSize(equalTo(2)));
            assertThat(alertsRaised, hasSize(1));
            assertThat(
                    alertsRaised.get(0).getEvidence(),
                    is(equalTo("HTTP/1.1 500 Internal Server Error")));
            assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
            assertThat(alertsRaised.get(0).getAttack(), is(equalTo("'")));
            assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
            assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        }

        @Test
        void shouldNotAlertIfAlways500() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            return error500Response();
                        }
                    });

            HttpMessage msg = getHttpMessage("/?" + param + "=test");
            msg.getResponseHeader().setStatusCode(500);
            msg.getResponseHeader().setReasonPhrase("Internal Server Error");

            rule.init(msg, parent);
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertIfInvalidValuesResultIn500() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            String value = getFirstParamValue(session, param);
                            if ("test".equals(value)) {
                                return newFixedLengthResponse("<html><body></body></html>");
                            }
                            return error500Response();
                        }
                    });

            HttpMessage msg = getHttpMessage("/?" + param + "=test");

            rule.init(msg, parent);
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    private static class ExpressionBasedHandler extends NanoServerHandler {

        public enum Expression {
            SUM("1", "3-2", "4-2"),
            MULT("1", "2/2", "4/2");

            private final String value;
            private final String baseExpression;
            private final String confirmationExpression;

            Expression(String value, String expression, String confirmationExpression) {
                this.value = value;
                this.baseExpression = expression;
                this.confirmationExpression = confirmationExpression;
            }
        }

        private final String param;
        private final Expression expression;
        private final boolean confirmationFails;
        private String contentAddition = "";

        public ExpressionBasedHandler(String path, String param, Expression expression) {
            this(path, param, expression, false);
        }

        public ExpressionBasedHandler(
                String path, String param, Expression expression, boolean confirmationFails) {
            super(path);

            this.param = param;
            this.expression = expression;
            this.confirmationFails = confirmationFails;
        }

        public ExpressionBasedHandler(
                String parth,
                String param,
                Expression expression,
                boolean confirmationFails,
                String contentAddition) {
            this(parth, param, expression, confirmationFails);
            this.contentAddition = contentAddition;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (isValidValue(value)) {
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(value));
            }
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
        }

        private boolean isValidValue(String value) {
            if (confirmationFails && expression.confirmationExpression.equals(value)) {
                return true;
            }
            return expression.value.equals(value) || expression.baseExpression.equals(value);
        }

        protected String getContent(String value) {
            return "Some Content " + contentAddition;
        }
    }
}
