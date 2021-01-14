/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.net.MalformedURLException;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class SpiderJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionSpider extSpider;

    @BeforeAll
    public static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    public static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    public void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extSpider = mock(ExtensionSpider.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionSpider.class)).willReturn(extSpider);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    public void shouldReturnDefaultFields() {
        // Given

        // When
        SpiderJob job = new SpiderJob();

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getName(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));
    }

    @Test
    public void shouldReturnCustomConfigParams() {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(2)));
        assertThat(params.get("failIfFoundUrlsLessThan"), is(equalTo("0")));
        assertThat(params.get("warnIfFoundUrlsLessThan"), is(equalTo("0")));
    }

    @Test
    public void shouldApplyCustomConfigParams() {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "10");
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "11");
        job.applyCustomParameter("maxDuration", "12");

        // Then
        assertThat(job.getFailIfFoundUrlsLessThan(), is(equalTo(10)));
        assertThat(job.getWarnIfFoundUrlsLessThan(), is(equalTo(11)));
        assertThat(job.getMaxDuration(), is(equalTo(12)));
    }

    @Test
    public void shouldRunValidJob() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        // When
        SpiderJob job = new SpiderJob();
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    public void shouldExitIfSpiderTakesTooLong() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(false);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("maxDuration", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    public void shouldWarnIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    public void shouldErrorIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
    }
}
