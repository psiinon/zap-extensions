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
package org.zaproxy.addon.dev;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for resetting the state of the test directories and pages. */
class TestStateResetUnitTest {

    @Test
    void shouldResetSubDirectoriesAndPages() {
        // Given
        TestProxyServer server = mock(TestProxyServer.class);
        List<String> resets = new ArrayList<>();
        TestDirectory root = recordingDir(server, "root", resets);
        TestDirectory sub = recordingDir(server, "sub", resets);
        TestDirectory subSub = recordingDir(server, "subSub", resets);
        root.addDirectory(sub);
        sub.addDirectory(subSub);
        root.addPage(recordingPage(server, "rootPage", resets));
        subSub.addPage(recordingPage(server, "subSubPage", resets));

        // When
        root.reset();

        // Then
        assertThat(resets.size(), is(equalTo(5)));
        assertThat(
                resets.containsAll(
                        List.of("root", "sub", "subSub", "page:rootPage", "page:subSubPage")),
                is(equalTo(true)));
    }

    @Test
    void shouldForgetAuthSessionsWhenReset() {
        // Given
        TestAuthDirectory dir = new TestAuthDirectory(mock(TestProxyServer.class), "auth") {};
        String token = dir.getToken("test@test.com");
        assertThat(dir.getUser(token), is(equalTo("test@test.com")));

        // When
        dir.reset();

        // Then
        assertThat(dir.getUser(token), is(nullValue()));
    }

    /**
     * Every collection the directories and pages keep must be emptied by {@code reset()}, or what
     * happened in an earlier ZAP session would affect the next. A new directory, or page, with
     * state needs adding here.
     */
    @ParameterizedTest
    @ValueSource(
            strings = {
                "org.zaproxy.addon.dev.auth.sso1.SSO1RootDir",
                "org.zaproxy.addon.dev.auth.sso2.SSO2RootDir",
                "org.zaproxy.addon.dev.auth.ssoMs.SSOMSRootDir",
                "org.zaproxy.addon.dev.auth.ssoMsPopup.SSOMSPopupRootDir",
                "org.zaproxy.addon.dev.auth.uuidLogin.UuidLoginRootDir",
                "org.zaproxy.addon.dev.auth.jsonMultipleCookies.JsonMultipleCookiesDir",
                "org.zaproxy.addon.dev.auth.simpleJsonBearerDiffCookies.SimpleJsonBearerDiffCookiesDir",
                "org.zaproxy.addon.dev.auth.oauth2.OAuth2RootDir",
                "org.zaproxy.addon.dev.seq.performance.SequencePage"
            })
    void shouldEmptyAllCollectionsWhenReset(String className) throws Exception {
        // Given
        Object instance = newInstance(Class.forName(className));
        List<Collection<Object>> collections = new ArrayList<>();
        List<Map<Object, Object>> maps = new ArrayList<>();
        for (Field field : stateFields(instance.getClass())) {
            field.setAccessible(true);
            Object value = field.get(instance);
            if (value instanceof Collection<?> collection) {
                @SuppressWarnings("unchecked")
                Collection<Object> objects = (Collection<Object>) collection;
                objects.add("state");
                collections.add(objects);
            } else if (value instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<Object, Object> objects = (Map<Object, Object>) map;
                objects.put("key", "state");
                maps.add(objects);
            }
        }
        assertThat(
                "No state found to reset, is the test out of date?",
                !collections.isEmpty() || !maps.isEmpty(),
                is(equalTo(true)));

        // When
        if (instance instanceof TestDirectory dir) {
            dir.reset();
        } else {
            ((TestPage) instance).reset();
        }

        // Then
        collections.forEach(collection -> assertThat(collection.isEmpty(), is(equalTo(true))));
        maps.forEach(map -> assertThat(map.isEmpty(), is(equalTo(true))));
    }

    /** The fields of the class and its super classes, down to (not including) the base classes. */
    private static List<Field> stateFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        for (Class<?> c = clazz;
                c != null && c != TestDirectory.class && c != TestPage.class && c != Object.class;
                c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers())) {
                    fields.add(field);
                }
            }
        }
        return fields;
    }

    private static Object newInstance(Class<?> clazz) throws Exception {
        TestProxyServer server = mock(TestProxyServer.class);
        for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
            Class<?>[] types = constructor.getParameterTypes();
            if (types.length == 2 && types[0] == TestProxyServer.class) {
                return constructor.newInstance(server, "name");
            }
            if (types.length == 1 && types[0] == TestProxyServer.class) {
                return constructor.newInstance(server);
            }
        }
        throw new IllegalStateException("No suitable constructor: " + clazz);
    }

    private static TestDirectory recordingDir(
            TestProxyServer server, String name, List<String> resets) {
        return new TestDirectory(server, name) {
            @Override
            public void reset() {
                super.reset();
                resets.add(name);
            }
        };
    }

    private static TestPage recordingPage(
            TestProxyServer server, String name, List<String> resets) {
        return new TestPage(server, name) {
            @Override
            public void reset() {
                resets.add("page:" + name);
            }

            @Override
            public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
                // Not used.
            }
        };
    }
}
