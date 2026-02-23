/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.domxss;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.ElementNotInteractableException;
import org.openqa.selenium.NoSuchSessionException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.remote.UnreachableBrowserException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.Stats;

/**
 * Shared DOM XSS scanning logic. Performs the browser-based checks (load URL, interact with inputs
 * and elements, detect alert) that can be used by both the traditional DomXssScanRule and the
 * client map-based DomXssClientScanRule.
 */
public final class DomXssScanLogic {

    private static final Logger LOGGER = LogManager.getLogger(DomXssScanLogic.class);

    public static final int UNLIKELY_INT = 5397;
    static final String UNLIKELY_STR = String.valueOf(UNLIKELY_INT);

    private DomXssScanLogic() {}

    static void getHelper(WebDriver driver, String url, List<String> steps) {
        getHelper(driver, url, steps, 3);
    }

    static void getHelper(WebDriver driver, String url, List<String> steps, int retry) {
        try {
            Stats.incCounter("domxss.gets.count");
            steps.add(Constant.messages.getString("domxss.step.access", url));
            driver.get(url);
        } catch (UnhandledAlertException uae) {
            throw uae;
        } catch (NoSuchSessionException enve) {
            sleep(1000);
            if (retry >= 0) {
                getHelper(driver, url, steps, retry - 1);
            }
        } catch (UnreachableBrowserException ube) {
            sleep(1000);
            if (retry >= 0) {
                getHelper(driver, url, steps, retry - 1);
            }
        } catch (ElementNotInteractableException enve) {
            LOGGER.debug(enve);
        } catch (TimeoutException wde) {
            LOGGER.debug(wde);
        } catch (WebDriverException wde) {
            LOGGER.debug(wde);
        }
    }

    static List<WebElement> findHelper(WebDriver driver, By by) {
        return findHelper(driver, by, 3);
    }

    static List<WebElement> findHelper(WebDriver driver, By by, int retry) {
        try {
            Stats.incCounter("domxss.gets.count");
            return driver.findElements(by);
        } catch (UnhandledAlertException uae) {
            throw uae;
        } catch (NoSuchSessionException enve) {
            sleep(1000);
            if (retry >= 0) {
                return findHelper(driver, by, retry - 1);
            }
        } catch (UnreachableBrowserException ube) {
            sleep(1000);
            if (retry >= 0) {
                return findHelper(driver, by, retry - 1);
            }
        } catch (ElementNotInteractableException enve) {
            LOGGER.debug(enve);
        } catch (TimeoutException wde) {
            LOGGER.debug(wde);
        } catch (WebDriverException wde) {
            LOGGER.debug(wde);
        }
        return new ArrayList<>();
    }

    static String getAlertDialogText(WebDriver driver) {
        try {
            org.openqa.selenium.Alert alertDialog = driver.switchTo().alert();
            String dialogText = alertDialog.getText();
            alertDialog.accept();
            return dialogText;
        } catch (WebDriverException wde) {
            return "";
        }
    }

    static String getXPath(WebElement element) {
        StringBuilder strBuilder = new StringBuilder(100);
        try {
            insertXPath(element, strBuilder);
        } catch (Exception e) {
            LOGGER.debug("Failed to obtain full XPath: {}", e.getMessage());
            strBuilder.insert(0, Constant.messages.getString("domxss.step.partial.xpath"));
        }
        return strBuilder.toString();
    }

    private static void insertXPath(WebElement element, StringBuilder path) {
        String tag = element.getTagName();
        if ("html".equalsIgnoreCase(tag)) {
            insertTag(path, tag);
            return;
        }
        WebElement parent = element.findElement(By.xpath(".."));
        List<WebElement> children = parent.findElements(By.tagName(tag));
        if (children.size() != 1) {
            path.insert(0, "]");
            path.insert(0, children.indexOf(element) + 1);
            path.insert(0, "[");
        }
        insertTag(path, tag);
        insertXPath(parent, path);
    }

    private static void insertTag(StringBuilder path, String tag) {
        path.insert(0, tag);
        path.insert(0, "/");
    }

    /**
     * Performs the DOM XSS scan for the given URL with the given attack vector.
     *
     * @param driver the WebDriver to use
     * @param attackVector the attack string to inject (e.g. in location hash)
     * @param url the full URL including the attack vector
     * @param isStop supplier that returns true when the scan should stop
     * @param steps list to collect scan steps for the alert (modified in place)
     * @return DomAlertInfo if a vulnerability was found, null otherwise
     */
    public static DomAlertInfo scan(
            WebDriver driver,
            String attackVector,
            String url,
            BooleanSupplier isStop,
            List<String> steps) {
        if (isStop != null && isStop.getAsBoolean()) {
            return null;
        }
        try {
            getHelper(driver, url, steps);
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.get1");
                return new DomAlertInfo(url, attackVector);
            }
        }

        List<WebElement> possibleDomXSSTriggers = new ArrayList<>();
        try {
            possibleDomXSSTriggers = findHelper(driver, By.tagName("input"));
            possibleDomXSSTriggers.addAll(findHelper(driver, By.tagName("button")));
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.input1");
                return new DomAlertInfo(url, attackVector);
            }
        }

        for (WebElement element : possibleDomXSSTriggers) {
            if (isStop != null && isStop.getAsBoolean()) {
                return null;
            }
            String xpath = getXPath(element);
            String tagName = null;
            String attributeId = null;
            String attributeName = null;
            try {
                tagName = element.getTagName();
                attributeId = element.getAttribute("id");
                attributeName = element.getAttribute("name");
                if ("input".equalsIgnoreCase(tagName)) {
                    steps.add(
                            Constant.messages.getString("domxss.step.input", xpath, attackVector));
                    element.sendKeys(attackVector);
                }
                steps.add(Constant.messages.getString("domxss.step.click", xpath));
                element.click();
            } catch (UnhandledAlertException uae) {
                // Ignore
            } catch (WebDriverException wde) {
                LOGGER.debug(wde);
            } finally {
                if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.possibleDomXSSTriggers2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }

            try {
                getHelper(driver, url, steps);
            } catch (UnhandledAlertException uae) {
                // Ignore
            } finally {
                if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.get2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
            try {
                possibleDomXSSTriggers = findHelper(driver, By.tagName("input"));
                possibleDomXSSTriggers.addAll(findHelper(driver, By.tagName("button")));
            } catch (UnhandledAlertException uae) {
                // Ignore
            } finally {
                if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.possibleDomXSSTriggers3");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
        }

        List<WebElement> allElements = new ArrayList<>();
        try {
            allElements = findHelper(driver, By.tagName("div"));
        } catch (UnhandledAlertException uae) {
            // Ignore
        } finally {
            if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                Stats.incCounter("domxss.vulns.div1");
                return new DomAlertInfo(url, attackVector);
            }
        }

        for (WebElement element : allElements) {
            if (isStop != null && isStop.getAsBoolean()) {
                return null;
            }
            String xpath = getXPath(element);
            String tagName = null;
            String attributeId = null;
            String attributeName = null;
            try {
                tagName = element.getTagName();
                attributeId = element.getAttribute("id");
                attributeName = element.getAttribute("name");
                steps.add(Constant.messages.getString("domxss.step.click", xpath));
                element.click();
                getHelper(driver, url, steps);
                allElements = findHelper(driver, By.tagName("div"));
            } catch (UnhandledAlertException uae) {
                // Ignore
            } catch (NoSuchSessionException enve) {
                LOGGER.debug(enve);
            } catch (ElementNotInteractableException enve) {
                LOGGER.debug(enve);
            } catch (TimeoutException wde) {
                LOGGER.debug(wde);
            } catch (WebDriverException wde) {
                LOGGER.debug(wde);
            } finally {
                if (getAlertDialogText(driver).equals(UNLIKELY_STR)) {
                    Stats.incCounter("domxss.vulns.div2");
                    return new DomAlertInfo(url, attackVector, tagName, attributeId, attributeName);
                }
            }
        }
        return null;
    }

    private static void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
