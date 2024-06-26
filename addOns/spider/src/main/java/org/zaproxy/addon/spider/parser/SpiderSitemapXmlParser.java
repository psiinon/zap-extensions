/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.addon.spider.parser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.logging.log4j.LogManager;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.zaproxy.zap.utils.XmlUtils;

/**
 * SitemapXMLParser is used for parsing URLs from a sitemap.xml file, which sometimes (very
 * helpfully) resides in the web root.
 *
 * @author 70pointer
 */
public class SpiderSitemapXmlParser extends SpiderParser {

    /** a pattern to match the sitemap.xml file name */
    private static final Pattern SITEMAP_XML_FILENAME_PATTERN = Pattern.compile("/sitemap\\.xml$");

    /** used to parse the XML based file format */
    private static DocumentBuilder dBuilder;

    /** an x path expression to match the "loc" tag in sitemap.xml */
    private static XPathExpression xpathLocationExpression;

    /** an x path expression to match xhtml:link hrefs in sitemap.xml */
    private static XPathExpression xpathXhtmlLinkHrefExpression;

    /** statically initialise the XML DocumentBuilderFactory and DocumentBuilder */
    static {
        try {
            dBuilder = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
            XPath xpath = XPathFactory.newInstance().newXPath();
            xpathLocationExpression = xpath.compile("/urlset/url/loc/text()");
            xpathXhtmlLinkHrefExpression = xpath.compile("//*[@href or @HREF]");
        } catch (ParserConfigurationException | XPathExpressionException e) {
            LogManager.getLogger(SpiderSitemapXmlParser.class).error(e);
        }
    }

    @Override
    public boolean parseResource(ParseContext ctx) {

        getLogger().debug("Parsing a sitemap.xml resource...");
        HttpMessage message = ctx.getHttpMessage();
        if (!ctx.getSpiderParam().isParseSitemapXml()
                || !message.getResponseHeader().isXml()
                || HttpStatusCode.isClientError(message.getResponseHeader().getStatusCode())
                || HttpStatusCode.isServerError(message.getResponseHeader().getStatusCode())) {
            return false;
        }

        // Get the response content
        byte[] response = message.getResponseBody().getBytes();
        boolean consumed = false;
        try {
            Document xmldoc = dBuilder.parse(new InputSource(new ByteArrayInputStream(response)));

            consumed |= processUrlset(xmldoc, ctx);
            consumed |= processXhtmlLinkHrefs(xmldoc, ctx);
        } catch (SAXException | IOException | XPathExpressionException e) {
            getLogger().warn("An error occurred trying to parse sitemap.xml. {}", e.getMessage());
            getLogger().debug(e, e);
            return false;
        }
        return consumed;
    }

    private boolean processUrlset(Document xmldoc, ParseContext ctx)
            throws XPathExpressionException {
        getLogger().debug("Processing sitemap Urlset...");

        NodeList locationNodes =
                (NodeList) xpathLocationExpression.evaluate(xmldoc, XPathConstants.NODESET);
        for (int i = 0; i < locationNodes.getLength(); i++) {
            processUrl(ctx, locationNodes.item(i).getNodeValue());
        }
        return locationNodes.getLength() != 0;
    }

    private boolean processXhtmlLinkHrefs(Document xmldoc, ParseContext ctx)
            throws XPathExpressionException {
        getLogger().debug("Processing sitemap.xml xhtml:link hrefs...");
        boolean consumed = false;

        NodeList xhtmlLinkHrefNodes =
                (NodeList) xpathXhtmlLinkHrefExpression.evaluate(xmldoc, XPathConstants.NODESET);
        for (int i = 0; i < xhtmlLinkHrefNodes.getLength(); i++) {
            NamedNodeMap attrs = xhtmlLinkHrefNodes.item(i).getAttributes();
            consumed |= processCandidate(attrs, "href", ctx);
            consumed |= processCandidate(attrs, "HREF", ctx);
        }
        return consumed;
    }

    private boolean processCandidate(NamedNodeMap attrs, String attrName, ParseContext ctx) {
        Node candidate = attrs.getNamedItem(attrName);
        if (candidate != null) {
            processUrl(ctx, candidate.getNodeValue());
            return true;
        }
        return false;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        String path = ctx.getPath();
        getLogger().debug("canParseResource called on '{}'", path);
        // matches the file name of files that should be parsed with the sitemap.xml file parser
        Matcher matcher = SITEMAP_XML_FILENAME_PATTERN.matcher(path);
        return matcher.find();
    }
}
