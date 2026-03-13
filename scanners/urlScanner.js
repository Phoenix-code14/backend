/**
 * CSPhoenix – URL Scanner
 * scanners/urlScanner.js
 *
 * Uses Playwright/Puppeteer to perform real browser-based scanning.
 * Falls back to HTTP-based analysis if browser launch fails.
 */

'use strict';

const https = require('https');
const http  = require('http');
const { URL } = require('url');
const { calculateRiskScore } = require('../utils/riskEngine');

/**
 * Main scan entry point
 * @param {string} targetUrl
 * @returns {Promise<Object>} scan result
 */
async function scanUrl(targetUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new Error('Invalid URL format');
  }

  console.log(`[SCAN] Starting scan: ${targetUrl}`);

  // Try browser scan first, fallback to HTTP scan
  let pageData;
  try {
    pageData = await browserScan(targetUrl);
  } catch (err) {
    console.warn('[SCAN] Browser scan unavailable, using HTTP scan:', err.message);
    pageData = await httpScan(targetUrl);
  }

  // Run risk scoring
  const riskData = calculateRiskScore(pageData);

  const result = {
    target: targetUrl,
    https: parsedUrl.protocol === 'https:',
    redirects: pageData.redirects || [],
    loginFormsDetected: pageData.loginFormsDetected || false,
    hiddenIframes: pageData.hiddenIframes || false,
    externalScripts: pageData.externalScripts || [],
    headers: pageData.headers || {},
    findings: riskData.findings,
    riskScore: riskData.score,
    riskLevel: riskData.level,
    recommendations: riskData.recommendations,
    screenshot: pageData.screenshot || null,
    timestamp: new Date().toISOString(),
    scanDuration: pageData.duration || 0
  };

  console.log(`[SCAN] Complete: ${targetUrl} | Risk: ${result.riskLevel} (${result.riskScore})`);
  return result;
}

/**
 * Browser-based scan using Playwright
 */
async function browserScan(url) {
  const startTime = Date.now();

  // Try to load playwright
  let chromium;
  try {
    const playwright = require('playwright');
    chromium = playwright.chromium;
  } catch {
    try {
      const puppeteer = require('puppeteer');
      return await puppeteerScan(url, puppeteer, startTime);
    } catch {
      throw new Error('No browser engine available');
    }
  }

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  try {
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    });

    const page = await context.newPage();

    const redirects = [];
    const externalScripts = [];
    let loginFormsDetected = false;
    let hiddenIframes = false;
    const headers = {};

    // Track redirects
    page.on('response', response => {
      const status = response.status();
      if ([301, 302, 303, 307, 308].includes(status)) {
        redirects.push(response.url());
      }
      if (response.url() === url) {
        response.headers && Object.assign(headers, response.headers());
      }
    });

    // Track scripts
    page.on('request', request => {
      if (request.resourceType() === 'script') {
        const reqUrl = request.url();
        try {
          const reqHost = new URL(reqUrl).hostname;
          const targetHost = new URL(url).hostname;
          if (reqHost !== targetHost) externalScripts.push(reqUrl);
        } catch {}
      }
    });

    // Navigate with timeout
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });

    // Analyze page DOM
    const analysis = await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      let hasLogin = false;

      forms.forEach(form => {
        const inputs = form.querySelectorAll('input[type="password"], input[name*="password"], input[name*="pass"]');
        if (inputs.length > 0) hasLogin = true;
      });

      const iframes = document.querySelectorAll('iframe');
      let hasHiddenIframe = false;
      iframes.forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        if (style.display === 'none' || style.visibility === 'hidden' ||
            iframe.width === '0' || iframe.height === '0') {
          hasHiddenIframe = true;
        }
      });

      const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');

      return {
        loginFormsDetected: hasLogin,
        hiddenIframes: hasHiddenIframe,
        hasMetaRefresh: !!metaRefresh,
        title: document.title,
        formCount: forms.length
      };
    });

    // Take screenshot
    const screenshotBuffer = await page.screenshot({ fullPage: false });
    const screenshot = `data:image/png;base64,${screenshotBuffer.toString('base64')}`;

    return {
      redirects,
      externalScripts: externalScripts.slice(0, 10),
      loginFormsDetected: analysis.loginFormsDetected,
      hiddenIframes: analysis.hiddenIframes,
      hasMetaRefresh: analysis.hasMetaRefresh,
      headers,
      screenshot,
      title: analysis.title,
      duration: Date.now() - startTime
    };

  } finally {
    await browser.close();
  }
}

/**
 * Puppeteer fallback scan
 */
async function puppeteerScan(url, puppeteer, startTime) {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    const redirects = [];
    const externalScripts = [];

    page.on('response', response => {
      const s = response.status();
      if ([301, 302, 307, 308].includes(s)) redirects.push(response.url());
    });

    page.on('request', request => {
      if (request.resourceType() === 'script') {
        try {
          const h1 = new URL(request.url()).hostname;
          const h2 = new URL(url).hostname;
          if (h1 !== h2) externalScripts.push(request.url());
        } catch {}
      }
    });

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });

    const analysis = await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      let hasLogin = false;
      forms.forEach(form => {
        if (form.querySelector('input[type="password"]')) hasLogin = true;
      });
      return { loginFormsDetected: hasLogin, title: document.title };
    });

    const screenshotBuffer = await page.screenshot();
    const screenshot = `data:image/png;base64,${screenshotBuffer.toString('base64')}`;

    return {
      redirects,
      externalScripts: externalScripts.slice(0, 10),
      loginFormsDetected: analysis.loginFormsDetected,
      hiddenIframes: false,
      screenshot,
      title: analysis.title,
      duration: Date.now() - startTime
    };

  } finally {
    await browser.close();
  }
}

/**
 * HTTP-based fallback scan (no browser required)
 */
function httpScan(url) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const parsedUrl = new URL(url);
    const transport = parsedUrl.protocol === 'https:' ? https : http;

    const options = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; CSPhoenix/2.4; Security Scanner)',
        'Accept': 'text/html'
      },
      timeout: 15000
    };

    const req = transport.request(options, res => {
      const headers = res.headers;
      const redirects = [];

      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        redirects.push(res.headers.location || url);
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { if (body.length < 50000) body += chunk; });
      res.on('end', () => {
        const loginFormsDetected = /type=["']password["']|name=["']pass/i.test(body);
        const hiddenIframes = /display:\s*none.*<iframe|<iframe.*display:\s*none/i.test(body);
        const externalScripts = [];

        const scriptRegex = /src=["']([^"']+)["']/gi;
        let match;
        while ((match = scriptRegex.exec(body)) !== null) {
          try {
            const scriptUrl = new URL(match[1], url);
            if (scriptUrl.hostname !== parsedUrl.hostname) {
              externalScripts.push(scriptUrl.href);
            }
          } catch {}
        }

        resolve({
          redirects,
          externalScripts: [...new Set(externalScripts)].slice(0, 10),
          loginFormsDetected,
          hiddenIframes,
          headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, String(v)])),
          screenshot: null,
          duration: Date.now() - startTime
        });
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.on('error', reject);
    req.end();
  });
}

module.exports = { scanUrl };
