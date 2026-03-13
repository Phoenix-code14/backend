/**
 * CSPhoenix – Phishing Detector
 * scanners/phishingDetector.js
 */

'use strict';

const { URL } = require('url');

const BRAND_KEYWORDS   = ['paypal','amazon','google','microsoft','apple','netflix','facebook','instagram','twitter','bank','chase','wellsfargo','citibank'];
const SUSPICIOUS_TLD   = ['xyz','top','click','work','gq','tk','ml','cf','ga','monster','buzz'];
const PHISH_KEYWORDS   = ['login','signin','account','secure','update','verify','banking','credential','password','confirm','validate'];

async function detectPhishing(url) {
  let parsedUrl;
  try { parsedUrl = new URL(url); }
  catch { throw new Error('Invalid URL'); }

  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl  = url.toLowerCase();
  const indicators = [];
  let score = 0;

  // HTTPS
  if (parsedUrl.protocol !== 'https:') {
    score += 20;
    indicators.push({ severity: 'High', type: 'no_https', description: 'No HTTPS encryption detected' });
  }

  // Brand impersonation
  const brands = BRAND_KEYWORDS.filter(b => hostname.includes(b) && !hostname.endsWith(`.${b}.com`));
  if (brands.length > 0) {
    score += 40;
    indicators.push({ severity: 'Critical', type: 'brand_impersonation', description: `Brand impersonation: ${brands.join(', ')}` });
  }

  // Phishing keywords in URL
  const kwds = PHISH_KEYWORDS.filter(k => fullUrl.includes(k));
  if (kwds.length > 1) {
    score += 25;
    indicators.push({ severity: 'High', type: 'phishing_keywords', description: `Phishing keywords: ${kwds.slice(0,3).join(', ')}` });
  }

  // Suspicious TLD
  const tld = hostname.split('.').pop();
  if (SUSPICIOUS_TLD.includes(tld)) {
    score += 20;
    indicators.push({ severity: 'High', type: 'suspicious_tld', description: `Suspicious TLD: .${tld}` });
  }

  // Hyphens in domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    score += 15;
    indicators.push({ severity: 'Medium', type: 'hyphen_domain', description: `${hyphenCount} hyphens in domain name` });
  }

  // Long hostname
  if (hostname.length > 40) {
    score += 10;
    indicators.push({ severity: 'Medium', type: 'long_domain', description: `Unusually long domain (${hostname.length} chars)` });
  }

  // Deep subdomain
  const domainParts = hostname.split('.').length;
  if (domainParts > 4) {
    score += 10;
    indicators.push({ severity: 'Medium', type: 'deep_subdomain', description: `Excessive subdomain depth: ${domainParts} levels` });
  }

  score = Math.min(score, 100);
  const riskLevel = score >= 61 ? 'High' : score >= 31 ? 'Medium' : 'Low';
  const isPhishing = score >= 61;

  const recommendations = [];
  if (isPhishing) {
    recommendations.push('Do not enter credentials on this page');
    recommendations.push('Report this URL to your security team immediately');
    recommendations.push('Block this domain at the network perimeter');
  }
  recommendations.push('Always verify the domain through trusted channels');
  recommendations.push('Enable browser phishing protection extensions');

  return {
    target: url,
    isPhishing,
    confidence: isPhishing ? 'High' : score >= 31 ? 'Moderate' : 'Low',
    riskScore: score,
    riskLevel,
    indicators,
    recommendations,
    timestamp: new Date().toISOString()
  };
}

module.exports = { detectPhishing };
