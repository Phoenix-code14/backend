/**
 * CSPhoenix – Risk Scoring Engine
 * utils/riskEngine.js
 */

'use strict';

const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'account', 'secure', 'update', 'verify', 'banking',
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'credential', 'password'
];

const BRAND_KEYWORDS = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram', 'twitter', 'bank'];

function calculateRiskScore(pageData) {
  const findings = [];
  const recommendations = [];
  let score = 0;
  
  const url = pageData.targetUrl || '';
  const hostname = (() => { try { return new URL(url).hostname.toLowerCase(); } catch { return ''; } })();
  
  // HTTPS
  if (!url.startsWith('https')) {
    score += 25;
    findings.push({ severity: 'High', icon: 'lock-open', title: 'Missing HTTPS', description: 'Connection is unencrypted. All transmitted data is exposed.' });
    recommendations.push('Ensure HTTPS is enabled with a valid TLS certificate.');
  }
  
  // Suspicious keywords
  const kwds = SUSPICIOUS_KEYWORDS.filter(k => hostname.includes(k));
  if (kwds.length > 0) {
    score += 20;
    findings.push({ severity: 'High', icon: 'triangle-exclamation', title: 'Suspicious Domain Keywords', description: `Keywords detected: ${kwds.join(', ')}` });
    recommendations.push('Verify domain ownership before interacting.');
  }
  
  // Login form
  if (pageData.loginFormsDetected) {
    score += 25;
    findings.push({ severity: 'High', icon: 'right-to-bracket', title: 'Login Form Detected', description: 'Credential input fields found. Verify site authenticity.' });
    recommendations.push('Confirm you are on the official domain before entering credentials.');
  }
  
  // Redirects
  const redirectCount = pageData.redirects?.length || 0;
  if (redirectCount > 0) {
    score += redirectCount * 8;
    findings.push({ severity: redirectCount > 1 ? 'High' : 'Medium', icon: 'arrow-right-arrow-left', title: `${redirectCount} Redirect(s) Detected`, description: 'Multiple redirects can obscure malicious destinations.' });
  }
  
  // External scripts
  const scriptCount = pageData.externalScripts?.length || 0;
  if (scriptCount > 3) {
    score += 10;
    findings.push({ severity: 'Medium', icon: 'code', title: 'Multiple External Scripts', description: `${scriptCount} external script sources detected.` });
    recommendations.push('Review external script origins for legitimacy.');
  }
  
  // Hidden iframes
  if (pageData.hiddenIframes) {
    score += 20;
    findings.push({ severity: 'High', icon: 'eye-slash', title: 'Hidden Iframe Detected', description: 'Concealed iframes may deliver malicious content or enable clickjacking.' });
    recommendations.push('Hidden iframes present — exercise extreme caution.');
  }
  
  // Brand impersonation
  const brandMatches = BRAND_KEYWORDS.filter(b => hostname.includes(b));
  if (brandMatches.length > 0) {
    score += 25;
    findings.push({ severity: 'High', icon: 'mask', title: 'Brand Impersonation Risk', description: `Domain may be impersonating: ${brandMatches.join(', ')}` });
    recommendations.push('Do not enter credentials — this may be a phishing site.');
  }
  
  score = Math.min(Math.max(score, 0), 100);
  const level = score >= 61 ? 'High' : score >= 31 ? 'Medium' : 'Low';
  
  if (findings.length === 0) {
    findings.push({ severity: 'Low', icon: 'shield-check', title: 'No Major Threats Found', description: 'Analysis did not detect any high-risk indicators.' });
  }
  
  if (recommendations.length === 0) {
    recommendations.push('No immediate action required. Continue to exercise general security hygiene.');
  }
  
  recommendations.push('Enable multi-factor authentication on all accounts.');
  
  return { score, level, findings, recommendations: [...new Set(recommendations)] };
}

module.exports = { calculateRiskScore };