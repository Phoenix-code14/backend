/**
 * CSPhoenix – Report Generator
 * utils/reportGenerator.js
 */

'use strict';

async function generateReport(scanResult) {
  const lines = [
    '================================================================',
    '  CSPhoenix Cybersecurity Intelligence Platform',
    '  Security Analysis Report',
    `  Generated: ${new Date().toISOString()}`,
    '================================================================',
    '',
    `  Target:     ${scanResult.target}`,
    `  Risk Level: ${scanResult.riskLevel}`,
    `  Risk Score: ${scanResult.riskScore}/100`,
    `  HTTPS:      ${scanResult.https ? 'Yes' : 'No'}`,
    `  Login Form: ${scanResult.loginFormsDetected ? 'Detected' : 'Not Found'}`,
    `  Redirects:  ${scanResult.redirects?.length || 0}`,
    '',
    '--- SECURITY FINDINGS ---',
    ...(scanResult.findings || []).map(f => `  [${f.severity}] ${f.title}: ${f.description}`),
    '',
    '--- EXTERNAL SCRIPTS ---',
    ...(scanResult.externalScripts?.length
      ? scanResult.externalScripts.map(s => `  • ${s}`)
      : ['  None detected']),
    '',
    '--- RECOMMENDATIONS ---',
    ...(scanResult.recommendations || []).map(r => `  • ${r}`),
    '',
    '================================================================',
    '  Phoenix Thabiso Group (Pty) Ltd – CSPhoenix v2.4.1',
    '================================================================',
  ];

  return {
    text: lines.join('\n'),
    filename: `csphoenix-report-${Date.now()}.txt`,
    scanResult
  };
}

module.exports = { generateReport };
