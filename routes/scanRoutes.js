/**
 * CSPhoenix – Scan Routes
 * routes/scanRoutes.js
 */

'use strict';

const express = require('express');
const router  = express.Router();

const { scanUrl }         = require('../scanners/urlScanner');
const { getDomainIntel }  = require('../scanners/domainIntel');
const { detectPhishing }  = require('../scanners/phishingDetector');
const { generateReport }  = require('../utils/reportGenerator');

// ── POST /api/scan-url ────────────────────────────────────
router.post('/scan-url', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const result = await scanUrl(url);
    res.json(result);
  } catch (err) {
    console.error('[scan-url error]', err.message);
    res.status(500).json({ error: 'Scan failed', detail: err.message });
  }
});

// ── POST /api/domain-intel ────────────────────────────────
router.post('/domain-intel', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const result = await getDomainIntel(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Domain intel failed', detail: err.message });
  }
});

// ── POST /api/detect-phishing ─────────────────────────────
router.post('/detect-phishing', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const result = await detectPhishing(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Phishing detection failed', detail: err.message });
  }
});

// ── POST /api/generate-report ─────────────────────────────
router.post('/generate-report', async (req, res) => {
  const { scanResult } = req.body;

  if (!scanResult) {
    return res.status(400).json({ error: 'Scan result is required' });
  }

  try {
    const report = await generateReport(scanResult);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: 'Report generation failed', detail: err.message });
  }
});

module.exports = router;
