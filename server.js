/**
 * CSPhoenix – Backend Scanning Server
 * server.js
 * Phoenix Thabiso Group (Pty) Ltd
 */

'use strict';

const express = require('express');
const cors    = require('cors');
const path    = require('path');

const scanRoutes = require('./routes/scanRoutes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────
app.use(cors({
  origin: ['http://localhost:8080', 'http://127.0.0.1:8080', '*'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Serve Frontend ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));

// ── Routes ────────────────────────────────────────────────
app.use('/api', scanRoutes);

// ── Health Check ──────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    platform: 'CSPhoenix v2.4.1',
    engine: 'active',
    timestamp: new Date().toISOString()
  });
});

// ── 404 ───────────────────────────────────────────────────
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ── Error Handler ─────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error', detail: err.message });
});

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║  CSPhoenix – Cybersecurity Intelligence      ║
  ║  Platform Backend v2.4.1                     ║
  ║  Phoenix Thabiso Group (Pty) Ltd             ║
  ╠══════════════════════════════════════════════╣
  ║  Server running on http://localhost:${PORT}     ║
  ║  Status: ONLINE                              ║
  ╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
