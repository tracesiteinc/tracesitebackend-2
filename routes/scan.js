const router = require('express').Router();
const { analyzeUrl } = require('../utils/scanner');
const { scanQueries } = require('../db/database');
const { optionalAuth, authenticate, adminOnly } = require('../middleware/auth');

// ─────────────────────────────────────────────
//  POST /api/scan
//  Analyze a URL — public, but logs user if authenticated
// ─────────────────────────────────────────────
router.post('/', optionalAuth, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'A URL is required.' });
    }

    if (url.trim().length > 2048) {
      return res.status(400).json({ success: false, message: 'URL is too long (max 2048 characters).' });
    }

    // Run the analysis engine
    const result = await analyzeUrl(url.trim());

    // Persist the scan record
    const scanRecord = scanQueries.create.run({
      user_id:    req.user?.id || null,
      url:        url.trim(),
      verdict:    result.verdict,
      score:      result.score,
      details:    JSON.stringify(result.details),
      ip_address: req.ip,
    });

    return res.json({
      success: true,
      scan_id: scanRecord.lastInsertRowid,
      url:     result.url,
      verdict: result.verdict,
      score:   result.score,
      details: result.details,
      scanned_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[SCAN] Error:', err.message);
    return res.status(500).json({ success: false, message: 'Scan failed. Please try again.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/scan/history  (authenticated)
//  Returns the logged-in user's recent scans
// ─────────────────────────────────────────────
router.get('/history', authenticate, (req, res) => {
  try {
    const scans = scanQueries.recentByUser.all(req.user.id).map(s => ({
      ...s,
      details: JSON.parse(s.details),
    }));
    return res.json({ success: true, scans });
  } catch (err) {
    console.error('[SCAN] History error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve scan history.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/scan/stats  (admin)
//  Platform-wide scan statistics
// ─────────────────────────────────────────────
router.get('/stats', authenticate, adminOnly, (req, res) => {
  try {
    const stats = scanQueries.stats.get();
    return res.json({ success: true, stats });
  } catch (err) {
    console.error('[SCAN] Stats error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve statistics.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/scan/lookup?url=...  (public)
//  Check if a URL has been scanned before
// ─────────────────────────────────────────────
router.get('/lookup', (req, res) => {
  try {
    const { url } = req.query;
    if (!url) {
      return res.status(400).json({ success: false, message: 'URL query parameter is required.' });
    }
    const scans = scanQueries.findByUrl.all(url).map(s => ({
      ...s,
      details: JSON.parse(s.details),
    }));
    return res.json({ success: true, scans });
  } catch (err) {
    console.error('[SCAN] Lookup error:', err.message);
    return res.status(500).json({ success: false, message: 'Lookup failed.' });
  }
});

module.exports = router;
