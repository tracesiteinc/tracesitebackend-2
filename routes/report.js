const router = require('express').Router();
const validator = require('validator');
const { reportQueries, flaggedQueries } = require('../db/database');
const { authenticate, adminOnly } = require('../middleware/auth');

const VALID_REASONS = ['phishing', 'investment_scam', 'fake_ecommerce', 'malware', 'impersonation', 'other'];

// ─────────────────────────────────────────────
//  POST /api/report
//  Submit a community report for a URL
// ─────────────────────────────────────────────
router.post('/', authenticate, (req, res) => {
  try {
    const { url, reason, description } = req.body;

    // Validation
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'A URL is required.' });
    }
    if (!reason || !VALID_REASONS.includes(reason)) {
      return res.status(400).json({
        success: false,
        message: `Reason must be one of: ${VALID_REASONS.join(', ')}.`,
      });
    }
    if (description && description.length > 1000) {
      return res.status(400).json({ success: false, message: 'Description must be under 1000 characters.' });
    }

    // Insert report
    const reportResult = reportQueries.create.run({
      user_id:     req.user.id,
      url:         url.trim(),
      reason,
      description: description?.trim() || null,
    });

    // Upsert into flagged_urls for scan engine to pick up
    flaggedQueries.upsert.run(url.trim());

    return res.status(201).json({
      success: true,
      message: 'Report submitted successfully. Thank you for protecting Nigeria's digital space.',
      report_id: reportResult.lastInsertRowid,
    });
  } catch (err) {
    console.error('[REPORT] Submit error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not submit report. Please try again.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/report/url?url=...  (public)
//  Get community reports for a specific URL
// ─────────────────────────────────────────────
router.get('/url', (req, res) => {
  try {
    const { url } = req.query;
    if (!url) {
      return res.status(400).json({ success: false, message: 'URL query parameter is required.' });
    }

    const reports = reportQueries.findByUrl.all(url);
    const flagged = flaggedQueries.findByUrl.get(url);

    return res.json({
      success: true,
      url,
      report_count:   reports.length,
      community_flag: flagged || null,
      reports: reports.map(r => ({
        id:          r.id,
        reason:      r.reason,
        status:      r.status,
        created_at:  r.created_at,
        // Don't expose reporter identity publicly
      })),
    });
  } catch (err) {
    console.error('[REPORT] URL lookup error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve reports.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/report/top-flagged  (public)
//  Most reported URLs (community intelligence)
// ─────────────────────────────────────────────
router.get('/top-flagged', (req, res) => {
  try {
    const flagged = flaggedQueries.topFlagged.all();
    return res.json({ success: true, flagged });
  } catch (err) {
    console.error('[REPORT] Top flagged error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve flagged URLs.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/report/pending  (admin only)
//  View all pending reports
// ─────────────────────────────────────────────
router.get('/pending', authenticate, adminOnly, (req, res) => {
  try {
    const reports = reportQueries.pending.all();
    return res.json({ success: true, reports });
  } catch (err) {
    console.error('[REPORT] Pending error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve pending reports.' });
  }
});

// ─────────────────────────────────────────────
//  PATCH /api/report/:id  (admin only)
//  Review a report — confirm or dismiss
// ─────────────────────────────────────────────
router.patch('/:id', authenticate, adminOnly, (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['confirmed', 'dismissed'].includes(status)) {
      return res.status(400).json({ success: false, message: "Status must be 'confirmed' or 'dismissed'." });
    }

    // Update report status
    reportQueries.updateStatus.run(status, req.user.id, id);

    // If confirmed, mark the URL in flagged_urls
    if (status === 'confirmed') {
      flaggedQueries.confirm.run(id);
    }

    return res.json({
      success: true,
      message: `Report ${status} successfully.`,
    });
  } catch (err) {
    console.error('[REPORT] Review error:', err.message);
    return res.status(500).json({ success: false, message: 'Could not update report.' });
  }
});

module.exports = router;
