require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const validator = require('validator');
const axios     = require('axios');
const { Pool }  = require('pg');

const app  = express();
const PORT = process.env.PORT || 5000;

// ═══════════════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
});

pool.on('error', err => console.error('[DB] Pool error:', err.message));

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      name       TEXT        NOT NULL,
      email      TEXT        NOT NULL UNIQUE,
      password   TEXT        NOT NULL,
      role       TEXT        NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scans (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      url        TEXT        NOT NULL,
      verdict    TEXT        NOT NULL,
      score      INTEGER     NOT NULL,
      details    JSONB       NOT NULL DEFAULT '{}',
      ip_address TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reports (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
      url         TEXT        NOT NULL,
      reason      TEXT        NOT NULL,
      description TEXT,
      status      TEXT        NOT NULL DEFAULT 'pending',
      reviewed_by INTEGER REFERENCES users(id),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS flagged_urls (
      id            SERIAL PRIMARY KEY,
      url           TEXT        NOT NULL UNIQUE,
      report_count  INTEGER     NOT NULL DEFAULT 1,
      confirmed     BOOLEAN     NOT NULL DEFAULT FALSE,
      first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_reported TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_scans_url   ON scans(url);
    CREATE INDEX IF NOT EXISTS idx_scans_user  ON scans(user_id);
    CREATE INDEX IF NOT EXISTS idx_reports_url ON reports(url);
    CREATE INDEX IF NOT EXISTS idx_flagged_url ON flagged_urls(url);
  `);
  console.log('[DB] Schema ready.');
}

// ═══════════════════════════════════════════════
//  IN-MEMORY CACHE (avoids hammering free APIs)
// ═══════════════════════════════════════════════
const cache = new Map();
function getCache(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) { cache.delete(key); return null; }
  return entry.value;
}
function setCache(key, value, ttlMs) {
  cache.set(key, { value, expires: Date.now() + ttlMs });
}

// ═══════════════════════════════════════════════
//  EXTERNAL API LOOKUPS
// ═══════════════════════════════════════════════

// Extract base domain: sub.domain.com → domain.com
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length > 2) return parts.slice(-2).join('.');
  return hostname;
}

// Format domain age from a date string
function calcDomainAge(dateStr) {
  if (!dateStr) return null;
  try {
    const reg  = new Date(dateStr);
    const now  = new Date();
    const days = Math.floor((now - reg) / (1000 * 60 * 60 * 24));
    if (days < 30)  return days + ' days old — very new domain';
    if (days < 365) return Math.floor(days / 30) + ' months old';
    const years  = Math.floor(days / 365);
    const months = Math.floor((days % 365) / 30);
    return years + ' year' + (years > 1 ? 's' : '') + (months > 0 ? ', ' + months + ' month' + (months > 1 ? 's' : '') : '');
  } catch (e) {
    return null;
  }
}

// 1. RDAP — domain registration data (completely free, no key)
async function fetchRDAP(hostname) {
  const base = getBaseDomain(hostname);
  const cacheKey = 'rdap:' + base;
  const cached = getCache(cacheKey);
  if (cached) return cached;

  try {
    const res = await axios.get('https://rdap.org/domain/' + base, { timeout: 8000 });
    const data = res.data;

    // Registration & expiry dates
    const events = data.events || [];
    const regEvent  = events.find(e => e.eventAction === 'registration');
    const expEvent  = events.find(e => e.eventAction === 'expiration');
    const dateRegistered = regEvent ? new Date(regEvent.eventDate).toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' }) : null;
    const dateExpiry     = expEvent ? new Date(expEvent.eventDate).toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' }) : null;
    const domainAge      = regEvent ? calcDomainAge(regEvent.eventDate) : null;

    // Registrant info (often privacy-protected)
    let owner = 'REDACTED FOR PRIVACY';
    let organization = 'REDACTED FOR PRIVACY';
    const registrant = (data.entities || []).find(e => e.roles && e.roles.includes('registrant'));
    if (registrant && registrant.vcardArray) {
      const vcard = registrant.vcardArray[1] || [];
      const fnEntry  = vcard.find(v => v[0] === 'fn');
      const orgEntry = vcard.find(v => v[0] === 'org');
      if (fnEntry  && fnEntry[3])  owner        = fnEntry[3];
      if (orgEntry && orgEntry[3]) organization = orgEntry[3];
    }

    // Registrar
    const registrar = (data.entities || []).find(e => e.roles && e.roles.includes('registrar'));
    let registrarName = null;
    if (registrar && registrar.vcardArray) {
      const vcard = registrar.vcardArray[1] || [];
      const fn = vcard.find(v => v[0] === 'fn');
      if (fn && fn[3]) registrarName = fn[3];
    }

    const result = { dateRegistered, dateExpiry, domainAge, owner, organization, registrar: registrarName };
    setCache(cacheKey, result, 24 * 60 * 60 * 1000); // cache 24h
    return result;
  } catch (e) {
    console.error('[RDAP] Error for ' + base + ':', e.message);
    return { dateRegistered: null, dateExpiry: null, domainAge: null, owner: 'Not Available', organization: 'Not Available', registrar: null };
  }
}

// 2. ip-api.com — hosting provider & geolocation (free, no key)
async function fetchIPInfo(hostname) {
  const base = getBaseDomain(hostname);
  const cacheKey = 'ipapi:' + base;
  const cached = getCache(cacheKey);
  if (cached) return cached;

  try {
    const res = await axios.get(
      'http://ip-api.com/json/' + hostname + '?fields=status,country,countryCode,regionName,city,isp,org,as',
      { timeout: 6000 }
    );
    const d = res.data;
    if (d.status !== 'success') throw new Error('ip-api returned fail status');

    const result = {
      hostingProvider: d.org || d.isp || 'Not Available',
      isp: d.isp || 'Not Available',
      country: d.country ? (d.city ? d.city + ', ' + d.country : d.country) : 'Not Available',
      countryCode: d.countryCode || null,
      asn: d.as || null,
    };
    setCache(cacheKey, result, 6 * 60 * 60 * 1000); // cache 6h
    return result;
  } catch (e) {
    console.error('[IPAPI] Error for ' + hostname + ':', e.message);
    return { hostingProvider: 'Not Available', isp: 'Not Available', country: 'Not Available', countryCode: null, asn: null };
  }
}

// 3. VirusTotal — threat intelligence (free key required)
async function fetchVirusTotal(url) {
  if (!process.env.VIRUSTOTAL_API_KEY) return null;
  const cacheKey = 'vt:' + url;
  const cached = getCache(cacheKey);
  if (cached) return cached;

  try {
    const encoded = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const res = await axios.get('https://www.virustotal.com/api/v3/urls/' + encoded, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
      timeout: 8000,
    });
    const stats = (res.data && res.data.data && res.data.data.attributes && res.data.data.attributes.last_analysis_stats) || {};
    const result = {
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
    };
    setCache(cacheKey, result, 60 * 60 * 1000); // cache 1h
    return result;
  } catch (e) {
    console.error('[VT] Error:', e.message);
    return null;
  }
}

// 4. SSL Check — validates certificate via ssl-checker.io (free, no key)
async function fetchSSL(hostname) {
  const base = getBaseDomain(hostname);
  const cacheKey = 'ssl:' + base;
  const cached = getCache(cacheKey);
  if (cached) return cached;

  try {
    const res = await axios.get('https://ssl-checker.io/api/v1/check/' + base, { timeout: 8000 });
    const d = res.data;
    const result = {
      valid:       d.valid === true,
      issuer:      d.issuer || null,
      validFrom:   d.valid_from  ? new Date(d.valid_from).toLocaleDateString('en-GB',  { day:'numeric', month:'long', year:'numeric' }) : null,
      validTo:     d.valid_till  ? new Date(d.valid_till).toLocaleDateString('en-GB',  { day:'numeric', month:'long', year:'numeric' }) : null,
      daysLeft:    d.days_left   || null,
    };
    setCache(cacheKey, result, 12 * 60 * 60 * 1000); // cache 12h
    return result;
  } catch (e) {
    console.error('[SSL] Error for ' + base + ':', e.message);
    return { valid: null, issuer: null, validFrom: null, validTo: null, daysLeft: null };
  }
}

// ═══════════════════════════════════════════════
//  SCANNER ENGINE
// ═══════════════════════════════════════════════
const SCAM_KEYWORDS = [
  'bvn-update','bvn-verify','bvnupdate','bvnverif','bank-verification',
  'gtbank-alert','firstbank-update','zenithbank-secure','accessbank-verify',
  'uba-alert','fcmb-login','sterling-bank-verify',
  'giveaway','free-airtime','free-data','claim-prize','you-have-won',
  'congratulations-winner','npower-portal','trader-moni','naira-gift',
  'invest-now','double-your','guaranteed-profit','crypto-alert',
  'forex-signal','mmm-nigeria','ponzi','100-percent-return',
  'opay-bonus','opay-gift','opay-verify','opay-update',
  'palmpay-bonus','palmpay-gift','palmpay-update',
  'nirsal-portal','efcc-alert','nigeria-customs-duty',
  'login-secure','account-suspended','verify-now',
  'urgent-action','update-information','confirm-identity',
];

const SAFE_DOMAINS = [
  'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
  'whatsapp.com','linkedin.com','github.com','wikipedia.org','microsoft.com',
  'gtbank.com','gtco.com','zenithbank.com','accessbankplc.com',
  'firstbanknigeria.com','ubagroup.com','fcmb.com',
  'opay.com','palmpay.com','konga.com','jumia.com.ng',
  'paystack.com','flutterwave.com','cowrywise.com','piggyvest.com',
  'mtnng.com','airtel.com.ng','cbn.gov.ng','nitda.gov.ng','tracesite.com',
];

const SUSPICIOUS_TLDS = ['.xyz','.top','.club','.online','.site','.icu','.buzz','.click','.link','.work','.gq','.ml','.cf','.tk'];

const TYPOSQUAT_BRANDS = [
  { brand: 'paystack',    patterns: ['paystck','paystcak','paysta-ck'] },
  { brand: 'flutterwave', patterns: ['flutterwav','fluter-wave'] },
  { brand: 'opay',        patterns: ['0pay','op4y','opay-ng','o-pay'] },
  { brand: 'palmpay',     patterns: ['pa1mpay','paalmpay','palm-pay-ng'] },
  { brand: 'gtbank',      patterns: ['gt-bank','gtb4nk','gtbankng'] },
];

function normalizeUrl(raw) {
  try {
    let u = raw.trim().toLowerCase();
    if (!u.startsWith('http://') && !u.startsWith('https://')) u = 'https://' + u;
    const parsed = new URL(u);
    return { href: parsed.href, hostname: parsed.hostname, pathname: parsed.pathname };
  } catch (e) {
    return { href: raw, hostname: raw.toLowerCase(), pathname: '' };
  }
}

async function analyzeUrl(rawUrl) {
  const { href, hostname, pathname } = normalizeUrl(rawUrl);
  const fullPath = hostname + pathname;
  const signals  = [];
  let score = 0;

  const isSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));

  // Run all external lookups in parallel
  const [rdap, ipInfo, vtResult, sslInfo, communityRow] = await Promise.allSettled([
    fetchRDAP(hostname),
    fetchIPInfo(hostname),
    fetchVirusTotal(href),
    fetchSSL(hostname),
    pool.query('SELECT * FROM flagged_urls WHERE url = $1 LIMIT 1', [href]),
  ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : null));

  // Community flags
  let community = { flagged: false, confirmed: false, report_count: 0 };
  const flagged = communityRow && communityRow.rows && communityRow.rows[0];
  if (flagged) {
    community = { flagged: true, confirmed: flagged.confirmed, report_count: flagged.report_count };
    if (flagged.confirmed) { score += 70; signals.push('Community confirmed scam — reported ' + flagged.report_count + ' time(s)'); }
    else { score += 30; signals.push('Reported by community ' + flagged.report_count + ' time(s) — unconfirmed'); }
  }

  if (!isSafe) {
    // Scam keywords
    const kw = SCAM_KEYWORDS.filter(k => fullPath.includes(k));
    if (kw.length > 0) { score += Math.min(kw.length * 20, 50); signals.push('High-risk keywords detected: ' + kw.join(', ')); }

    // Suspicious TLD
    const tlds = SUSPICIOUS_TLDS.filter(t => hostname.endsWith(t));
    if (tlds.length) { score += 15; signals.push('Suspicious domain extension: ' + tlds.join(', ')); }

    // Typosquatting
    for (const item of TYPOSQUAT_BRANDS) {
      if (item.patterns.some(p => hostname.includes(p))) { score += 35; signals.push('Possible impersonation of ' + item.brand); }
    }

    // Raw IP
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { score += 20; signals.push('URL uses a raw IP address instead of a domain name'); }

    // Excessive subdomains
    if (hostname.split('.').length >= 5) { score += 10; signals.push('Unusually deep subdomain structure'); }

    // New domain (< 1 year) is higher risk
    if (rdap && rdap.domainAge && rdap.domainAge.includes('days old')) {
      score += 25; signals.push('Very new domain — registered within the last year (high risk indicator)');
    } else if (rdap && rdap.domainAge && rdap.domainAge.includes('months old')) {
      score += 15; signals.push('Recently registered domain — less than 1 year old');
    }

    // No SSL
    const isHttps = rawUrl.trim().toLowerCase().startsWith('https://');
    if (!isHttps) { score += 15; signals.push('No HTTPS — connection is not encrypted'); }
    if (sslInfo && sslInfo.valid === false) { score += 20; signals.push('SSL certificate is invalid or expired'); }
    if (sslInfo && sslInfo.daysLeft !== null && sslInfo.daysLeft < 7) { score += 10; signals.push('SSL certificate expires very soon (' + sslInfo.daysLeft + ' days left)'); }

    // VirusTotal
    if (vtResult) {
      score += (vtResult.malicious * 15) + (vtResult.suspicious * 8);
      if (vtResult.malicious > 0) signals.push('VirusTotal: ' + vtResult.malicious + '/' + vtResult.total + ' security engines flagged as malicious');
      else if (vtResult.suspicious > 0) signals.push('VirusTotal: ' + vtResult.suspicious + '/' + vtResult.total + ' security engines flagged as suspicious');
      else if (vtResult.harmless > 0) signals.push('VirusTotal: Clean — ' + vtResult.harmless + '/' + vtResult.total + ' engines found no threats');
    }
  }

  if (signals.length === 0) {
    signals.push('No threat patterns detected across all analysis checks');
    if (!score) score = 5;
  }

  score = Math.min(isSafe ? 5 : score, 100);
  const verdict = isSafe ? 'safe' : score <= 20 ? 'safe' : score <= 55 ? 'suspicious' : 'scam';

  // Build SSL status string
  const isHttpsFinal = rawUrl.trim().toLowerCase().startsWith('https://');
  let sslStatus = isHttpsFinal ? 'HTTPS Enabled' : 'HTTP Only — Not Encrypted';
  if (sslInfo && sslInfo.valid !== null) {
    if (sslInfo.valid) {
      sslStatus = 'Valid SSL Certificate';
      if (sslInfo.issuer)   sslStatus += ' — Issued by ' + sslInfo.issuer;
      if (sslInfo.validTo)  sslStatus += ' — Expires ' + sslInfo.validTo;
      if (sslInfo.daysLeft) sslStatus += ' (' + sslInfo.daysLeft + ' days remaining)';
    } else {
      sslStatus = 'Invalid or Expired SSL Certificate';
    }
  }

  const riskLevel = score <= 20 ? 'Low' : score <= 40 ? 'Moderate' : score <= 65 ? 'High' : 'Critical';

  const verificationStatus = verdict === 'safe' ? 'Verified Safe' : verdict === 'suspicious' ? 'Unverified — Exercise Caution' : 'Flagged as Malicious';

  const recommendation = verdict === 'safe'
    ? 'This website appears safe to visit. Always stay cautious and avoid sharing sensitive personal or financial information unless you are certain of the site legitimacy.'
    : verdict === 'suspicious'
    ? 'Exercise extreme caution. Do not enter personal details, banking credentials, or make payments on this site until you have verified its legitimacy through official channels.'
    : 'Do NOT visit this website. It has been flagged as highly dangerous. Never enter any personal, financial, or login information. Report this link and warn others.';

  const description = verdict === 'safe'
    ? hostname + ' appears to be a legitimate website. Our analysis across multiple intelligence sources found no significant threat indicators.'
    : verdict === 'suspicious'
    ? hostname + ' has raised several red flags. While not conclusively confirmed as malicious, it exhibits patterns commonly associated with phishing or fraudulent websites targeting Nigerian users.'
    : hostname + ' has been identified as highly dangerous. It matches multiple known scam patterns targeting Nigerian internet users, with indicators of phishing, impersonation, or financial fraud.';

  // VirusTotal summary for report
  let vtSummary = 'Not checked (API key not configured)';
  if (vtResult) vtSummary = vtResult.malicious + ' malicious, ' + vtResult.suspicious + ' suspicious, ' + vtResult.harmless + ' clean out of ' + vtResult.total + ' engines';

  return {
    url: rawUrl, verdict, score,
    details: {
      signals, community, virustotal: vtResult,
      report: {
        website_url:         rawUrl,
        trust_score:         score,
        verification_status: verificationStatus,
        domain_name:         hostname,
        hosting_provider:    ipInfo ? ipInfo.hostingProvider : 'Not Available',
        isp:                 ipInfo ? ipInfo.isp : 'Not Available',
        date_registered:     rdap && rdap.dateRegistered ? rdap.dateRegistered : 'Not Available',
        date_expiry:         rdap && rdap.dateExpiry ? rdap.dateExpiry : 'Not Available',
        domain_age:          rdap && rdap.domainAge ? rdap.domainAge : 'Not Available',
        website_owner:       rdap && rdap.owner ? rdap.owner : 'Not Available',
        organization:        rdap && rdap.organization ? rdap.organization : 'Not Available',
        registrar:           rdap && rdap.registrar ? rdap.registrar : 'Not Available',
        country_location:    ipInfo ? ipInfo.country : 'Not Available',
        ssl_status:          sslStatus,
        ssl_secure:          isHttpsFinal && (sslInfo ? sslInfo.valid !== false : true),
        ssl_issuer:          sslInfo && sslInfo.issuer ? sslInfo.issuer : null,
        virustotal_summary:  vtSummary,
        risk_level:          riskLevel,
        description:         description,
        risk_reasons:        signals,
        recommendation:      recommendation,
      }
    }
  };
}

// ═══════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════
app.use(helmet());
app.set('trust proxy', 1);
app.use(cors({ origin: '*', credentials: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));
app.use(express.json({ limit: '10kb' }));
app.use(morgan('dev'));

function signToken(id, role) {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

async function verifyToken(req, res, next, required) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    if (required) return res.status(401).json({ success: false, message: 'No token provided. Please log in.' });
    return next();
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    const r = await pool.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [decoded.id]);
    const user = r.rows[0];
    if (!user) {
      if (required) return res.status(401).json({ success: false, message: 'User no longer exists.' });
      return next();
    }
    const { password, ...safe } = user;
    req.user = safe;
    next();
  } catch (e) {
    if (required) return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    next();
  }
}

const auth      = (req, res, next) => verifyToken(req, res, next, true);
const optAuth   = (req, res, next) => verifyToken(req, res, next, false);
const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin access required.' });
  next();
};

// ═══════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({ success: true, service: 'Tracesite API', status: 'operational', time: new Date().toISOString(), virustotal: !!process.env.VIRUSTOTAL_API_KEY });
});

app.get('/', (req, res) => {
  res.json({ success: true, message: "Tracesite API v3 — Protecting Nigeria's Digital Future" });
});

// ═══════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════
app.post('/api/auth/register', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
    if (!validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email address.' });
    if (password.length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
    const hashed = await bcrypt.hash(password, 12);
    const role   = email.toLowerCase() === (process.env.ADMIN_EMAIL || '').toLowerCase() ? 'admin' : 'user';
    const r      = await pool.query('INSERT INTO users (name, email, password, role) VALUES ($1,$2,$3,$4) RETURNING *', [name.trim(), email.toLowerCase().trim(), hashed, role]);
    const user   = r.rows[0];
    const token  = signToken(user.id, user.role);
    const { password: _, ...safeUser } = user;
    return res.status(201).json({ success: true, token, user: safeUser });
  } catch (err) {
    console.error('[AUTH] Register:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
    const r = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    const token = signToken(user.id, user.role);
    const { password: _, ...safeUser } = user;
    return res.json({ success: true, token, user: safeUser });
  } catch (err) {
    console.error('[AUTH] Login:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

app.get('/api/auth/me', auth, (req, res) => res.json({ success: true, user: req.user }));

// ═══════════════════════════════════════════════
//  SCAN ROUTES
// ═══════════════════════════════════════════════
app.post('/api/scan', rateLimit({ windowMs: 60 * 1000, max: 20 }), optAuth, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || !url.trim()) return res.status(400).json({ success: false, message: 'A URL is required.' });
    if (url.trim().length > 2048) return res.status(400).json({ success: false, message: 'URL is too long.' });
    const result = await analyzeUrl(url.trim());
    const r = await pool.query(
      'INSERT INTO scans (user_id, url, verdict, score, details, ip_address) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.user ? req.user.id : null, url.trim(), result.verdict, result.score, JSON.stringify(result.details), req.ip]
    );
    return res.json({ success: true, scan_id: r.rows[0].id, url: result.url, verdict: result.verdict, score: result.score, details: result.details, scanned_at: new Date().toISOString() });
  } catch (err) {
    console.error('[SCAN]', err.message);
    return res.status(500).json({ success: false, message: 'Scan failed. Please try again.' });
  }
});

app.get('/api/scan/history', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20', [req.user.id]);
    return res.json({ success: true, scans: r.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not retrieve scan history.' });
  }
});

app.get('/api/scan/stats', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query("SELECT COUNT(*)::int AS total_scans, SUM(CASE WHEN verdict='scam' THEN 1 ELSE 0 END)::int AS total_scams, SUM(CASE WHEN verdict='safe' THEN 1 ELSE 0 END)::int AS total_safe FROM scans");
    return res.json({ success: true, stats: r.rows[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not retrieve statistics.' });
  }
});

// ═══════════════════════════════════════════════
//  REPORT ROUTES
// ═══════════════════════════════════════════════
const VALID_REASONS = ['phishing','investment_scam','fake_ecommerce','malware','impersonation','other'];

app.post('/api/report', auth, async (req, res) => {
  try {
    const { url, reason, description } = req.body;
    if (!url || !url.trim()) return res.status(400).json({ success: false, message: 'A URL is required.' });
    if (!reason || !VALID_REASONS.includes(reason)) return res.status(400).json({ success: false, message: 'Invalid reason.' });
    const r = await pool.query('INSERT INTO reports (user_id, url, reason, description) VALUES ($1,$2,$3,$4) RETURNING id', [req.user.id, url.trim(), reason, description || null]);
    await pool.query('INSERT INTO flagged_urls (url) VALUES ($1) ON CONFLICT (url) DO UPDATE SET report_count = flagged_urls.report_count + 1, last_reported = NOW()', [url.trim()]);
    return res.status(201).json({ success: true, message: 'Report submitted successfully.', report_id: r.rows[0].id });
  } catch (err) {
    console.error('[REPORT]', err.message);
    return res.status(500).json({ success: false, message: 'Could not submit report.' });
  }
});

app.get('/api/report/top-flagged', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM flagged_urls ORDER BY report_count DESC LIMIT 20');
    return res.json({ success: true, flagged: r.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not retrieve flagged URLs.' });
  }
});

app.get('/api/report/pending', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query("SELECT r.*, u.name AS reporter_name FROM reports r LEFT JOIN users u ON r.user_id = u.id WHERE r.status = 'pending' ORDER BY r.created_at DESC");
    return res.json({ success: true, reports: r.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not retrieve reports.' });
  }
});

app.patch('/api/report/:id', auth, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['confirmed','dismissed'].includes(status)) return res.status(400).json({ success: false, message: "Status must be confirmed or dismissed." });
    await pool.query('UPDATE reports SET status = $1, reviewed_by = $2 WHERE id = $3', [status, req.user.id, req.params.id]);
    if (status === 'confirmed') await pool.query('UPDATE flagged_urls SET confirmed = TRUE WHERE id = $1', [req.params.id]);
    return res.json({ success: true, message: 'Report ' + status + ' successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not update report.' });
  }
});

// ═══════════════════════════════════════════════
//  404 & ERROR
// ═══════════════════════════════════════════════
app.use((req, res) => res.status(404).json({ success: false, message: 'Route not found.' }));
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, message: 'An unexpected error occurred.' });
});

// ═══════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════
async function start() {
  try {
    await initSchema();
    app.listen(PORT, () => console.log('[Tracesite] API running on port ' + PORT));
  } catch (err) {
    console.error('[FATAL]', err.message);
    process.exit(1);
  }
}

start();
