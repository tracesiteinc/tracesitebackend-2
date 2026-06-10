const axios = require('axios');
const { flaggedQueries } = require('../db/database');

// ─────────────────────────────────────────────
//  NIGERIAN SCAM PATTERN DATABASE
// ─────────────────────────────────────────────

const SCAM_KEYWORDS = [
  // BVN / Banking
  'bvn-update', 'bvn-verify', 'bvnupdate', 'bvnverif',
  'bank-verification', 'bankverif',
  // Common Nigerian bank impersonation patterns
  'gtbank-alert', 'firstbank-update', 'zenithbank-secure',
  'accessbank-verify', 'uba-alert', 'fidelitybank-update',
  'fcmb-login', 'sterling-bank-verify', 'keystone-bank',
  // Giveaway / promo scams
  'giveaway', 'free-airtime', 'free-data', 'claim-prize',
  'you-have-won', 'youhavewon', 'congratulations-winner',
  'npower-portal', 'trader-moni', 'naira-gift',
  // Crypto / investment scams
  'invest-now', 'double-your', 'guaranteed-profit',
  'crypto-alert', 'forex-signal', 'mmm-nigeria',
  'ponzi', 'pyramid', '100-percent-return',
  // OPay / PalmPay impersonation
  'opay-bonus', 'opay-gift', 'opay-verify', 'opay-update',
  'palmpay-bonus', 'palmpay-gift', 'palmpay-update',
  // Fake government portals
  'nirsal-portal', 'cac-registration-update',
  'efcc-alert', 'dss-notice', 'nigeria-customs-duty',
  // Generic phishing signals
  'login-secure', 'account-suspended', 'verify-now',
  'urgent-action', 'update-information', 'confirm-identity',
];

const SAFE_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'whatsapp.com', 'linkedin.com', 'github.com',
  'stackoverflow.com', 'wikipedia.org', 'microsoft.com', 'apple.com',
  'amazon.com', 'netflix.com', 'anthropic.com',
  // Legit Nigerian domains
  'gtbank.com', 'gtco.com', 'zenithbank.com', 'accessbankplc.com',
  'firstbanknigeria.com', 'ubagroup.com', 'fcmb.com',
  'opay.com', 'palmpay.com', 'konga.com', 'jumia.com.ng',
  'paystack.com', 'flutterwave.com', 'cowrywise.com',
  'piggyvest.com', 'mtnng.com', 'airtel.com.ng',
  'nbc.gov.ng', 'cbn.gov.ng', 'nitda.gov.ng', 'efcc.gov.ng',
  'tracesite.com',
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.online', '.site', '.icu',
  '.buzz', '.click', '.link', '.work', '.gq', '.ml', '.cf', '.tk',
];

const TYPOSQUAT_BRANDS = [
  { brand: 'paystack',    patterns: ['paystck', 'paystcak', 'paysta-ck'] },
  { brand: 'flutterwave', patterns: ['flutterwav', 'fluter-wave', 'flutterwaye'] },
  { brand: 'opay',        patterns: ['0pay', 'op4y', 'opay-ng', 'o-pay'] },
  { brand: 'palmpay',     patterns: ['pa1mpay', 'paalmpay', 'palm-pay-ng'] },
  { brand: 'gtbank',      patterns: ['gt-bank', 'gtb4nk', 'gtbankng'] },
];

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────

function normalizeUrl(raw) {
  try {
    let u = raw.trim().toLowerCase();
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      u = 'https://' + u;
    }
    const parsed = new URL(u);
    return { href: parsed.href, hostname: parsed.hostname, pathname: parsed.pathname };
  } catch {
    return { href: raw, hostname: raw.toLowerCase(), pathname: '' };
  }
}

function checkSafeDomain(hostname) {
  return SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
}

function checkScamKeywords(url) {
  const lower = url.toLowerCase();
  const matched = SCAM_KEYWORDS.filter(k => lower.includes(k));
  return matched;
}

function checkSuspiciousTLD(hostname) {
  return SUSPICIOUS_TLDS.filter(tld => hostname.endsWith(tld));
}

function checkTyposquatting(hostname) {
  const flags = [];
  for (const { brand, patterns } of TYPOSQUAT_BRANDS) {
    if (patterns.some(p => hostname.includes(p))) {
      flags.push(`Possible impersonation of ${brand}`);
    }
  }
  return flags;
}

function checkIPAddress(hostname) {
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  return ipv4.test(hostname) ? ['URL uses raw IP address instead of domain name'] : [];
}

function checkExcessiveSubdomains(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 5 ? ['Unusually deep subdomain structure'] : [];
}

function checkCommunityFlags(url) {
  try {
    const flagged = flaggedQueries.findByUrl.get(url);
    if (flagged) {
      return {
        flagged: true,
        confirmed: !!flagged.confirmed,
        report_count: flagged.report_count,
      };
    }
  } catch (_) {}
  return { flagged: false, confirmed: false, report_count: 0 };
}

// ─────────────────────────────────────────────
//  VIRUSTOTAL INTEGRATION (optional)
// ─────────────────────────────────────────────

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  try {
    const encoded = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const res = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      {
        headers: { 'x-apikey': apiKey },
        timeout: 5000,
      }
    );
    const stats = res.data?.data?.attributes?.last_analysis_stats || {};
    return {
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      undetected: stats.undetected || 0,
    };
  } catch {
    return null; // Don't fail the scan if VT is unavailable
  }
}

// ─────────────────────────────────────────────
//  MAIN SCAN FUNCTION
// ─────────────────────────────────────────────

async function analyzeUrl(rawUrl) {
  const { href, hostname, pathname } = normalizeUrl(rawUrl);
  const fullPath = hostname + pathname;

  const signals = [];
  let score = 0;

  // 1. Safe domain whitelist (fast pass)
  if (checkSafeDomain(hostname)) {
    return {
      url: rawUrl,
      verdict: 'safe',
      score: 5,
      details: {
        signals: ['Domain is on the verified safe list'],
        community: { flagged: false, report_count: 0 },
        virustotal: null,
      },
    };
  }

  // 2. Community flags (high weight)
  const community = checkCommunityFlags(href) || checkCommunityFlags(hostname);
  if (community.confirmed) {
    score += 70;
    signals.push(`⚠️ Community confirmed scam — reported ${community.report_count} time(s)`);
  } else if (community.flagged) {
    score += 30;
    signals.push(`🚩 Reported by community ${community.report_count} time(s) — unconfirmed`);
  }

  // 3. Scam keywords
  const kwMatches = checkScamKeywords(fullPath);
  if (kwMatches.length > 0) {
    score += Math.min(kwMatches.length * 20, 50);
    signals.push(`🔴 High-risk keywords detected: ${kwMatches.join(', ')}`);
  }

  // 4. Suspicious TLD
  const tldFlags = checkSuspiciousTLD(hostname);
  if (tldFlags.length > 0) {
    score += 15;
    signals.push(`🔶 Suspicious top-level domain: ${tldFlags.join(', ')}`);
  }

  // 5. Typosquatting
  const typoFlags = checkTyposquatting(hostname);
  typoFlags.forEach(f => { score += 35; signals.push(`🔴 ${f}`); });

  // 6. Raw IP address
  const ipFlags = checkIPAddress(hostname);
  ipFlags.forEach(f => { score += 20; signals.push(`🔶 ${f}`); });

  // 7. Excessive subdomains
  const subFlags = checkExcessiveSubdomains(hostname);
  subFlags.forEach(f => { score += 10; signals.push(`🔶 ${f}`); });

  // 8. No signals at all = slightly safer
  if (signals.length === 0 && score === 0) {
    signals.push('✅ No threat patterns detected');
    score = 8;
  }

  // 9. VirusTotal (async, adds to score if available)
  const vtResult = await checkVirusTotal(href);
  if (vtResult) {
    const vtScore = (vtResult.malicious * 15) + (vtResult.suspicious * 8);
    score += vtScore;
    if (vtResult.malicious > 0) {
      signals.push(`🔴 VirusTotal: ${vtResult.malicious} engine(s) flagged as malicious`);
    } else if (vtResult.suspicious > 0) {
      signals.push(`🔶 VirusTotal: ${vtResult.suspicious} engine(s) flagged as suspicious`);
    } else {
      signals.push(`✅ VirusTotal: Clean across ${vtResult.harmless} engines`);
    }
  }

  // Cap score at 100
  score = Math.min(score, 100);

  // Determine verdict
  let verdict;
  if (score <= 20)      verdict = 'safe';
  else if (score <= 55) verdict = 'suspicious';
  else                   verdict = 'scam';

  return {
    url: rawUrl,
    verdict,
    score,
    details: { signals, community, virustotal: vtResult },
  };
}

module.exports = { analyzeUrl };
