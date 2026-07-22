/**
 * ════════════════════════════════════════════════════════════════
 * PhishGuard AI — Background Service Worker
 * Manifest V3 · Monitors tabs, scans URLs, stores results.
 * ════════════════════════════════════════════════════════════════
 */

/* ══════════════════════════════════════════════════════════════
   CONFIGURATION
   ══════════════════════════════════════════════════════════════ */

/** Threshold above which the content-script overlay fires. */
const PHISHING_THRESHOLD = 65;

/** Maximum scan-history entries persisted. */
const MAX_HISTORY = 50;

/** In-memory cache of latest results per tab id. */
const resultCache = new Map();

/* ══════════════════════════════════════════════════════════════
   URL ANALYSIS ENGINE
   ══════════════════════════════════════════════════════════════ */

/**
 * Known URL-shortening domains.
 */
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
  'bl.ink', 'lnkd.in', 'rb.gy', 'short.io',
]);

/**
 * Suspicious TLDs commonly abused in phishing campaigns.
 */
const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.click', '.link', '.info',
  '.online', '.site', '.icu', '.buzz', '.tk', '.ml', '.ga', '.cf',
  '.gq', '.pw', '.cc', '.ws',
]);

/**
 * Keywords commonly found in phishing URLs.
 */
const PHISH_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'update', 'secure',
  'banking', 'confirm', 'password', 'credential', 'authenticate',
  'wallet', 'paypal', 'apple', 'amazon', 'microsoft', 'netflix',
  'support', 'helpdesk', 'recover', 'unlock', 'suspend',
];

/**
 * Characters used in homograph/IDN attacks (non-ASCII look-alikes).
 */
const HOMOGRAPH_CHARS = /[а-яА-Я\u0400-\u04FF\u0370-\u03FF\u00C0-\u024F]/;

/**
 * Analyse a URL and return a detailed risk assessment.
 *
 * @param {string} rawUrl — The full URL string to evaluate.
 * @returns {Object}  { safetyScore, riskScore, riskLevel, verdict, threats, reputation }
 */
function analyseUrl(rawUrl) {
  const threats = [];
  let riskPoints = 0; // accumulates; max ≈ 100

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return buildResult(rawUrl, 0, 100, 'High', 'phishing', [
      { label: 'Malformed URL — unable to parse', severity: 'critical' },
    ]);
  }

  const hostname = parsed.hostname;
  const fullUrl  = rawUrl.toLowerCase();

  /* ── 1. IP-based URL ───────────────────────────────────── */
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) {
    threats.push({ label: 'IP-based URL detected (no domain name)', severity: 'critical' });
    riskPoints += 25;
  }

  /* ── 2. Excessive subdomains ───────────────────────────── */
  const subdomainCount = hostname.split('.').length - 2; // minus TLD + SLD
  if (subdomainCount > 3) {
    threats.push({ label: `Excessive subdomains (${subdomainCount})`, severity: 'critical' });
    riskPoints += 20;
  } else if (subdomainCount > 1) {
    threats.push({ label: `Multiple subdomains (${subdomainCount})`, severity: 'warning' });
    riskPoints += 8;
  }

  /* ── 3. URL shortener ──────────────────────────────────── */
  if (SHORTENERS.has(hostname)) {
    threats.push({ label: 'URL shortening service detected', severity: 'warning' });
    riskPoints += 15;
  }

  /* ── 4. Suspicious keywords ────────────────────────────── */
  const matched = PHISH_KEYWORDS.filter((kw) => fullUrl.includes(kw));
  if (matched.length >= 3) {
    threats.push({ label: `Multiple phishing keywords: ${matched.join(', ')}`, severity: 'critical' });
    riskPoints += 20;
  } else if (matched.length > 0) {
    threats.push({ label: `Suspicious keywords: ${matched.join(', ')}`, severity: 'warning' });
    riskPoints += matched.length * 4;
  }

  /* ── 5. Special characters in hostname ─────────────────── */
  if (/[@!$%^&*()_+=~`]/.test(hostname)) {
    threats.push({ label: 'Special characters in hostname', severity: 'critical' });
    riskPoints += 15;
  }

  /* ── 6. Homograph / IDN attacks ────────────────────────── */
  if (HOMOGRAPH_CHARS.test(hostname)) {
    threats.push({ label: 'Possible IDN homograph attack (non-ASCII chars)', severity: 'critical' });
    riskPoints += 25;
  }

  /* ── 7. Suspicious TLD ─────────────────────────────────── */
  const tld = '.' + hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    threats.push({ label: `Suspicious TLD: ${tld}`, severity: 'warning' });
    riskPoints += 10;
  }

  /* ── 8. No HTTPS ───────────────────────────────────────── */
  if (parsed.protocol !== 'https:') {
    threats.push({ label: 'Connection is not secure (no HTTPS)', severity: 'warning' });
    riskPoints += 10;
  }

  /* ── 9. Long URL ───────────────────────────────────────── */
  if (rawUrl.length > 150) {
    threats.push({ label: 'Unusually long URL', severity: 'warning' });
    riskPoints += 5;
  }

  /* ── 10. @ symbol in URL ───────────────────────────────── */
  if (rawUrl.includes('@')) {
    threats.push({ label: '@ symbol in URL — possible credential injection', severity: 'critical' });
    riskPoints += 20;
  }

  /* ── 11. Double dashes / many hyphens ──────────────────── */
  if ((hostname.match(/-/g) || []).length > 3) {
    threats.push({ label: 'Excessive hyphens in hostname', severity: 'warning' });
    riskPoints += 8;
  }

  /* ── 12. Port number in URL ────────────────────────────── */
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    threats.push({ label: `Non-standard port: ${parsed.port}`, severity: 'warning' });
    riskPoints += 8;
  }

  /* ── Clamp ─────────────────────────────────────────────── */
  riskPoints = Math.min(riskPoints, 100);

  const safetyScore = 100 - riskPoints;
  const riskLevel   = riskPoints >= 60 ? 'High' : riskPoints >= 30 ? 'Medium' : 'Low';
  const verdict     = riskPoints >= 60 ? 'phishing' : riskPoints >= 30 ? 'suspicious' : 'safe';

  return buildResult(rawUrl, safetyScore, riskPoints, riskLevel, verdict, threats);
}

/**
 * Build a normalised result object.
 */
function buildResult(url, safetyScore, riskScore, riskLevel, verdict, threats) {
  return {
    url,
    safetyScore,
    riskScore,
    riskLevel,
    verdict,
    threats,
    reputation: computeReputation(url, safetyScore),
    timestamp: Date.now(),
  };
}

/**
 * Simple heuristic domain reputation (placeholder for a real API lookup).
 */
function computeReputation(url, safety) {
  let trust = safety;
  let age   = 50;
  let popularity = 50;

  try {
    const hostname = new URL(url).hostname;

    // Well-known domains get high reputation
    const knownDomains = [
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
      'github.com', 'stackoverflow.com', 'wikipedia.org', 'amazon.com',
      'microsoft.com', 'apple.com', 'linkedin.com', 'reddit.com',
    ];
    const baseDomain = hostname.split('.').slice(-2).join('.');
    if (knownDomains.includes(baseDomain)) {
      trust = Math.max(trust, 95);
      age   = 95;
      popularity = 95;
    } else {
      // Simulate values based on safety — in production, query WHOIS / rank APIs
      age = Math.min(100, Math.round(safety * 0.8 + Math.random() * 20));
      popularity = Math.min(100, Math.round(safety * 0.6 + Math.random() * 25));
    }
  } catch { /* ignore */ }

  return { trust, age, popularity };
}

/* ══════════════════════════════════════════════════════════════
   AI PREDICTION PLACEHOLDER
   Swap this with a real API call to Flask / FastAPI backend.
   ══════════════════════════════════════════════════════════════ */

/**
 * Placeholder ML prediction function.
 *
 * In production, this issues a POST to your AI backend, e.g.:
 *   const res = await fetch('https://your-api.com/predict', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ url }),
 *   });
 *   return await res.json(); // { verdict, confidence }
 *
 * @param {string} url
 * @returns {Promise<{verdict: string, confidence: number}>}
 */
async function predictPhishing(url) {
  // --- BEGIN PLACEHOLDER ---
  // Simulates network latency + returns deterministic result based on URL analysis.
  // Replace this block with a real API call when your backend is ready.
  await new Promise((r) => setTimeout(r, 300 + Math.random() * 400));

  const analysis = analyseUrl(url);
  return {
    verdict: analysis.verdict,
    confidence: analysis.safetyScore / 100,
  };
  // --- END PLACEHOLDER ---
}

/* ══════════════════════════════════════════════════════════════
   SCAN ORCHESTRATOR
   ══════════════════════════════════════════════════════════════ */

/**
 * Run a full scan on the given URL.
 * Combines heuristic analysis with the AI prediction layer.
 *
 * @param {string} url
 * @returns {Promise<Object>}  Full result object.
 */
async function scanUrl(url) {
  // 1. Heuristic analysis
  const result = analyseUrl(url);

  // 2. AI prediction (blended)
  try {
    const prediction = await predictPhishing(url);
    // Blend: AI can nudge the verdict but heuristics remain primary
    if (prediction.verdict === 'phishing' && result.verdict !== 'phishing') {
      result.verdict   = 'suspicious';
      result.riskLevel = 'Medium';
      result.threats.push({ label: 'AI model flagged as potentially phishing', severity: 'warning' });
    }
  } catch { /* AI unavailable — rely on heuristics */ }

  // 3. Persist in history
  await persistHistory(result);

  return result;
}

/**
 * Save a result to chrome.storage.local scan history.
 */
async function persistHistory(result) {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
  scanHistory.push({
    url:       result.url,
    verdict:   result.verdict,
    safetyScore: result.safetyScore,
    riskScore: result.riskScore,
    timestamp: result.timestamp,
  });
  // Trim to MAX_HISTORY
  if (scanHistory.length > MAX_HISTORY) {
    scanHistory.splice(0, scanHistory.length - MAX_HISTORY);
  }
  await chrome.storage.local.set({ scanHistory });
}

/* ══════════════════════════════════════════════════════════════
   CONTENT-SCRIPT OVERLAY TRIGGER
   ══════════════════════════════════════════════════════════════ */

/**
 * If a scanned URL is phishing, inject the warning overlay
 * into the active tab's content script.
 */
async function notifyContentScript(tabId, result) {
  if (result.riskScore >= PHISHING_THRESHOLD) {
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'PHISHING_WARNING',
        result,
      });
    } catch {
      // Content script may not be loaded yet; inject it first
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ['content.js'],
        });
        // Retry
        await chrome.tabs.sendMessage(tabId, {
          type: 'PHISHING_WARNING',
          result,
        });
      } catch { /* Uninjectable tab (chrome://, etc.) */ }
    }
  }
}

/**
 * Send a Chrome notification for high-risk sites.
 */
function sendNotification(result) {
  if (result.riskScore >= PHISHING_THRESHOLD) {
    chrome.notifications.create(`phish-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '⚠️ PhishGuard AI Alert',
      message: `Phishing risk detected on ${truncateStr(result.url, 60)}.\nRisk Level: ${result.riskLevel} (${result.riskScore}%)`,
      priority: 2,
    });
  }
}

/* ══════════════════════════════════════════════════════════════
   TAB & NAVIGATION MONITORING
   ══════════════════════════════════════════════════════════════ */

/**
 * Scan the URL when a tab is activated (switched to).
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url && isScannableUrl(tab.url)) {
      const result = await scanUrl(tab.url);
      resultCache.set(activeInfo.tabId, result);
      await notifyContentScript(activeInfo.tabId, result);
      sendNotification(result);
    }
  } catch { /* ignore */ }
});

/**
 * Scan the URL when a tab finishes loading a new page.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && isScannableUrl(tab.url)) {
    const result = await scanUrl(tab.url);
    resultCache.set(tabId, result);
    await notifyContentScript(tabId, result);
    sendNotification(result);

    // Push result to popup if it's open
    chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result }).catch(() => {
      // Safe to ignore: popup is closed, so no receiving end exists.
    });
  }
});

/**
 * Clean up cache when tab closes.
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  resultCache.delete(tabId);
});

/* ══════════════════════════════════════════════════════════════
   MESSAGE HANDLERS (from popup & content scripts)
   ══════════════════════════════════════════════════════════════ */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    /* ── Popup requests a manual scan ───────────────────── */
    case 'SCAN_URL':
      (async () => {
        try {
          const result = await scanUrl(msg.url);
          // Also inject overlay if needed
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) {
            resultCache.set(tab.id, result);
            await notifyContentScript(tab.id, result);
            sendNotification(result);
          }
          sendResponse({ result });
        } catch (err) {
          sendResponse({ error: err.message });
        }
      })();
      return true; // keep channel open for async response

    /* ── Popup requests cached result ───────────────────── */
    case 'GET_RESULT':
      (async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && resultCache.has(tab.id)) {
          sendResponse({ result: resultCache.get(tab.id) });
        } else {
          sendResponse({ result: null });
        }
      })();
      return true;

    /* ── Content script reports page-level threats ──────── */
    case 'PAGE_THREATS':
      // Merge page-level threats into the cached result
      if (sender.tab && resultCache.has(sender.tab.id)) {
        const cached = resultCache.get(sender.tab.id);
        const pageThreats = msg.threats || [];
        pageThreats.forEach((t) => {
          cached.threats.push(t);
          cached.riskScore = Math.min(100, cached.riskScore + 5);
        });
        cached.safetyScore = 100 - cached.riskScore;
        if (cached.riskScore >= 60) { cached.verdict = 'phishing'; cached.riskLevel = 'High'; }
        else if (cached.riskScore >= 30) { cached.verdict = 'suspicious'; cached.riskLevel = 'Medium'; }
        resultCache.set(sender.tab.id, cached);
        // Push update to popup
        chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result: cached }).catch(() => {
          // Safe to ignore: popup is closed, so no receiving end exists.
        });
      }
      break;
  }
});

/* ══════════════════════════════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════════════════════════════ */

/**
 * Only scan http/https URLs (skip chrome://, about:, etc.)
 */
function isScannableUrl(url) {
  return url.startsWith('http://') || url.startsWith('https://');
}

function truncateStr(s, max) {
  return s.length > max ? s.slice(0, max) + '…' : s;
}

/* ── Service worker installed / activated lifecycle ────── */
chrome.runtime.onInstalled.addListener(() => {
  console.log('[PhishGuard AI] Extension installed / updated');
});

console.log('[PhishGuard AI] Background service worker loaded');
