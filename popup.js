/**
 * ════════════════════════════════════════════════════════════════
 * PhishGuard AI — Popup Controller
 * Orchestrates the popup dashboard: scanning, history, reports.
 * ════════════════════════════════════════════════════════════════
 */

/* ──────────────────────── DOM Cache ──────────────────────── */
const $ = (id) => document.getElementById(id);

const dom = {
  currentUrl:   $('currentUrl'),
  domainLabel:  $('domainLabel'),
  protocolLabel:$('protocolLabel'),

  ringFg:       $('ringFg'),
  safetyPct:    $('safetyPct'),
  riskLevel:    $('riskLevel'),
  riskScore:    $('riskScore'),
  aiVerdict:    $('aiVerdict'),
  lastScan:     $('lastScan'),

  threatList:   $('threatList'),
  threatEmpty:  $('threatEmpty'),

  repTrust:     $('repTrust'),
  repTrustVal:  $('repTrustVal'),
  repAge:       $('repAge'),
  repAgeVal:    $('repAgeVal'),
  repPop:       $('repPop'),
  repPopVal:    $('repPopVal'),

  btnScan:      $('btnScan'),
  btnDetails:   $('btnDetails'),
  btnReport:    $('btnReport'),
  btnExport:    $('btnExport'),

  historyList:  $('historyList'),
  historyEmpty: $('historyEmpty'),

  detailModal:  $('detailModal'),
  modalBody:    $('modalBody'),
  modalClose:   $('modalClose'),

  toast:        $('toast'),
  statusBadge:  $('statusBadge'),
  scoreCard:    $('scoreCard'),
};

/* ────────────────────── Constants ────────────────────────── */
const RING_CIRCUMFERENCE = 326.73; // 2 * π * 52
const MAX_HISTORY = 10;

/* ──────────────────────── State ─────────────────────────── */
let currentTabUrl = '';
let latestResult  = null;

/* ════════════════════════════════════════════════════════════
   INITIALIZATION
   ════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  // 1. Get current tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabUrl = tab.url;
      renderSiteInfo(tab.url);
    } else {
      dom.currentUrl.textContent = 'Unable to read URL';
    }
  } catch (err) {
    dom.currentUrl.textContent = 'Unable to read URL';
  }

  // 2. Check for cached scan result from background
  chrome.runtime.sendMessage({ type: 'GET_RESULT', url: currentTabUrl }, (res) => {
    if (chrome.runtime.lastError) return;
    if (res && res.result) {
      applyResult(res.result);
    }
  });

  // 3. Render history
  renderHistory();

  // 4. Bind events
  dom.btnScan.addEventListener('click', handleScan);
  dom.btnDetails.addEventListener('click', handleDetails);
  dom.btnReport.addEventListener('click', handleReport);
  dom.btnExport.addEventListener('click', handleExport);
  dom.modalClose.addEventListener('click', () => dom.detailModal.classList.remove('open'));
  dom.detailModal.addEventListener('click', (e) => {
    if (e.target === dom.detailModal) dom.detailModal.classList.remove('open');
  });
});

/* ── Listen for background pushes ────────────────────────── */
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SCAN_RESULT' && msg.result) {
    applyResult(msg.result);
    renderHistory();
  }
});

/* ════════════════════════════════════════════════════════════
   RENDER HELPERS
   ════════════════════════════════════════════════════════════ */

/**
 * Display basic site info from the URL.
 */
function renderSiteInfo(url) {
  dom.currentUrl.textContent = url;
  try {
    const u = new URL(url);
    dom.domainLabel.textContent  = u.hostname;
    dom.protocolLabel.textContent = u.protocol.replace(':', '').toUpperCase();
    dom.protocolLabel.style.color = u.protocol === 'https:' ? 'var(--green)' : 'var(--red)';
  } catch {
    dom.domainLabel.textContent  = '—';
    dom.protocolLabel.textContent = '—';
  }
}

/**
 * Apply a full scan result to the popup UI.
 * @param {Object} result  { url, safetyScore, riskScore, riskLevel, verdict, threats, reputation, timestamp }
 */
function applyResult(result) {
  latestResult = result;

  // ── Safety ring ──
  const safety = result.safetyScore ?? 0;
  const offset = RING_CIRCUMFERENCE - (RING_CIRCUMFERENCE * safety / 100);
  dom.ringFg.style.strokeDashoffset = offset;

  // Ring colour
  if (safety >= 70) {
    dom.ringFg.style.stroke = 'var(--green)';
  } else if (safety >= 40) {
    dom.ringFg.style.stroke = 'var(--amber)';
  } else {
    dom.ringFg.style.stroke = 'var(--red)';
  }

  dom.safetyPct.textContent = `${safety}%`;

  // ── Risk level ──
  dom.riskLevel.textContent = result.riskLevel || '—';
  dom.riskLevel.className   = `detail-val risk-${(result.riskLevel || '').toLowerCase()}`;

  // ── Risk score ──
  dom.riskScore.textContent = `${result.riskScore ?? 0}%`;

  // ── AI verdict ──
  dom.aiVerdict.textContent     = capitalise(result.verdict || '—');
  dom.aiVerdict.dataset.level   = (result.verdict || '').toLowerCase();

  // ── Last scan ──
  dom.lastScan.textContent = formatTime(result.timestamp);

  // ── Threats ──
  renderThreats(result.threats || []);

  // ── Reputation ──
  renderReputation(result.reputation || {});

  // ── Status badge ──
  updateBadge(result.verdict);
}

/**
 * Render threat indicator list.
 */
function renderThreats(threats) {
  dom.threatList.innerHTML = '';
  if (threats.length === 0) {
    dom.threatEmpty.classList.remove('hidden');
    return;
  }
  dom.threatEmpty.classList.add('hidden');
  threats.forEach((t, i) => {
    const li = document.createElement('li');
    li.className = `threat-item ${t.severity === 'warning' ? 'warn' : ''}`;
    li.style.animationDelay = `${i * .06}s`;
    li.innerHTML = `<span class="threat-icon">${t.severity === 'critical' ? '🔴' : '🟠'}</span>
      <span>${escapeHtml(t.label)}</span>`;
    dom.threatList.appendChild(li);
  });
}

/**
 * Render domain reputation bars.
 */
function renderReputation(rep) {
  const trust = rep.trust ?? 0;
  const age   = rep.age   ?? 0;
  const pop   = rep.popularity ?? 0;

  dom.repTrust.style.width = `${trust}%`;
  dom.repTrustVal.textContent = `${trust}%`;

  dom.repAge.style.width = `${age}%`;
  dom.repAgeVal.textContent = `${age}%`;

  dom.repPop.style.width = `${pop}%`;
  dom.repPopVal.textContent = `${pop}%`;
}

/**
 * Update the header badge to reflect overall status.
 */
function updateBadge(verdict) {
  const badge = dom.statusBadge;
  const dot   = badge.querySelector('.badge-dot');
  const text  = badge.querySelector('.badge-text');
  switch ((verdict || '').toLowerCase()) {
    case 'phishing':
      badge.style.background  = 'rgba(255,59,92,.08)';
      badge.style.borderColor = 'rgba(255,59,92,.2)';
      badge.style.color       = 'var(--red)';
      dot.style.background    = 'var(--red)';
      text.textContent        = 'Danger';
      break;
    case 'suspicious':
      badge.style.background  = 'rgba(245,166,35,.08)';
      badge.style.borderColor = 'rgba(245,166,35,.2)';
      badge.style.color       = 'var(--amber)';
      dot.style.background    = 'var(--amber)';
      text.textContent        = 'Warning';
      break;
    default:
      badge.style.background  = 'rgba(34,214,126,.08)';
      badge.style.borderColor = 'rgba(34,214,126,.2)';
      badge.style.color       = 'var(--green)';
      dot.style.background    = 'var(--green)';
      text.textContent        = 'Safe';
  }
}

/* ════════════════════════════════════════════════════════════
   SCAN HISTORY
   ════════════════════════════════════════════════════════════ */

async function renderHistory() {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
  dom.historyList.innerHTML = '';
  if (scanHistory.length === 0) {
    dom.historyEmpty.classList.remove('hidden');
    return;
  }
  dom.historyEmpty.classList.add('hidden');

  // Show most recent first, limited to MAX_HISTORY
  scanHistory.slice(-MAX_HISTORY).reverse().forEach((entry) => {
    const li = document.createElement('li');
    li.className = 'history-item';

    const verdict = (entry.verdict || 'safe').toLowerCase();
    li.innerHTML = `
      <span class="history-url" title="${escapeHtml(entry.url)}">${escapeHtml(truncate(entry.url, 38))}</span>
      <span class="history-badge badge-${verdict}">${capitalise(verdict)}</span>
      <span class="history-time">${formatTime(entry.timestamp)}</span>`;
    dom.historyList.appendChild(li);
  });
}

/* ════════════════════════════════════════════════════════════
   ACTIONS
   ════════════════════════════════════════════════════════════ */

/**
 * Trigger a manual scan of the current tab.
 */
async function handleScan() {
  if (!currentTabUrl) { showToast('No URL to scan', true); return; }

  dom.btnScan.classList.add('scanning');
  dom.btnScan.innerHTML = '<span class="btn-icon">⟳</span> Scanning…';

  // Ask the background service worker to scan
  chrome.runtime.sendMessage({ type: 'SCAN_URL', url: currentTabUrl }, (res) => {
    dom.btnScan.classList.remove('scanning');
    dom.btnScan.innerHTML = '<span class="btn-icon">⟳</span> Scan Site';

    if (chrome.runtime.lastError || !res || !res.result) {
      showToast('Scan failed', true);
      return;
    }

    applyResult(res.result);
    renderHistory();
    showToast('Scan complete ✓');
  });
}

/**
 * Show the scan detail modal.
 */
function handleDetails() {
  if (!latestResult) {
    showToast('Scan the site first', true);
    return;
  }
  const r = latestResult;
  dom.modalBody.innerHTML = `
    <p><strong>URL:</strong> ${escapeHtml(r.url)}</p>
    <p><strong>Safety Score:</strong> ${r.safetyScore}%</p>
    <p><strong>Risk Score:</strong> ${r.riskScore}%</p>
    <p><strong>Risk Level:</strong> ${r.riskLevel}</p>
    <p><strong>AI Verdict:</strong> ${capitalise(r.verdict)}</p>
    <p><strong>Scanned:</strong> ${new Date(r.timestamp).toLocaleString()}</p>
    <p style="margin-top:10px"><strong>Threats (${(r.threats||[]).length}):</strong></p>
    <ul style="padding-left:18px">
      ${(r.threats||[]).map(t => `<li>${escapeHtml(t.label)} <em>(${t.severity})</em></li>`).join('')}
    </ul>
    <p style="margin-top:10px"><strong>Raw Analysis:</strong></p>
    <pre>${JSON.stringify(r, null, 2)}</pre>`;
  dom.detailModal.classList.add('open');
}

/**
 * Report the current site and save to phishing history.
 */
async function handleReport() {
  if (!currentTabUrl) { showToast('No URL to report', true); return; }
  const { reportedSites = [] } = await chrome.storage.local.get('reportedSites');
  if (reportedSites.includes(currentTabUrl)) {
    showToast('Already reported', true);
    return;
  }
  reportedSites.push(currentTabUrl);
  await chrome.storage.local.set({ reportedSites });
  showToast('Site reported 🚩');
}

/**
 * Export scan history as JSON file.
 */
async function handleExport() {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
  if (scanHistory.length === 0) {
    showToast('No history to export', true);
    return;
  }
  const blob = new Blob([JSON.stringify(scanHistory, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `phishguard-history-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('History exported ⬇');
}

/* ════════════════════════════════════════════════════════════
   UTILITIES
   ════════════════════════════════════════════════════════════ */

function showToast(msg, isError = false) {
  dom.toast.textContent = msg;
  dom.toast.className   = `toast show ${isError ? 'error' : ''}`;
  setTimeout(() => dom.toast.classList.remove('show'), 2600);
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function capitalise(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function truncate(s, max) {
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return str.replace(/[&<>"']/g, (c) => map[c]);
}
