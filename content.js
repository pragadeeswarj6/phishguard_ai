/**
 * ════════════════════════════════════════════════════════════════
 * PhishGuard AI — Content Script
 * Injected into every page. Performs page-level threat detection
 * and renders the full-screen phishing warning overlay.
 * ════════════════════════════════════════════════════════════════
 */

(() => {
  'use strict';

  /* ─── Guard against double-injection ────────────────────── */
  if (window.__phishGuardInjected) return;
  window.__phishGuardInjected = true;

  /* ══════════════════════════════════════════════════════════
     PAGE-LEVEL THREAT DETECTION
     ══════════════════════════════════════════════════════════ */

  /**
   * Analyse the current page DOM for phishing indicators.
   * Results are sent back to the background service worker.
   */
  function detectPageThreats() {
    const threats = [];

    /* ── 1. Password fields on insecure (HTTP) pages ────── */
    if (location.protocol === 'http:') {
      const pwFields = document.querySelectorAll('input[type="password"]');
      if (pwFields.length > 0) {
        threats.push({
          label: `Password field on insecure page (HTTP)`,
          severity: 'critical',
        });
      }
    }

    /* ── 2. Hidden forms ────────────────────────────────── */
    const hiddenForms = document.querySelectorAll(
      'form[style*="display:none"], form[style*="display: none"], form[style*="visibility:hidden"], form.hidden'
    );
    if (hiddenForms.length > 0) {
      threats.push({
        label: `${hiddenForms.length} hidden form(s) detected`,
        severity: 'critical',
      });
    }

    /* ── 3. Fake login form heuristics ──────────────────── */
    const forms = document.querySelectorAll('form');
    forms.forEach((form) => {
      const action = (form.action || '').toLowerCase();
      const inputs = form.querySelectorAll('input');
      const hasPassword = [...inputs].some((i) => i.type === 'password');
      const hasEmail    = [...inputs].some((i) =>
        i.type === 'email' || (i.name || '').match(/email|user|login/i)
      );

      if (hasPassword && hasEmail) {
        // Check if form action points to a different domain
        try {
          if (action && action.startsWith('http')) {
            const formDomain = new URL(action).hostname;
            if (formDomain !== location.hostname) {
              threats.push({
                label: `Login form submits data to external domain: ${formDomain}`,
                severity: 'critical',
              });
            }
          }
        } catch { /* ignore parse errors */ }
      }
    });

    /* ── 4. Password inputs with autocomplete off ───────── */
    const pwInputs = document.querySelectorAll('input[type="password"][autocomplete="off"]');
    if (pwInputs.length > 0) {
      threats.push({
        label: 'Password input has autocomplete disabled (possible phishing)',
        severity: 'warning',
      });
    }

    /* ── 5. External script injection ───────────────────── */
    const scripts = document.querySelectorAll('script[src]');
    let externalScriptCount = 0;
    scripts.forEach((s) => {
      try {
        const src = new URL(s.src, location.href);
        if (src.hostname !== location.hostname) externalScriptCount++;
      } catch { /* ignore */ }
    });
    if (externalScriptCount > 10) {
      threats.push({
        label: `High number of external scripts (${externalScriptCount})`,
        severity: 'warning',
      });
    }

    /* ── 6. IFrame to different origin ──────────────────── */
    const iframes = document.querySelectorAll('iframe[src]');
    iframes.forEach((iframe) => {
      try {
        const iSrc = new URL(iframe.src, location.href);
        if (iSrc.hostname !== location.hostname) {
          // Check for hidden iframes
          const style = window.getComputedStyle(iframe);
          if (
            parseInt(style.width) <= 1 ||
            parseInt(style.height) <= 1 ||
            style.display === 'none' ||
            style.visibility === 'hidden'
          ) {
            threats.push({
              label: `Hidden iframe loading external content: ${iSrc.hostname}`,
              severity: 'critical',
            });
          }
        }
      } catch { /* ignore */ }
    });

    /* ── 7. Page title mimicking known brands ───────────── */
    const brandNames = [
      'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
      'facebook', 'instagram', 'bank', 'chase', 'wells fargo', 'citibank',
    ];
    const title = (document.title || '').toLowerCase();
    const matchedBrand = brandNames.find((b) => title.includes(b));
    if (matchedBrand) {
      // Check if the actual domain matches the brand
      const hostname = location.hostname.toLowerCase();
      if (!hostname.includes(matchedBrand.replace(' ', ''))) {
        threats.push({
          label: `Page title mimics "${matchedBrand}" but domain does not match`,
          severity: 'critical',
        });
      }
    }

    /* ── Send threats to background ─────────────────────── */
    if (threats.length > 0) {
      chrome.runtime.sendMessage({ type: 'PAGE_THREATS', threats }).catch(() => {
        // Safe to ignore: background script not ready or context invalidated
      });
    }
  }

  // Run detection after a brief delay to ensure page is rendered
  setTimeout(detectPageThreats, 1500);

  /* ══════════════════════════════════════════════════════════
     PHISHING WARNING OVERLAY
     ══════════════════════════════════════════════════════════ */

  /**
   * Inject a full-screen warning overlay into the page.
   * Called by the background service worker via message.
   */
  function showPhishingOverlay(result) {
    // Prevent duplicate overlays
    if (document.getElementById('phishguard-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-overlay';

    overlay.innerHTML = `
      <style>
        #phishguard-overlay {
          position: fixed !important;
          inset: 0 !important;
          z-index: 2147483647 !important;
          background: rgba(5, 8, 18, 0.97) !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: 'Segoe UI', system-ui, -apple-system, sans-serif !important;
          animation: pgFadeIn 0.4s ease-out !important;
          backdrop-filter: blur(8px) !important;
        }

        @keyframes pgFadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }

        @keyframes pgPulse {
          0%, 100% { transform: scale(1); }
          50%      { transform: scale(1.05); }
        }

        @keyframes pgSlideUp {
          from { opacity: 0; transform: translateY(20px); }
          to   { opacity: 1; transform: translateY(0); }
        }

        @keyframes pgGlow {
          0%, 100% { box-shadow: 0 0 30px rgba(255,59,92,0.2); }
          50%      { box-shadow: 0 0 50px rgba(255,59,92,0.35); }
        }

        .pg-card {
          max-width: 480px;
          width: 90%;
          background: linear-gradient(145deg, #111827, #0d1117) !important;
          border: 1px solid rgba(255,59,92,0.25) !important;
          border-radius: 20px !important;
          padding: 40px 36px !important;
          text-align: center !important;
          animation: pgSlideUp 0.5s ease-out 0.1s both, pgGlow 3s ease-in-out infinite !important;
        }

        .pg-shield {
          font-size: 64px !important;
          line-height: 1 !important;
          margin-bottom: 12px !important;
          animation: pgPulse 2s ease-in-out infinite !important;
          display: block !important;
        }

        .pg-title {
          font-size: 22px !important;
          font-weight: 800 !important;
          color: #ff3b5c !important;
          margin: 0 0 6px !important;
          letter-spacing: -0.3px !important;
          text-transform: uppercase !important;
        }

        .pg-subtitle {
          font-size: 13px !important;
          color: #8896b3 !important;
          margin: 0 0 24px !important;
        }

        .pg-risk-bar {
          width: 100% !important;
          height: 6px !important;
          background: #1a2236 !important;
          border-radius: 99px !important;
          overflow: hidden !important;
          margin-bottom: 24px !important;
        }

        .pg-risk-fill {
          height: 100% !important;
          background: linear-gradient(90deg, #f5a623, #ff3b5c) !important;
          border-radius: 99px !important;
          transition: width 1s ease-out !important;
        }

        .pg-threats {
          text-align: left !important;
          margin: 0 0 28px !important;
          padding: 0 !important;
          list-style: none !important;
        }

        .pg-threats li {
          display: flex !important;
          align-items: center !important;
          gap: 10px !important;
          font-size: 14px !important;
          color: #c4cee0 !important;
          padding: 8px 14px !important;
          margin-bottom: 6px !important;
          background: rgba(255,59,92,0.06) !important;
          border-radius: 10px !important;
          border-left: 3px solid #ff3b5c !important;
        }

        .pg-threats li .pg-icon {
          font-size: 18px !important;
          flex-shrink: 0 !important;
        }

        .pg-actions {
          display: flex !important;
          gap: 12px !important;
          justify-content: center !important;
        }

        .pg-btn {
          padding: 12px 28px !important;
          border-radius: 12px !important;
          border: none !important;
          font-family: inherit !important;
          font-size: 14px !important;
          font-weight: 700 !important;
          cursor: pointer !important;
          transition: transform 0.15s, box-shadow 0.25s !important;
        }

        .pg-btn:active {
          transform: scale(0.96) !important;
        }

        .pg-btn-leave {
          background: linear-gradient(135deg, #ff3b5c, #d62246) !important;
          color: #fff !important;
          box-shadow: 0 4px 20px rgba(255,59,92,0.3) !important;
        }

        .pg-btn-leave:hover {
          box-shadow: 0 4px 28px rgba(255,59,92,0.45) !important;
        }

        .pg-btn-continue {
          background: #1a2236 !important;
          color: #8896b3 !important;
          border: 1px solid rgba(255,255,255,0.06) !important;
        }

        .pg-btn-continue:hover {
          background: #1f2c42 !important;
          color: #c4cee0 !important;
        }

        .pg-footer {
          margin-top: 20px !important;
          font-size: 11px !important;
          color: #3e4f6e !important;
        }
      </style>

      <div class="pg-card">
        <span class="pg-shield">⚠️</span>
        <h1 class="pg-title">Phishing Website Detected</h1>
        <p class="pg-subtitle">PhishGuard AI has flagged this website as potentially dangerous.</p>

        <div class="pg-risk-bar">
          <div class="pg-risk-fill" style="width: ${result.riskScore || 80}%"></div>
        </div>

        <ul class="pg-threats">
          <li><span class="pg-icon">🔑</span> <span>This website may steal your <strong>passwords</strong></span></li>
          <li><span class="pg-icon">🏦</span> <span>Your <strong>banking information</strong> could be compromised</span></li>
          <li><span class="pg-icon">👤</span> <span>Your <strong>personal data</strong> is at risk</span></li>
        </ul>

        <div class="pg-actions">
          <button class="pg-btn pg-btn-leave" id="pgLeave">← Leave Website</button>
          <button class="pg-btn pg-btn-continue" id="pgContinue">Continue Anyway</button>
        </div>

        <p class="pg-footer">Protected by PhishGuard AI · SIH25159</p>
      </div>
    `;

    document.body.appendChild(overlay);

    /* ── Leave button: navigate to safety ─────────────── */
    document.getElementById('pgLeave').addEventListener('click', () => {
      window.location.href = 'https://www.google.com';
    });

    /* ── Continue: dismiss overlay ────────────────────── */
    document.getElementById('pgContinue').addEventListener('click', () => {
      overlay.style.animation = 'pgFadeIn 0.3s ease-in reverse forwards';
      setTimeout(() => overlay.remove(), 300);
    });
  }

  /* ══════════════════════════════════════════════════════════
     MESSAGE LISTENER
     ══════════════════════════════════════════════════════════ */

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'PHISHING_WARNING' && msg.result) {
      showPhishingOverlay(msg.result);
    }
  });
})();
