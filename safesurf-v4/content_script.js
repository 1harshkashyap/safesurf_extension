/**
 * SafeSurf AI – Content Script v5.0 (Hackathon Winner Edition)
 * =============================================================
 * v5 UPGRADES:
 *  + Floating real-time risk badge on every page
 *  + Live DOM threat tracking (enhanced MutationObserver)
 *  + Behavioral anomaly detection
 *  + Domain reputation intelligence layer
 *  + Deep explainability engine (weighted signal reasoning)
 *  + Auto form blocking on danger pages
 *  + Attack category tagging
 *  + Safe preview mode
 *  + Demo mode support
 *  + Analysis timing
 *  + Fail-safe messaging
 *
 *  v4 FEATURES (retained):
 *  + Adaptive trust system + Smart false positive filter
 *  + Attack simulation + Trust explanation engine
 *  + Real-time scan state + Visit counter
 *
 *  Architecture: Layered (Detection → Scoring → Explanation → UI)
 *  100% self-contained, no ES module imports.
 */

(function SafeSurfAI_v5() {
  'use strict';

  if (window.__SafeSurf && window.__SafeSurf.v >= 5) return;
  window.__SafeSurf = { v: 5, state: null, scanCount: 0, demoMode: false };
  console.log('[SafeSurf v5] Loaded →', location.href);

  // ================================================================
  // CONSTANTS
  // ================================================================

  const PHISHING_KEYWORDS = [
    'verify your account','confirm your identity','urgent action required',
    'account suspended','login immediately','your account will be closed',
    'verify now','act immediately','security alert','unusual activity',
    'click here to verify','update your payment','your password expired',
    'winner','you have been selected','free gift','claim your prize',
    'limited time offer','expires soon','last chance','bank details',
    'social security','enter your otp','enter your pin','confirm payment',
    'validate your','reactivate your','suspicious login','blocked account',
    'unauthorized access','final notice','last warning','action required'
  ];

  const URGENCY_WORDS = [
    'verify','urgent','immediately','suspended','confirm','validate',
    'expires','blocked','act now','warning','critical','alert',
    'important','required','locked','restricted','unauthorized',
    'limited time','final notice','last warning','action required'
  ];

  // FIXED: Only truly high-risk inputs — NOT generic search/email fields
  const SUSPICIOUS_INPUT_NAMES = [
    'ssn','social_security','cvv','cvc','card_number','cardnumber',
    'credit_card','creditcard','debit_card','debitcard','bank_account',
    'bankaccount','routing_number','passport','drivers_license',
    'license_number','tax_id','taxid','pin_number','pin_code',
    'secret_answer','security_answer','mothers_maiden'
  ];

  const TRUSTED_DOMAINS = [
    'google.com','microsoft.com','apple.com','amazon.com','github.com',
    'stackoverflow.com','mozilla.org','wikipedia.org','youtube.com',
    'linkedin.com','twitter.com','x.com','facebook.com','instagram.com',
    'netflix.com','spotify.com','adobe.com','cloudflare.com','reddit.com',
    'anthropic.com','openai.com','stripe.com','paypal.com','shopify.com',
    'dropbox.com','notion.so','slack.com','zoom.us','discord.com',
    'httpbin.org','example.com','w3schools.com','codepen.io',
    'twitch.tv','ebay.com','walmart.com','bestbuy.com','target.com',
    'localhost','127.0.0.1'
  ];

  const BRAND_LOOKALIKES = [
    'paypal','google','microsoft','apple','amazon','netflix',
    'facebook','instagram','twitter','linkedin','chase','wellsfargo',
    'citibank','hsbc','barclays','dropbox','github','yahoo',
    'gmail','outlook','hotmail','coinbase','binance','robinhood'
  ];

  const SUSPICIOUS_URL_TERMS = [
    'login','signin','verify','secure','account','update',
    'confirm','banking','payment','wallet','recover','auth',
    'credential','password','billing'
  ];

  // ================================================================
  // UTILITIES
  // ================================================================

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = [];
    for (let i = 0; i <= m; i++) {
      dp[i] = [i];
      for (let j = 1; j <= n; j++) dp[i][j] = i === 0 ? j : 0;
    }
    for (let i = 1; i <= m; i++)
      for (let j = 1; j <= n; j++)
        dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[m][n];
  }

  function checkLookalike(hostname) {
    const clean = hostname.replace(/^www\./, '').toLowerCase();
    for (const brand of BRAND_LOOKALIKES) {
      const canonical = brand + '.com';
      if (clean === canonical) return false;
      if (clean.includes(brand) && clean !== canonical) return true;
      if (clean.length < 30 && levenshtein(clean, canonical) <= 2) return true;
    }
    return false;
  }

  function isTrustedDomain(hostname) {
    const clean = hostname.replace(/^www\./, '').toLowerCase();
    if (clean === 'localhost' || /^127\.|^192\.168\./.test(clean)) return true;
    return TRUSTED_DOMAINS.some(d => clean === d || clean.endsWith('.' + d));
  }

  function safeText(el) {
    try { return (el.innerText || el.textContent || '').toLowerCase().trim(); } catch { return ''; }
  }

  /** ✅ FIX: Detect if a form is a benign search/GET form */
  function isSearchOrGetForm(form) {
    const method = (form.method || form.getAttribute('method') || 'get').toLowerCase();
    if (method === 'get') return true;
    const action = (form.action || '').toLowerCase();
    if (/search|query|find|q=/.test(action)) return true;
    const inputs = Array.from(form.querySelectorAll('input'));
    const hasSearch = inputs.some(i => i.type === 'search' || (i.name||'').toLowerCase() === 'q');
    const hasPassword = inputs.some(i => i.type === 'password');
    return hasSearch && !hasPassword;
  }

  // ================================================================
  // DETECTION ENGINES
  // ================================================================

  function analyzeURL() {
    const hostname = location.hostname;
    const signals = [];
    let riskScore = 0;

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      riskScore += 40;
      signals.push({ text: 'IP address used instead of domain name', severity: 'high', confidence: 95 });
    }
    const parts = hostname.split('.');
    if (parts.length > 4) {
      riskScore += 20;
      signals.push({ text: `Deep subdomain chain (${parts.length - 2} levels)`, severity: 'medium', confidence: 75 });
    }
    const domainLower = hostname.toLowerCase();
    const foundTerms = SUSPICIOUS_URL_TERMS.filter(t => domainLower.includes(t));
    if (foundTerms.length > 0 && !isTrustedDomain(hostname)) {
      riskScore += Math.min(25, foundTerms.length * 8);
      signals.push({ text: `Security-sensitive keywords in domain: "${foundTerms.slice(0,2).join('", "')}"`, severity: 'medium', confidence: 68 });
    }
    if (checkLookalike(hostname)) {
      riskScore += 40;
      signals.push({ text: 'Domain resembles a major brand — possible impersonation', severity: 'high', confidence: 88 });
    }
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 1 && !isTrustedDomain(hostname)) {
      riskScore += Math.min(18, hyphenCount * 6);
      signals.push({ text: `${hyphenCount} hyphens in domain (common in phishing URLs)`, severity: hyphenCount > 2 ? 'medium' : 'low', confidence: 62 });
    }
    if (hostname.length > 40) {
      riskScore += 8;
      signals.push({ text: `Unusually long domain name (${hostname.length} chars)`, severity: 'low', confidence: 55 });
    }
    if (location.protocol === 'http:' && /login|signin|auth|account/.test(location.pathname.toLowerCase())) {
      riskScore += 25;
      signals.push({ text: 'Login/auth page served over unencrypted HTTP', severity: 'high', confidence: 92 });
    }

    return {
      hostname,
      riskScore: Math.min(100, riskScore),
      level: riskScore >= 55 ? 'high' : riskScore >= 25 ? 'medium' : 'low',
      signals
    };
  }

  function detectPhishingIntent() {
    const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5'));
    const buttons  = Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a[class*="btn"]'));
    const labels   = Array.from(document.querySelectorAll('label,p,span,li'));

    const hText = headings.map(safeText).join(' ');
    const bText = buttons.map(el => safeText(el) || (el.value||'').toLowerCase()).join(' ');
    const lText = labels.slice(0, 60).map(safeText).join(' ');

    const inH = URGENCY_WORDS.filter(w => hText.includes(w));
    const inB = URGENCY_WORDS.filter(w => bText.includes(w));
    const inL = URGENCY_WORDS.filter(w => lText.includes(w));
    const all = [...new Set([...inH, ...inB, ...inL])];

    const score = Math.min(100, inH.length * 20 + inB.length * 15 + inL.length * 4);
    const detected = score >= 25;
    let detail = '';
    if (inH.length) detail += `Headings use urgency: "${inH.slice(0,2).join('", "')}". `;
    if (inB.length) detail += `Buttons use pressure: "${inB.slice(0,2).join('", "')}". `;

    return {
      detected, intentScore: score,
      confidence: detected ? Math.min(90, 40 + score) : 85,
      allFound: all.slice(0, 7), foundInHeadings: inH, foundInButtons: inB,
      detail: detail.trim(),
      aiExplanation: detected
        ? `Phishing pages use psychological pressure to bypass rational thought. Phrases like "${all.slice(0,2).join('" and "')}" in headings and buttons trigger fear responses that make you act without verifying the site.`
        : null
    };
  }

  function detectFakeLogin() {
    const hostname    = location.hostname;
    const isLookalike = checkLookalike(hostname);
    const isUntrusted = !isTrustedDomain(hostname);
    const isHttp      = location.protocol === 'http:';
    const hasPwField  = !!document.querySelector('input[type="password"]');

    const imgs = Array.from(document.querySelectorAll('img'));
    const brandNames = ['logo','brand','paypal','google','microsoft','apple','amazon','bank','chase'];
    const hasBrandImg = imgs.some(img => {
      const src = (img.src || '').toLowerCase();
      const alt = (img.alt || '').toLowerCase();
      return brandNames.some(b => src.includes(b) || alt.includes(b));
    });

    const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4'));
    const loginWords = ['sign in','log in','login','signin','verify','authenticate','account access'];
    const hasLoginHeading = headings.some(h => loginWords.some(w => safeText(h).includes(w)));
    const formsWithPw = Array.from(document.querySelectorAll('form')).filter(f => f.querySelector('input[type="password"]'));

    let score = 0;
    const signals = [], indicators = [];
    if (hasPwField)                             { score += 20; indicators.push('Password field present'); }
    if (isLookalike)                            { score += 45; signals.push('Domain impersonates a trusted brand'); indicators.push('Lookalike domain'); }
    if (isHttp && hasPwField)                   { score += 30; signals.push('Credentials sent over unencrypted HTTP'); indicators.push('HTTP login'); }
    if (isUntrusted && formsWithPw.length > 0) { score += 20; indicators.push('Login form on unverified domain'); }
    if (hasBrandImg && isUntrusted)             { score += 15; signals.push('Brand imagery on unverified domain'); indicators.push('Brand image mismatch'); }
    if (hasLoginHeading && isUntrusted && isLookalike) { score += 20; signals.push('Impersonates a trusted service login page'); }

    const detected = score >= 50;
    return {
      detected, score: Math.min(100, score),
      confidence: detected ? Math.min(93, 35 + score) : 82,
      signals, indicators, hasPasswordField: hasPwField, isLookalike,
      hasBrandImage: hasBrandImg, formsWithPassword: formsWithPw.length,
      aiExplanation: detected
        ? `This page exhibits ${signals.length} credential-harvesting indicators. ${signals[0] ? signals[0] + '. ' : ''}Submitting your credentials here would send them directly to the attacker. Navigate directly to the real service via a bookmark or by manually typing the URL.`
        : null
    };
  }

  // ================================================================
  // FORM ANALYSIS — v4 FALSE POSITIVE FIX
  // ================================================================

  function analyzeForms(isTrusted) {
    const formEls = document.querySelectorAll('form');
    console.log(`[SafeSurf v4] Forms found: ${formEls.length}`);
    const results = [];

    formEls.forEach((form, idx) => {
      const isBenignForm = isSearchOrGetForm(form);
      const inputs       = Array.from(form.querySelectorAll('input,select,textarea'));
      const inputNames   = inputs.map(i => (i.name || i.id || i.getAttribute('type') || '').toLowerCase());
      const inputTypes   = inputs.map(i => (i.type || '').toLowerCase());

      // ── CSRF detection (SMART — skip for GET/search forms) ──
      const CSRF_NAMES = ['csrf','_token','authenticity_token','__requestverificationtoken',
        'csrftoken','csrf_token','_csrf','xsrf','xsrf_token','_wpnonce','nonce'];
      const hasCSRFToken = inputs.some(inp => {
        const n = (inp.name || inp.id || '').toLowerCase();
        return inp.type === 'hidden' && CSRF_NAMES.some(c => n.includes(c));
      });

      // ── FIXED: Only warn about missing CSRF on POST forms with sensitive data ──
      // GET forms and search forms don't need CSRF tokens
      const csrfWarningApplies = !isBenignForm && !hasCSRFToken;
      // Trusted domains: downgrade CSRF to informational only
      const csrfSeverity = isTrusted ? 'info' : 'medium';

      const action = form.action || form.getAttribute('action') || '';
      let actionDiffDomain = false, actionIsHttp = false;
      if (action && action.startsWith('http')) {
        try {
          const u = new URL(action);
          actionDiffDomain = u.hostname !== location.hostname;
          actionIsHttp     = u.protocol === 'http:';
        } catch {}
      }

      const hasSuspiciousFields = inputNames.some(n => SUSPICIOUS_INPUT_NAMES.some(s => n.includes(s)));
      const hasPasswordField    = inputTypes.includes('password');
      const hasEmailField       = inputTypes.includes('email');
      const method              = (form.method || form.getAttribute('method') || 'get').toLowerCase();
      const visibleInputs       = inputs.filter(i => !['hidden','submit','button','reset'].includes(i.type));
      const label               = form.id || form.name || form.getAttribute('aria-label') || `form_${idx + 1}`;

      // ── Form risk level (v4: smarter) ──
      let riskLevel = 'low';
      if (actionDiffDomain || actionIsHttp || hasSuspiciousFields) {
        riskLevel = 'high';
      } else if (csrfWarningApplies && csrfSeverity !== 'info' && hasPasswordField) {
        riskLevel = 'medium';
      } else if (csrfWarningApplies && csrfSeverity !== 'info') {
        riskLevel = 'medium';
      }

      // Search/GET forms are always low risk
      if (isBenignForm) riskLevel = 'low';

      results.push({
        index: idx, id: label, action: action.substring(0, 120),
        method, inputCount: inputs.length, visibleInputCount: visibleInputs.length,
        hiddenFieldCount: inputs.filter(i => i.type === 'hidden').length,
        hasCSRFToken, csrfWarningApplies, csrfSeverity,
        actionDiffDomain, actionIsHttp, hasSuspiciousFields,
        hasPasswordField, hasEmailField, isBenignForm,
        fieldNames: inputNames.filter(n => n).slice(0, 15),
        fieldTypes: [...new Set(inputTypes)].slice(0, 10),
        riskLevel
      });
    });

    return results;
  }

  function detectPhishingText() {
    const text = (document.body?.innerText || '').toLowerCase();
    return PHISHING_KEYWORDS.filter(kw => text.includes(kw));
  }

  function detectMixedContent() {
    if (location.protocol !== 'https:') return false;
    return Array.from(document.querySelectorAll('img[src],script[src],iframe[src]'))
      .some(el => (el.src || '').startsWith('http://'));
  }

  function countSuspiciousIframes() {
    return Array.from(document.querySelectorAll('iframe')).filter(fr => {
      try {
        const cs = window.getComputedStyle(fr);
        return cs.display === 'none' || cs.visibility === 'hidden'
          || parseFloat(cs.width) < 2 || parseFloat(cs.height) < 2
          || (fr.src && !fr.src.startsWith(location.origin) && !fr.src.startsWith('about:'));
      } catch { return false; }
    }).length;
  }

  function getRedirectCount() {
    try { return performance.getEntriesByType('navigation')[0]?.redirectCount || 0; }
    catch { return 0; }
  }

  function countExternalLinks() {
    return Array.from(document.querySelectorAll('a[href]')).filter(a => {
      try { return new URL(a.href).hostname !== location.hostname; } catch { return false; }
    }).length;
  }

  // ================================================================
  // EXTERNAL THREAT INTEL (NEW) — FREE URLHAUS + OPTIONAL GSB
  // ================================================================

  function requestThreatIntel(url) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage({ type: 'CHECK_THREAT_INTEL', url }, resp => {
          if (chrome.runtime.lastError) {
            resolve({ enabled: true, checked: false, malicious: false, threatTypes: [], source: 'runtime_error' });
            return;
          }
          resolve(resp && resp.intel ? resp.intel : { enabled: true, checked: false, malicious: false, threatTypes: [], source: 'empty_response' });
        });
      } catch {
        resolve({ enabled: true, checked: false, malicious: false, threatTypes: [], source: 'request_failed' });
      }
    });
  }

  // ================================================================
  // ADAPTIVE TRUST SYSTEM (NEW v4)
  // ================================================================

  /**
   * Reads visit history from storage to determine if user has
   * safely visited this hostname before. Returns adaptive trust data.
   * This runs async and updates state when complete.
   */
  function loadAdaptiveTrust(hostname) {
    return new Promise(resolve => {
      chrome.storage.local.get(['ss_history', 'ss_visit_counts'], data => {
        const history    = data.ss_history    || [];
        const counts     = data.ss_visit_counts || {};
        const visitCount = counts[hostname] || 0;

        // Previous safe visits to this domain
        const prevSafeVisits = history.filter(h =>
          h.hostname === hostname && h.level === 'safe'
        ).length;

        // Previous risk visits
        const prevRiskyVisits = history.filter(h =>
          h.hostname === hostname && (h.level === 'warning' || h.level === 'danger')
        ).length;

        // Adaptive trust boost
        let adaptiveBoost = 0;
        let adaptiveMessage = null;

        if (prevSafeVisits >= 10) {
          adaptiveBoost = 12;
          adaptiveMessage = `You've visited this site ${visitCount || prevSafeVisits} times safely — trust confidence increased.`;
        } else if (prevSafeVisits >= 5) {
          adaptiveBoost = 8;
          adaptiveMessage = `${prevSafeVisits} previous safe visits to this site — trust increased.`;
        } else if (prevSafeVisits >= 2) {
          adaptiveBoost = 4;
          adaptiveMessage = `${prevSafeVisits} previous safe visits noted.`;
        }

        // Penalise repeat risky visits (shouldn't trust a site you've flagged before)
        if (prevRiskyVisits >= 2) {
          adaptiveBoost -= 5;
          adaptiveMessage = `⚠️ This site has been flagged ${prevRiskyVisits} times in your history.`;
        }

        // Increment visit count in storage
        counts[hostname] = (counts[hostname] || 0) + 1;
        chrome.storage.local.set({ ss_visit_counts: counts });

        resolve({
          visitCount: counts[hostname],
          prevSafeVisits,
          prevRiskyVisits,
          adaptiveBoost: Math.max(-10, Math.min(15, adaptiveBoost)),
          adaptiveMessage,
          isRepeatVisitor: visitCount >= 2
        });
      });
    });
  }

  // ================================================================
  // CONFIDENCE SCORE
  // ================================================================

  function calculateConfidence(raw, scored, urlRisk, fakeLogin, phishIntent, adaptive, safeBrowsing) {
    let conf = 50;
    const issues = scored.risks.length + scored.warnings.length;

    if (issues >= 4) conf += 15;
    else if (issues >= 2) conf += 10;
    else if (issues >= 1) conf += 5;

    conf += 5; // HTTPS is always definitive
    if (raw.forms.length > 0) conf += 4;
    if (urlRisk.signals.length > 0) conf += 5;
    if (phishIntent.detected) conf += 8;
    if (fakeLogin.detected) conf += 10;
    if (raw.isTrustedDomain) conf += 8;
    if (safeBrowsing && safeBrowsing.checked) conf += 6;
    if (safeBrowsing && safeBrowsing.malicious) conf += 8;

    const corroborating = [
      urlRisk.riskScore > 30,
      phishIntent.detected,
      fakeLogin.detected,
      raw.phishingKeywordsFound.length > 0,
      scored.risks.some(r => r.id === 'no_https'),
      scored.risks.some(r => r.id === 'form_diff_domain'),
      safeBrowsing && safeBrowsing.malicious
    ].filter(Boolean).length;

    if (corroborating >= 3) conf += 18;
    else if (corroborating >= 2) conf += 10;

    // Adaptive: more history data = higher confidence in assessment
    if (adaptive.prevSafeVisits >= 5) conf += 5;
    if (adaptive.isRepeatVisitor) conf += 3;

    return Math.round(Math.min(95, Math.max(42, conf)) / 5) * 5;
  }

  // ================================================================
  // MASTER SCORING ENGINE
  // ================================================================

  function scoreData(raw, urlRisk, fakeLogin, phishIntent, adaptive, trusted, safeBrowsing) {
    let score = 100;
    const risks = [], warnings = [], passes = [];

    // 1. HTTPS
    if (!raw.isHttps) {
      score -= 30;
      risks.push({ id:'no_https', severity:'high',
        title:'No Secure Connection (HTTP)',
        detail:'All data you submit travels as readable plain text across the network.',
        tip:'Never enter passwords or payment info on HTTP sites.',
        confidence: 98,
        aiExplanation:'HTTP sends your data as readable text. Anyone on the same WiFi — at a café, airport, or office — can intercept and read every keystroke using freely available tools. This is a Man-in-the-Middle attack requiring zero technical skill to execute.'
      });
    } else {
      passes.push({ id:'https', title:'Encrypted HTTPS Connection', detail:'Data is protected in transit using TLS encryption.', confidence: 98 });
    }

    // 2. Fake Login
    if (fakeLogin.detected) {
      score -= 38;
      risks.push({ id:'fake_login', severity:'critical',
        title:'🚨 Fake Login Page Detected',
        detail:`${fakeLogin.indicators.slice(0,3).join(', ')}. Confidence: ${fakeLogin.confidence}%`,
        tip:'Do NOT enter credentials. Close this tab immediately.',
        confidence: fakeLogin.confidence,
        aiExplanation: fakeLogin.aiExplanation
      });
    }

    // 3. Phishing Intent
    if (phishIntent.detected) {
      score -= Math.min(18, Math.round(phishIntent.intentScore / 5));
      risks.push({ id:'phishing_intent', severity: phishIntent.intentScore > 50 ? 'high' : 'medium',
        title:'Phishing Intent Language Detected',
        detail: phishIntent.detail || `Urgency phrases: "${phishIntent.allFound.slice(0,3).join('", "')}"`,
        tip:'Legitimate services never pressure or threaten you through their UI.',
        confidence: phishIntent.confidence,
        aiExplanation: phishIntent.aiExplanation
      });
    }

    // 4. URL Risk
    if (urlRisk.riskScore >= 55) {
      score -= Math.min(28, Math.round(urlRisk.riskScore / 3.5));
      risks.push({ id:'url_risk', severity:'high',
        title:'High-Risk URL Structure',
        detail: urlRisk.signals.map(s => s.text).join('. '),
        tip:'Read the domain name carefully — the real domain is always immediately before .com/.net/etc.',
        confidence: 78,
        aiExplanation:'Attackers craft URLs exploiting cognitive shortcuts. They embed familiar brand names in subdomains, add hyphens, and use long strings to create an illusion of legitimacy.'
      });
    } else if (urlRisk.riskScore >= 25) {
      score -= Math.min(10, Math.round(urlRisk.riskScore / 5));
      warnings.push({ id:'url_caution', severity:'medium',
        title:'URL Contains Suspicious Patterns',
        detail: urlRisk.signals[0]?.text || 'URL structure has unusual patterns.',
        tip:'Verify this is the site you intended to visit.',
        confidence: 65, aiExplanation: null
      });
    }

    // 5. Lookalike
    if (raw.isLookalike && !fakeLogin.detected) {
      score -= 25;
      risks.push({ id:'lookalike', severity:'high',
        title:'Lookalike Domain Detected',
        detail:`"${raw.hostname}" closely mimics a well-known brand's domain.`,
        tip:'Check every character carefully. Look for digit substitutions (1→l, 0→o) or extra words.',
        confidence: 85,
        aiExplanation:'Typosquatting registers visually similar domains (paypa1.com, g00gle.com). Users scan URLs quickly and miss subtle differences. This domain appears engineered to deceive at a glance.'
      });
    }

    // 6. Form Security (v4: SMART false positive filter applied)
    if (raw.forms.length > 0) {
      const badForms     = raw.forms.filter(f => !f.isBenignForm);
      const noCSRF       = badForms.filter(f => f.csrfWarningApplies);
      const diffDomain   = raw.forms.filter(f => f.actionDiffDomain);
      const suspFields   = raw.forms.filter(f => f.hasSuspiciousFields);
      const httpAction   = raw.forms.filter(f => f.actionIsHttp);
      const pwUnknown    = raw.forms.filter(f => f.hasPasswordField && !trusted);
      const benignForms  = raw.forms.filter(f => f.isBenignForm);

      if (diffDomain.length > 0) {
        score -= 25;
        risks.push({ id:'form_diff_domain', severity:'high',
          title:`Form Submits to External Domain (${diffDomain.length})`,
          detail:`${diffDomain.length} form(s) send your input to a different domain. Current page: ${raw.hostname}`,
          tip:"This is the #1 phishing form technique. Your data goes to the attacker's server.",
          confidence: 93,
          aiExplanation:"The form's action attribute points to an attacker-controlled server. When you click Submit, all entered data — username, password, card number — is transmitted directly to that external server instead of the site you think you're using."
        });
      }
      if (httpAction.length > 0) {
        score -= 18;
        risks.push({ id:'form_http_action', severity:'high',
          title:`Form Transmits Data Over HTTP (${httpAction.length})`,
          detail:'Even on an HTTPS page, this form sends your data unencrypted.',
          tip:'The HTTPS padlock is meaningless if the form action URL uses HTTP.',
          confidence: 96, aiExplanation: null
        });
      }
      if (suspFields.length > 0) {
        score -= 16;
        risks.push({ id:'suspicious_fields', severity:'high',
          title:'Highly Sensitive Field Names Detected',
          detail:'Forms collect extremely sensitive data: CVV, SSN, card numbers, or PINs.',
          tip:'PCI-compliant payment processors use isolated iframes — never plain HTML inputs.',
          confidence: 88, aiExplanation: null
        });
      }

      // ✅ FIXED: Only warn about CSRF if it's a real POST form and not trusted domain
      if (noCSRF.length > 0 && !trusted) {
        score -= 8;
        warnings.push({ id:'no_csrf', severity:'medium',
          title:`CSRF Protection Missing (${noCSRF.length} form${noCSRF.length > 1 ? 's' : ''})`,
          detail:`${noCSRF.length} POST form(s) lack CSRF security tokens. Search/GET forms are excluded from this check.`,
          tip:'Well-secured sites include hidden tokens in every POST form to prevent unauthorised submissions.',
          confidence: 80,
          aiExplanation:"CSRF tokens prevent attackers from tricking your browser into submitting forms while you're authenticated. Without them, visiting a malicious page could trigger actions (bank transfers, email changes) on sites where you're logged in."
        });
      } else if (noCSRF.length > 0 && trusted) {
        // Trusted domain: downgrade to informational pass
        passes.push({ id:'csrf_trusted', title:'CSRF Check (Trusted Domain)', detail:'CSRF token absent but domain is on trusted list — risk is negligible.', confidence: 70 });
      } else if (badForms.length > 0) {
        passes.push({ id:'csrf_ok', title:`CSRF Tokens Present (${badForms.length} form${badForms.length > 1 ? 's' : ''})`, detail:'POST forms include CSRF protection tokens.', confidence: 85 });
      }

      if (pwUnknown.length > 0) {
        score -= 7;
        warnings.push({ id:'password_unknown', severity:'medium',
          title:'Password Field on Unverified Domain',
          detail:'A password form was found on an unrecognised domain.',
          tip:'Verify you know and trust this site before typing any password.',
          confidence: 73, aiExplanation: null
        });
      }

      if (benignForms.length > 0) {
        passes.push({ id:'benign_forms', title:`${benignForms.length} Search/GET Form${benignForms.length > 1 ? 's' : ''} (Low Risk)`, detail:`${benignForms.length} form(s) use GET method or are search forms — no sensitive data risk.`, confidence: 95 });
      }

      passes.push({ id:'forms_scanned', title:`${raw.forms.length} Form${raw.forms.length > 1 ? 's' : ''} Fully Scanned`, detail:`All forms analysed with smart false-positive filtering.`, confidence: 99 });
    } else {
      passes.push({ id:'no_forms', title:'No Input Forms Detected', detail:'No HTML form elements found — no form-based attack vectors on this page.', confidence: 99 });
    }

    // 7. Phishing text
    if (raw.phishingKeywordsFound.length > 0) {
      const ded = Math.min(15, raw.phishingKeywordsFound.length * 3);
      score -= ded;
      risks.push({ id:'phishing_text', severity: raw.phishingKeywordsFound.length >= 4 ? 'high' : 'medium',
        title:`Phishing Language in Content (${raw.phishingKeywordsFound.length} phrase${raw.phishingKeywordsFound.length > 1 ? 's' : ''})`,
        detail:`Detected: "${raw.phishingKeywordsFound.slice(0,3).join('", "')}"`,
        tip:'These phrases are designed to create panic. Verify the URL before acting.',
        confidence: 76, aiExplanation: null
      });
    }

    // 8. External threat intelligence (Google Safe Browsing)
    if (safeBrowsing && safeBrowsing.malicious) {
      score -= 35;
      risks.push({ id:'threat_intel_match', severity:'critical',
        title:'External Threat Intel Flagged This URL',
        detail:`External threat intelligence matched: ${safeBrowsing.threatTypes.join(', ') || 'known malicious URL pattern'}.`,
        tip:'Leave immediately and do not submit credentials or downloads on this page.',
        confidence: 97,
        aiExplanation:'Independent threat-intelligence feeds reported this URL as malicious based on large-scale telemetry. This external signal strongly corroborates local detections and indicates active abuse infrastructure.'
      });
    } else if (safeBrowsing && safeBrowsing.checked) {
      passes.push({
        id:'threat_intel_clear',
        title:'External Threat Intel: No Match',
        detail:'External threat intelligence did not flag this URL.',
        confidence: 90
      });
    }

    // 9. Mixed content
    if (raw.hasMixedContent) {
      score -= 7;
      warnings.push({ id:'mixed_content', severity:'medium',
        title:'Mixed Content (HTTP resources on HTTPS page)',
        detail:'Some assets load over HTTP, weakening encryption.',
        confidence: 90, aiExplanation: null
      });
    }

    // 10. Iframes
    if (raw.suspiciousIframes > 0) {
      score -= Math.min(12, raw.suspiciousIframes * 4);
      warnings.push({ id:'suspicious_iframes', severity:'medium',
        title:`${raw.suspiciousIframes} Suspicious Hidden Iframe${raw.suspiciousIframes > 1 ? 's' : ''}`,
        detail:`${raw.suspiciousIframes} hidden/cross-origin iframe(s) detected.`,
        confidence: 78, aiExplanation: null
      });
    }

    // 11. Redirects
    if (raw.redirectCount > 2) {
      score -= 7;
      warnings.push({ id:'many_redirects', severity:'medium',
        title:`Redirect Chain: ${raw.redirectCount} Hops`,
        detail:`Went through ${raw.redirectCount} redirects to reach this page.`,
        confidence: 82, aiExplanation: null
      });
    }

    // 12. Trusted domain bonus
    if (trusted) {
      score = Math.min(100, score + 5);
      passes.push({ id:'trusted_domain', title:'Verified Trusted Domain', detail:'Domain is on the SafeSurf verified-safe list.', confidence: 96 });
    }

    // 13. ADAPTIVE TRUST BOOST
    if (adaptive.adaptiveBoost > 0) {
      score = Math.min(100, score + adaptive.adaptiveBoost);
      passes.push({
        id: 'adaptive_trust',
        title: `Adaptive Trust: +${adaptive.adaptiveBoost} points`,
        detail: adaptive.adaptiveMessage || `Previous safe visits boosted trust score.`,
        confidence: 85
      });
    } else if (adaptive.adaptiveBoost < 0) {
      score = Math.max(0, score + adaptive.adaptiveBoost);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = score >= 75 ? 'safe' : score >= 45 ? 'warning' : 'danger';

    return { score, level, label: score >= 75 ? 'Safe' : score >= 45 ? 'Caution' : 'High Risk', risks, warnings, passes };
  }

  // ================================================================
  // ATTACK SIMULATION ENGINE (NEW v4) — JUDGE KILLER FEATURE
  // ================================================================

  function buildAttackSimulation(scored, raw, fakeLogin, phishIntent) {
    const attacks = [];

    if (scored.risks.some(r => r.id === 'no_https')) {
      attacks.push({
        type: 'Network Interception',
        icon: '📡',
        severity: 'critical',
        whatHappens: 'Attacker on same WiFi reads every keystroke you type in real time.',
        stolen: ['Passwords', 'Session cookies', 'Form data', 'Credit card numbers'],
        consequence: 'Full account takeover on any service you log into on this connection.',
        difficulty: 'Trivial — free tools available, no technical skill needed'
      });
    }

    if (scored.risks.some(r => r.id === 'fake_login') || scored.risks.some(r => r.id === 'lookalike')) {
      attacks.push({
        type: 'Credential Harvesting',
        icon: '🎣',
        severity: 'critical',
        whatHappens: 'You enter your password thinking you\'re on the real site. It goes to the attacker.',
        stolen: ['Username', 'Password', 'Two-factor codes (if entered)', 'Security answers'],
        consequence: 'Immediate account takeover. Attacker logs into real service using your credentials.',
        difficulty: 'Common — millions of phishing pages created daily'
      });
    }

    if (scored.risks.some(r => r.id === 'form_diff_domain')) {
      attacks.push({
        type: 'Data Exfiltration via Form Hijack',
        icon: '📋',
        severity: 'high',
        whatHappens: 'Form sends submitted data to attacker\'s server instead of this site.',
        stolen: ['All form inputs', 'Passwords', 'Personal information', 'Payment data'],
        consequence: 'Data sold on dark web or used for identity theft within hours.',
        difficulty: 'Easy to execute, extremely hard to detect without tools like SafeSurf'
      });
    }

    if (scored.warnings.some(w => w.id === 'no_csrf')) {
      attacks.push({
        type: 'Cross-Site Request Forgery (CSRF)',
        icon: '🔄',
        severity: 'medium',
        whatHappens: 'A malicious page tricks your browser into submitting this form while you\'re logged in.',
        stolen: ['Actions performed in your name', 'Account changes', 'Unauthorised transactions'],
        consequence: 'Transfers, email changes, or data deletion executed without your knowledge.',
        difficulty: 'Moderate — requires you to visit a malicious page while logged in here'
      });
    }

    if (phishIntent.detected) {
      attacks.push({
        type: 'Social Engineering via Fear Manipulation',
        icon: '🧠',
        severity: 'medium',
        whatHappens: 'Urgency language triggers your amygdala, bypassing rational threat assessment.',
        stolen: ['Your judgement', 'Credentials entered in panic', 'Personal data submitted under pressure'],
        consequence: 'You act before verifying, providing attackers with exactly what they need.',
        difficulty: 'Highly effective — bypasses technical knowledge entirely'
      });
    }

    if (!attacks.length) {
      attacks.push({
        type: 'No Active Threats Simulated',
        icon: '✅',
        severity: 'none',
        whatHappens: 'No significant attack vectors detected on this page.',
        stolen: [],
        consequence: 'This page appears safe based on current analysis.',
        difficulty: 'N/A'
      });
    }

    return { attacks, generatedAt: Date.now() };
  }

  // ================================================================
  // TRUST EXPLANATION ENGINE (NEW v4)
  // ================================================================

  function buildTrustExplanation(scored, raw, fakeLogin, phishIntent, urlRisk, adaptive, trusted) {
    const positive = [], negative = [];

    // Positive factors
    if (raw.isHttps) positive.push('✔ HTTPS encryption enabled — data in transit is protected');
    if (trusted) positive.push('✔ Recognised trusted domain on SafeSurf verified list');
    if (adaptive.prevSafeVisits >= 2) positive.push(`✔ You've safely visited this site ${adaptive.prevSafeVisits} times before`);
    if (!raw.isLookalike) positive.push('✔ Domain name does not resemble known brand impersonations');
    if (!phishIntent.detected) positive.push('✔ No urgency or pressure language found on page');
    if (!fakeLogin.detected) positive.push('✔ No fake login page indicators detected');
    if (raw.forms.every(f => !f.actionDiffDomain)) positive.push('✔ All forms submit to the same domain');
    if (urlRisk.riskScore < 20) positive.push('✔ URL structure shows no suspicious patterns');
    if (scored.passes.some(p => p.id === 'threat_intel_clear')) positive.push('✔ External threat-intel feeds did not report this URL as malicious');

    // Negative factors
    if (!raw.isHttps) negative.push('✗ HTTP connection — data transmitted unencrypted');
    if (raw.isLookalike) negative.push('✗ Domain name resembles a known trusted brand');
    if (fakeLogin.detected) negative.push('✗ Fake login page indicators detected');
    if (phishIntent.detected) negative.push(`✗ ${phishIntent.allFound.length} urgency/pressure phrases found`);
    if (urlRisk.riskScore >= 40) negative.push(`✗ URL risk score: ${urlRisk.riskScore}/100`);
    if (scored.risks.some(r => r.id === 'threat_intel_match')) negative.push('✗ External threat-intel feeds flagged this URL as malicious');
    if (raw.forms.some(f => f.actionDiffDomain)) negative.push('✗ Form(s) submit data to external domain');
    if (raw.phishingKeywordsFound.length > 0) negative.push(`✗ ${raw.phishingKeywordsFound.length} phishing phrases in page content`);
    if (adaptive.prevRiskyVisits >= 2) negative.push(`✗ Previously flagged ${adaptive.prevRiskyVisits} times in your history`);

    return { positive: positive.slice(0, 6), negative: negative.slice(0, 6) };
  }

  // ================================================================
  // DOMAIN REPUTATION INTELLIGENCE (NEW v5)
  // ================================================================

  const SUSPICIOUS_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.buzz','.club','.work','.click','.link','.icu','.monster'];
  const FREE_HOSTING = ['000webhostapp.com','netlify.app','vercel.app','herokuapp.com','glitch.me','repl.co','github.io','pages.dev','web.app','firebaseapp.com','surge.sh','render.com'];
  const FINANCIAL_DOMAINS = ['paypal.com','stripe.com','chase.com','bankofamerica.com','wellsfargo.com','citibank.com','capitalone.com','amex.com','hsbc.com','barclays.com','revolut.com','wise.com'];
  const GOV_DOMAINS = ['.gov','.gov.uk','.gov.au','.gc.ca','.europa.eu'];

  function checkDomainReputation(hostname) {
    const clean = hostname.replace(/^www\./, '').toLowerCase();
    const tld = '.' + clean.split('.').slice(-1)[0];
    const fullTld = clean.substring(clean.lastIndexOf('.'));

    // Trusted
    if (isTrustedDomain(hostname)) return { status: 'trusted', icon: '🟢', reason: 'Verified trusted domain in SafeSurf database', category: 'known' };
    if (GOV_DOMAINS.some(g => clean.endsWith(g))) return { status: 'trusted', icon: '🏛️', reason: 'Government domain', category: 'government' };
    if (FINANCIAL_DOMAINS.some(f => clean === f || clean.endsWith('.' + f))) return { status: 'trusted', icon: '🏦', reason: 'Recognized financial institution', category: 'financial' };

    // Suspicious
    if (SUSPICIOUS_TLDS.includes(tld) || SUSPICIOUS_TLDS.includes(fullTld)) return { status: 'suspicious', icon: '🔴', reason: `High-risk TLD (${tld}) — commonly used in phishing`, category: 'risky_tld' };
    if (FREE_HOSTING.some(f => clean.endsWith(f))) return { status: 'caution', icon: '🟡', reason: 'Free hosting platform — verify content authenticity', category: 'free_hosting' };
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return { status: 'suspicious', icon: '🔴', reason: 'IP address used instead of domain name', category: 'ip_address' };
    if (clean.length > 30 && clean.split('.').length > 3) return { status: 'caution', icon: '🟡', reason: 'Unusually complex domain structure', category: 'complex' };

    return { status: 'unknown', icon: '⚪', reason: 'Domain not in reputation database — exercise normal caution', category: 'unknown' };
  }

  // ================================================================
  // BEHAVIORAL ANOMALY DETECTION (NEW v5)
  // ================================================================

  function detectBehavioralAnomalies() {
    const anomalies = [];
    let anomalyScore = 0;

    // 1. Auto-focus on password field
    try {
      if (document.activeElement && document.activeElement.type === 'password') {
        anomalies.push({ type: 'auto_password_focus', severity: 'high', detail: 'Password field is auto-focused — may trick users into typing credentials', weight: 15 });
        anomalyScore += 15;
      }
    } catch {}

    // 2. Hidden forms that became visible (potential popup trap)
    try {
      const forms = document.querySelectorAll('form');
      forms.forEach(f => {
        const rect = f.getBoundingClientRect();
        const style = window.getComputedStyle(f);
        if (f.querySelector('input[type="password"]') && (style.position === 'fixed' || style.position === 'absolute') && rect.width > 200) {
          anomalies.push({ type: 'popup_login', severity: 'high', detail: 'Positioned login form detected — potential popup credential trap', weight: 12 });
          anomalyScore += 12;
        }
      });
    } catch {}

    // 3. Clipboard hijacking listeners
    try {
      const el = document.body;
      const events = ['copy','paste','cut'];
      events.forEach(ev => {
        const listeners = getEventListeners ? null : null; // Can't detect reliably
      });
      // Check for onpaste/oncopy attributes
      const clipboardEls = document.querySelectorAll('[oncopy],[onpaste],[oncut]');
      if (clipboardEls.length > 0) {
        anomalies.push({ type: 'clipboard_hijack', severity: 'medium', detail: `${clipboardEls.length} element(s) with clipboard interception handlers`, weight: 8 });
        anomalyScore += 8;
      }
    } catch {}

    // 4. Multiple overlapping forms (confusion attack)
    try {
      const pwForms = Array.from(document.querySelectorAll('form')).filter(f => f.querySelector('input[type="password"]'));
      if (pwForms.length >= 2) {
        anomalies.push({ type: 'multiple_login_forms', severity: 'high', detail: `${pwForms.length} login forms detected — potential credential confusion attack`, weight: 14 });
        anomalyScore += 14;
      }
    } catch {}

    // 5. Page tries to prevent closing
    try {
      if (window.onbeforeunload) {
        anomalies.push({ type: 'exit_prevention', severity: 'medium', detail: 'Page attempts to prevent you from leaving', weight: 6 });
        anomalyScore += 6;
      }
    } catch {}

    // 6. Hidden iframes with forms
    try {
      const hiddenIframeWithForm = Array.from(document.querySelectorAll('iframe')).filter(f => {
        const s = window.getComputedStyle(f);
        return (parseFloat(s.width) < 3 || parseFloat(s.height) < 3 || s.display === 'none');
      });
      if (hiddenIframeWithForm.length > 0) {
        anomalies.push({ type: 'hidden_iframe', severity: 'medium', detail: `${hiddenIframeWithForm.length} hidden iframe(s) — may load tracking or attack content`, weight: 7 });
        anomalyScore += 7;
      }
    } catch {}

    return {
      detected: anomalies.length > 0,
      anomalies,
      score: Math.min(100, anomalyScore),
      count: anomalies.length
    };
  }

  // ================================================================
  // DEEP EXPLAINABILITY ENGINE (NEW v5)
  // ================================================================

  function buildDeepExplanations(scored, raw, fakeLogin, phishIntent, urlRisk, reputation, behavioral) {
    const explanations = [];

    scored.risks.forEach(r => {
      const exp = { id: r.id, title: r.title, severity: r.severity, signals: [], weight: 0, summary: '' };
      if (r.id === 'no_https') {
        exp.signals = [{ text: 'Protocol is HTTP (not HTTPS)', weight: 30 }, { text: 'All data transmitted in plaintext', weight: 20 }];
        exp.weight = 50; exp.summary = 'Connection is unencrypted — any data you submit can be intercepted by anyone on the same network.';
      } else if (r.id === 'fake_login') {
        exp.signals = (fakeLogin.indicators || []).map((ind, i) => ({ text: ind, weight: 20 - i * 3 }));
        exp.weight = 95; exp.summary = `${fakeLogin.indicators?.length || 0} independent signals confirm credential harvesting with ${fakeLogin.confidence}% confidence.`;
      } else if (r.id === 'phishing_intent') {
        const inH = phishIntent.foundInHeadings || [];
        const inB = phishIntent.foundInButtons || [];
        exp.signals = [];
        inH.forEach(w => exp.signals.push({ text: `Urgency phrase "${w}" in heading (4× weight)`, weight: 20 }));
        inB.forEach(w => exp.signals.push({ text: `Pressure word "${w}" in button (3× weight)`, weight: 15 }));
        exp.weight = phishIntent.intentScore; exp.summary = `Detected ${phishIntent.allFound?.length || 0} manipulative phrases positioned in high-impact page elements.`;
      } else if (r.id === 'url_risk') {
        exp.signals = (urlRisk.signals || []).map(s => ({ text: s.text, weight: s.severity === 'high' ? 18 : 10 }));
        exp.weight = urlRisk.riskScore; exp.summary = `URL structure shows ${urlRisk.signals?.length || 0} anomalies consistent with phishing infrastructure.`;
      } else if (r.id === 'form_diff_domain') {
        exp.signals = [{ text: 'Form action URL points to different domain', weight: 25 }, { text: 'Submitted data will leave this website', weight: 20 }];
        exp.weight = 45; exp.summary = 'Form data is exfiltrated to an external server — classic credential interception.';
      } else if (r.id === 'threat_intel_match') {
        exp.signals = [{ text: 'URL matched external threat-intelligence feed', weight: 35 }, { text: 'Global telemetry identifies active abuse patterns', weight: 20 }];
        exp.weight = 92; exp.summary = 'External threat intelligence confirms this URL has malicious indicators at internet scale.';
      } else {
        exp.signals = [{ text: r.detail, weight: 15 }];
        exp.weight = 15; exp.summary = r.detail;
      }
      explanations.push(exp);
    });

    return explanations;
  }

  // ================================================================
  // ATTACK CATEGORY TAGGING (NEW v5)
  // ================================================================

  function buildAttackCategories(scored, fakeLogin, phishIntent, urlRisk, reputation, behavioral) {
    const categories = [];
    if (fakeLogin.detected) categories.push({ tag: '🚨 Credential Harvesting', severity: 'critical' });
    if (phishIntent.detected) categories.push({ tag: '🎣 Phishing Attack', severity: 'high' });
    if (scored.risks.some(r => r.id === 'form_diff_domain')) categories.push({ tag: '📤 Data Exfiltration', severity: 'high' });
    if (scored.risks.some(r => r.id === 'no_https')) categories.push({ tag: '🔓 Insecure Connection', severity: 'high' });
    if (scored.risks.some(r => r.id === 'threat_intel_match')) categories.push({ tag: '🛰️ Threat Intel Match', severity: 'critical' });
    if (urlRisk.riskScore >= 40) categories.push({ tag: '🔗 Suspicious URL', severity: 'medium' });
    if (reputation.status === 'suspicious') categories.push({ tag: '🌐 Untrusted Domain', severity: 'medium' });
    if (behavioral.detected) categories.push({ tag: '🧠 Behavioral Anomaly', severity: 'medium' });
    if (scored.risks.some(r => r.id === 'lookalike')) categories.push({ tag: '🎭 Brand Impersonation', severity: 'high' });
    if (phishIntent.detected && fakeLogin.detected) categories.push({ tag: '⚡ Multi-Vector Attack', severity: 'critical' });
    return categories.slice(0, 5);
  }
  // ================================================================

  function generateAISummary(score, scored, raw, fakeLogin, phishIntent, urlRisk, confidence, adaptive) {
    if (fakeLogin.detected) {
      return `⛔ SafeSurf AI has detected a fake login page (${fakeLogin.confidence}% confidence). This matches known credential-harvesting attack profiles targeting "${raw.hostname}". ${fakeLogin.signals[0] ? fakeLogin.signals[0] + '. ' : ''}Do not enter any credentials. Navigate directly to the real service via a trusted bookmark.`;
    }
    if (score <= 30) {
      return `This page shows ${scored.risks.length} overlapping high-risk indicators with ${confidence}% confidence. ${scored.risks[0]?.aiExplanation || 'Multiple critical issues detected.'} SafeSurf strongly recommends leaving immediately without submitting any information.`;
    }
    if (score <= 55) {
      const top = scored.risks[0] || scored.warnings[0];
      return `SafeSurf detected ${scored.risks.length + scored.warnings.length} security concerns (${confidence}% confidence). ${top ? top.detail + ' ' : ''}${phishIntent.detected ? 'Urgency language consistent with social engineering was also found. ' : ''}Avoid submitting sensitive data.`;
    }
    if (score <= 80) {
      const adapt = adaptive.adaptiveMessage ? ' ' + adaptive.adaptiveMessage : '';
      return `Page is generally safe (${confidence}% confidence) with ${scored.warnings.length} minor concern${scored.warnings.length !== 1 ? 's' : ''}.${adapt} ${scored.warnings[0] ? scored.warnings[0].detail : ''}`;
    }
    const adapt = adaptive.adaptiveMessage ? ' ' + adaptive.adaptiveMessage : '';
    return `SafeSurf AI assessed this page as safe (${confidence}% confidence). ${raw.isTrustedDomain ? 'This is a verified trusted domain.' : 'No significant threats detected.'}${adapt}${raw.forms.length > 0 ? ` ${raw.forms.length} form${raw.forms.length > 1 ? 's' : ''} scanned and cleared.` : ''}`;
  }

  // ================================================================
  // MASTER ANALYSIS — v5 SINGLE SOURCE OF TRUTH
  // ================================================================

  async function analyzePage() {
    const analysisStart = performance.now();
    window.__SafeSurf.scanCount++;
    const n = window.__SafeSurf.scanCount;
    console.log(`[SafeSurf v5] === Analysis #${n}: ${location.hostname} ===`);

    try { chrome.runtime.sendMessage({ type: 'SCAN_STARTED', hostname: location.hostname }); } catch {}

    const hostname = location.hostname;
    const trusted  = isTrustedDomain(hostname);

    // Adaptive trust (async from storage)
    let adaptive;
    try { adaptive = await loadAdaptiveTrust(hostname); }
    catch { adaptive = { visitCount: 1, prevSafeVisits: 0, prevRiskyVisits: 0, adaptiveBoost: 0, adaptiveMessage: null, isRepeatVisitor: false }; }

    const isHttps     = location.protocol === 'https:';
    const forms       = analyzeForms(trusted);
    const urlRisk     = analyzeURL();
    const fakeLogin   = window.__SafeSurf.demoMode ? forceDemoFakeLogin() : detectFakeLogin();
    const phishInt    = detectPhishingIntent();
    const phishText   = detectPhishingText();
    const reputation  = checkDomainReputation(hostname);
    const behavioral  = detectBehavioralAnomalies();
    const safeBrowsing = await requestThreatIntel(location.href);

    const raw = {
      url: location.href, hostname, pageTitle: document.title, isHttps,
      forms, phishingKeywordsFound: phishText,
      hasMixedContent: detectMixedContent(),
      suspiciousIframes: countSuspiciousIframes(),
      redirectCount: getRedirectCount(),
      externalLinks: countExternalLinks(),
      isLookalike: checkLookalike(hostname),
      isTrustedDomain: trusted,
      safeBrowsing
    };

    const scored       = scoreData(raw, urlRisk, fakeLogin, phishInt, adaptive, trusted, safeBrowsing);
    const confidence   = calculateConfidence(raw, scored, urlRisk, fakeLogin, phishInt, adaptive, safeBrowsing);
    const aiSummary    = generateAISummary(scored.score, scored, raw, fakeLogin, phishInt, urlRisk, confidence, adaptive);
    const attackSim    = buildAttackSimulation(scored, raw, fakeLogin, phishInt);
    const trustExpl    = buildTrustExplanation(scored, raw, fakeLogin, phishInt, urlRisk, adaptive, trusted);
    const deepExpl     = buildDeepExplanations(scored, raw, fakeLogin, phishInt, urlRisk, reputation, behavioral);
    const attackCats   = buildAttackCategories(scored, fakeLogin, phishInt, urlRisk, reputation, behavioral);

    const analysisTime = Math.round(performance.now() - analysisStart);

    // Decision line
    const decision = scored.score >= 75
      ? { text: '🟢 Safe to proceed', level: 'safe' }
      : scored.score >= 45
        ? { text: '🟡 Proceed with caution', level: 'warning' }
        : { text: '🔴 Do not enter sensitive information', level: 'danger' };

    const result = {
      ...scored,
      url: raw.url, hostname, pageTitle: raw.pageTitle, isHttps,
      forms, phishingKeywordsFound: phishText,
      hasMixedContent: raw.hasMixedContent,
      suspiciousIframes: raw.suspiciousIframes,
      redirectCount: raw.redirectCount,
      externalLinks: raw.externalLinks,
      isLookalike: raw.isLookalike,
      isTrustedDomain: trusted,
      safeBrowsing,
      urlRisk, fakeLogin, phishingIntent: phishInt, adaptive,
      confidence, aiSummary, attackSimulation: attackSim,
      trustExplanation: trustExpl,
      // v5 additions
      domainReputation: reputation,
      behavioral, deepExplanations: deepExpl,
      attackCategories: attackCats,
      decision,
      analysisTimeMs: analysisTime,
      scannedAt: Date.now(), scanVersion: 5
    };

    window.__SafeSurf.state = result;

    console.log(`[SafeSurf v5] Done in ${analysisTime}ms: score=${result.score} level=${result.level} conf=${confidence}% reputation=${reputation.status} anomalies=${behavioral.count} categories=${attackCats.length}`);

    notifyBackground(result);
    applyVisuals(result);

    try { chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', result: { score: result.score, level: result.level, confidence, hostname } }); } catch {}

    return result;
  }

  // Demo mode fake login (forces fake detection for demos)
  function forceDemoFakeLogin() {
    return {
      detected: true, score: 85, confidence: 92,
      signals: ['Domain impersonates a trusted brand', 'Password field on unverified domain', 'Brand imagery mismatch detected'],
      indicators: ['Lookalike domain', 'Password field present', 'Brand image mismatch', 'Login heading on untrusted domain'],
      hasPasswordField: true, isLookalike: true, hasBrandImage: true, formsWithPassword: 1,
      aiExplanation: 'This page exhibits 4 credential-harvesting indicators. Domain impersonates a trusted brand. Submitting your credentials here would send them directly to the attacker.'
    };
  }

  // ================================================================
  // TIMING SYSTEM — v5 ENHANCED
  // ================================================================

  let _running = false, _done = false, _mutTimer = null, _lastForms = -1, _domChangeCount = 0;

  function triggerAnalysis(reason, delay) {
    delay = delay || 0;
    if (_running) return;
    console.log(`[SafeSurf v5] Trigger: ${reason} (${delay}ms)`);
    setTimeout(() => {
      _running = true;
      analyzePage().then(() => { _done = true; }).catch(e => {
        console.error('[SafeSurf v5] Error:', e);
        showFailSafe();
      }).finally(() => { _running = false; });
    }, delay);
  }

  function showFailSafe() {
    // Fail-safe: if analysis errors, show a cautious badge
    updateFloatingBadge({ score: '?', level: 'warning', label: 'Unknown' });
  }

  function initTiming() {
    if (document.readyState === 'complete') {
      triggerAnalysis('dom_complete', 80);
    } else {
      window.addEventListener('load', () => triggerAnalysis('window_load', 80), { once: true });
    }
    setTimeout(() => { if (!_done) triggerAnalysis('fallback_3s', 0); }, 3000);
  }

  // v5: Enhanced MutationObserver — live DOM threat tracking
  function initMutationObserver() {
    if (!document.body) return;
    let timeout;
    new MutationObserver(mutations => {
      _domChangeCount++;
      const fc = document.querySelectorAll('form').length;
      const hasNewPassword = mutations.some(m =>
        Array.from(m.addedNodes).some(n =>
          n.nodeType === 1 && (
            n.tagName === 'FORM' ||
            n.querySelector?.('form') ||
            n.querySelector?.('input[type="password"]') ||
            (n.tagName === 'INPUT' && n.type === 'password')
          )
        )
      );
      const hasNewIframe = mutations.some(m =>
        Array.from(m.addedNodes).some(n => n.nodeType === 1 && (n.tagName === 'IFRAME' || n.querySelector?.('iframe')))
      );

      if (fc !== _lastForms || hasNewPassword || hasNewIframe) {
        _lastForms = fc;
        clearTimeout(timeout);
        timeout = setTimeout(() => {
          console.log(`[SafeSurf v5] DOM change detected — rescanning (changes: ${_domChangeCount})`);
          triggerAnalysis('live_dom_change', 0);
        }, 300);
      }
    }).observe(document.body, { childList: true, subtree: true });
    _lastForms = document.querySelectorAll('form').length;
  }

  function initSpaDetection() {
    let lastUrl = location.href;
    new MutationObserver(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href; _done = false;
        triggerAnalysis('spa_nav', 600);
      }
    }).observe(document, { subtree: true, childList: true });
  }

  // ================================================================
  // BACKGROUND & POPUP COMMUNICATION — v5
  // ================================================================

  function notifyBackground(result) {
    try {
      chrome.runtime.sendMessage({ type: 'PAGE_DATA', data: {
        url: result.url, hostname: result.hostname, pageTitle: result.pageTitle,
        score: result.score, level: result.level, label: result.label,
        forms: result.forms, risks: result.risks, warnings: result.warnings,
        passes: result.passes, isHttps: result.isHttps, confidence: result.confidence,
        aiSummary: result.aiSummary, phishingKeywordsFound: result.phishingKeywordsFound,
        urlRisk: result.urlRisk, fakeLogin: result.fakeLogin,
        phishingIntent: result.phishingIntent, adaptive: result.adaptive,
        safeBrowsing: result.safeBrowsing,
        attackSimulation: result.attackSimulation, trustExplanation: result.trustExplanation,
        // v5 data
        domainReputation: result.domainReputation, behavioral: result.behavioral,
        deepExplanations: result.deepExplanations, attackCategories: result.attackCategories,
        decision: result.decision, analysisTimeMs: result.analysisTimeMs,
        scannedAt: result.scannedAt
      }}, () => { if (chrome.runtime.lastError) {} });
    } catch {}
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'PING') {
      sendResponse({ alive: true, hasState: !!window.__SafeSurf.state, v: 5 });
      return false;
    }
    if (msg.type === 'GET_ANALYSIS') {
      console.log('[SafeSurf v5] GET_ANALYSIS from popup');
      analyzePage().then(result => { sendResponse({ ok: true, result }); });
      return true;
    }
    // v5: Protection actions from popup
    if (msg.type === 'BLOCK_FORMS') {
      blockAllForms();
      sendResponse({ ok: true });
      return false;
    }
    if (msg.type === 'SAFE_PREVIEW') {
      toggleSafePreview(msg.enable !== false);
      sendResponse({ ok: true });
      return false;
    }
    if (msg.type === 'LEAVE_PAGE') {
      window.history.back();
      sendResponse({ ok: true });
      return false;
    }
    if (msg.type === 'SET_DEMO_MODE') {
      window.__SafeSurf.demoMode = !!msg.enabled;
      console.log(`[SafeSurf v5] Demo mode: ${window.__SafeSurf.demoMode}`);
      if (window.__SafeSurf.demoMode) {
        _done = false;
        triggerAnalysis('demo_mode', 200);
      }
      sendResponse({ ok: true });
      return false;
    }
  });

  // ================================================================
  // VISUAL ENHANCEMENTS — v5
  // ================================================================

  let _overlayShown = false;

  function applyVisuals(result) {
    applyFormHighlights(result.forms);
    attachInterceptors(result.forms, result);
    updateFloatingBadge(result);
    if (!_overlayShown) showSmartOverlay(result);
    // Auto form blocking for danger pages
    if (result.score < 35 && result.fakeLogin?.detected) {
      blockAllForms();
    }
  }

  // ── Floating Risk Badge (NEW v5) ──────────────────────────────
  function updateFloatingBadge(result) {
    let badge = document.getElementById('__ss5-badge');
    if (!badge) {
      badge = document.createElement('div');
      badge.id = '__ss5-badge';
      badge.addEventListener('click', () => {
        try { chrome.runtime.sendMessage({ type: 'OPEN_POPUP' }); } catch {}
      });
      document.body.appendChild(badge);
    }
    const level = result.level || 'warning';
    badge.className = level;
    const statusText = level === 'safe' ? 'SAFE' : level === 'warning' ? 'CAUTION' : 'DANGER';
    const shield = level === 'safe' ? '🛡️' : level === 'warning' ? '⚠️' : '🚨';
    badge.innerHTML = `<span class="badge-shield">${shield}</span><span class="badge-score">${result.score ?? '?'}</span><span class="badge-text">${statusText}</span>`;
    badge.title = `SafeSurf AI: ${statusText} (${result.score ?? '?'}/100) — Click to open`;
  }

  // ── Auto Form Blocking (NEW v5) ───────────────────────────────
  function blockAllForms() {
    document.querySelectorAll('input,select,textarea').forEach(el => {
      el.disabled = true;
      el.setAttribute('data-ss5-blocked-input', '1');
      el.style.cssText += 'opacity:0.4!important;pointer-events:none!important;';
    });
    document.querySelectorAll('form').forEach(f => {
      f.setAttribute('data-ss5-blocked', '1');
    });
    console.log('[SafeSurf v5] All forms blocked');
  }

  // ── Safe Preview Mode (NEW v5) ────────────────────────────────
  function toggleSafePreview(enable) {
    if (enable) {
      document.body.classList.add('__ss5-safe-preview');
      console.log('[SafeSurf v5] Safe preview mode ON');
    } else {
      document.body.classList.remove('__ss5-safe-preview');
      // Re-enable blocked inputs
      document.querySelectorAll('[data-ss5-blocked-input]').forEach(el => {
        el.disabled = false;
        el.removeAttribute('data-ss5-blocked-input');
        el.style.opacity = '';
        el.style.pointerEvents = '';
      });
      document.querySelectorAll('[data-ss5-blocked]').forEach(f => f.removeAttribute('data-ss5-blocked'));
      console.log('[SafeSurf v5] Safe preview mode OFF');
    }
  }

  function applyFormHighlights(forms) {
    forms.forEach((fr, idx) => {
      const el = document.querySelectorAll('form')[idx];
      if (!el || el.hasAttribute('data-ss4')) return;
      el.setAttribute('data-ss4', '1');
      const c = fr.riskLevel === 'high' ? '#ef4444' : fr.riskLevel === 'medium' ? '#f59e0b' : '#22c55e';
      const t = fr.isBenignForm ? '✅ SafeSurf: Search/GET form (low risk)'
        : fr.riskLevel === 'high' ? '🔴 SafeSurf: High-risk form detected'
        : fr.riskLevel === 'medium' ? '⚠️ SafeSurf: Caution with this form'
        : '✅ SafeSurf: Form appears secure';
      el.style.cssText += `outline:2px solid ${c}!important;outline-offset:3px;border-radius:4px;`;
      el.title = t;
    });
  }

  function attachInterceptors(forms, result) {
    forms.forEach((fr, idx) => {
      const el = document.querySelectorAll('form')[idx];
      if (!el || el.hasAttribute('data-ss4i') || fr.isBenignForm) return;
      if (!fr.actionDiffDomain && !fr.hasSuspiciousFields && !fr.actionIsHttp && !(fr.hasPasswordField && !result.isTrustedDomain)) return;
      el.setAttribute('data-ss4i', '1');
      el.addEventListener('submit', function onS(e) {
        e.preventDefault(); e.stopImmediatePropagation();
        showSubmitModal(el, fr, onS);
      }, { capture: true });
    });
  }

  function showSmartOverlay(result) {
    if (result.level === 'danger' || result.fakeLogin.detected) {
      if (!sessionStorage.getItem('__ss4_overlay')) {
        sessionStorage.setItem('__ss4_overlay', '1');
        _overlayShown = true;
        showDangerOverlay(result);
      }
    } else if (result.level === 'warning' && !sessionStorage.getItem('__ss4_banner')) {
      sessionStorage.setItem('__ss4_banner', '1');
      showBanner(result);
    }
  }

  function showDangerOverlay(result) {
    if (document.getElementById('__ss4-ov')) return;
    const fl  = result.fakeLogin.detected;
    const col = fl ? '#ef4444' : '#f59e0b';
    const top = result.risks.slice(0, 3);
    const cats = (result.attackCategories || []).map(c => `<span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;background:rgba(239,68,68,0.15);color:#fca5a5;margin:2px">${c.tag}</span>`).join('');

    const ov = document.createElement('div');
    ov.id = '__ss4-ov';
    ov.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,0.92);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;animation:__ss4fi 0.3s ease';
    ov.innerHTML = `
      <style>
        @keyframes __ss4fi{from{opacity:0}to{opacity:1}}
        @keyframes __ss4su{from{transform:translateY(28px);opacity:0}to{transform:translateY(0);opacity:1}}
        @keyframes __ss4pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.06)}}
        #__ss4-card{animation:__ss4su 0.35s cubic-bezier(.34,1.56,.64,1)}
        #__ss4-ico{animation:__ss4pulse 2.2s ease-in-out infinite}
      </style>
      <div id="__ss4-card" style="background:#09111e;color:#f1f5f9;border:2px solid ${col};border-radius:22px;padding:30px;max-width:490px;width:94%;box-shadow:0 0 70px rgba(239,68,68,0.25),0 32px 90px rgba(0,0,0,0.8)">
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px">
          <div id="__ss4-ico" style="width:54px;height:54px;border-radius:50%;background:${fl?'#450a0a':'#431407'};display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0">${fl?'🚨':'⚠️'}</div>
          <div>
            <div style="font-size:17px;font-weight:800;color:${col};letter-spacing:-0.3px">${fl?'FAKE LOGIN PAGE DETECTED':'HIGH RISK PAGE DETECTED'}</div>
            <div style="font-size:11px;color:#64748b;margin-top:3px">SafeSurf AI v5 · ${result.analysisTimeMs || 0}ms analysis · ${result.confidence}% confidence</div>
          </div>
        </div>
        ${cats ? '<div style="margin-bottom:12px;display:flex;flex-wrap:wrap;gap:2px">' + cats + '</div>' : ''}
        <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:10px 14px;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:12px;color:#94a3b8">Trust Score</span>
          <span style="font-size:24px;font-weight:800;font-family:monospace;color:${col}">${result.score}/100</span>
        </div>
        <p style="font-size:12px;color:#94a3b8;line-height:1.7;margin:0 0 14px">${result.aiSummary}</p>
        ${top.length ? '<div style="display:flex;flex-direction:column;gap:7px;margin-bottom:20px">' + top.map(r => `<div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:9px 12px;border-left:3px solid ${r.severity==='critical'||r.severity==='high'?'#ef4444':'#f59e0b'}"><div style="font-size:12px;font-weight:700;color:${r.severity==='critical'||r.severity==='high'?'#fca5a5':'#fcd34d'};margin-bottom:2px">${r.title}</div><div style="font-size:11px;color:#64748b">${r.detail}</div></div>`).join('') + '</div>' : ''}
        <div style="display:flex;gap:10px">
          <button id="__ss4-leave" style="flex:1;padding:13px;border-radius:11px;border:none;cursor:pointer;background:#dc2626;color:#fff;font-size:14px;font-weight:800;font-family:inherit;letter-spacing:0.2px">⬅ Leave Page Now</button>
          <button id="__ss4-cont" style="flex:0 0 auto;padding:13px 18px;border-radius:11px;border:1px solid rgba(255,255,255,0.1);cursor:pointer;background:rgba(255,255,255,0.04);color:#64748b;font-size:12px;font-family:inherit">I know the risks</button>
        </div>
        <p style="margin:12px 0 0;font-size:10px;color:#334155;text-align:center">Passive analysis only · Not legal or security advice</p>
      </div>`;
    document.body.appendChild(ov);
    ov.querySelector('#__ss4-leave').onclick = () => window.history.back();
    ov.querySelector('#__ss4-cont').onclick  = () => ov.remove();
  }

  function showBanner(result) {
    if (document.getElementById('__ss4-ban')) return;
    const b = document.createElement('div');
    b.id = '__ss4-ban';
    b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483646;background:linear-gradient(90deg,#78350f,#92400e);color:#fef3c7;font-size:13px;padding:9px 18px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 4px 20px rgba(245,158,11,0.4);font-family:-apple-system,sans-serif;';
    b.innerHTML = `<span>⚠️ <b>SafeSurf AI:</b> Caution — score ${result.score}/100 · ${result.confidence}% confidence. ${result.warnings[0]?.title || 'Security concerns detected.'}</span><button id="__ss4-bc" style="background:none;border:none;color:#fef3c7;cursor:pointer;font-size:18px;padding:0 4px">×</button>`;
    document.body.prepend(b);
    document.getElementById('__ss4-bc').onclick = () => b.remove();
  }

  function showSubmitModal(formEl, fr, onS) {
    if (document.getElementById('__ss4-mod')) return;
    const isH = fr.riskLevel === 'high';
    const reasons = [];
    if (fr.actionDiffDomain)  reasons.push('Form submits to a <b>different domain</b> than this site');
    if (fr.actionIsHttp)      reasons.push('Sends data over <b>insecure HTTP</b>');
    if (fr.hasSuspiciousFields) reasons.push('Collects <b>highly sensitive fields</b> (CVV/SSN/card)');
    if (!fr.hasCSRFToken && fr.hasPasswordField && !fr.isBenignForm) reasons.push('Password form <b>lacks CSRF protection</b>');
    if (!reasons.length) reasons.push('Potential security concern detected');

    const m = document.createElement('div');
    m.id = '__ss4-mod';
    m.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,0.82);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif';
    m.innerHTML = `<div style="background:#0f172a;color:#f1f5f9;border:1px solid ${isH?'#ef4444':'#f59e0b'};border-radius:18px;padding:26px;max-width:420px;width:93%;box-shadow:0 30px 70px rgba(0,0,0,0.6)"><div style="display:flex;align-items:center;gap:12px;margin-bottom:16px"><div style="width:44px;height:44px;border-radius:50%;background:${isH?'#450a0a':'#431407'};display:flex;align-items:center;justify-content:center;font-size:20px">${isH?'🛑':'⚠️'}</div><div><div style="font-size:15px;font-weight:700;color:${isH?'#fca5a5':'#fcd34d'}">${isH?'High Risk — Do Not Submit':'Security Warning'}</div><div style="font-size:10px;color:#64748b;margin-top:1px">SafeSurf AI · Form Security Check</div></div></div><div style="display:flex;flex-direction:column;gap:7px;margin-bottom:20px">${reasons.map(r=>`<div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:8px 12px;font-size:12px;color:#cbd5e1;border-left:3px solid ${isH?'#ef4444':'#f59e0b'}">${r}</div>`).join('')}</div><div style="display:flex;gap:8px"><button id="__ss4-safe" style="flex:1;padding:11px;border-radius:10px;border:none;cursor:pointer;background:#16a34a;color:#fff;font-size:14px;font-weight:700;font-family:inherit">✓ Stay Safe</button><button id="__ss4-proc" style="flex:0 0 auto;padding:11px 16px;border-radius:10px;border:1px solid rgba(255,255,255,0.1);cursor:pointer;background:transparent;color:#64748b;font-size:12px;font-family:inherit">Submit anyway</button></div><p style="margin:12px 0 0;font-size:10px;color:#334155;text-align:center">Passive analysis only · Not legal advice</p></div>`;
    document.body.appendChild(m);
    m.querySelector('#__ss4-safe').onclick = () => m.remove();
    m.querySelector('#__ss4-proc').onclick = () => { m.remove(); formEl.removeEventListener('submit', onS, { capture: true }); formEl.submit(); };
    m.addEventListener('click', e => { if (e.target === m) m.remove(); });
  }

  // ================================================================
  // BOOTSTRAP — v5
  // ================================================================

  initTiming();
  setTimeout(initMutationObserver, 200);
  initSpaDetection();
  console.log('[SafeSurf v5] Bootstrap complete ✓');

})();
