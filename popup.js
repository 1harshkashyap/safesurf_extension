/**
 * SafeSurf AI – Popup Script v4.0
 * No imports. Standalone. All judge upgrades rendered here.
 */
'use strict';

const LC = { safe:'var(--safe)', warning:'var(--warn)', danger:'var(--danger)' };
const LG = { safe:'rgba(34,197,94,0.15)', warning:'rgba(245,158,11,0.15)', danger:'rgba(239,68,68,0.18)' };

function esc(s) {
  if (typeof s !== 'string') s = String(s || '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Scan Status Indicator ────────────────────────────────────────
var _scanDoneTimer = null;

function showScanStatus(state, text) {
  var bar  = document.getElementById('scan-prog');
  var wrap = document.getElementById('scan-status');
  var dot  = document.getElementById('scan-dot');
  var txt  = document.getElementById('scan-status-text');

  clearTimeout(_scanDoneTimer);

  if (state === 'scanning') {
    bar.classList.add('active');
    wrap.classList.add('show');
    dot.classList.remove('scan-done');
    txt.textContent = text || '🔍 Scanning page…';
  } else if (state === 'complete') {
    bar.classList.remove('active');
    wrap.classList.add('show');
    dot.classList.add('scan-done');
    txt.textContent = text || '✔ Analysis complete';
    _scanDoneTimer = setTimeout(function() { wrap.classList.remove('show'); }, 3000);
  } else {
    bar.classList.remove('active');
    wrap.classList.remove('show');
  }
}

// ── Tabs ─────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(function(tab) {
  tab.addEventListener('click', function() {
    document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'history') loadHistory();
  });
});

// ── Messaging ────────────────────────────────────────────────────
function msgTab(tabId, msg, ms) {
  ms = ms || 6000;
  return new Promise(function(res, rej) {
    var done = false;
    var t = setTimeout(function() { done = true; rej(new Error('Timeout')); }, ms);
    chrome.tabs.sendMessage(tabId, msg, function(r) {
      clearTimeout(t);
      if (done) return;
      done = true;
      chrome.runtime.lastError ? rej(new Error(chrome.runtime.lastError.message)) : res(r);
    });
  });
}
function msgBg(msg) {
  return new Promise(function(res, rej) {
    chrome.runtime.sendMessage(msg, function(r) {
      chrome.runtime.lastError ? rej(new Error(chrome.runtime.lastError.message)) : res(r);
    });
  });
}

// ── Get analysis (PING → GET_ANALYSIS → BG cache) ────────────────
async function getAnalysis() {
  var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || !tabs[0]) return null;
  var tab = tabs[0];

  showScanStatus('scanning', '🔍 Contacting page…');

  var alive = false;
  try {
    var p = await msgTab(tab.id, { type: 'PING' }, 1500);
    alive = p && p.alive;
  } catch(e) {}

  if (alive) {
    showScanStatus('scanning', '🔍 Running security analysis…');
    try {
      var r = await msgTab(tab.id, { type: 'GET_ANALYSIS' }, 8000);
      if (r && r.result) {
        showScanStatus('complete', '✔ Analysis complete — score: ' + r.result.score + '/100');
        return r.result;
      }
    } catch(e) { console.log('[Popup] GET_ANALYSIS failed:', e.message); }
  }

  try {
    var bg = await msgBg({ type: 'GET_RESULT', tabId: tab.id });
    if (bg && bg.result) {
      showScanStatus('complete', '✔ Cached result loaded');
      return bg.result;
    }
  } catch(e) {}

  showScanStatus('hidden');
  return null;
}

// ── RENDER: Overview ─────────────────────────────────────────────
function renderOverview(r) {
  document.getElementById('ov-load').style.display = 'none';
  var el = document.getElementById('ov-content');
  el.style.display = 'block';

  var C   = 2 * Math.PI * 32; // r=32
  var col = LC[r.level] || 'var(--muted)';
  var glo = LG[r.level] || 'transparent';
  var conf  = r.confidence || 70;
  var adapt = r.adaptive || {};
  var bds   = buildBreakdowns(r);
  var lvlTxt = r.level === 'safe' ? '✓ Safe' : r.level === 'warning' ? '⚠ Caution' : '✕ High Risk';

  // Fake Login Alert
  var flaHtml = '';
  if (r.fakeLogin && r.fakeLogin.detected) {
    flaHtml = '<div class="fla">'
      + '<div class="fla-hdr"><span style="font-size:20px">🚨</span><div><div class="fla-title">FAKE LOGIN DETECTED</div><div style="font-size:9px;color:#94a3b8;margin-top:1px">Confidence: ' + r.fakeLogin.confidence + '%</div></div></div>'
      + '<div class="fla-sigs">' + (r.fakeLogin.signals||[]).map(function(s) { return '<div class="fla-sig">' + esc(s) + '</div>'; }).join('') + '</div>'
      + '<div class="fla-tip">⛔ Do NOT enter credentials — navigate away immediately</div>'
      + '</div>';
  }

  // Phishing Intent
  var intentHtml = '';
  var pi = r.phishingIntent;
  if (pi && pi.detected) {
    intentHtml = '<div class="intent">'
      + '<div class="intent-hdr"><span style="font-size:18px">🎯</span><div><div class="intent-title">Phishing Intent Detected</div><div style="font-size:9px;color:var(--muted);margin-top:1px">Score: ' + pi.intentScore + '/100 · Confidence: ' + pi.confidence + '%</div></div></div>'
      + (pi.detail ? '<div style="font-size:10px;color:var(--muted);margin-bottom:5px;line-height:1.5">' + esc(pi.detail) + '</div>' : '')
      + (pi.allFound.length ? '<div class="intent-words">' + pi.allFound.map(function(w) { return '<span class="iw">' + esc(w) + '</span>'; }).join('') + '</div>' : '')
      + '</div>';
  }

  // URL Risk
  var urlHtml = '';
  var ur = r.urlRisk;
  if (ur && (ur.riskScore > 0 || ur.signals.length > 0)) {
    var sigHtml = (ur.signals||[]).slice(0,4).map(function(s) {
      var dc = s.severity === 'high' ? 'var(--danger)' : s.severity === 'medium' ? 'var(--warn)' : '#64748b';
      return '<div class="url-sig"><div class="url-dot" style="background:' + dc + '"></div><span style="color:var(--muted)">' + esc(s.text) + '</span></div>';
    }).join('');
    urlHtml = '<div class="url-card ' + esc(ur.level) + '">'
      + '<div class="url-hdr"><span class="url-lbl">URL Risk Analysis</span><span class="url-chip ' + esc(ur.level) + '">' + ur.riskScore + '/100</span></div>'
      + '<div class="url-host">' + esc(ur.hostname || r.hostname) + '</div>'
      + (sigHtml || '<div style="font-size:11px;color:var(--safe)">✓ No URL risk signals</div>')
      + '</div>';
  }

  // Trust Explanation
  var trustHtml = '';
  var te = r.trustExplanation;
  if (te && (te.positive.length > 0 || te.negative.length > 0)) {
    trustHtml = '<div class="trust-card">'
      + '<div class="trust-hdr">Why this page is ' + (r.level === 'safe' ? 'safe' : r.level === 'warning' ? 'flagged' : 'high risk') + '</div>'
      + '<div class="trust-cols">'
      + '<div><div class="trust-col-lbl pos">✅ Positive Factors</div>' + te.positive.map(function(p) { return '<div class="trust-item">' + esc(p) + '</div>'; }).join('') + '</div>'
      + '<div><div class="trust-col-lbl neg">⚠️ Risk Factors</div>' + te.negative.map(function(n) { return '<div class="trust-item">' + esc(n) + '</div>'; }).join('') + (te.negative.length === 0 ? '<div class="trust-item" style="color:var(--safe)">None detected</div>' : '') + '</div>'
      + '</div></div>';
  }

  // Attack Simulation
  var simHtml = '';
  var as = r.attackSimulation;
  if (as && as.attacks && as.attacks.length > 0) {
    var attacksHtml = as.attacks.map(function(a) {
      return '<div class="sim-attack ' + esc(a.severity) + '">'
        + '<div class="sim-atk-hdr"><span class="sim-atk-icon">' + a.icon + '</span><span class="sim-atk-name">' + esc(a.type) + '</span><span class="sim-atk-sev ' + esc(a.severity) + '">' + a.severity.toUpperCase() + '</span></div>'
        + '<div class="sim-what">' + esc(a.whatHappens) + '</div>'
        + '<div class="sim-consequence">Impact: ' + esc(a.consequence) + '</div>'
        + (a.difficulty !== 'N/A' ? '<div class="sim-diff">Attacker difficulty: ' + esc(a.difficulty) + '</div>' : '')
        + '</div>';
    }).join('');
    simHtml = '<div class="sim-card">'
      + '<div class="sim-hdr" id="sim-hdr">'
      +   '<div class="sim-hdr-left"><span style="font-size:16px">⚗️</span><div><div class="sim-title">Attack Simulation</div><div class="sim-sub">What would happen if these risks were real</div></div></div>'
      +   '<span class="sim-toggle" id="sim-toggle">▼</span>'
      + '</div>'
      + '<div class="sim-body" id="sim-body">' + attacksHtml + '</div>'
      + '</div>';
  }

  // AI Summary
  var aiLabelText = r.claudeEnriched ? '⚡ Claude AI Security Analysis' : '🤖 AI Security Analysis';
  var aiHtml = r.aiSummary
    ? '<div class="ai-card"><div class="ai-lbl">' + aiLabelText + '</div><div class="ai-txt">' + esc(r.aiSummary) + '</div>'
      + (r.claudeEnriched ? '<div class="claude-extra">'
        + (r.claudeTopThreat ? '<div>🎯 <strong>Top Threat:</strong> ' + esc(r.claudeTopThreat) + '</div>' : '')
        + (r.claudeAttackVector ? '<div>🛡️ <strong>Attack Vector:</strong> ' + esc(r.claudeAttackVector) + '</div>' : '')
        + (r.claudeWhySafe ? '<div>💡 ' + esc(r.claudeWhySafe) + '</div>' : '')
        + (r.claudePositive && r.claudePositive.length ? '<div style="margin-top:4px">✅ ' + r.claudePositive.map(function(s) { return esc(s); }).join(' · ') + '</div>' : '')
        + (r.claudeRecommendation ? '<div style="margin-top:3px;font-weight:700;color:' + (r.claudeRecommendation === 'leave_immediately' ? 'var(--danger)' : r.claudeRecommendation === 'proceed_with_caution' ? 'var(--warn)' : 'var(--safe)') + '">' + (r.claudeRecommendation === 'leave_immediately' ? '🚨 Leave Immediately' : r.claudeRecommendation === 'proceed_with_caution' ? '⚠️ Proceed With Caution' : '✅ Safe to Use') + '</div>' : '')
        + '</div>' : '')
      + '</div>'
    : '';

  // Risks / Warnings / Passes
  var risksHtml = '', warnsHtml = '', passesHtml = '';
  if (r.risks && r.risks.length) {
    risksHtml = '<div class="sec">Risks Found (' + r.risks.length + ')</div>' + r.risks.map(renderRiskItem).join('');
  }
  if (r.warnings && r.warnings.length) {
    warnsHtml = '<div class="sec">Warnings (' + r.warnings.length + ')</div>' + r.warnings.map(renderRiskItem).join('');
  }
  if (r.passes && r.passes.length) {
    passesHtml = '<div class="sec">Passed (' + r.passes.length + ')</div>'
      + r.passes.map(function(p) {
          return '<div class="ri pass"><div class="ri-hdr"><div class="ri-dot"></div><div class="ri-title">' + esc(p.title) + '</div>' + (p.confidence ? '<span style="font-size:8px;font-family:monospace;color:rgba(34,197,94,0.5)">' + p.confidence + '%</span>' : '') + '</div><div class="ri-detail">' + esc(p.detail) + '</div></div>';
        }).join('');
  }

  el.innerHTML = ''
    // Score hero
    + '<div class="hero" style="--hg:' + glo + '">'
    +   '<div class="score-row">'
    +     '<div class="ring">'
    +       '<svg viewBox="0 0 72 72" width="74" height="74">'
    +         '<circle class="rt" cx="36" cy="36" r="32"/>'
    +         '<circle class="rf" id="score-arc" cx="36" cy="36" r="32" stroke="' + col + '" style="stroke-dasharray:' + C + ';stroke-dashoffset:' + C + '"/>'
    +       '</svg>'
    +       '<div class="rv"><span class="rn" id="score-num" style="color:' + col + '">0</span><span class="rd">/100</span></div>'
    +     '</div>'
    +     '<div class="si2">'
    +       '<div class="sl" style="color:' + col + '">' + esc(r.label) + '</div>'
    +       '<div class="sh">' + esc(r.hostname || 'Unknown') + '</div>'
    +       '<div class="sbadges">'
    +         '<span class="lbadge ' + esc(r.level) + '">' + lvlTxt + '</span>'
    +         '<span class="cbadge">🧠 ' + conf + '%</span>'
    +       '</div>'
    +       (adapt.adaptiveMessage ? '<div class="adpt show">' + esc(adapt.adaptiveMessage) + '</div>' : '')
    +     '</div>'
    +   '</div>'
    +   '<div class="cbar-row"><span class="cbar-lbl">AI Confidence</span><div class="cbar"><div class="cbar-fill" id="cbar" data-pct="' + conf + '"></div></div><span class="cbar-pct">' + conf + '%</span></div>'
    +   '<div class="bds">' + bds.map(function(b) { return '<div class="bd-row"><span class="bd-lbl">' + esc(b.label) + '</span><div class="bd-bar"><div class="bd-fill" data-pct="' + b.pct + '" style="background:' + b.color + '"></div></div><span class="bd-val" style="color:' + b.color + '">' + b.val + '</span></div>'; }).join('') + '</div>'
    + '</div>'
    + flaHtml + intentHtml + urlHtml + trustHtml + simHtml + aiHtml
    + risksHtml + warnsHtml + passesHtml;

  // Wire attack sim toggle
  var simHdr = el.querySelector('#sim-hdr');
  if (simHdr) {
    simHdr.addEventListener('click', function() {
      var body = el.querySelector('#sim-body');
      var tog  = el.querySelector('#sim-toggle');
      if (body) body.classList.toggle('open');
      if (tog)  tog.classList.toggle('open');
    });
  }

  // Wire AI explanation toggles
  el.querySelectorAll('.ait').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var exp = btn.nextElementSibling;
      if (exp && exp.classList.contains('aie')) {
        exp.classList.toggle('open');
        btn.textContent = exp.classList.contains('open') ? '▲ Hide explanation' : '▼ Why is this risky?';
      }
    });
  });

  // Animate ring
  var arc = document.getElementById('score-arc');
  var num = document.getElementById('score-num');
  var target = Number(r.score) || 0;
  var start  = performance.now();
  function tick(now) {
    var t = Math.min((now - start) / 1000, 1);
    var e = 1 - Math.pow(1 - t, 3);
    var c = Math.round(e * target);
    if (num) num.textContent = c;
    if (arc) arc.style.strokeDashoffset = C * (1 - c / 100);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // Animate bars
  setTimeout(function() {
    el.querySelectorAll('[data-pct]').forEach(function(f) {
      f.style.width = f.getAttribute('data-pct') + '%';
    });
  }, 100);
}

function renderRiskItem(item) {
  var sev = item.severity || 'medium';
  var cls = { critical:'critical', high:'high', medium:'medium', low:'low' }[sev] || 'medium';
  var ai  = item.aiExplanation
    ? '<button class="ait">▼ Why is this risky?</button><div class="aie">' + esc(item.aiExplanation) + '</div>'
    : '';
  return '<div class="ri ' + cls + '">'
    + '<div class="ri-hdr"><div class="ri-dot"></div><div class="ri-title">' + esc(item.title) + '</div>'
    + (item.confidence ? '<span style="font-size:8px;font-family:monospace;color:rgba(56,189,248,0.4)">' + item.confidence + '%</span>' : '')
    + '</div>'
    + '<div class="ri-detail">' + esc(item.detail) + '</div>'
    + (item.tip ? '<div class="ri-tip">💡 ' + esc(item.tip) + '</div>' : '')
    + ai + '</div>';
}

function buildBreakdowns(r) {
  function has(id) {
    return (r.risks||[]).some(function(x){return x.id===id;})
      || (r.warnings||[]).some(function(x){return x.id===id;});
  }
  return [
    { label:'HTTPS',           pct:has('no_https')?0:100,                 color:has('no_https')?'var(--danger)':'var(--safe)',  val:has('no_https')?'✕':'✓' },
    { label:'Form Security',   pct:has('form_diff_domain')||has('form_http_action')?10:has('no_csrf')?55:100, color:has('form_diff_domain')||has('form_http_action')?'var(--danger)':has('no_csrf')?'var(--warn)':'var(--safe)', val:has('form_diff_domain')?'✕':has('no_csrf')?'~':'✓' },
    { label:'Domain Trust',    pct:has('lookalike')?10:has('url_risk')?45:100,        color:has('lookalike')?'var(--danger)':has('url_risk')?'var(--warn)':'var(--safe)', val:has('lookalike')?'✕':has('url_risk')?'~':'✓' },
    { label:'Phishing Signals',pct:has('phishing_text')||has('phishing_intent')?20:100, color:has('phishing_text')||has('phishing_intent')?'var(--danger)':'var(--safe)', val:has('phishing_text')||has('phishing_intent')?'!':'✓' },
    { label:'Fake Login',      pct:has('fake_login')?5:100,                color:has('fake_login')?'var(--danger)':'var(--safe)',  val:has('fake_login')?'✕':'✓' }
  ];
}

// ── RENDER: Forms ────────────────────────────────────────────────
function renderForms(r) {
  document.getElementById('fm-load').style.display = 'none';
  var el = document.getElementById('fm-content');
  el.style.display = 'block';
  var forms = r.forms || [];

  if (!forms.length) {
    el.innerHTML = '<div class="sw"><div class="si">📋</div>'
      + '<div class="st">No HTML form elements detected on this page.<br><span style="font-size:10px;opacity:.6">Fields outside &lt;form&gt; tags are not counted.</span></div></div>';
    return;
  }

  var html = '<div class="sec">' + forms.length + ' Form' + (forms.length > 1 ? 's' : '') + ' Detected</div>';
  forms.forEach(function(f) {
    var lvl = f.riskLevel || 'low';
    var st  = lvl === 'high' ? ['bad','🔴 High Risk'] : lvl === 'medium' ? ['warn','⚠️ Caution'] : ['ok','✅ Secure'];
    var csrfNote = f.isBenignForm ? 'ℹ️ Search/GET' : f.hasCSRFToken ? '✓ CSRF' : f.csrfWarningApplies ? '✕ CSRF' : '— CSRF';
    var csrfCls  = f.isBenignForm ? 'info' : f.hasCSRFToken ? 'ok' : f.csrfWarningApplies ? 'bad' : 'info';
    html += '<div class="fc ' + lvl + '">'
      + '<div class="fc-hdr"><span class="fc-id">#' + esc(String(f.id)) + '</span><span class="chip ' + st[0] + '">' + st[1] + '</span>' + (f.isBenignForm ? '<span class="chip info">GET/Search</span>' : '') + '</div>'
      + '<div class="fc-meta">'
      +   '<div class="mi"><div class="mk">Fields</div><div class="mv">' + (f.inputCount||0) + '</div></div>'
      +   '<div class="mi"><div class="mk">Visible</div><div class="mv">' + (f.visibleInputCount||0) + '</div></div>'
      +   '<div class="mi"><div class="mk">Method</div><div class="mv" style="text-transform:uppercase">' + esc(f.method||'get') + '</div></div>'
      + '</div>'
      + '<div class="chips">'
      +   '<span class="chip ' + csrfCls + '">' + csrfNote + '</span>'
      +   '<span class="chip ' + (f.actionDiffDomain?'bad':'ok') + '">' + (f.actionDiffDomain?'✕':'✓') + ' Domain</span>'
      +   '<span class="chip ' + (f.actionIsHttp?'bad':'ok') + '">' + (f.actionIsHttp?'✕':'✓') + ' Encrypted</span>'
      +   '<span class="chip ' + (f.hasSuspiciousFields?'bad':'ok') + '">' + (f.hasSuspiciousFields?'⚠':'✓') + ' Fields</span>'
      +   '<span class="chip ' + (f.hasPasswordField?'warn':'ok') + '">' + (f.hasPasswordField?'🔑 Password':'✓ No Pw') + '</span>'
      + '</div>'
      + (f.action ? '<div class="fc-act">→ ' + esc(f.action) + '</div>' : '')
      + (f.fieldNames&&f.fieldNames.length ? '<div class="fc-act" style="margin-top:3px">Fields: ' + esc(f.fieldNames.slice(0,8).join(', ')) + '</div>' : '')
      + '</div>';
  });
  el.innerHTML = html;
}

// ── RENDER: History ──────────────────────────────────────────────
function loadHistory() {
  Promise.all([
    msgBg({ type: 'GET_HISTORY' }),
    msgBg({ type: 'GET_TODAY_TIMELINE' })
  ]).then(function(results) {
    renderHistory(results[0].history || [], results[1].timeline || null);
  }).catch(function() {
    chrome.storage.local.get(['ss_history'], function(d) { renderHistory(d.ss_history || [], null); });
  });
}

function renderHistory(history, timeline) {
  document.getElementById('hi-load').style.display = 'none';
  var el = document.getElementById('hi-content');
  el.style.display = 'block';

  // Today's timeline card
  var tlHtml = '';
  if (timeline) {
    tlHtml = '<div class="tl-card">'
      + '<div class="tl-title">📅 Today\'s Activity</div>'
      + '<div class="tl-grid">'
      +   '<div class="tl-cell"><div class="tl-num" style="color:var(--muted)">' + timeline.total + '</div><div class="tl-lbl">Analysed</div></div>'
      +   '<div class="tl-cell"><div class="tl-num" style="color:var(--safe)">' + timeline.safe + '</div><div class="tl-lbl">Safe</div></div>'
      +   '<div class="tl-cell"><div class="tl-num" style="color:var(--danger)">' + timeline.blocked + '</div><div class="tl-lbl">Blocked</div></div>'
      +   '<div class="tl-cell"><div class="tl-num" style="color:var(--danger)">' + timeline.fakes + '</div><div class="tl-lbl">Fake Logins</div></div>'
      + '</div>'
      + '<div class="tl-insight">' + esc(timeline.insight) + '</div>'
      + '</div>';
  }

  if (!history.length) {
    el.innerHTML = tlHtml + '<div class="sw"><div class="si">📭</div><div class="st">No history yet. Visit some websites and scores will appear here.</div></div>';
    return;
  }

  var safe  = history.filter(function(h){return h.level==='safe';}).length;
  var warn  = history.filter(function(h){return h.level==='warning';}).length;
  var dang  = history.filter(function(h){return h.level==='danger';}).length;
  var fakes = history.filter(function(h){return h.fakeLoginDetected;}).length;
  var phish = history.filter(function(h){return h.phishingIntentDetected;}).length;

  var html = tlHtml
    + '<div class="stats-row">'
    +   '<div class="sc"><div class="sn" style="color:var(--safe)">' + safe + '</div><div class="sl2">Safe</div></div>'
    +   '<div class="sc"><div class="sn" style="color:var(--warn)">' + warn + '</div><div class="sl2">Caution</div></div>'
    +   '<div class="sc"><div class="sn" style="color:var(--danger)">' + dang + '</div><div class="sl2">High Risk</div></div>'
    + '</div>'
    + (fakes||phish ? '<div style="display:flex;gap:5px;margin-bottom:9px">' + (fakes?'<span class="chip bad">🚨 ' + fakes + ' Fake Login' + (fakes>1?'s':'') + '</span>':'') + (phish?'<span class="chip warn">🎯 ' + phish + ' Phishing' + (phish>1?' Intents':' Intent') + '</span>':'') + '</div>' : '')
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px">'
    +   '<div class="sec" style="margin:0">All Visits (' + history.length + ')</div>'
    +   '<button class="pb" id="btn-clr">Clear</button>'
    + '</div>';

  history.slice(0, 60).forEach(function(h) {
    var col = LC[h.level] || 'var(--muted)';
    var tags = '';
    if (h.fakeLoginDetected)       tags += '<span class="htag fake">🚨 Fake</span>';
    if (h.phishingIntentDetected)  tags += '<span class="htag phi">🎯 Phishing</span>';
    if ((h.adaptiveBoost||0) >= 4) tags += '<span class="htag adp">+' + h.adaptiveBoost + ' Trust</span>';
    html += '<div class="hi">'
      + '<div class="hd ' + (h.level||'default') + '"></div>'
      + '<div class="hin"><div class="hh">' + esc(h.hostname||h.url||'—') + '</div>'
      + '<div class="hm">' + timeAgo(h.visitedAt) + (tags ? '<span style="display:flex;gap:3px">' + tags + '</span>' : '') + '</div></div>'
      + '<div class="hscore" style="color:' + col + '">' + (h.score||'?') + '</div></div>';
  });

  el.innerHTML = html;
  var c = el.querySelector('#btn-clr');
  if (c) c.addEventListener('click', function() {
    msgBg({type:'CLEAR_HISTORY'}).catch(function(){chrome.storage.local.set({ss_history:[],ss_visit_counts:{}});});
    renderHistory([], timeline);
  });
}

function timeAgo(ts) {
  if (!ts) return '—';
  var d = Math.floor((Date.now()-ts)/86400000);
  var h = Math.floor((Date.now()-ts)/3600000);
  var m = Math.floor((Date.now()-ts)/60000);
  return d>0?d+'d ago':h>0?h+'h ago':m>0?m+'m ago':'just now';
}

// ── Buttons ──────────────────────────────────────────────────────
document.getElementById('btn-refresh').addEventListener('click', async function() {
  ['ov','fm'].forEach(function(p) {
    document.getElementById(p+'-load').style.display = '';
    document.getElementById(p+'-content').style.display = 'none';
  });
  var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs[0]) {
    try { await chrome.scripting.executeScript({ target:{tabId:tabs[0].id}, files:['content_script.js'] }); }
    catch(e) {}
  }
  setTimeout(init, 900);
});

document.getElementById('btn-report').addEventListener('click', openReport);
document.getElementById('btn-details').addEventListener('click', openReport);

async function openReport() {
  var r = await getAnalysis();
  if (!r) {
    chrome.storage.local.get(['ss_last_scan'], function(d) {
      if (d.ss_last_scan) openReportTab(d.ss_last_scan);
      else alert('No analysis data yet. Visit a website first.');
    });
    return;
  }
  openReportTab(r);
}

function openReportTab(data) {
  chrome.storage.local.set({ ss_report_data: data }, function() {
    chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
  });
}

document.getElementById('btn-phish').addEventListener('click', function() {
  chrome.tabs.create({ url: 'https://safebrowsing.google.com/safebrowsing/report_phish/' });
});

// ── Init ─────────────────────────────────────────────────────────
async function init() {
  var r = await getAnalysis();
  if (!r) {
    document.getElementById('ov-load').innerHTML =
      '<div class="sw"><div class="si">🔍</div><div class="st">Not available for this page.<br><span style="font-size:10px;opacity:.6">Try visiting a regular website.</span></div></div>';
    document.getElementById('fm-load').innerHTML =
      '<div class="sw"><div class="si">📋</div><div class="st">No data available.</div></div>';
    return;
  }
  renderOverview(r);
  renderForms(r);
}

init();

// ── Claude AI Enrichment Listener ───────────────────────────────────
chrome.runtime.onMessage.addListener(function(msg) {
  if (msg.type === 'CLAUDE_ENRICHMENT_READY') {
    // Re-render with Claude-enriched data
    renderOverview(msg.result);
    renderForms(msg.result);
    // Show "Powered by Claude AI" badge
    var badge = document.getElementById('claude-badge');
    if (badge) badge.classList.add('show');
  }
});
