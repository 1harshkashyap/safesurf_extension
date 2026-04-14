/**
 * SafeSurf AI – Report.js v4.0
 * Reads from chrome.storage, renders full report including
 * attack simulation, trust explanation, adaptive trust, and all v4 intelligence.
 */
'use strict';

var LC = { safe:'#22c55e', warning:'#f59e0b', danger:'#ef4444' };
var LG = { safe:'rgba(34,197,94,0.15)', warning:'rgba(245,158,11,0.18)', danger:'rgba(239,68,68,0.22)' };

function esc(s) {
  if (typeof s !== 'string') s = String(s||'');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fch(cls, t) { return '<span class="fch ' + cls + '">' + esc(t) + '</span>'; }
function ig2(k, v) { return '<div class="ig-c"><div class="ig-k">' + esc(k) + '</div><div class="ig-v">' + esc(String(v||'—')) + '</div></div>'; }
function has(r, id) {
  return (r.risks||[]).some(function(x){return x.id===id;})
    || (r.warnings||[]).some(function(x){return x.id===id;});
}

function render(r) {
  if (!r) {
    document.getElementById('root').innerHTML = '<div style="text-align:center;padding:60px;color:#ef4444"><div style="font-size:40px;margin-bottom:12px">⚠️</div><div style="font-size:16px;font-weight:700;margin-bottom:8px">No report data</div><div style="font-size:13px;color:#4a6a86">Open this page from the SafeSurf popup.</div></div>';
    return;
  }

  var col  = LC[r.level]||'#64748b';
  var glow = LG[r.level]||'transparent';
  var conf = r.confidence || 70;
  var fl   = r.fakeLogin || {};
  var pi   = r.phishingIntent || {};
  var ur   = r.urlRisk || {};
  var ad   = r.adaptive || {};
  var te   = r.trustExplanation || {};
  var as2  = r.attackSimulation || {};
  var all  = (r.risks||[]).concat(r.warnings||[]);
  var forms = r.forms || [];
  var passes = r.passes || [];

  // ── Header ─────────────────────────────────────────────────────
  var fakeBadge = fl.detected ? '<span class="badge fake">🚨 FAKE LOGIN</span>' : '';
  var adptBadge = (ad.adaptiveBoost||0) > 0 ? '<span class="badge conf">🧬 +' + ad.adaptiveBoost + ' Adaptive Trust</span>' : '';
  var hdr = '<div class="rh" style="--hg:' + glow + '">'
    + '<div class="bs" style="color:' + col + '">' + (r.score||0) + '</div>'
    + '<div class="rm"><h1>' + esc(r.label||'Security Report') + '</h1>'
    +   '<div class="host">' + esc(r.hostname||r.url||'Unknown') + '</div>'
    +   '<div class="bds-row">'
    +     '<span class="badge ' + esc(r.level) + '">' + (r.level==='safe'?'✓ Safe':r.level==='warning'?'⚠ Caution':'✕ High Risk') + '</span>'
    +     '<span class="badge conf">🧠 ' + conf + '% confidence</span>'
    +     fakeBadge + adptBadge
    +   '</div>'
    +   (ad.adaptiveMessage ? '<div style="font-size:11px;color:#86efac;margin-bottom:4px">' + esc(ad.adaptiveMessage) + '</div>' : '')
    +   '<div class="ts">Analysed: ' + (r.scannedAt?new Date(r.scannedAt).toLocaleString():'—') + '</div>'
    + '</div></div>';

  // ── AI Summary ──────────────────────────────────────────────────
  var ai = r.aiSummary
    ? '<div class="ai-box"><div class="ai-lbl">🤖 AI Security Analysis</div><div class="ai-txt">' + esc(r.aiSummary) + '</div></div>'
    : '';

  // ── Score Breakdown Bars ────────────────────────────────────────
  var bars = [
    { l:'HTTPS',          pct:has(r,'no_https')?0:100,          c:has(r,'no_https')?'#ef4444':'#22c55e',  t:has(r,'no_https')?'✕ Not Encrypted':'✓ Encrypted' },
    { l:'Form Security',  pct:has(r,'form_diff_domain')||has(r,'form_http_action')?10:has(r,'no_csrf')?55:100, c:has(r,'form_diff_domain')||has(r,'form_http_action')?'#ef4444':has(r,'no_csrf')?'#f59e0b':'#22c55e', t:has(r,'form_diff_domain')?'✕ External':'✓ Secure' },
    { l:'Domain Trust',   pct:has(r,'lookalike')?10:has(r,'url_risk')?45:100, c:has(r,'lookalike')?'#ef4444':has(r,'url_risk')?'#f59e0b':'#22c55e', t:has(r,'lookalike')?'✕ Lookalike':r.isTrustedDomain?'✓ Trusted':'~ Unknown' },
    { l:'Phishing',       pct:has(r,'phishing_text')||has(r,'phishing_intent')?15:100, c:has(r,'phishing_text')||has(r,'phishing_intent')?'#ef4444':'#22c55e', t:has(r,'phishing_text')||has(r,'phishing_intent')?'✕ Detected':'✓ Clean' },
    { l:'Fake Login',     pct:fl.detected?5:100, c:fl.detected?'#ef4444':'#22c55e', t:fl.detected?'✕ Detected':'✓ Clear' }
  ];
  var barsHtml = '<div class="grid2">' + bars.map(function(b) {
    return '<div class="sbc"><div class="sbc-l">' + esc(b.l) + '</div>'
      + '<div class="sbc-b"><div class="sbc-f" style="width:' + b.pct + '%;background:' + b.c + '"></div></div>'
      + '<div class="sbc-r"><span class="sbc-v" style="color:' + b.c + '">' + b.pct + '%</span><span class="sbc-t">' + esc(b.t) + '</span></div></div>';
  }).join('') + '</div>';

  // ── Trust Explanation ───────────────────────────────────────────
  var teHtml = '';
  if ((te.positive&&te.positive.length)||(te.negative&&te.negative.length)) {
    teHtml = '<div class="sh">Why This Page Is ' + esc(r.level==='safe'?'Safe':r.level==='warning'?'Flagged':'High Risk') + '</div>'
      + '<div class="te-grid">'
      +   '<div class="te-card"><div class="te-lbl pos">✅ Positive Factors</div>' + (te.positive||[]).map(function(p){return '<div class="te-item">'+esc(p)+'</div>';}).join('') + (!(te.positive&&te.positive.length)?'<div class="te-item" style="color:#64748b">None detected</div>':'') + '</div>'
      +   '<div class="te-card"><div class="te-lbl neg">⚠️ Risk Factors</div>' + (te.negative||[]).map(function(n){return '<div class="te-item">'+esc(n)+'</div>';}).join('') + (!(te.negative&&te.negative.length)?'<div class="te-item" style="color:var(--safe)">None detected ✓</div>':'') + '</div>'
      + '</div>';
  }

  // ── Intelligence Panel (Fake Login + Phishing + URL) ───────────
  var intelHtml = '';
  var intelCards = '';
  if (fl.detected) {
    var flSigs = (fl.signals||[]).map(function(s){return '<div style="font-size:11px;color:#fca5a5;margin-bottom:4px;display:flex;align-items:flex-start;gap:5px"><span>•</span><span>'+esc(s)+'</span></div>';}).join('');
    intelCards += '<div class="ic" style="border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.07)">'
      + '<div class="ih"><div class="id2" style="background:#ef4444"></div><div class="it" style="color:#fca5a5">🚨 Fake Login Analysis (' + fl.confidence + '% confidence)</div></div>'
      + flSigs
      + (fl.aiExplanation ? '<div class="iai">🤖 ' + esc(fl.aiExplanation) + '</div>' : '') + '</div>';
  }
  if (pi.detected) {
    var piWds = (pi.allFound||[]).map(function(w){return '<span style="background:rgba(245,158,11,0.15);color:#f59e0b;padding:1px 7px;border-radius:20px;font-size:9px;font-weight:700;margin:2px">'+esc(w)+'</span>';}).join('');
    intelCards += '<div class="ic" style="border-color:rgba(245,158,11,0.25);background:rgba(245,158,11,0.05)">'
      + '<div class="ih"><div class="id2" style="background:#f59e0b"></div><div class="it" style="color:#fcd34d">🎯 Phishing Intent (' + pi.intentScore + '/100 · ' + pi.confidence + '% conf.)</div></div>'
      + (pi.detail ? '<div class="idet">' + esc(pi.detail) + '</div>' : '')
      + (piWds ? '<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:5px">' + piWds + '</div>' : '')
      + (pi.aiExplanation ? '<div class="iai">🤖 ' + esc(pi.aiExplanation) + '</div>' : '') + '</div>';
  }
  if (ur.signals && ur.signals.length) {
    var urSigs = ur.signals.map(function(s){var dc=s.severity==='high'?'#ef4444':s.severity==='medium'?'#f59e0b':'#94a3b8';return '<div style="font-size:11px;color:var(--muted);margin-bottom:4px;display:flex;gap:5px"><div style="width:5px;height:5px;border-radius:50%;background:'+dc+';flex-shrink:0;margin-top:4px"></div><span>'+esc(s.text)+'</span></div>';}).join('');
    intelCards += '<div class="ic"><div class="ih"><div class="id2" style="background:#38bdf8"></div><div class="it" style="color:#7dd3fc">🔗 URL Risk (' + ur.riskScore + '/100)</div></div>'
      + '<div style="font-family:monospace;font-size:10px;color:#38bdf8;margin-bottom:7px">' + esc(ur.hostname||r.hostname) + '</div>'
      + urSigs + '</div>';
  }
  if (intelCards) intelHtml = '<div class="sh">AI Intelligence Analysis</div>' + intelCards;

  // ── Attack Simulation ───────────────────────────────────────────
  var simHtml = '';
  if (as2.attacks && as2.attacks.length) {
    simHtml = '<div class="sh">⚗️ Attack Simulation</div>'
      + '<div style="font-size:12px;color:var(--muted);margin-bottom:10px">What would happen if these risks were exploited by a real attacker:</div>'
      + '<div class="as-grid">' + as2.attacks.map(function(a) {
          var stolenHtml = (a.stolen||[]).map(function(s){return '<span class="as-item">'+esc(s)+'</span>';}).join('');
          return '<div class="as-card ' + esc(a.severity) + '">'
            + '<div class="as-hdr"><span class="as-icon">' + a.icon + '</span><span class="as-name">' + esc(a.type) + '</span><span class="as-sev ' + esc(a.severity) + '">' + a.severity.toUpperCase() + '</span></div>'
            + '<div class="as-what">' + esc(a.whatHappens) + '</div>'
            + (stolenHtml ? '<div class="as-stolen">' + stolenHtml + '</div>' : '')
            + '<div class="as-cons">Impact: ' + esc(a.consequence) + '</div>'
            + (a.difficulty!=='N/A' ? '<div class="as-diff">Difficulty: ' + esc(a.difficulty) + '</div>' : '')
            + '</div>';
        }).join('') + '</div>';
  }

  // ── Issues ──────────────────────────────────────────────────────
  var issHtml = '<div class="sh">Issues Found (' + all.length + ')</div>';
  if (!all.length) {
    issHtml += '<div style="color:#22c55e;font-size:13px;padding:8px 0">✓ No security issues detected.</div>';
  } else {
    all.forEach(function(item) {
      var sev = item.severity||'medium';
      var dc  = (sev==='high'||sev==='critical')?'#ef4444':sev==='low'?'#94a3b8':'#f59e0b';
      issHtml += '<div class="ic"><div class="ih"><div class="id2" style="background:'+dc+'"></div><div class="it">'+esc(item.title)+'</div><span class="sv '+esc(sev)+'">'+sev.toUpperCase()+'</span></div>'
        + '<div class="idet">'+esc(item.detail)+'</div>'
        + (item.tip?'<div class="itip">💡 '+esc(item.tip)+'</div>':'')
        + (item.aiExplanation?'<div class="iai">🤖 '+esc(item.aiExplanation)+'</div>':'')
        + (item.confidence?'<div class="icf">Confidence: '+item.confidence+'%</div>':'')
        + '</div>';
    });
  }

  // ── Passes ──────────────────────────────────────────────────────
  var passHtml = '<div class="sh">Passed Checks (' + passes.length + ')</div>'
    + passes.map(function(p) {
        return '<div class="ic"><div class="ih"><div class="id2" style="background:#22c55e"></div><div class="it" style="color:#86efac">'+esc(p.title)+'</div>' + (p.confidence?'<span class="sv" style="background:rgba(34,197,94,0.1);color:#22c55e">'+p.confidence+'%</span>':'') + '</div><div class="idet">'+esc(p.detail)+'</div></div>';
      }).join('');

  // ── Forms ────────────────────────────────────────────────────────
  var formsHtml = '<div class="sh">Forms (' + forms.length + ')</div>';
  if (!forms.length) {
    formsHtml += '<div style="color:var(--muted);font-size:13px;padding:8px 0">No HTML form elements found.</div>';
  } else {
    forms.forEach(function(f) {
      var isH=f.riskLevel==='high',isM=f.riskLevel==='medium';
      var idc=isH?'#ef4444':isM?'#f59e0b':'#22c55e';
      var csrfCls=f.isBenignForm?'info':f.hasCSRFToken?'ok':f.csrfWarningApplies?'bad':'info';
      var csrfTxt=f.isBenignForm?'GET/Search':f.hasCSRFToken?'✓ CSRF':f.csrfWarningApplies?'✕ CSRF':'— CSRF';
      formsHtml += '<div class="fr-row"><div class="fi" style="background:'+idc+'"></div><div class="fn"><div class="fid">#'+esc(String(f.id))+'</div><div class="fm2">'+(f.inputCount||0)+' fields · '+(f.method||'get').toUpperCase()+(f.action?' → '+esc(f.action.substring(0,55)):'')+(f.isBenignForm?' (Search/GET)':'')+'</div><div class="fc2">'+fch(csrfCls,csrfTxt)+fch(f.actionDiffDomain?'bad':'ok',(f.actionDiffDomain?'✕':'✓')+' Domain')+fch(f.actionIsHttp?'bad':'ok',(f.actionIsHttp?'✕':'✓')+' Encrypted')+fch(f.hasSuspiciousFields?'bad':'ok',(f.hasSuspiciousFields?'⚠':'✓')+' Fields')+fch(f.hasPasswordField?'warn':'ok',f.hasPasswordField?'🔑 Password':'No Password')+'</div></div></div>';
    });
  }

  // ── Page Info ────────────────────────────────────────────────────
  var infoHtml = '<div class="sh">Page Information</div><div class="ic"><div class="ig">'
    + ig2('URL', r.url) + ig2('Protocol', r.isHttps?'✓ HTTPS':'✕ HTTP')
    + ig2('Hostname', r.hostname) + ig2('Title', r.pageTitle)
    + ig2('Forms', String(forms.length)) + ig2('Phishing Phrases', String((r.phishingKeywordsFound||[]).length))
    + ig2('Fake Login', fl.detected?'🚨 Detected ('+fl.confidence+'%)':'Not detected')
    + ig2('Phishing Intent', pi.detected?'🎯 Score: '+pi.intentScore+'/100':'Not detected')
    + ig2('URL Risk', (ur.riskScore||0)+'/100')
    + ig2('Trusted Domain', r.isTrustedDomain?'✓ Yes':'No')
    + ig2('Lookalike', r.isLookalike?'⚠ Yes':'No')
    + ig2('Visit History', (r.adaptive?r.adaptive.prevSafeVisits+' safe visits':'—'))
    + ig2('Adaptive Boost', (r.adaptive&&r.adaptive.adaptiveBoost>0?'+'+r.adaptive.adaptiveBoost+' pts':'—'))
    + '</div></div>';

  document.getElementById('root').innerHTML = hdr + ai + barsHtml + teHtml + intelHtml + simHtml + issHtml + passHtml + formsHtml + infoHtml;
  document.title = 'SafeSurf – ' + (r.hostname||'Report') + ' (' + r.score + '/100)';
}

// Load data
if (typeof chrome !== 'undefined' && chrome.storage) {
  chrome.storage.local.get(['ss_report_data','ss_last_scan'], function(d) {
    var r = d.ss_report_data || d.ss_last_scan || null;
    if (!r) { try { r = JSON.parse(decodeURIComponent(new URLSearchParams(location.search).get('data')||'')); } catch(e){} }
    render(r);
  });
} else {
  var p = new URLSearchParams(location.search).get('data');
  try { render(p ? JSON.parse(decodeURIComponent(p)) : null); } catch(e) { render(null); }
}
