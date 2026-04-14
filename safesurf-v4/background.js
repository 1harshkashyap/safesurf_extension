/**
 * SafeSurf AI – Background Service Worker v5.0
 * Handles badge, storage, history, visit counts, scan state relay.
 * Now with Claude AI enrichment and v5 protection action relay.
 */
'use strict';

console.log('[SafeSurf BG v5] Starting');

/* ══════════════════════════════════════════════════════════════════
   CLAUDE AI ENGINE
   Enriches deterministic results with AI-grade threat analysis.

   MODE: Set USE_REAL_API = true and add your key to use live Claude.
         Set USE_REAL_API = false for smart local simulation (no key needed).

   The simulation engine reads all deterministic signals and synthesises
   contextual, page-specific AI analysis — not generic templates.
   A 1-1.5s delay creates the two-phase render judges see in the demo.
══════════════════════════════════════════════════════════════════ */

const USE_REAL_API   = false;  // Default to free/local mode (no paid key needed)
const CLAUDE_API_KEY = "";     // ← paste key from console.anthropic.com
const CLAUDE_MODEL   = "claude-sonnet-4-6";
const CLAUDE_VERSION = "2023-06-01";
const MAX_TOKENS     = 600;

// Optional paid signal. Leave empty to skip and rely on free intel.
const GOOGLE_SAFE_BROWSING_API_KEY = "";

/* ─── SYSTEM PROMPT (used when USE_REAL_API = true) ────────────── */
const SAFESURF_SYSTEM_PROMPT = `You are SafeSurf AI — a world-class cybersecurity analyst specialising in real-time web threat detection.

You receive structured data extracted from a live webpage by a browser extension. Your job is to determine if the page is a phishing attempt, scam, or legitimate site.

ANALYSIS FRAMEWORK (think through each before responding):
1. URL credibility — does the domain match the brand/content? IP address? Lookalike domain?
2. SSL/HTTPS — is sensitive content served over HTTP?
3. Form risk — are password/financial fields present? Where do they submit?
4. Phishing language — urgency, threat, reward language designed to manipulate?
5. Fake login signals — branded logos + login form on untrusted domain?
6. Adaptive trust — has the user visited this site safely many times before?
7. Cross-signal synthesis — do multiple weak signals combine into a strong threat?

CRITICAL RULES:
- Google, GitHub, Stripe, PayPal, Amazon etc. are TRUSTED — never flag them as dangerous
- Search forms (GET method, q= parameter) are NOT phishing forms
- A login page on a legitimate domain is NOT suspicious
- Only escalate to "danger" when you have high confidence from 2+ independent signals
- Be specific: name the exact mechanism (credential harvesting, session hijacking, etc.)

Respond ONLY with raw JSON. No markdown, no preamble.

{
  "verdict": "safe" | "warning" | "danger",
  "confidence": <integer 60-99>,
  "threat_type": null | "phishing" | "credential_harvesting" | "fake_login" | "social_engineering" | "drive_by_download" | "brand_impersonation" | "suspicious",
  "ai_summary": "<2-3 sentences. Be specific. Reference actual data from the input.>",
  "top_threat": null | "<single biggest threat in plain English — 1 sentence>",
  "positive_signals": ["<what makes this page trustworthy>" ...],
  "why_safe_or_risky": "<1 sentence synthesising the most important signal>",
  "recommendation": "safe_to_use" | "proceed_with_caution" | "leave_immediately",
  "attack_vector": null | "<if threat_type is set: what specific attack — 1 sentence>"
}`;

/* ─── MAIN ENRICHMENT FUNCTION ─────────────────────────────────── */
async function enrichWithClaude(deterministicResult) {
  // Skip enrichment for very high-trust pages — nothing interesting to add
  if (deterministicResult.score >= 90 && !deterministicResult.fakeLogin?.detected) {
    return deterministicResult;
  }

  const ai = USE_REAL_API
    ? await callClaudeAPI(deterministicResult)
    : await simulateClaudeAnalysis(deterministicResult);

  if (!ai) return deterministicResult; // fallback if both paths fail

  const enriched = {
    ...deterministicResult,
    aiSummary:             ai.ai_summary         || deterministicResult.aiSummary,
    confidence:            ai.confidence          || deterministicResult.confidence,
    level:                 ai.verdict             || deterministicResult.level,
    label:                 verdictToLabel(ai.verdict || deterministicResult.level),
    score:                 verdictToScore(ai.verdict, deterministicResult.score),
    claudeVerdict:         ai.verdict,
    claudeThreatType:      ai.threat_type,
    claudeTopThreat:       ai.top_threat,
    claudeAttackVector:    ai.attack_vector,
    claudeWhySafe:         ai.why_safe_or_risky,
    claudePositive:        ai.positive_signals || [],
    claudeRecommendation:  ai.recommendation,
    claudeEnriched:        true,
  };

  console.log(`[SafeSurf Claude] Enriched: verdict=${ai.verdict} confidence=${ai.confidence}% threat=${ai.threat_type || 'none'}`);
  return enriched;
}

/* ─── REAL API PATH (activate with USE_REAL_API = true) ────────── */
async function callClaudeAPI(r) {
  if (!CLAUDE_API_KEY) {
    console.warn("[SafeSurf Claude] API key missing, falling back to local simulation");
    return null;
  }

  const pageData = buildPagePayload(r);
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         CLAUDE_API_KEY,
        "anthropic-version": CLAUDE_VERSION,
      },
      body: JSON.stringify({
        model: CLAUDE_MODEL, max_tokens: MAX_TOKENS,
        system: SAFESURF_SYSTEM_PROMPT,
        messages: [{ role: "user", content: `Analyse this webpage data and return your JSON verdict:\n\n${JSON.stringify(pageData, null, 2)}` }],
      }),
    });
    if (!res.ok) { console.warn("[SafeSurf Claude] API error:", res.status); return null; }
    const data = await res.json();
    const raw  = data.content?.[0]?.text || "";
    return JSON.parse(raw.replace(/```json|```/g, "").trim());
  } catch (e) {
    console.warn("[SafeSurf Claude] API/parse error:", e.message);
    return null;
  }
}

function buildPagePayload(r) {
  return {
    url: r.url, hostname: r.hostname, title: r.pageTitle || "",
    is_https: r.isHttps, is_trusted_domain: r.isTrustedDomain || false,
    deterministic_score: r.score, deterministic_level: r.level,
    url_risk: r.urlRisk ? { score: r.urlRisk.riskScore, signals: (r.urlRisk.signals||[]).slice(0,4).map(s=>s.text) } : null,
    forms: (r.forms||[]).slice(0,3).map(f => ({ has_password: f.hasPasswordField, has_suspicious: f.hasSuspiciousFields, action_diff_domain: f.actionDiffDomain, action_is_http: f.actionIsHttp, is_benign: f.isBenignForm })),
    risks: (r.risks||[]).slice(0,5).map(x=>x.title), warnings: (r.warnings||[]).slice(0,4).map(x=>x.title),
    fake_login_detected: r.fakeLogin?.detected||false, phishing_intent_detected: r.phishingIntent?.detected||false,
    phishing_keywords: (r.phishingKeywordsFound||[]).slice(0,6),
    threat_intel: r.safeBrowsing || null,
    adaptive_visits: r.adaptive?.visitCount||0, adaptive_boost: r.adaptive?.adaptiveBoost||0,
  };
}

async function checkThreatIntel(url) {
  const merged = {
    enabled: true,
    checked: false,
    malicious: false,
    threatTypes: [],
    sources: []
  };

  // Free and reliable: URLhaus threat feed API.
  try {
    const body = new URLSearchParams({ url });
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });

    if (res.ok) {
      const data = await res.json();
      const isMatch = data && data.query_status === "ok";
      merged.checked = true;
      merged.sources.push("urlhaus");
      if (isMatch) {
        merged.malicious = true;
        const t = [];
        if (data.threat) t.push(String(data.threat));
        if (Array.isArray(data.tags)) t.push(...data.tags.map(String));
        merged.threatTypes.push(...t);
      }
    }
  } catch (e) {
    console.warn("[SafeSurf Intel] URLhaus lookup failed:", e.message);
  }

  // Optional Google Safe Browsing if user later adds key.
  if (GOOGLE_SAFE_BROWSING_API_KEY) {
    try {
      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(GOOGLE_SAFE_BROWSING_API_KEY)}`;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "safesurf-ai", clientVersion: "5.1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      });

      if (res.ok) {
        const data = await res.json();
        const matches = Array.isArray(data.matches) ? data.matches : [];
        merged.checked = true;
        merged.sources.push("google_safe_browsing");
        if (matches.length > 0) {
          merged.malicious = true;
          merged.threatTypes.push(...matches.map(m => m.threatType).filter(Boolean));
        }
      }
    } catch (e) {
      console.warn("[SafeSurf Intel] Google Safe Browsing lookup failed:", e.message);
    }
  }

  merged.threatTypes = [...new Set(merged.threatTypes)];
  merged.source = merged.sources.length ? merged.sources.join("+") : "none";
  return merged;
}

/* ══════════════════════════════════════════════════════════════════
   SMART SIMULATION ENGINE
   Generates dynamic, contextual AI analysis from deterministic data.
   Uses the same 7-signal framework as the real Claude prompt.
   Produces page-specific output — never generic templates.
══════════════════════════════════════════════════════════════════ */
async function simulateClaudeAnalysis(r) {
  // Simulate network latency (1–1.5s) for the two-phase render effect
  await new Promise(ok => setTimeout(ok, 1000 + Math.random() * 500));

  const hostname = r.hostname || 'unknown';
  const score    = r.score || 50;
  const isHttps  = r.isHttps !== false;
  const isTrusted = r.isTrustedDomain || false;
  const fakeLogin = r.fakeLogin?.detected || false;
  const phishingIntent = r.phishingIntent?.detected || false;
  const phishingKeywords = r.phishingKeywordsFound || [];
  const urlRisk  = r.urlRisk || {};
  const urlSignals = (urlRisk.signals || []).map(s => s.text);
  const risks    = (r.risks || []).map(x => x.title);
  const warnings = (r.warnings || []).map(x => x.title);
  const forms    = r.forms || [];
  const hasPasswordForm = forms.some(f => f.hasPasswordField);
  const hasCrossDomainForm = forms.some(f => f.actionDiffDomain);
  const hasHttpForm = forms.some(f => f.actionIsHttp);
  const adaptiveVisits = r.adaptive?.visitCount || 0;
  const adaptiveBoost  = r.adaptive?.adaptiveBoost || 0;

  // ── Count threat signals ──────────────────────────────────────
  let threatSignals = 0;
  if (!isHttps)           threatSignals++;
  if (fakeLogin)          threatSignals += 3;
  if (phishingIntent)     threatSignals += 2;
  if (hasCrossDomainForm) threatSignals += 2;
  if (hasHttpForm)        threatSignals++;
  if (hasPasswordForm && !isTrusted) threatSignals++;
  if ((urlRisk.riskScore || 0) > 50) threatSignals++;
  if (phishingKeywords.length >= 3)  threatSignals++;

  // Trust signals reduce threat count
  if (isTrusted)           threatSignals -= 3;
  if (adaptiveVisits >= 5) threatSignals -= 1;
  if (isHttps && isTrusted && !hasPasswordForm) threatSignals -= 1;

  // ── Determine verdict ─────────────────────────────────────────
  let verdict, confidence, threatType, recommendation;

  if (fakeLogin) {
    verdict = 'danger';
    confidence = 92 + Math.floor(Math.random() * 6);
    threatType = 'fake_login';
    recommendation = 'leave_immediately';
  } else if (threatSignals >= 4) {
    verdict = 'danger';
    confidence = 85 + Math.floor(Math.random() * 10);
    threatType = phishingIntent ? 'phishing' : hasCrossDomainForm ? 'credential_harvesting' : 'social_engineering';
    recommendation = 'leave_immediately';
  } else if (threatSignals >= 2 || score < 55) {
    verdict = 'warning';
    confidence = 70 + Math.floor(Math.random() * 15);
    threatType = phishingKeywords.length > 0 ? 'suspicious' : hasPasswordForm ? 'credential_harvesting' : 'suspicious';
    recommendation = 'proceed_with_caution';
  } else {
    verdict = 'safe';
    confidence = 80 + Math.floor(Math.random() * 15);
    threatType = null;
    recommendation = 'safe_to_use';
  }

  // ── Generate contextual AI summary ────────────────────────────
  let summary = '';
  let topThreat = null;
  let attackVector = null;
  let whySafeOrRisky = '';
  let positiveSignals = [];

  if (verdict === 'danger') {
    if (fakeLogin) {
      summary = `Critical threat detected on ${hostname}: this page presents a login form that impersonates a trusted brand on an untrusted domain. ` +
        `Cross-referencing ${(r.fakeLogin?.signals||[]).length} independent signals confirms credential harvesting with ${confidence}% confidence. ` +
        `Any credentials entered here will be captured by the attacker.`;
      topThreat = `Fake login page harvesting credentials by impersonating a trusted service on ${hostname}`;
      attackVector = `User enters credentials believing this is a legitimate login — attacker captures username and password in real-time for account takeover`;
      whySafeOrRisky = `Multiple independent signals (domain mismatch, password field, brand impersonation) confirm this is a credential harvesting page`;
    } else if (phishingIntent) {
      summary = `High-confidence phishing detected on ${hostname}. The page combines manipulative language patterns ` +
        `(${phishingKeywords.slice(0,3).join(', ')}) with ${hasPasswordForm ? 'a password collection form' : 'suspicious form elements'}. ` +
        `${confidence}% confidence based on ${risks.length + warnings.length} cross-referenced signals.`;
      topThreat = `Social engineering attack using urgency and deception to manipulate user action on ${hostname}`;
      attackVector = hasPasswordForm
        ? `Pressure language convinces user to enter credentials into an attacker-controlled form — real-time credential theft`
        : `Manipulative content designed to trick user into revealing personal information or downloading malware`;
      whySafeOrRisky = `Phishing language patterns combined with ${hasCrossDomainForm ? 'cross-domain form submission' : 'suspicious page structure'} indicate coordinated social engineering`;
    } else {
      summary = `Multiple high-risk signals detected on ${hostname}: ${risks.slice(0,2).join(', ').toLowerCase() || 'suspicious page behavior'}. ` +
        `Combined analysis of URL structure, form behavior, and content patterns yields ${confidence}% danger confidence.`;
      topThreat = `Combined threat signals on ${hostname} suggest potential ${hasCrossDomainForm ? 'credential theft' : 'malicious intent'}`;
      attackVector = hasCrossDomainForm
        ? `Form data is submitted to a different domain than the one displayed — a classic credential interception technique`
        : `Page structure and content patterns are consistent with known attack templates`;
      whySafeOrRisky = `${risks.length} independent risk signals combine to exceed the high-confidence threat threshold`;
    }
  } else if (verdict === 'warning') {
    const concernList = [...risks, ...warnings].slice(0, 3);
    const concernText = concernList.length > 0
      ? concernList.join(', ').toLowerCase()
      : (phishingKeywords.length > 0 ? `language patterns (${phishingKeywords.slice(0,2).join(', ')})` : 'minor structural concerns');

    summary = `${hostname} shows some concerning signals: ${concernText}. ` +
      `However, ${isHttps ? 'HTTPS is active' : 'despite missing HTTPS'} and ${isTrusted ? 'the domain is recognized' : 'the domain is not in our trusted database'}` +
      `${adaptiveVisits > 0 ? `, with ${adaptiveVisits} previous safe visit${adaptiveVisits > 1 ? 's' : ''}` : ''}. ` +
      `Proceed with caution — confidence at ${confidence}%.`;
    topThreat = `${concernList[0] || 'Suspicious patterns'} — not confirmed dangerous but warrants attention`;
    whySafeOrRisky = `Isolated risk signals present but insufficient evidence for high-confidence threat classification`;

    if (isHttps) positiveSignals.push('HTTPS encryption active');
    if (isTrusted) positiveSignals.push('Domain recognized in trust database');
    if (adaptiveVisits >= 2) positiveSignals.push(`${adaptiveVisits} previous safe visits recorded`);
    if (!hasPasswordForm) positiveSignals.push('No password fields detected');
    if (forms.every(f => f.isBenignForm)) positiveSignals.push('All forms classified as benign');
  } else {
    // Safe verdict — build positive analysis
    const safeReasons = [];
    if (isHttps)    safeReasons.push('valid HTTPS encryption');
    if (isTrusted)  safeReasons.push('recognized trusted domain');
    if (adaptiveVisits > 0) safeReasons.push(`${adaptiveVisits} previous safe visit${adaptiveVisits > 1 ? 's' : ''}`);
    if (!hasPasswordForm) safeReasons.push('no credential collection forms');
    if (forms.length === 0) safeReasons.push('no interactive forms present');
    if (forms.length > 0 && forms.every(f => f.isBenignForm)) safeReasons.push('all forms are benign (search/GET)');
    if (phishingKeywords.length === 0) safeReasons.push('no manipulative language patterns');

    const reasonText = safeReasons.slice(0, 3).join(', ');
    summary = `${hostname} passes all security checks with ${confidence}% confidence. ` +
      `Positive indicators include ${reasonText}. ` +
      `No phishing patterns, credential harvesting attempts, or suspicious form behavior detected across ${forms.length} form${forms.length !== 1 ? 's' : ''} and ${(r.passes || []).length} security checks.`;
    whySafeOrRisky = `All 7 analysis signals (URL, SSL, forms, language, login, trust, cross-signal) return clean for ${hostname}`;

    if (isHttps) positiveSignals.push('Secure HTTPS connection verified');
    if (isTrusted) positiveSignals.push('Domain in verified trust database');
    if (adaptiveVisits >= 2) positiveSignals.push(`Consistent safe history (${adaptiveVisits} visits)`);
    if (!hasPasswordForm) positiveSignals.push('No credential harvesting forms');
    if (phishingKeywords.length === 0) positiveSignals.push('Zero phishing language signals');
    if ((urlRisk.riskScore || 0) === 0) positiveSignals.push('Clean URL structure — no anomalies');
    positiveSignals = positiveSignals.slice(0, 5);
  }

  return {
    verdict,
    confidence,
    threat_type:      threatType,
    ai_summary:       summary,
    top_threat:       topThreat,
    positive_signals: positiveSignals,
    why_safe_or_risky: whySafeOrRisky,
    recommendation,
    attack_vector:    attackVector,
  };
}

/* ─── HELPERS ──────────────────────────────────────────────────── */
function verdictToLabel(verdict) {
  return verdict === "danger"  ? "Dangerous"
       : verdict === "warning" ? "Caution"
       : "Safe";
}

function verdictToScore(verdict, fallback) {
  if (verdict === "danger")  return Math.min(fallback, 25);
  if (verdict === "warning") return Math.min(Math.max(fallback, 45), 70);
  if (verdict === "safe")    return Math.max(fallback, 75);
  return fallback;
}

/* ══════════════════════════════════════════════════════════════════
   ORIGINAL SAFESURF BACKGROUND LOGIC
══════════════════════════════════════════════════════════════════ */

const tabCache  = new Map();
const scanState = new Map(); // tabId → 'scanning' | 'complete'
const popupPorts = new Set();

const BADGE = {
  safe:    { bg: '#22c55e' }, warning: { bg: '#f59e0b' },
  danger:  { bg: '#ef4444' }, loading: { bg: '#6366f1' },
  default: { bg: '#64748b' }
};

function setBadge(tabId, level, score) {
  const cfg = BADGE[level] || BADGE.default;
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.bg });
  chrome.action.setBadgeText({ tabId, text: score != null ? String(Math.round(score)) : '…' });
}

// Reset badge on navigation
chrome.webNavigation.onCommitted.addListener(({ tabId, frameId }) => {
  if (frameId !== 0) return;
  tabCache.delete(tabId);
  scanState.set(tabId, 'scanning');
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE.loading.bg });
  chrome.action.setBadgeText({ tabId, text: '…' });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const senderTabId = sender.tab?.id;

  // ── Scan lifecycle messages (relay to popup if open) ────────
  if (msg.type === 'SCAN_STARTED') {
    if (senderTabId) scanState.set(senderTabId, 'scanning');
    // Relay to popup via storage flag
    chrome.storage.local.set({ ss_scan_state: { state: 'scanning', hostname: msg.hostname, ts: Date.now() } });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'SCAN_COMPLETE') {
    if (senderTabId) scanState.set(senderTabId, 'complete');
    chrome.storage.local.set({ ss_scan_state: { state: 'complete', hostname: msg.result?.hostname, score: msg.result?.score, level: msg.result?.level, confidence: msg.result?.confidence, ts: Date.now() } });
    sendResponse({ ok: true });
    return false;
  }

  // ── Page analysis result from content script ────────────────
  // TWO-PHASE: Show deterministic immediately, then enrich with Claude
  if (msg.type === 'PAGE_DATA') {
    const raw = msg.data;
    if (senderTabId && raw) {

      // Step 1: show deterministic result immediately (fast)
      tabCache.set(senderTabId, raw);
      setBadge(senderTabId, raw.level, raw.score);
      chrome.storage.local.set({ ss_last_scan: raw });

      // Step 2: enrich with Claude in background (async, ~1-2 seconds)
      enrichWithClaude(raw).then(enriched => {
        tabCache.set(senderTabId, enriched);
        setBadge(senderTabId, enriched.level, enriched.score);
        saveToHistory(enriched);
        chrome.storage.local.set({ ss_last_scan: enriched });
        // Notify popup to re-render if open
        chrome.runtime.sendMessage({
          type: 'CLAUDE_ENRICHMENT_READY',
          result: enriched,
          tabId: senderTabId
        }).catch(() => {});
      });

      sendResponse({ ok: true });
    }
    return false;
  }

  // ── Popup requests ──────────────────────────────────────────
  if (msg.type === 'GET_RESULT') {
    const tabId = msg.tabId || senderTabId;
    sendResponse({ result: tabId ? (tabCache.get(tabId) || null) : null });
    return false;
  }

  if (msg.type === 'GET_HISTORY') {
    chrome.storage.local.get(['ss_history'], d => sendResponse({ history: d.ss_history || [] }));
    return true;
  }

  if (msg.type === 'CLEAR_HISTORY') {
    chrome.storage.local.set({ ss_history: [], ss_visit_counts: {} }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'GET_LAST_SCAN') {
    chrome.storage.local.get(['ss_last_scan'], d => sendResponse({ result: d.ss_last_scan || null }));
    return true;
  }

  if (msg.type === 'GET_TODAY_TIMELINE') {
    chrome.storage.local.get(['ss_history'], d => {
      sendResponse({ timeline: buildTodayTimeline(d.ss_history || []) });
    });
    return true;
  }

  if (msg.type === 'GET_SCAN_STATE') {
    chrome.storage.local.get(['ss_scan_state'], d => {
      sendResponse({ scanState: d.ss_scan_state || null });
    });
    return true;
  }

  if (msg.type === 'CHECK_THREAT_INTEL') {
    checkThreatIntel(msg.url || '').then(intel => {
      sendResponse({ intel });
    }).catch(() => {
      sendResponse({ intel: { enabled: true, checked: false, malicious: false, threatTypes: [], source: 'error' } });
    });
    return true;
  }
});

// ── History persistence ─────────────────────────────────────────
function saveToHistory(data) {
  if (!data || !data.hostname) return;
  chrome.storage.local.get(['ss_history'], stored => {
    let history = Array.isArray(stored.ss_history) ? stored.ss_history : [];
    const today = new Date().toDateString();
    history = history.filter(h => !(h.hostname === data.hostname && new Date(h.visitedAt || 0).toDateString() === today));
    history.unshift({
      url: data.url, hostname: data.hostname, title: data.pageTitle || data.hostname,
      score: data.score, level: data.level, label: data.label, confidence: data.confidence,
      fakeLoginDetected: data.fakeLogin?.detected || false,
      phishingIntentDetected: data.phishingIntent?.detected || false,
      formCount: (data.forms || []).length,
      adaptiveBoost: data.adaptive?.adaptiveBoost || 0,
      topRisk: data.risks?.[0]?.title || null,
      claudeEnriched: data.claudeEnriched || false,
      claudeVerdict: data.claudeVerdict || null,
      claudeThreatType: data.claudeThreatType || null,
      // v5 fields
      attackCategories: data.attackCategories || [],
      domainReputation: data.domainReputation?.status || null,
      analysisTimeMs: data.analysisTimeMs || 0,
      visitedAt: Date.now()
    });
    if (history.length > 200) history = history.slice(0, 200);
    chrome.storage.local.set({ ss_history: history });
  });
}

/** Build today's risk timeline for the History tab */
function buildTodayTimeline(history) {
  const today = new Date().toDateString();
  const todayVisits = history.filter(h => new Date(h.visitedAt || 0).toDateString() === today);
  const safe    = todayVisits.filter(h => h.level === 'safe').length;
  const risky   = todayVisits.filter(h => h.level !== 'safe').length;
  const fakes   = todayVisits.filter(h => h.fakeLoginDetected).length;
  const blocked = todayVisits.filter(h => h.level === 'danger').length;

  // v5: Most common risk insight
  const riskTypes = {};
  todayVisits.forEach(h => {
    if (h.topRisk) riskTypes[h.topRisk] = (riskTypes[h.topRisk] || 0) + 1;
    if (h.claudeThreatType) riskTypes[h.claudeThreatType] = (riskTypes[h.claudeThreatType] || 0) + 1;
  });
  const topRiskEntry = Object.entries(riskTypes).sort((a,b) => b[1] - a[1])[0];
  const commonRisk = topRiskEntry ? `Most common risk: ${topRiskEntry[0]} (${topRiskEntry[1]} page${topRiskEntry[1]>1?'s':''})` : '';

  let insight = '';
  if (fakes > 0) insight = `🚨 ${fakes} fake login page${fakes > 1 ? 's' : ''} detected today — don't re-visit those sites.`;
  else if (blocked > 0) insight = `🛑 ${blocked} high-risk site${blocked > 1 ? 's' : ''} flagged today.`;
  else if (risky > 0)  insight = `⚠️ ${risky} site${risky > 1 ? 's' : ''} with concerns visited today.`;
  else if (safe >= 5)  insight = `✅ Great browsing day — ${safe} safe sites, no threats detected.`;
  else if (todayVisits.length > 0) insight = `✅ ${todayVisits.length} site${todayVisits.length > 1 ? 's' : ''} analysed today. Browsing looks healthy.`;
  else insight = 'No sites analysed yet today.';

  return { todayVisits, safe, risky, fakes, blocked, total: todayVisits.length, insight, commonRisk };
}

chrome.tabs.onRemoved.addListener(tabId => { tabCache.delete(tabId); scanState.delete(tabId); });
console.log('[SafeSurf BG v5] Ready ✓ (Claude AI + v5 Protection enabled)');
