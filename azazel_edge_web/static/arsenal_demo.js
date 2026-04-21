const LANG_KEY = 'azazel_lang';
const ARSENAL_AUTH_TOKEN = localStorage.getItem('azazel_token') || '';
const ARSENAL_LANG = window.AZAZEL_LANG || localStorage.getItem(LANG_KEY) || 'ja';
const ARSENAL_I18N = window.AZAZEL_I18N || {};
const ARSENAL_POLL_MS = 2500;

let arsenalClockTimer = null;

function arsenalTr(key, fallback) {
    return ARSENAL_I18N[key] || fallback || key;
}

function switchLanguage(lang) {
    const next = lang === 'en' ? 'en' : 'ja';
    localStorage.setItem(LANG_KEY, next);
    const url = new URL(window.location.href);
    url.searchParams.set('lang', next);
    window.location.assign(url.toString());
}

function syncLanguageUi() {
    const jaBtn = document.getElementById('langJaBtn');
    const enBtn = document.getElementById('langEnBtn');
    if (jaBtn) {
        jaBtn.classList.toggle('active', ARSENAL_LANG === 'ja');
        jaBtn.classList.toggle('lang-active-ja', ARSENAL_LANG === 'ja');
        jaBtn.classList.remove('lang-active-en');
    }
    if (enBtn) {
        enBtn.classList.toggle('active', ARSENAL_LANG === 'en');
        enBtn.classList.toggle('lang-active-en', ARSENAL_LANG === 'en');
        enBtn.classList.remove('lang-active-ja');
    }
}

function arsenalHeaders() {
    const headers = {
        'X-AZAZEL-LANG': ARSENAL_LANG,
    };
    if (ARSENAL_AUTH_TOKEN) {
        headers['X-Auth-Token'] = ARSENAL_AUTH_TOKEN;
    }
    return headers;
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value ?? '');
}

function setTone(id, tone) {
    const node = document.getElementById(id);
    if (!node) return;
    node.classList.remove('arsenal-tone-idle', 'arsenal-tone-watch', 'arsenal-tone-throttle', 'arsenal-tone-redirect');
    node.classList.add(tone);
}

function proofTone(status, fallbackTone) {
    const value = String(status || '').toLowerCase();
    if (value === 'redirect') return 'arsenal-tone-redirect';
    if (value === 'active' || value === 'sync') return fallbackTone || 'arsenal-tone-throttle';
    if (value === 'observe') return 'arsenal-tone-watch';
    return 'arsenal-tone-idle';
}

function toneForBand(band) {
    const value = String(band || '').toUpperCase();
    if (value === 'DECOY REDIRECT') return 'arsenal-tone-redirect';
    if (value === 'THROTTLE') return 'arsenal-tone-throttle';
    if (value === 'WATCH') return 'arsenal-tone-watch';
    return 'arsenal-tone-idle';
}

function renderProof(cardId, valueId, detailId, evidenceId, proof, fallbackValue, fallbackDetail, fallbackEvidence, tone) {
    const item = proof && typeof proof === 'object' ? proof : {};
    setText(valueId, item.headline || fallbackValue || '-');
    setText(detailId, item.detail || fallbackDetail || '-');
    setText(evidenceId, item.evidence || fallbackEvidence || '-');
    setTone(cardId, proofTone(item.status, tone));
}

function primaryStateForBand(active, band) {
    if (!active) {
        return {
            headline: arsenalTr('arsenal.normal_baseline', 'NORMAL BASELINE'),
            summary: arsenalTr('arsenal.waiting_title', 'Waiting for a demo stage'),
            message: arsenalTr('arsenal.waiting_message', 'Run azazel-edge-arsenal-demo from the terminal to activate the exhibition state.'),
        };
    }
    const value = String(band || '').toUpperCase();
    if (value === 'DECOY REDIRECT') {
        return {
            headline: arsenalTr('arsenal.redirect_active', 'DECOY REDIRECT ACTIVE'),
            summary: arsenalTr('arsenal.redirect_title', 'High-confidence anomaly is being redirected'),
            message: arsenalTr('arsenal.redirect_message', 'The gateway is preserving the main segment while diverting the suspicious flow into the decoy path.'),
        };
    }
    if (value === 'THROTTLE') {
        return {
            headline: arsenalTr('arsenal.throttle_active', 'ACTIVE DEFENSE'),
            summary: arsenalTr('arsenal.throttle_title', 'Anomaly confirmed and bounded control is active'),
            message: arsenalTr('arsenal.throttle_message', 'The suspicious flow is being rate-limited with reversible traffic shaping.'),
        };
    }
    return {
        headline: arsenalTr('arsenal.alert_detected', 'ANOMALY DETECTED'),
        summary: arsenalTr('arsenal.watch_title', 'Detection is active but control is still conservative'),
        message: arsenalTr('arsenal.watch_message', 'The alert is visible, the score is elevated, and the gateway remains in watch mode.'),
    };
}

function decisionTone(status, fallbackTone) {
    const value = String(status || '').toLowerCase();
    if (value === 'used') return 'arsenal-tone-throttle';
    if (value === 'not-needed' || value === 'skipped') return 'arsenal-tone-idle';
    return fallbackTone || 'arsenal-tone-watch';
}

function tickClock() {
    const now = new Date();
    setText('arsenalClock', now.toLocaleTimeString([], { hour12: false }));
}

async function fetchArsenalState() {
    const res = await fetch('/api/arsenal-demo/state', { headers: arsenalHeaders() });
    const payload = await res.json();
    if (!res.ok || payload.ok === false) {
        throw new Error(payload.error || 'arsenal_state_failed');
    }
    return payload;
}

function renderArsenalState(payload) {
    const active = Boolean(payload.active);
    const band = String(payload.band || 'IDLE');
    const tone = toneForBand(active ? band : 'IDLE');
    const action = String(payload.action || 'observe');
    const controlMode = String(payload.control_mode || 'none');
    const scoreFactors = Array.isArray(payload.score_factors) ? payload.score_factors : [];
    const epd = payload.epd && typeof payload.epd === 'object' ? payload.epd : {};
    const proofs = payload.proofs && typeof payload.proofs === 'object' ? payload.proofs : {};
    const decisionPath = payload.decision_path && typeof payload.decision_path === 'object' ? payload.decision_path : {};
    const primary = primaryStateForBand(active, band);
    const firstPass = decisionPath.first_pass && typeof decisionPath.first_pass === 'object' ? decisionPath.first_pass : {};
    const ollamaReview = decisionPath.ollama_review && typeof decisionPath.ollama_review === 'object' ? decisionPath.ollama_review : {};
    const finalPolicy = decisionPath.final_policy && typeof decisionPath.final_policy === 'object' ? decisionPath.final_policy : {};

    setText('arsenalPrimaryState', primary.headline);
    setText('arsenalHeroTitle', active ? primary.summary : primary.summary);
    setText('arsenalHeroMessage', active ? primary.message : primary.message);
    setText('arsenalAttackLabel', active ? (payload.attack_label || arsenalTr('arsenal.attack_unknown', 'Active exhibition attack')) : arsenalTr('arsenal.attack_idle', 'Awaiting exhibition attack stage'));
    setText('arsenalScoreValue', active ? payload.score : 0);
    setText('arsenalBandValue', active ? band : arsenalTr('arsenal.idle', 'IDLE'));
    setText('arsenalDetectValue', active ? arsenalTr('arsenal.yes', 'YES') : arsenalTr('arsenal.no', 'NO'));
    setText('arsenalDetectDetail', active ? arsenalTr('arsenal.detect_live', 'Suricata alert is active on the current demo stage') : arsenalTr('arsenal.detect_note', 'Suricata alert observed'));
    setText('arsenalScoreBandValue', active ? band : arsenalTr('arsenal.idle', 'IDLE'));
    setText('arsenalScoreFactors', active ? scoreFactors.join(' | ') : arsenalTr('arsenal.waiting_factors', 'Waiting for deterministic score factors'));
    setText('arsenalPolicyValue', active ? String(action).toUpperCase() : '-');
    setText('arsenalPolicyMode', active ? controlMode : '-');
    renderProof(
        'arsenalTcCard',
        'arsenalTcValue',
        'arsenalTcDetail',
        'arsenalTcEvidence',
        proofs.tc,
        arsenalTr('arsenal.idle', 'IDLE'),
        arsenalTr('arsenal.proof_waiting', 'Waiting for proof state'),
        '-',
        tone,
    );
    renderProof(
        'arsenalFirewallCard',
        'arsenalFirewallValue',
        'arsenalFirewallDetail',
        'arsenalFirewallEvidence',
        proofs.firewall,
        arsenalTr('arsenal.idle', 'IDLE'),
        arsenalTr('arsenal.proof_waiting', 'Waiting for proof state'),
        '-',
        tone,
    );
    renderProof(
        'arsenalDecoyCard',
        'arsenalDecoyValue',
        'arsenalDecoyDetail',
        'arsenalDecoyEvidence',
        proofs.decoy,
        active && band === 'DECOY REDIRECT' ? arsenalTr('arsenal.active', 'ACTIVE') : arsenalTr('arsenal.standby', 'STANDBY'),
        arsenalTr('arsenal.decoy_note', 'OpenCanary redirect status'),
        '-',
        tone,
    );
    renderProof(
        'arsenalOfflineCard',
        'arsenalOfflineValue',
        'arsenalOfflineDetail',
        'arsenalOfflineEvidence',
        proofs.offline,
        arsenalTr('arsenal.active', 'ACTIVE'),
        arsenalTr('arsenal.offline_note', 'Local-only control path'),
        arsenalTr('arsenal.offline_evidence', 'No cloud dependency'),
        tone,
    );
    renderProof(
        'arsenalEpdCard',
        'arsenalEpdValue',
        'arsenalEpdDetail',
        'arsenalEpdEvidence',
        proofs.epd,
        epd.risk_status || epd.state || '-',
        epd.ts ? `${epd.mode_label || '-'} | ${epd.ts}` : arsenalTr('arsenal.epd_waiting', 'Waiting for EPD refresh'),
        epd.ts || '-',
        tone,
    );
    setText('arsenalPresentationBadge', active ? band : arsenalTr('arsenal.idle', 'IDLE'));
    setText('arsenalFirstPassValue', active ? (firstPass.headline || arsenalTr('arsenal.decision_waiting', 'WAITING')) : arsenalTr('arsenal.decision_waiting', 'WAITING'));
    setText('arsenalFirstPassDetail', active ? (firstPass.detail || '-') : arsenalTr('arsenal.decision_waiting_detail', 'The deterministic scorer path will appear here when a stage is active.'));
    setText('arsenalOllamaValue', active ? (ollamaReview.headline || arsenalTr('arsenal.decision_waiting', 'WAITING')) : arsenalTr('arsenal.decision_waiting', 'WAITING'));
    setText('arsenalOllamaDetail', active ? (ollamaReview.detail || '-') : arsenalTr('arsenal.decision_ollama_waiting', 'If the first-pass score is ambiguous, the local Ollama review path appears here.'));
    setText('arsenalOllamaEvidence', active ? (ollamaReview.evidence || '-') : '-');
    setText('arsenalFinalPolicyValue', active ? (finalPolicy.headline || arsenalTr('arsenal.decision_waiting', 'WAITING')) : arsenalTr('arsenal.decision_waiting', 'WAITING'));
    setText('arsenalFinalPolicyDetail', active ? (finalPolicy.detail || '-') : arsenalTr('arsenal.decision_final_waiting', 'The final policy selection will appear here.'));

    ['arsenalPresentationBadge', 'arsenalHeroCard', 'arsenalHeroScoreCard', 'arsenalDetectCard', 'arsenalScoreCard', 'arsenalPolicyCard'].forEach((id) => setTone(id, tone));
    setTone('arsenalFirstPassCard', tone);
    setTone('arsenalOllamaCard', active ? decisionTone(ollamaReview.status, tone) : 'arsenal-tone-idle');
    setTone('arsenalFinalPolicyCard', tone);
}

async function refreshArsenalState() {
    try {
        const payload = await fetchArsenalState();
        renderArsenalState(payload);
    } catch (_error) {
        renderArsenalState({ active: false });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    syncLanguageUi();
    const jaBtn = document.getElementById('langJaBtn');
    const enBtn = document.getElementById('langEnBtn');
    if (jaBtn) jaBtn.addEventListener('click', () => switchLanguage('ja'));
    if (enBtn) enBtn.addEventListener('click', () => switchLanguage('en'));
    tickClock();
    refreshArsenalState();
    arsenalClockTimer = window.setInterval(tickClock, 1000);
    window.setInterval(refreshArsenalState, ARSENAL_POLL_MS);
});

window.addEventListener('beforeunload', () => {
    if (arsenalClockTimer) clearInterval(arsenalClockTimer);
});
