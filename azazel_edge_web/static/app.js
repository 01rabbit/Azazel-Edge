const AUTH_TOKEN = String(localStorage.getItem('azazel_token') || '').trim();
const AUDIENCE_KEY = 'azazel_dashboard_audience';
const LANG_KEY = 'azazel_lang';
const PROGRESS_SESSION_KEY = 'azazel_operator_progress_session';
const ONBOARDING_DISMISSED_KEY = 'azazel_dashboard_onboarding_v3_dismissed';
const POLL_INTERVAL_MS = 4000;
const CURRENT_LANG = window.AZAZEL_LANG || localStorage.getItem(LANG_KEY) || 'ja';
const I18N = window.AZAZEL_I18N || {};
const CURRENT_PAGE = document.body?.dataset?.page || 'dashboard';

let dashboardTimer = null;
let currentAudience = resolveInitialAudience();
let latestState = {};
let latestSummary = {};
let latestMattermost = {};
let lastRefreshWarning = '';
let demoScenarioItems = [];
let demoOverlayResult = null;
let showNormalClients = false;
let headerClockTimer = null;
let headerClockBaseMs = null;
let headerClockSeedMs = null;
let currentProgress = {};
let currentHandoff = {};
let onboardingStepIndex = 0;

function advanceOnboardingStep() {
    onboardingStepIndex = (onboardingStepIndex + 1) % 3;
    syncOnboardingBanner();
}

function dismissOnboardingGuide() {
    localStorage.setItem(ONBOARDING_DISMISSED_KEY, '1');
    syncOnboardingBanner();
}

function reopenOnboardingGuide() {
    localStorage.removeItem(ONBOARDING_DISMISSED_KEY);
    onboardingStepIndex = 0;
    syncOnboardingBanner();
}

window.__azOnboardingNext = advanceOnboardingStep;
window.__azOnboardingDismiss = dismissOnboardingGuide;
window.__azOnboardingReopen = reopenOnboardingGuide;

function tr(key, fallback, vars = null) {
    const base = I18N[key] || fallback || key;
    if (!vars || typeof base !== 'string') return base;
    return base.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, name) => {
        return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`;
    });
}

function normalizeAudience(value) {
    const text = String(value || '').trim().toLowerCase();
    if (['temporary', 'beginner', 'casual'].includes(text)) return 'temporary';
    if (['professional', 'operator', 'pro', 'expert'].includes(text)) return 'professional';
    return '';
}

function resolveInitialAudience() {
    const url = new URL(window.location.href);
    const queryAudience = normalizeAudience(url.searchParams.get('audience'));
    const savedAudience = normalizeAudience(localStorage.getItem(AUDIENCE_KEY));
    return queryAudience || savedAudience || 'temporary';
}

function authHeaders() {
    const headers = {
        'Content-Type': 'application/json',
        'X-AZAZEL-LANG': CURRENT_LANG,
    };
    if (AUTH_TOKEN) {
        headers['X-Auth-Token'] = AUTH_TOKEN;
    }
    return headers;
}

function ensureProgressSessionId() {
    let sessionId = String(localStorage.getItem(PROGRESS_SESSION_KEY) || '').trim();
    if (sessionId) return sessionId;
    sessionId = `ops-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    localStorage.setItem(PROGRESS_SESSION_KEY, sessionId);
    return sessionId;
}

async function copyTextToClipboard(text) {
    const value = String(text || '').trim();
    if (!value) return false;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(value);
        return true;
    }
    const area = document.createElement('textarea');
    area.value = value;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'absolute';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok;
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
        jaBtn.classList.toggle('active', CURRENT_LANG === 'ja');
        jaBtn.classList.toggle('lang-active-ja', CURRENT_LANG === 'ja');
        jaBtn.classList.remove('lang-active-en');
    }
    if (enBtn) {
        enBtn.classList.toggle('active', CURRENT_LANG === 'en');
        enBtn.classList.toggle('lang-active-en', CURRENT_LANG === 'en');
        enBtn.classList.remove('lang-active-ja');
    }
}

function setDemoOverlayVisualState(active) {
    document.body.classList.toggle('demo-overlay-active', CURRENT_PAGE === 'demo' && !!active);
}

function resetDemoOverlayPresentation() {
    setDemoOverlayVisualState(false);
    updateElement('demoStatusBadge', tr('dashboard.demo_ready', 'READY'));
    const badge = document.getElementById('demoStatusBadge');
    if (badge) badge.className = 'assistant-status status-neutral';
    updateElement('demoScenarioId', '-');
    updateElement('demoEventCount', '-');
    updateElement('demoExecutionMode', 'deterministic_replay');
    updateElement('demoAiCore', 'not-used');
    updateElement('demoNocStatus', '-');
    updateElement('demoSocStatus', '-');
    updateElement('demoAction', '-');
    updateElement('demoReason', '-');
    updateElement('demoSafetyReversible', '-');
    updateElement('demoSafetyApproval', '-');
    updateElement('demoSafetyAudited', '-');
    updateElement('demoSafetyEffect', '-');
    updateElement('demoTraceNocFragile', '-');
    updateElement('nocCapacityState', '-');
    updateElement('nocCapacityUtilization', '-');
    updateElement('nocCapacityMode', '-');
    updateElement('nocCapacityTopTalker', '-');
    updateElement('nocClientCurrent', '0');
    updateElement('nocClientUnknown', '0');
    updateElement('nocClientUnauthorized', '0');
    updateElement('nocClientMismatch', '0');
    updateElement('demoTraceStrongSoc', '-');
    updateElement('demoTraceBlastConfidence', '-');
    updateElement('demoTraceClientImpact', '-');
    updateElement('demoBoundaryMode', 'DETERMINISTIC REPLAY');
    updateElement('demoBoundarySummary', tr('dashboard.demo_boundary_summary', 'Deterministic replay path. This does not replace the live Tactical first-pass path, and AI is not used in the core demo decision loop.'));
    updateElement('demoOperatorWording', tr('dashboard.no_demo', 'No demo overlay is active.'));
    updateElement('demoResponse', tr('dashboard.no_demo_response', 'Run a scenario to preview the deterministic pipeline.'));
    renderList('demoNextChecks', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
    renderList('demoEvidenceIds', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
    renderList('demoRejectedAlternatives', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
}

function updateDemoModeBanner(result) {
    const banner = document.getElementById('demoModeBanner');
    const text = document.getElementById('demoModeBannerText');
    if (!banner || CURRENT_PAGE !== 'dashboard') return;
    if (!result || !result.active) {
        banner.hidden = true;
        if (text) {
            text.textContent = tr(
                'dashboard.demo_banner_default',
                'A demo overlay is active. Review replay output on the dedicated demo page, not on the operational dashboard.'
            );
        }
        return;
    }
    banner.hidden = false;
    const scenarioId = String(result.scenario_id || 'demo').trim() || 'demo';
    const action = String(result.arbiter?.action || '-').trim() || '-';
    if (text) {
        text.textContent = tr(
            'dashboard.demo_banner_active',
            'Demo overlay {scenario} is active with action {action}. The operational dashboard remains on live telemetry; use /demo for replay output and reviewer state.',
            { scenario: scenarioId, action }
        );
    }
}

function updateSyntheticModeBanner(summary, evidence) {
    const banner = document.getElementById('syntheticModeBanner');
    const text = document.getElementById('syntheticModeBannerText');
    if (!banner || !text) return;
    const mode = String(summary?.topolite?.mode || 'live').toLowerCase();
    const isSynthetic = mode === 'synthetic' || String(evidence?.data_source || 'live') === 'synthetic';
    banner.hidden = !isSynthetic;
    if (isSynthetic) {
        text.textContent = String(summary?.topolite?.watermark || evidence?.watermark || 'SYNTHETIC DATA - NOT LIVE EVIDENCE');
    }
    const toggle = document.getElementById('topoliteSyntheticToggleBtn');
    if (toggle) {
        toggle.textContent = isSynthetic ? 'Switch to Live' : 'Switch to Synthetic';
    }
}

const shortcutQuestions = {
    wifi: tr('dashboard.question_wifi_trouble', 'How should I guide a user who cannot connect to Wi-Fi?'),
    reconnect: tr('dashboard.question_reconnect', 'How should I guide a user who cannot reconnect?'),
    onboarding: tr('dashboard.question_onboarding', 'How should I guide a first-time onboarding user?'),
    dns: tr('dashboard.question_dns_failure', 'What should I verify when DNS lookup fails?'),
    uplink: tr('dashboard.question_gateway_uplink', 'What should I verify when the gateway or uplink looks unhealthy?'),
    service: tr('dashboard.question_service_status', 'What should I verify when a service appears unhealthy?'),
    portal: tr('dashboard.question_portal', 'How should I guide a user when the portal does not appear?'),
};

const triageIntentBySymptom = {
    wifi: 'wifi_connectivity',
    reconnect: 'wifi_reconnect',
    onboarding: 'wifi_onboarding',
    dns: 'dns_resolution',
    uplink: 'uplink_reachability',
    service: 'service_status',
    portal: 'portal_access',
};

const temporaryFlows = {
    wifi: {
        ask: CURRENT_LANG === 'ja' ? [
            '最初に失敗している端末はどれですか？',
            '端末から SSID は見えていますか？',
            '問題は 1 台だけですか、それとも複数台ですか？'
        ] : [
            'Which device is failing first?',
            'Does the device see the SSID at all?',
            'Is this only one device or multiple devices?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            '端末の再起動を繰り返さないでください。',
            '単一端末の問題か、広域の Wi-Fi 問題かを確認しています。'
        ] : [
            'Do not repeatedly reboot the device yet.',
            'We are checking whether this is a single-device issue or a wider Wi-Fi issue.'
        ],
    },
    reconnect: {
        ask: CURRENT_LANG === 'ja' ? [
            '以前は正常に接続できていましたか？',
            '場所の移動やパスワード変更の後に失敗し始めましたか？',
            '問題は 1 台だけですか？'
        ] : [
            'Was the user connected successfully before?',
            'Did the failure start after moving location or after a password change?',
            'Is the problem only on one device?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            '保存済みプロファイルの問題か、広域の無線問題かを確認しています。',
            '当面は通常利用位置の近くで待機し、再接続の連打は避けてください。'
        ] : [
            'We are checking whether this is a saved-profile issue or a broader wireless issue.',
            'Please keep the device near the normal usage area and avoid repeated reconnect attempts for the moment.'
        ],
    },
    onboarding: {
        ask: CURRENT_LANG === 'ja' ? [
            'この端末がネットワークへ参加するのは初めてですか？',
            '端末から想定の SSID は見えていますか？',
            '標準のオンボーディング手順どおりに進めていますか？'
        ] : [
            'Is this the first time this device is joining the network?',
            'Can the device see the expected SSID?',
            'Is the user following the standard onboarding steps?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            'ネットワーク設定変更の前に、オンボーディング経路を先に確認しています。',
            '端末名と、どの手順で止まったかを控えてください。'
        ] : [
            'We are checking the onboarding path first before changing any network settings.',
            'Please prepare the device name and the exact step where the user got stuck.'
        ],
    },
    dns: {
        ask: CURRENT_LANG === 'ja' ? [
            'どのサイトまたはホスト名が開けませんか？',
            'IP アドレス直打ちでは開けますか？',
            '複数の利用者に影響していますか？'
        ] : [
            'Which site or hostname fails to open?',
            'Does access by IP address work?',
            'Is the issue affecting multiple users?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            'まず名前解決の状態を確認しています。',
            'DNS と gateway を確認する間、そのまま接続状態を維持してください。'
        ] : [
            'We are checking name resolution first.',
            'Please keep the device connected while we verify DNS and gateway status.'
        ],
    },
    uplink: {
        ask: CURRENT_LANG === 'ja' ? [
            '全利用者に影響していますか、それとも一部の区画だけですか？',
            '問題はいつ始まりましたか？',
            '外部サイトへまったく到達できませんか？'
        ] : [
            'Are all users affected or only one area?',
            'When did the problem start?',
            'Is any external site reachable at all?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            '上位回線と gateway 到達性を確認しています。',
            '最初の確認が終わるまでケーブル変更やモード変更は行わないでください。'
        ] : [
            'We are checking upstream connectivity and gateway reachability.',
            'Please avoid changing cables or mode settings until the first check completes.'
        ],
    },
    service: {
        ask: CURRENT_LANG === 'ja' ? [
            'どの機能が使えないように見えますか？',
            'UI 表示の問題ですか、それとも本当に機能停止ですか？',
            '最後に正常に使えたのはいつですか？'
        ] : [
            'Which function appears unavailable?',
            'Is the UI wrong, or is the function really down?',
            'When was the last successful use?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            '再起動前に実サービス状態を確認しています。',
            'status と journal を確認する間、そのままお待ちください。'
        ] : [
            'We are confirming actual service status before any restart.',
            'Please wait while we check status and journal information.'
        ],
    },
    portal: {
        ask: CURRENT_LANG === 'ja' ? [
            '接続後にブラウザは表示されますか？',
            '通常サイトを入力すると何か表示されますか？',
            '問題は 1 人だけですか、それとも複数人ですか？'
        ] : [
            'Does the device show a browser at all after connecting?',
            'Can the user reach any page by typing a normal website address?',
            'Is this one user or multiple users?'
        ],
        tell: CURRENT_LANG === 'ja' ? [
            'ポータルトリガーかブラウザ転送が失われていないか確認しています。',
            '最初の確認が終わるまで、接続を維持したままお待ちください。'
        ] : [
            'We are checking whether the portal trigger or browser redirection is missing.',
            'Please stay connected and avoid switching Wi-Fi networks until the first check completes.'
        ],
    },
};

function formatAssistResponse(result) {
    const lines = [];
    const surfaceMessages = result.surface_messages && typeof result.surface_messages === 'object' ? result.surface_messages : {};
    const preferred = surfaceMessages.dashboard || result.surface_message || result.answer || '-';
    lines.push(preferred);
    const rationale = Array.isArray(result.rationale) && result.rationale.length
        ? result.rationale.join(' | ')
        : '-';
    lines.push(`${tr('api.rationale', 'Rationale')}: ${rationale}`);
    lines.push(`${tr('api.user_guidance', 'User Guidance')}: ${result.user_message || '-'}`);
    lines.push(`${tr('api.suggested_runbook', 'Suggested Runbook')}: ${result.runbook_id || tr('api.no_suggestion', 'no suggestion')}`);
    lines.push(`${tr('api.review_prefix', 'Review')}: ${result.runbook_review?.final_status || tr('dashboard.no_review_data', 'No review data')}`);
    const handoff = result.handoff && typeof result.handoff === 'object' ? result.handoff : {};
    const handoffParts = [];
    if (handoff.ops_comm) handoffParts.push(`Ops Comm ${handoff.ops_comm}`);
    if (handoff.mattermost) handoffParts.push(`Mattermost ${handoff.mattermost}`);
    lines.push(`${tr('api.continue', 'Continue')}: ${handoffParts.length ? handoffParts.join(' / ') : '-'}`);
    return lines.join('\n\n');
}

document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.lang = CURRENT_LANG;
    syncLanguageUi();
    bindStaticHandlers();
    startHeaderClock();
    setAudience(currentAudience);
    refreshDashboard();
    dashboardTimer = window.setInterval(refreshDashboard, POLL_INTERVAL_MS);
});

window.addEventListener('beforeunload', () => {
    if (dashboardTimer) {
        clearInterval(dashboardTimer);
    }
    if (headerClockTimer) {
        clearInterval(headerClockTimer);
    }
});

function bindStaticHandlers() {
    document.getElementById('langJaBtn')?.addEventListener('click', () => switchLanguage('ja'));
    document.getElementById('langEnBtn')?.addEventListener('click', () => switchLanguage('en'));
    document.getElementById('audienceProfessional')?.addEventListener('click', () => setAudience('professional'));
    document.getElementById('audienceTemporary')?.addEventListener('click', () => setAudience('temporary'));
    document.getElementById('showGuideBtn')?.addEventListener('click', reopenOnboardingGuide);

    document.getElementById('modePortalBtn')?.addEventListener('click', () => switchMode('portal'));
    document.getElementById('modeShieldBtn')?.addEventListener('click', () => switchMode('shield'));
    document.getElementById('modeScapegoatBtn')?.addEventListener('click', () => switchMode('scapegoat'));
    document.getElementById('topoliteSyntheticToggleBtn')?.addEventListener('click', toggleTopoliteSyntheticMode);
    document.getElementById('portalAssistBtn')?.addEventListener('click', openPortalViewer);
    document.getElementById('containBtn')?.addEventListener('click', () => executeAction('contain'));
    document.getElementById('releaseBtn')?.addEventListener('click', () => executeAction('release'));
    document.getElementById('clientIdentityToggle')?.addEventListener('click', () => {
        showNormalClients = !showNormalClients;
        updateClientIdentityView(latestSummary);
    });
    document.getElementById('clientIdentityList')?.addEventListener('change', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement) || !target.classList.contains('client-trust-checkbox')) return;
        const previous = String(target.dataset.trusted || 'false') === 'true';
        target.disabled = true;
        try {
            await updateClientTrust(target);
            target.dataset.trusted = target.checked ? 'true' : 'false';
        } catch (error) {
            target.checked = previous;
        } finally {
            target.disabled = false;
        }
    });
    document.getElementById('clientIdentityList')?.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const button = target.closest('.client-ignore-button');
        if (!(button instanceof HTMLButtonElement)) return;
        button.disabled = true;
        try {
            await ignoreClientCandidate(button);
        } finally {
            button.disabled = false;
        }
    });
    document.getElementById('clientIdentityList')?.addEventListener('submit', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLFormElement) || !target.classList.contains('client-profile-form')) return;
        event.preventDefault();
        const submit = target.querySelector('button[type="submit"]');
        if (submit instanceof HTMLButtonElement) {
            submit.disabled = true;
        }
        try {
            await saveClientProfile(target);
        } finally {
            if (submit instanceof HTMLButtonElement) {
                submit.disabled = false;
            }
        }
    });

    document.querySelectorAll('.shortcut-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const question = btn.dataset.question || '';
            const area = document.getElementById('mioQuestion');
            if (area) area.value = question;
            if (question) askMio(question);
        });
    });

    document.querySelectorAll('.context-ask-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const question = btn.dataset.question || '';
            const area = document.getElementById('mioQuestion');
            if (area) area.value = question;
            if (question) askMio(question);
        });
    });

    document.querySelectorAll('.temp-flow-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const symptom = String(btn.dataset.symptom || '').trim();
            applyTemporaryFlow(symptom);
            updateTemporaryOpsCommLink(symptom);
        });
    });

    document.getElementById('mioAskForm')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const area = document.getElementById('mioQuestion');
        const question = String(area?.value || '').trim();
        if (!question) {
            showToast(tr('dashboard.question_required', 'Enter a question first.'), 'info');
            return;
        }
        await askMio(question);
    });

    document.getElementById('progressChecklistList')?.addEventListener('change', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement) || !target.classList.contains('progress-checklist-checkbox')) return;
        try {
            await fetchJson('/api/operator-progress', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({
                    session_id: ensureProgressSessionId(),
                    item_id: target.dataset.itemId || '',
                    done: target.checked,
                }),
            });
            await refreshDashboard();
        } catch (error) {
            target.checked = !target.checked;
            showToast(error.message || String(error), 'error');
        }
    });
    document.getElementById('progressBlockedSaveBtn')?.addEventListener('click', async () => {
        const reason = String(document.getElementById('progressBlockedReason')?.value || '').trim();
        try {
            await fetchJson('/api/operator-progress', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({
                    session_id: ensureProgressSessionId(),
                    blocked_reason: reason,
                    blocked_prompt: currentProgress.blocked_prompt || '',
                }),
            });
            await refreshDashboard();
        } catch (error) {
            showToast(error.message || String(error), 'error');
        }
    });
    document.getElementById('progressBlockedClearBtn')?.addEventListener('click', async () => {
        try {
            await fetchJson('/api/operator-progress', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({
                    session_id: ensureProgressSessionId(),
                    clear_blocked: true,
                }),
            });
            await refreshDashboard();
        } catch (error) {
            showToast(error.message || String(error), 'error');
        }
    });
    document.getElementById('handoffCopyBtn')?.addEventListener('click', async () => {
        try {
            const ok = await copyTextToClipboard(currentHandoff.brief_text || '');
            showToast(ok ? tr('dashboard.handoff_copied', 'Handoff brief copied.') : tr('dashboard.handoff_copy_failed', 'Could not copy handoff brief.'), ok ? 'info' : 'error');
        } catch (error) {
            showToast(error.message || String(error), 'error');
        }
    });
    document.getElementById('handoffMattermostBtn')?.addEventListener('click', async () => {
        try {
            await fetchJson('/api/dashboard/handoff', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({ session_id: ensureProgressSessionId(), target: 'mattermost' }),
            });
            showToast(tr('dashboard.handoff_sent_mattermost', 'Handoff brief sent to Mattermost.'), 'info');
        } catch (error) {
            showToast(error.message || String(error), 'error');
        }
    });
    document.getElementById('demoScenarioSelect')?.addEventListener('change', updateDemoScenarioDescription);
    document.getElementById('demoRunForm')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await runDemoScenario();
    });
    document.getElementById('demoClearOverlayBtn')?.addEventListener('click', clearDemoOverlay);
    document.getElementById('reviewOpenCapabilitiesBtn')?.addEventListener('click', () => {
        void openAuthenticatedJson('/api/demo/capabilities', 'Azazel-Edge Capability Boundary');
    });
    document.getElementById('reviewOpenExplanationBtn')?.addEventListener('click', () => {
        void openAuthenticatedJson('/api/demo/explanation/latest', 'Azazel-Edge Latest Explanation');
    });

    loadDemoScenarios();
}

async function toggleTopoliteSyntheticMode() {
    const currentMode = String(latestSummary?.topolite?.mode || 'live').toLowerCase();
    const nextMode = currentMode === 'synthetic' ? 'live' : 'synthetic';
    try {
        await fetchJson('/api/topolite/seed-mode', {
            method: 'POST',
            body: JSON.stringify({
                mode: nextMode,
                seed_id: String(latestSummary?.topolite?.seed_id || 'topolite-default'),
                updated_by: 'dashboard',
            }),
        });
        await refreshDashboard();
        showToast(`Topo-Lite mode changed to ${nextMode.toUpperCase()}`, 'success');
    } catch (error) {
        showToast(`Topo-Lite mode change failed: ${error.message}`, 'error');
    }
}

function buildOpsCommTriageUrl(intentId = '', question = '') {
    const url = new URL('/ops-comm', window.location.origin);
    url.searchParams.set('lang', CURRENT_LANG);
    url.searchParams.set('audience', currentAudience === 'temporary' ? 'beginner' : 'operator');
    if (intentId) url.searchParams.set('triage_intent', intentId);
    if (question) url.searchParams.set('message', question);
    return `${url.pathname}${url.search}`;
}

function updateTemporaryOpsCommLink(symptom = 'wifi') {
    const link = document.getElementById('temporaryOpsCommLink');
    if (!link) return;
    const key = triageIntentBySymptom[symptom] ? symptom : 'wifi';
    link.href = buildOpsCommTriageUrl(triageIntentBySymptom[key], shortcutQuestions[key] || '');
}

function setAudience(audience) {
    currentAudience = normalizeAudience(audience) || 'temporary';
    localStorage.setItem(AUDIENCE_KEY, currentAudience);
    document.body.dataset.audience = currentAudience;
    document.getElementById('audienceProfessional')?.classList.toggle('active', currentAudience === 'professional');
    document.getElementById('audienceTemporary')?.classList.toggle('active', currentAudience === 'temporary');
    updateElement('audienceSummary', currentAudience === 'temporary'
        ? tr('dashboard.temporary_summary', 'Temporary mode prioritizes simpler wording, safe next steps, and user-facing guidance.')
        : tr('dashboard.professional_summary', 'Professional mode shows deeper evidence, review status, and control context.'));
    if (currentAudience === 'temporary') {
        applyTemporaryFlow('wifi', false);
    }
    updateTemporaryOpsCommLink('wifi');
    applyAudienceControlPolicy();
    syncOnboardingBanner();
}

function applyAudienceControlPolicy() {
    const temporary = currentAudience === 'temporary';
    ['modePortalBtn', 'modeShieldBtn', 'modeScapegoatBtn'].forEach((id) => {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.disabled = temporary;
        btn.title = temporary ? tr('dashboard.temp_do_not_do_default', 'Do not change mode or restart services until the first checks are done.') : '';
    });
}

function applyTemporaryFlow(symptom, triggerAsk = true) {
    const selected = temporaryFlows[symptom] ? symptom : 'wifi';
    const flow = temporaryFlows[selected];
    updateTemporaryOpsCommLink(selected);
    renderList('temporaryAskList', flow.ask || [], (item) => item);
    renderList('temporaryTellList', flow.tell || [], (item) => item);
    updateGuidanceToggleSummary();
    if (!triggerAsk) return;
    const question = document.querySelector(`.temp-flow-btn[data-symptom="${selected}"]`)?.dataset.question || shortcutQuestions[selected] || '';
    const area = document.getElementById('mioQuestion');
    if (area) area.value = question;
    if (question) askMio(question);
}

function formatLocalDateTime(rawValue) {
    const raw = String(rawValue || '').trim();
    if (!raw) return '-';
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return raw;
    const formatter = new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short',
    });
    return formatter.format(date);
}

function formatRelativeTime(rawValue) {
    const raw = String(rawValue || '').trim();
    if (!raw) return '';
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return '';
    const diffSec = Math.round((date.getTime() - Date.now()) / 1000);
    const absSec = Math.abs(diffSec);
    let value = diffSec;
    let unit = 'second';
    if (absSec >= 86400) {
        value = Math.round(diffSec / 86400);
        unit = 'day';
    } else if (absSec >= 3600) {
        value = Math.round(diffSec / 3600);
        unit = 'hour';
    } else if (absSec >= 60) {
        value = Math.round(diffSec / 60);
        unit = 'minute';
    }
    return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(value, unit);
}

function formatHumanDateTime(rawValue) {
    const local = formatLocalDateTime(rawValue);
    if (local === '-' || local === String(rawValue || '').trim()) return local;
    const relative = formatRelativeTime(rawValue);
    return relative ? `${local} (${relative})` : local;
}

function formatFreshness(ageSec, rawTime, stale, idle = false) {
    const label = formatHumanDateTime(rawTime);
    if (ageSec == null) {
        if (idle) return `${tr('dashboard.status_idle', 'IDLE')} | ${label}`;
        return stale ? `${tr('dashboard.status_stale', 'STALE')} | ${label}` : label;
    }
    const seconds = Number(ageSec);
    let bucket = `${Math.round(seconds)}s ago`;
    if (seconds >= 3600) {
        bucket = `${Math.round(seconds / 3600)}h ago`;
    } else if (seconds >= 60) {
        bucket = `${Math.round(seconds / 60)}m ago`;
    }
    if (idle) {
        return `${tr('dashboard.status_idle', 'IDLE')} | ${bucket} | ${label}`;
    }
    return `${stale ? tr('dashboard.status_stale', 'STALE') : tr('dashboard.status_live', 'LIVE')} | ${bucket} | ${label}`;
}

function renderHeaderClock() {
    if (headerClockBaseMs == null || headerClockSeedMs == null) return;
    const elapsedMs = Date.now() - headerClockSeedMs;
    const current = new Date(headerClockBaseMs + Math.max(0, elapsedMs));
    const hh = String(current.getHours()).padStart(2, '0');
    const mm = String(current.getMinutes()).padStart(2, '0');
    const ss = String(current.getSeconds()).padStart(2, '0');
    updateElement('headerClock', `${hh}:${mm}:${ss}`);
}

function seedHeaderClock(rawTime) {
    const text = String(rawTime || '').trim();
    const now = new Date();
    const match = text.match(/^(\d{1,2}):(\d{2}):(\d{2})$/);
    if (match) {
        now.setHours(Number(match[1]), Number(match[2]), Number(match[3]), 0);
    }
    headerClockBaseMs = now.getTime();
    headerClockSeedMs = Date.now();
    renderHeaderClock();
}

function startHeaderClock() {
    if (headerClockTimer) {
        clearInterval(headerClockTimer);
    }
    seedHeaderClock('');
    headerClockTimer = window.setInterval(renderHeaderClock, 1000);
}

function updateMissionRow(summary, actions) {
    const recommendation = String(summary.current_recommendation || '-').trim();
    const userGuidance = String(actions.current_user_guidance || '').trim();
    const doNext = Array.isArray(actions.do_next) ? actions.do_next : [];
    const whyNow = Array.isArray(actions.why_now) ? actions.why_now : [];
    const doNotDo = Array.isArray(actions.do_not_do) ? actions.do_not_do : [];

    const temporary = currentAudience === 'temporary';
    const headline = temporary
        ? (userGuidance || doNext[0] || recommendation || tr('dashboard.mission_headline_temporary_fallback', 'Guide the user safely.'))
        : (doNext[0] || recommendation || tr('dashboard.mission_headline_professional_fallback', 'Review current operator action.'));
    const summaryLine = temporary
        ? tr('dashboard.mission_summary_temporary', 'Temporary mode reduces the task to a safe first response and a user-facing explanation.')
        : tr('dashboard.mission_summary_professional', 'Professional mode compresses the first operator action, the current reason, and the non-negotiable safety rails.');
    const focusItems = temporary
        ? ([
            ...(Array.isArray(actions.current_operator_actions) ? actions.current_operator_actions.slice(0, 2) : []),
            ...(doNext.slice(0, 1)),
        ].filter(Boolean))
        : doNext.slice(0, 3);
    const safetyItems = doNotDo.length ? doNotDo.slice(0, 3) : [tr('dashboard.mission_safety_default', 'Do not act on stale data without confirming freshness.')];

    updateElement('missionHeadline', headline || '-');
    updateElement('missionSummary', summaryLine);
    updateElement('missionAudienceNote', temporary
        ? tr('dashboard.mission_note_temporary', 'Temporary mode places the first safe action and the user-facing instruction ahead of deep evidence.')
        : tr('dashboard.mission_note_professional', 'Professional mode places the first operator action and the causal summary ahead of deep history.'));
    renderList('missionReasonList', whyNow.length ? whyNow.slice(0, 3) : [tr('dashboard.waiting_causal_summary_ui', 'Waiting for causal summary.')], (item) => item);
    renderList('missionFocusList', focusItems.length ? focusItems : [tr('dashboard.waiting_next_checks_ui', 'Waiting for next checks.')], (item) => item);
    renderList('missionSafetyList', safetyItems, (item) => item);
}

function updateTemporaryMission(actions) {
    const doNext = Array.isArray(actions.do_next) ? actions.do_next : [];
    const doNotDo = Array.isArray(actions.do_not_do) ? actions.do_not_do : [];
    const askItems = Array.from(document.querySelectorAll('#temporaryAskList li'))
        .map((item) => item.textContent || '')
        .filter(Boolean);
    const tellItems = Array.from(document.querySelectorAll('#temporaryTellList li'))
        .map((item) => item.textContent || '')
        .filter(Boolean);
    updateElement('temporaryMissionHeadline', actions.current_user_guidance || doNext[0] || tr('dashboard.temp_headline_fallback', 'Guide the user safely.'));
    updateElement('temporaryMissionSummary', tr('dashboard.temp_summary_ui', 'Temporary mode compresses the first safe response, the interview prompts, and the forbidden actions into one block.'));
    renderList('temporaryMissionAskList', askItems, (item) => item);
    renderList('temporaryMissionTellList', tellItems, (item) => item);
    renderList('temporaryMissionDoNotDoList', doNotDo.length ? doNotDo : [tr('dashboard.temp_do_not_do_default', 'Do not change mode or restart services until the first checks are done.')], (item) => item);
    updateGuidanceToggleSummary(doNotDo.length ? doNotDo.length : 1);
}

async function refreshDashboard() {
    const progressSessionId = ensureProgressSessionId();
    const actionsUrl = new URL('/api/dashboard/actions', window.location.origin);
    actionsUrl.searchParams.set('audience', currentAudience);
    actionsUrl.searchParams.set('surface', 'dashboard');
    const progressUrl = new URL('/api/operator-progress', window.location.origin);
    progressUrl.searchParams.set('session_id', progressSessionId);
    const handoffUrl = new URL('/api/dashboard/handoff', window.location.origin);
    handoffUrl.searchParams.set('session_id', progressSessionId);
    const requests = [
        ['summary', '/api/dashboard/summary', true],
        ['topoliteMode', '/api/topolite/seed-mode', false],
        ['actions', actionsUrl.pathname + actionsUrl.search, false],
        ['progress', progressUrl.pathname + progressUrl.search, false],
        ['handoff', handoffUrl.pathname + handoffUrl.search, false],
        ['evidence', '/api/dashboard/evidence', false],
        ['health', '/api/dashboard/health', false],
        ['trends', '/api/dashboard/trends?limit=60', false],
        ['state', '/api/state', true],
        ['mattermost', '/api/mattermost/status', false],
        ['capabilities', '/api/ai/capabilities', false],
        ['demoCapabilities', '/api/demo/capabilities', false],
        ['demoOverlay', '/api/demo/overlay', false],
    ];

    const resolved = await Promise.all(
        requests.map(async ([name, path, required]) => {
            try {
                const data = await fetchJson(path);
                return [name, { ok: true, data, required }];
            } catch (error) {
                return [name, { ok: false, error: error.message || String(error), required }];
            }
        })
    );

    const resultMap = Object.fromEntries(resolved);
    const failures = Object.entries(resultMap)
        .filter(([, item]) => !item.ok)
        .map(([name, item]) => `${name}: ${item.error}`);
    const hardFailures = Object.entries(resultMap)
        .filter(([, item]) => !item.ok && item.required)
        .map(([name, item]) => `${name}: ${item.error}`);

    if (hardFailures.length > 0) {
        console.error('Dashboard refresh failed:', hardFailures);
        showToast(tr('dashboard.refresh_failed', 'Dashboard refresh failed: {error}', { error: hardFailures.join(' | ') }), 'error');
        return;
    }

    const summary = resultMap.summary?.data || {};
    const actions = resultMap.actions?.data || {};
    const progress = resultMap.progress?.data?.operator_progress_state || {};
    const handoff = resultMap.handoff?.data?.handoff_brief_pack || {};
    const evidence = resultMap.evidence?.data || {};
    const health = resultMap.health?.data || {};
    const trends = resultMap.trends?.data || {};
    const state = resultMap.state?.data || {};
    const mattermost = resultMap.mattermost?.data || { reachable: false, command_triggers: [] };
    const capabilities = resultMap.capabilities?.data || { mattermost_triggers: [] };
    const demoCapabilities = resultMap.demoCapabilities?.data || { boundary: {}, execution_mode: 'deterministic_replay' };
    const demoOverlay = resultMap.demoOverlay?.data?.overlay || {};
    const topoliteMode = resultMap.topoliteMode?.data?.topolite_seed_mode || {};

    latestState = state || {};
    latestSummary = summary || {};
    if (!latestSummary.topolite && topoliteMode && typeof topoliteMode === 'object') {
        latestSummary.topolite = {
            mode: topoliteMode.mode || 'live',
            seed_id: topoliteMode.seed_id || 'topolite-default',
            data_source: topoliteMode.mode === 'synthetic' ? 'synthetic' : 'live',
            watermark: topoliteMode.watermark || '',
            story: topoliteMode.story || {},
        };
    }
    latestMattermost = mattermost || {};
    currentProgress = progress || {};
    currentHandoff = handoff || {};
    demoOverlayResult = demoOverlay && demoOverlay.active ? demoOverlay : null;
    setDemoOverlayVisualState(!!demoOverlayResult);
    updateDemoModeBanner(demoOverlayResult);
    updateSyntheticModeBanner(summary, resultMap.evidence?.data || {});
    if (!demoOverlayResult) {
        resetDemoOverlayPresentation();
    }

    try {
        updateHeader(state, mattermost);
        updateClientIdentityView(summary);
        updateCommandStrip(summary, health, failures);
        updateOperationalResourceGuard(health);
        updateAIGovernanceSnapshot(health.ai_governance || {});
        updateSituationBoard(summary, state, health, mattermost);
        updateSplitBoard(summary, actions);
        updateActionBoard(actions, state);
        updateTopoliteSingleScreen(summary, evidence, actions);
        updateMissionRow(summary, actions);
        updateTemporaryMission(actions);
        updateProgressChecklist(progress);
        updateHandoffPack(handoff);
        syncOnboardingBanner();
        updateEvidenceBoard(evidence, health, trends);
        updateAssistant(actions, mattermost, capabilities);
        if (CURRENT_PAGE === 'demo') {
            updateReviewReadiness(resultMap.health, resultMap.demoCapabilities, demoOverlayResult);
        }
        updateControlButtons(summary, state);
        if (CURRENT_PAGE === 'demo' && demoOverlayResult) {
            applyDemoOverlay(demoOverlayResult);
        }
    } catch (error) {
        console.error('Dashboard render failed:', error);
        showToast(tr('dashboard.render_failed', 'Dashboard render failed: {error}', { error: error.message }), 'error');
        return;
    }

    if (failures.length > 0) {
        const warning = tr('dashboard.partial_refresh', 'Partial refresh: {error}', { error: failures.join(' | ') });
        if (warning !== lastRefreshWarning) {
            showToast(warning, 'info');
            lastRefreshWarning = warning;
        }
    } else {
        lastRefreshWarning = '';
    }
}

async function loadDemoScenarios() {
    const select = document.getElementById('demoScenarioSelect');
    if (!select) return;
    try {
        const payload = await fetchJson('/api/demo/scenarios');
        demoScenarioItems = Array.isArray(payload.items) ? payload.items : [];
        if (!demoScenarioItems.length) {
            select.innerHTML = `<option value="">${escapeHtml(tr('dashboard.demo_no_scenarios', 'No scenarios available.'))}</option>`;
            updateElement('demoScenarioDescription', tr('dashboard.demo_no_scenario_desc', 'No scenario is currently available.'));
            return;
        }
        select.innerHTML = demoScenarioItems
            .map((item) => `<option value="${escapeAttribute(item.scenario_id)}">${escapeHtml(item.scenario_id)}</option>`)
            .join('');
        updateDemoScenarioDescription();
    } catch (error) {
        select.innerHTML = `<option value="">${escapeHtml(tr('dashboard.demo_load_failed', 'Failed to load scenarios: {error}', { error: '...' }))}</option>`;
        updateElement('demoScenarioDescription', tr('dashboard.demo_load_failed', 'Failed to load scenarios: {error}', { error: error.message }));
    }
}

function updateDemoScenarioDescription() {
    const select = document.getElementById('demoScenarioSelect');
    const selected = String(select?.value || '').trim();
    const item = demoScenarioItems.find((row) => row.scenario_id === selected) || demoScenarioItems[0];
    if (!item) {
        updateElement('demoScenarioDescription', tr('dashboard.demo_no_selection', 'No scenario selected.'));
        return;
    }
    if (select && !select.value) {
        select.value = item.scenario_id;
    }
    updateElement('demoScenarioDescription', `${item.description || '-'} | events=${item.event_count ?? 0}`);
}

async function runDemoScenario() {
    const select = document.getElementById('demoScenarioSelect');
    const submit = document.getElementById('demoRunSubmit');
    const scenarioId = String(select?.value || '').trim();
    if (!scenarioId) {
        showToast(tr('dashboard.demo_scenario_required', 'Scenario is required.'), 'info');
        return;
    }
    if (submit) submit.disabled = true;
    updateElement('demoResponse', tr('dashboard.demo_running', 'Running demo scenario...'));
    updateElement('demoOperatorWording', tr('dashboard.demo_preparing', 'Preparing scenario replay...'));
    updateElement('demoBoundaryMode', 'DETERMINISTIC REPLAY');
    updateElement('demoBoundarySummary', tr('dashboard.demo_boundary_summary', 'Deterministic replay path. This does not replace the live Tactical first-pass path, and AI is not used in the core demo decision loop.'));
    updateElement('demoNocStatus', '-');
    updateElement('demoSocStatus', '-');
    updateElement('demoAction', '-');
    updateElement('demoReason', '-');
    renderList('demoNextChecks', [tr('dashboard.demo_waiting_output', 'Waiting for scenario output')], (item) => item);
    renderList('demoEvidenceIds', [tr('dashboard.demo_waiting_output', 'Waiting for scenario output')], (item) => item);
    renderList('demoRejectedAlternatives', [tr('dashboard.demo_waiting_output', 'Waiting for scenario output')], (item) => item);
    const statusBadge = document.getElementById('demoStatusBadge');
    updateElement('demoStatusBadge', 'RUNNING');
    if (statusBadge) statusBadge.className = 'assistant-status status-caution';
    try {
        const payload = await fetchJson(`/api/demo/run/${encodeURIComponent(scenarioId)}`, { method: 'POST' });
        const result = payload.result || {};
        const overlay = payload.overlay || {};
        applyDemoDerivedFields(result);
        updateElement('demoNocStatus', result.noc?.summary?.status || '-');
        updateElement('demoSocStatus', result.soc?.summary?.status || '-');
        updateElement('demoAction', result.arbiter?.action || '-');
        updateElement('demoReason', result.arbiter?.reason || '-');
        updateElement('demoOperatorWording', result.explanation?.operator_wording || tr('dashboard.demo_no_explanation', 'No explanation returned.'));
        renderList('demoNextChecks', result.explanation?.next_checks || [], (item) => item);
        renderList('demoEvidenceIds', result.explanation?.evidence_ids || result.arbiter?.chosen_evidence_ids || [], (item) => item);
        renderList(
            'demoRejectedAlternatives',
            result.explanation?.why_not_others || result.arbiter?.rejected_alternatives || [],
            (item) => `${item.action || '-'}: ${item.reason || '-'}`,
        );
        updateElement('demoResponse', JSON.stringify(result, null, 2));
        updateElement('demoStatusBadge', 'DONE');
        if (statusBadge) statusBadge.className = 'assistant-status status-safe';
        demoOverlayResult = overlay && overlay.active ? overlay : null;
        if (demoOverlayResult) {
            setDemoOverlayVisualState(true);
            applyDemoOverlay(demoOverlayResult);
        }
        await askMioWithOptions(buildDemoMioQuestion(result), {
            silent: true,
            source: 'dashboard_demo',
            context: {
                audience: currentAudience,
                demo_overlay: {
                    scenario_id: overlay.scenario_id || result.scenario_id || scenarioId,
                    noc_status: overlay.noc_status || result.noc?.summary?.status || '-',
                    soc_status: overlay.soc_status || result.soc?.summary?.status || '-',
                    action: overlay.action || result.arbiter?.action || '-',
                    reason: overlay.reason || result.arbiter?.reason || '-',
                },
            },
        });
        showToast(tr('dashboard.demo_completed', 'Demo completed: {scenario}', { scenario: scenarioId }), 'success');
    } catch (error) {
        updateElement('demoResponse', tr('dashboard.demo_failed', 'Demo failed: {error}', { error: error.message }));
        updateElement('demoStatusBadge', 'FAILED');
        updateElement('demoOperatorWording', tr('dashboard.demo_failed', 'Demo failed: {error}', { error: error.message }));
        if (statusBadge) statusBadge.className = 'assistant-status status-danger';
        showToast(tr('dashboard.demo_failed', 'Demo failed: {error}', { error: error.message }), 'error');
    } finally {
        if (submit) submit.disabled = false;
    }
}

async function clearDemoOverlay() {
    try {
        demoOverlayResult = null;
        resetDemoOverlayPresentation();
        await fetchJson('/api/demo/overlay/clear', { method: 'POST' });
        const overlayState = await fetchJson('/api/demo/overlay');
        demoOverlayResult = overlayState && overlayState.active ? overlayState.overlay : null;
        if (!demoOverlayResult) {
            resetDemoOverlayPresentation();
            setDemoOverlayVisualState(false);
        }
        await refreshDashboard();
        showToast(tr('dashboard.demo_cleared', 'Demo overlay cleared.'), 'success');
    } catch (error) {
        showToast(tr('dashboard.demo_failed', 'Demo failed: {error}', { error: error.message }), 'error');
    }
}

function applyDemoOverlay(result) {
    if (!result || typeof result !== 'object') return;

    const raw = result.raw_result && typeof result.raw_result === 'object' ? result.raw_result : {};
    const scenarioId = String(result.scenario_id || raw.scenario_id || 'demo').trim();
    const description = String(result.description || raw.description || '').trim();
    const nocStatus = String(result.noc_status || raw.noc?.summary?.status || '-').trim();
    const socStatus = String(result.soc_status || raw.soc?.summary?.status || '-').trim();
    const action = String(result.action || raw.arbiter?.action || '-').trim();
    const reason = String(result.reason || raw.arbiter?.reason || '-').trim();
    const suspicion = Number(result.soc_suspicion || raw.soc?.suspicion?.score || 0);
    const evidenceIds = Array.isArray(result.chosen_evidence_ids)
        ? result.chosen_evidence_ids
        : (Array.isArray(raw.explanation?.evidence_ids) ? raw.explanation.evidence_ids : []);
    const nextChecks = Array.isArray(result.next_checks)
        ? result.next_checks
        : (Array.isArray(raw.explanation?.next_checks) ? raw.explanation.next_checks : []);
    const rejected = Array.isArray(result.rejected_alternatives)
        ? result.rejected_alternatives
        : (Array.isArray(raw.explanation?.why_not_others) ? raw.explanation.why_not_others : []);
    const operatorWording = String(result.operator_wording || raw.explanation?.operator_wording || '').trim();
    applyDemoDerivedFields({
        scenario_id: scenarioId,
        event_count: Number(result.event_count || raw.event_count || 0),
        execution: result.execution || raw.execution || {},
        action_profile: result.action_profile || raw.arbiter?.action_profile || {},
        decision_trace: result.decision_trace || raw.arbiter?.decision_trace || {},
        capability_boundary: result.capability_boundary || raw.capability_boundary || {},
    });
    updateElement('demoNocStatus', nocStatus || '-');
    updateElement('demoSocStatus', socStatus || '-');
    updateElement('demoAction', action || '-');
    updateElement('demoReason', reason || '-');
    updateElement('demoOperatorWording', operatorWording || tr('dashboard.demo_no_explanation', 'No explanation returned.'));
    renderList('demoNextChecks', nextChecks.length ? nextChecks : [tr('dashboard.demo_no_next_checks', 'No next checks')], (item) => item);
    renderList('demoEvidenceIds', evidenceIds.length ? evidenceIds : [tr('dashboard.demo_no_evidence', 'No evidence ids')], (item) => item);
    renderList('demoRejectedAlternatives', rejected.length ? rejected : [tr('dashboard.demo_no_rejections', 'No rejected alternatives')], (item) =>
        typeof item === 'string' ? item : `${item.action || '-'}: ${item.reason || '-'}`,
    );
    updateElement('demoResponse', JSON.stringify(raw && Object.keys(raw).length ? raw : result, null, 2));
    setDemoOverlayVisualState(true);
    updateElement('demoStatusBadge', 'DEMO ACTIVE');
    const demoStatusBadge = document.getElementById('demoStatusBadge');
    if (demoStatusBadge) demoStatusBadge.className = 'assistant-status status-demo';

    const userState = socStatus === 'critical'
        ? 'DECEPTION'
        : (nocStatus === 'critical' || nocStatus === 'degraded' ? 'LIMITED' : 'SAFE');
    const stateName = socStatus === 'critical' ? 'DEMO-SOC' : 'DEMO-NOC';
    const postureTone = toneForRisk(userState, suspicion);
    const postureCard = document.getElementById('postureCard');
    if (postureCard) postureCard.className = `situation-card posture-card ${postureTone}`;

    updateElement('commandStripNote', tr('dashboard.demo_overlay_note', 'Demo overlay active: {scenario}. {description}', {
        scenario: scenarioId,
        description: description || tr('dashboard.demo_overlay_note_fallback', 'Synthetic scenario replay.'),
    }));
    updateElement('stripMode', 'DEMO');
    updateElement('stripRisk', userState);
    updateElement('stripUplink', scenarioId);
    updateElement('stripInternet', action === 'notify' ? 'OBSERVE' : action.toUpperCase());
    updateElement('stripCritical', String(socStatus === 'critical' ? evidenceIds.length || 1 : 0));
    updateElement('stripDeferred', '0');
    updateElement('stripQueue', 'demo');
    updateElement('stripStale', 'NO');

    updateElement('postureState', `${userState} / ${stateName}`);
    updateElement('riskScore', String(suspicion));
    updateElement('postureRecommendation', tr('dashboard.demo_selected_action', 'Demo selected {action} because {reason}.', { action, reason }));
    updateElement('postureCurrentRecommendation', `Scenario ${scenarioId}: ${action}`);
    updateElement('postureConfidence', result.soc?.confidence?.label || nocStatus || '-');
    updateElement('postureLastAlert', scenarioId);
    updateElement('postureLlmStatus', 'demo-overlay');

    updateElement('networkSsid', `DEMO:${scenarioId}`);
    updateElement('networkGateway', 'demo-target');
    updateElement('networkInternet', action === 'notify' ? 'CHECK' : 'CONTROL');
    updateElement('networkPortal', 'N/A');
    updateElement('networkScope', 'demo:synthetic');
    updateElement('networkDnsMismatch', '0');
    updateElement('networkSignals', joinList(result.noc?.summary?.reasons || []));
    updateElement('socThreatLevel', String(socStatus || 'quiet').toUpperCase());
    updateElement('socThreatSummary', `${scenarioId} | action=${action} | reason=${reason}`);
    updateElement('socAttackType', joinList(result.soc?.summary?.attack_candidates || []));
    updateElement('socTopSource', '-');
    updateElement('socTopDestination', '-');
    updateElement('socTopSignature', '-');
    updateElement('socAlertCounts', `${socStatus === 'critical' ? 1 : 0} / 0`);
    updateElement('socConfidenceSignal', `suspicion=${suspicion}`);
    updateElement('socCorrelationStatus', result.soc?.summary?.correlation?.status || '-');
    renderList('socCorrelationReasons', result.soc?.summary?.correlation?.reasons || [], (item) => item);
    renderList(
        'socKnowledgeList',
        [
            ...(result.soc?.summary?.attack_candidates || []),
            ...(result.soc?.summary?.ti_matches || []),
            ...(result.soc?.summary?.sigma_hits || []),
            ...(result.soc?.summary?.yara_hits || []),
        ],
        (item) => item,
    );
    updateElement('nocPathStatus', String(nocStatus || 'unknown').toUpperCase());
    updateElement('nocPathUplink', scenarioId);
    updateElement('nocPathGateway', 'demo-target');
    updateElement('nocPathInternet', action === 'notify' ? 'CHECK' : 'CONTROL');
    renderList('nocPathSignals', result.noc?.summary?.reasons || [], (item) => item);
    renderList('nocServiceList', [
        tr('dashboard.demo_service_simulated', 'demo-services: simulated'),
        tr('dashboard.demo_control_mode', 'control-mode: {mode}', { mode: result.arbiter?.control_mode || 'none' }),
    ], (item) => item);
    updateElement('nocCapacityState', String(result.noc?.capacity_health?.label || 'unknown').toUpperCase());
    updateElement('nocCapacityUtilization', '-');
    updateElement('nocCapacityMode', 'demo');
    updateElement('nocCapacityTopTalker', '-');
    updateElement('nocClientCurrent', String(result.noc?.client_inventory_health?.score != null ? 1 : 0));
    updateElement('nocClientUnknown', '0');
    updateElement('nocClientUnauthorized', '0');
    updateElement('nocClientMismatch', '0');
    updateToggleSummary(
        'splitBoardDetailsToggle',
        tr('dashboard.split_board_details_summary', 'SOC {soc} | NOC {noc}', {
            soc: String(socStatus || 'unknown').toUpperCase(),
            noc: String(nocStatus || 'unknown').toUpperCase(),
        }),
        strongestTone(
            socStatus === 'critical' ? 'status-danger' : (socStatus ? 'status-caution' : 'status-neutral'),
            ['critical', 'degraded'].includes(String(nocStatus || '').toLowerCase()) ? 'status-caution' : 'status-neutral',
        ),
    );
    renderList(
        'rejectedStrongerActionsList',
        rejected.length ? rejected : [tr('dashboard.no_active_rejections', 'No rejected stronger actions')],
        (item) => typeof item === 'string' ? item : `${item.action || '-'}: ${item.reason || '-'}`,
    );

    renderList('whyNowList', [
        tr('dashboard.scenario_active', 'Scenario {scenario} is active.', { scenario: scenarioId }),
        tr('dashboard.noc_status_line', 'NOC status: {status}', { status: nocStatus }),
        tr('dashboard.soc_status_line', 'SOC status: {status}', { status: socStatus }),
        tr('dashboard.reason_line', 'Reason: {reason}', { reason }),
    ], (item) => item);
    renderList('nextActionsList', nextChecks.length ? nextChecks : [tr('dashboard.demo_review_action_path', 'Review {action} path for {scenario}.', { action, scenario: scenarioId })], (item) => item);
    renderList('doNotDoList', [
        tr('dashboard.demo_do_not_1', 'Do not treat demo output as live telemetry.'),
        tr('dashboard.demo_do_not_2', 'Do not change gateway mode based on demo data alone.'),
    ], (item) => item);
    renderList('escalateIfList', [tr('dashboard.demo_escalate_if', 'Move to ops review if the same pattern appears in live telemetry.')], (item) => item);
    updateElement('userGuidanceText', tr('dashboard.demo_user_guidance', 'This is a demo overlay. Compare it against live telemetry before acting.'));
    updateToggleSummary(
        'actionBoardPrimaryDetailsToggle',
        tr('dashboard.action_board_primary_details_summary', 'Why {why} | Next {next}', { why: 4, next: nextChecks.length || 1 }),
        'status-caution',
    );
    updateToggleSummary(
        'actionBoardGuidanceDetailsToggle',
        tr('dashboard.action_board_guidance_details_summary', 'Ask {ask} | Tell {tell} | Avoid {avoid}', { ask: 1, tell: 1, avoid: 2 }),
        'status-caution',
    );
    updateElement('runbookTitle', tr('dashboard.demo_runbook_title', 'Demo scenario summary'));
    updateElement('runbookId', scenarioId);
    updateElement('runbookEffect', tr('dashboard.display_only', 'display_only'));
    updateElement('runbookApproval', tr('dashboard.not_applicable', 'Not applicable'));
    renderList('runbookSteps', nextChecks.length ? nextChecks : [tr('dashboard.demo_runbook_step_1', 'Inspect explanation output'), tr('dashboard.demo_runbook_step_2', 'Compare with live telemetry before acting')], (item) => item);
    updateToggleSummary(
        'actionBoardRunbookDetailsToggle',
        tr('dashboard.action_board_runbook_details_summary', 'Steps {steps} | Approval {approval}', {
            steps: nextChecks.length || 2,
            approval: tr('dashboard.not_applicable', 'Not applicable'),
        }),
        'status-neutral',
    );
    updateToggleSummary(
        'actionBoardDecisionDetailsToggle',
        tr('dashboard.action_board_decision_details_summary', '2nd pass {status}', { status: 'demo' }),
        'status-neutral',
    );
    updateToggleSummary(
        'actionBoardRejectedDetailsToggle',
        tr('dashboard.action_board_rejected_details_summary', 'Rejected {count}', { count: rejected.length }),
        rejected.length > 0 ? 'status-neutral' : 'status-safe',
    );
    updateToggleSummary(
        'actionBoardControlDetailsToggle',
        tr('dashboard.action_board_control_details_summary', 'Mode {mode}', {
            mode: String(result.arbiter?.control_mode || 'demo').toUpperCase(),
        }),
        'status-neutral',
    );

    renderTimeline('currentTriggersTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'demo',
            title: tr('dashboard.demo_trigger_title', 'Scenario {scenario}', { scenario: scenarioId }),
            detail: description || tr('dashboard.demo_trigger_detail', 'Synthetic demo scenario replay'),
        },
    ], (item) => item);
    renderTimeline('decisionChangesTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'arbiter',
            title: tr('dashboard.demo_decision_title', '{action} selected', { action }),
            detail: reason || tr('dashboard.demo_decision_no_reason', 'No reason provided'),
        },
    ], (item) => item);
    renderTimeline('operatorInteractionsTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'demo',
            title: tr('dashboard.demo_operator_interaction_title', 'Demo overlay applied to dashboard'),
            detail: tr('dashboard.demo_operator_interaction_detail', 'Display state is synthetic until cleared.'),
        },
    ], (item) => item);
    renderTimeline('backgroundHistoryTimeline', rejected, (item) => ({
        ts_iso: result.ts || raw.explanation?.ts || '-',
        kind: 'rejected',
        title: item.action || '-',
        detail: item.reason || '-',
    }));
    updateElement('healthSummaryLine', tr('dashboard.demo_health_summary', 'Demo overlay active | scenario={scenario} | action={action} | evidence={count}', { scenario: scenarioId, action, count: evidenceIds.length }));
    updateToggleSummary(
        'evidenceTimelineDetailsToggle',
        tr('dashboard.evidence_timeline_details_summary', 'Triggers {triggers} | Changes {changes} | Audit {audit}', {
            triggers: 1,
            changes: 1,
            audit: 0,
        }),
        'status-caution',
    );

    updateElement('mioCurrentAnswer', tr('dashboard.demo_mio_answer', 'Demo overlay active for {scenario}. {wording}', { scenario: scenarioId, wording: operatorWording }).trim());
    updateElement('mioRecommendation', tr('dashboard.demo_mio_recommendation', 'Demo scenario {scenario} selected {action}.', { scenario: scenarioId, action }));
    updateElement('mioLastAsk', tr('dashboard.demo_mio_last_ask', 'Demo scenario replay | {scenario}', { scenario: scenarioId }));
    updateElement('mioRunbookSummary', tr('dashboard.demo_mio_runbook', 'Scenario {scenario} | display_only', { scenario: scenarioId }));
    renderList('mioRationaleList', [
        tr('dashboard.demo_mio_rationale_1', 'Demo scenario: {scenario}', { scenario: scenarioId }),
        tr('dashboard.demo_mio_rationale_2', 'NOC={noc}, SOC={soc}', { noc: nocStatus, soc: socStatus }),
        tr('dashboard.demo_mio_rationale_3', 'Arbiter action={action}', { action }),
        tr('dashboard.demo_mio_rationale_4', 'Reason={reason}', { reason }),
    ], (item) => item);
    updateElement('mioUserGuidance', tr('dashboard.demo_user_guidance', 'This is a demo overlay. Compare it against live telemetry before acting.'));
    updateElement('mioReview', 'demo-overlay');
    updateToggleSummary(
        'mioAssistDetailsToggle',
        tr('dashboard.mio_details_summary', 'Rationale {count} | Review {review}', { count: 4, review: 'demo-overlay' }),
        'status-neutral',
    );
    const mioStatusBadge = document.getElementById('mioStatusBadge');
    if (mioStatusBadge) {
        mioStatusBadge.textContent = 'DEMO';
        mioStatusBadge.className = 'assistant-status status-demo';
    }
    updateTemporaryMission({
        current_user_guidance: tr('dashboard.demo_user_guidance', 'This is a demo overlay. Compare it against live telemetry before acting.'),
        do_next: nextChecks,
        do_not_do: [
            tr('dashboard.demo_user_guidance', 'This is a demo overlay. Compare it against live telemetry before acting.'),
            tr('dashboard.temp_do_not_do_default', 'Do not change mode or restart services until the first checks are done.'),
        ],
    });
}

async function fetchJson(path, options = {}) {
    const headers = Object.assign({}, options.headers || {}, { 'X-Auth-Token': AUTH_TOKEN, 'X-AZAZEL-LANG': CURRENT_LANG });
    const response = await fetch(path, { ...options, headers });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) {
        throw new Error(payload.error || `Request failed: ${path}`);
    }
    return payload;
}

function updateHeader(state, mattermost) {
    seedHeaderClock(state.now_time || '');
    updateElement('headerCpuUsage', state.cpu_percent != null ? `${state.cpu_percent}%` : '--%');
    updateElement('headerMemUsage', state.mem_percent != null ? `${state.mem_percent}%` : '--%');
    updateElement('headerCpuTemp', state.temp_c != null ? `${state.temp_c}°C` : '--°C');
    const mattermostUrl = mattermost.open_url || '/ops-comm';
    const mmLink = document.getElementById('openMattermostLink');
    if (mmLink) mmLink.href = mattermostUrl;
}

function updateNormalAssurance(summary) {
    const panel = document.getElementById('normalAssurancePanel');
    if (!panel) return;
    const assurance = summary && typeof summary === 'object' && summary.normal_assurance && typeof summary.normal_assurance === 'object'
        ? summary.normal_assurance
        : {};
    const gates = Array.isArray(assurance.gates) ? assurance.gates : [];
    const failedGateIds = Array.isArray(assurance.failed_gates) ? assurance.failed_gates.map((item) => String(item)) : [];
    const failedGateSet = new Set(failedGateIds);
    const failedGates = gates.filter((gate) => !gate?.ok || failedGateSet.has(String(gate?.id || '')));
    const status = String(assurance.status || '').toLowerCase();
    const level = String(assurance.level || '').toLowerCase();
    const statusLabel = status === 'normal'
        ? tr('dashboard.normal_assurance_state_normal', 'NORMAL')
        : (status === 'alert'
            ? tr('dashboard.normal_assurance_state_alert', 'ALERT')
            : (status === 'watch'
                ? tr('dashboard.normal_assurance_state_watch', 'WATCH')
                : tr('dashboard.status_idle', 'IDLE')));
    updateElement('normalAssuranceState', statusLabel);

    if (!gates.length) {
        updateElement('normalAssuranceSummary', tr('dashboard.normal_assurance_waiting', 'Waiting for normal-assurance evaluation.'));
        renderList('normalAssuranceFailedList', [tr('dashboard.normal_assurance_gate_waiting', 'Waiting for gate evaluation.')], (item) => item);
        renderList('normalAssuranceGateList', [tr('dashboard.normal_assurance_gate_waiting', 'Waiting for gate evaluation.')], (item) => item);
    } else if (!failedGates.length) {
        const passed = Number(assurance.passed_count ?? gates.length);
        const total = Number(assurance.gate_count ?? gates.length);
        updateElement(
            'normalAssuranceSummary',
            tr('dashboard.normal_assurance_all_clear', 'All required gates are healthy ({passed}/{total}).', { passed, total }),
        );
        renderList('normalAssuranceFailedList', [tr('dashboard.normal_assurance_no_failed_gate', 'No failed gates.')], (item) => item);
        renderList(
            'normalAssuranceGateList',
            gates.map((gate) => `OK | ${String(gate.label || gate.id || '-')}: ${String(gate.detail || '-')}`),
            (item) => item,
        );
    } else {
        const failedCount = failedGates.length;
        const total = Number(assurance.gate_count ?? gates.length);
        updateElement(
            'normalAssuranceSummary',
            tr('dashboard.normal_assurance_attention', '{failed} of {total} gates need attention.', { failed: failedCount, total }),
        );
        renderList(
            'normalAssuranceFailedList',
            failedGates.map((gate) => `${String(gate.label || gate.id || '-')}: ${String(gate.detail || '-')}`),
            (item) => item,
        );
        renderList(
            'normalAssuranceGateList',
            gates.map((gate) => `${gate?.ok ? 'OK' : 'NG'} | ${String(gate?.label || gate?.id || '-')}: ${String(gate?.detail || '-')}`),
            (item) => item,
        );
    }

    panel.classList.remove('normal-assurance-safe', 'normal-assurance-caution', 'normal-assurance-danger');
    if (level === 'safe') {
        panel.classList.add('normal-assurance-safe');
    } else if (level === 'danger') {
        panel.classList.add('normal-assurance-danger');
    } else if (level === 'caution') {
        panel.classList.add('normal-assurance-caution');
    }
}

function updatePrimaryAnomalyCard(actions) {
    const panel = document.getElementById('primaryAnomalyPanel');
    if (!panel) return;
    const card = actions && typeof actions === 'object' && actions.primary_anomaly_card && typeof actions.primary_anomaly_card === 'object'
        ? actions.primary_anomaly_card
        : {};
    const status = String(card.status || 'none').toLowerCase();
    const severity = String(card.severity || 'none').toLowerCase();
    const severityLabel = severity === 'critical'
        ? tr('dashboard.primary_anomaly_severity_critical', 'CRITICAL')
        : (severity === 'warning'
            ? tr('dashboard.primary_anomaly_severity_warning', 'WARNING')
            : (severity === 'info'
                ? tr('dashboard.primary_anomaly_severity_info', 'INFO')
                : tr('dashboard.primary_anomaly_severity_none', 'NONE')));
    const tone = severity === 'critical'
        ? 'status-danger'
        : (severity === 'warning' ? 'status-caution' : (severity === 'info' ? 'status-safe' : 'status-neutral'));
    const title = String(card.title || '').trim() || tr('dashboard.primary_anomaly_none_title', 'No primary anomaly right now');
    const what = String(card.what_happened || '').trim() || tr('dashboard.primary_anomaly_none_what', 'No SOC/NOC anomaly has been selected as the current primary trigger.');
    const impact = String(card.impact || '').trim() || tr('dashboard.primary_anomaly_none_impact', 'Keep the normal baseline visible and continue routine monitoring.');
    const doNow = Array.isArray(card.do_now) ? card.do_now.filter(Boolean).slice(0, 3) : [];
    const dontDo = Array.isArray(card.dont_do) ? card.dont_do.filter(Boolean).slice(0, 3) : [];

    updateElement('primaryAnomalySeverity', severityLabel);
    updateElement('primaryAnomalyHeading', title);
    updateElement('primaryAnomalyWhat', what);
    updateElement('primaryAnomalyImpact', impact);
    renderList(
        'primaryAnomalyDoNowList',
        doNow.length ? doNow : [tr('dashboard.primary_anomaly_waiting', 'Waiting for anomaly synthesis.')],
        (item) => item,
    );
    renderList(
        'primaryAnomalyDontDoList',
        dontDo.length ? dontDo : [tr('dashboard.primary_anomaly_waiting', 'Waiting for anomaly synthesis.')],
        (item) => item,
    );

    const severityEl = document.getElementById('primaryAnomalySeverity');
    if (severityEl) {
        severityEl.className = `assistant-status ${tone}`;
    }

    panel.classList.remove('primary-anomaly-none', 'primary-anomaly-warning', 'primary-anomaly-critical');
    if (status === 'anomaly' && severity === 'critical') {
        panel.classList.add('primary-anomaly-critical');
    } else if (status === 'anomaly' && severity === 'warning') {
        panel.classList.add('primary-anomaly-warning');
    } else {
        panel.classList.add('primary-anomaly-none');
    }
}

function updateClientIdentityView(summary) {
    const view = summary && typeof summary === 'object'
        ? (summary.noc_focus && typeof summary.noc_focus === 'object' ? summary.noc_focus.client_identity_view : null)
        : null;
    const remotePeers = summary && typeof summary === 'object'
        ? (summary.noc_focus && typeof summary.noc_focus === 'object' ? (summary.noc_focus.remote_peers || {}) : {})
        : {};
    const items = view && Array.isArray(view.items) ? view.items : [];
    const attentionItems = items.filter((item) => Boolean(item?.requires_attention));
    const attentionCount = Number(view?.attention_count ?? attentionItems.length);
    const normalCount = Number(view?.normal_count ?? items.filter((item) => String(item?.state || '') === 'normal').length);
    const currentCount = items.filter((item) => String(item?.state || '') !== 'missing').length;
    const anomalyCount = items.filter((item) => ['unauthorized', 'mismatch', 'missing'].includes(String(item?.state || ''))).length;
    const unidentifiedCount = items.filter((item) => String(item?.state || '') === 'unknown').length;
    const staleCount = items.filter((item) => String(item?.state || '') === 'stale').length;
    const rows = showNormalClients ? items : attentionItems;
    const segmentCounts = view && typeof view.segment_counts === 'object' ? view.segment_counts : {};
    const ethCount = Number(segmentCounts.eth || 0);
    const wlanCount = Number(segmentCounts.wlan || 0);
    const otherCount = Number(segmentCounts.other || 0);
    const unknownSegmentCount = Number(segmentCounts.unknown || 0);
    const arpOnlyCount = Number(view?.arp_only_count || 0);
    const infraFilteredCount = Number(view?.infra_filtered_count || 0);
    const ignoredFilteredCount = Number(view?.ignored_filtered_count || 0);
    const expectedLinkMismatchCount = Number(view?.expected_link_mismatch_count || 0);

    const setTile = (tileId, countId, value, tone) => {
        updateElement(countId, String(value));
        const tile = document.getElementById(tileId);
        if (!tile) return;
        tile.className = `client-identity-tile ${tone}`;
    };

    const toggle = document.getElementById('clientIdentityToggle');
    const summaryEl = document.getElementById('clientIdentitySummary');
    if (summaryEl) {
        summaryEl.textContent = tr(
            'dashboard.client_identity_summary',
            'ETH {eth} / WLAN {wlan} / ARP-only {arp_only} / link drift {link_drift}',
            { eth: ethCount, wlan: wlanCount, arp_only: arpOnlyCount, link_drift: expectedLinkMismatchCount, anomaly: anomalyCount, unidentified: unidentifiedCount, normal: normalCount, attention: attentionCount },
        );
    }
    setTile('clientIdentityCurrentTile', 'clientIdentityCurrentCount', currentCount, currentCount > 0 ? 'status-neutral' : 'status-safe');
    setTile('clientIdentityEthTile', 'clientIdentityEthCount', ethCount, ethCount > 0 ? 'status-neutral' : 'status-safe');
    setTile('clientIdentityWlanTile', 'clientIdentityWlanCount', wlanCount, wlanCount > 0 ? 'status-neutral' : 'status-safe');
    setTile('clientIdentityAnomalyTile', 'clientIdentityAnomalyCount', anomalyCount, anomalyCount > 0 ? 'status-danger' : 'status-safe');
    setTile(
        'clientIdentityUnidentifiedTile',
        'clientIdentityUnidentifiedCount',
        unidentifiedCount,
        unidentifiedCount > 0 ? 'status-neutral' : 'status-safe',
    );
    setTile(
        'clientIdentityNormalTile',
        'clientIdentityNormalCount',
        normalCount,
        staleCount > 0 ? 'status-caution' : 'status-safe',
    );
    if (toggle) {
        toggle.textContent = showNormalClients
            ? tr('dashboard.client_identity_toggle_attention_only', 'Show attention only')
            : tr('dashboard.client_identity_toggle_show_normal', 'Show normal too');
        toggle.disabled = !items.length || (normalCount <= 0 && !showNormalClients);
    }

    const stateLabel = (state) => {
        const text = String(state || 'unknown');
        if (text === 'normal') return tr('dashboard.client_identity_state_normal', 'NORMAL');
        if (text === 'unauthorized') return tr('dashboard.client_identity_state_unauthorized', 'UNAUTHORIZED');
        if (text === 'mismatch') return tr('dashboard.client_identity_state_mismatch', 'MISMATCH');
        if (text === 'stale') return tr('dashboard.client_identity_state_stale', 'STALE');
        if (text === 'missing') return tr('dashboard.client_identity_state_missing', 'MISSING');
        return tr('dashboard.client_identity_state_unknown', 'UNKNOWN');
    };

    const stateTone = (state) => {
        const text = String(state || 'unknown');
        if (text === 'normal') return 'status-safe';
        if (text === 'stale') return 'status-caution';
        if (['unauthorized', 'mismatch', 'missing'].includes(text)) return 'status-danger';
        return 'status-neutral';
    };

    const originLabel = (origin) => {
        const text = String(origin || 'unknown');
        if (text === 'dhcp_arp') return tr('dashboard.client_identity_origin_dhcp_arp', 'DHCP + ARP');
        if (text === 'dhcp') return tr('dashboard.client_identity_origin_dhcp', 'DHCP');
        if (text === 'arp_only') return tr('dashboard.client_identity_origin_arp_only', 'ARP only');
        return tr('dashboard.client_identity_origin_unknown', 'Unknown');
    };

    const familyLabel = (family) => {
        const text = String(family || 'unknown');
        if (text === 'eth') return tr('dashboard.client_identity_family_eth', 'ETH');
        if (text === 'wlan') return tr('dashboard.client_identity_family_wlan', 'WLAN');
        if (text === 'other') return tr('dashboard.client_identity_family_other', 'OTHER');
        return tr('dashboard.client_identity_family_unknown', 'UNKNOWN');
    };

    const connectionLabel = (family) => {
        const text = String(family || 'unknown');
        if (text === 'eth') return tr('dashboard.client_identity_connection_wired', 'WIRED');
        if (text === 'wlan') return tr('dashboard.client_identity_connection_wireless', 'WIRELESS');
        return tr('dashboard.client_identity_connection_unknown', 'UNKNOWN LINK');
    };

    const classMeta = (item) => {
        if (Boolean(item?.trusted)) {
            return {
                className: 'trusted',
                label: tr('dashboard.client_identity_legend_trusted', 'Trusted'),
            };
        }
        if (String(item?.session_origin || '') === 'arp_only' || ['unauthorized', 'mismatch', 'missing'].includes(String(item?.state || ''))) {
            return {
                className: 'suspicious',
                label: tr('dashboard.client_identity_legend_suspicious', 'Suspicious candidate'),
            };
        }
        return {
            className: 'unidentified',
            label: tr('dashboard.client_identity_legend_unidentified', 'Unidentified'),
        };
    };

    const fallback = items.length
        ? tr('dashboard.client_identity_no_attention', 'No attention-required clients.')
        : tr('dashboard.client_identity_empty', 'No client identity data.');
    const listEl = document.getElementById('clientIdentityList');
    if (listEl) {
        if (!rows.length) {
            listEl.innerHTML = `<div class="client-identity-empty">${escapeHtml(fallback)}</div>`;
        } else {
            const grouped = new Map([
                ['eth', []],
                ['wlan', []],
                ['unknown', []],
                ['other', []],
            ]);
            rows.forEach((item) => {
                const family = grouped.has(item?.interface_family) ? item.interface_family : 'other';
                grouped.get(family).push(item);
            });
            const renderRow = (item) => {
                if (typeof item === 'string') {
                    return `<div class="client-identity-empty">${escapeHtml(item)}</div>`;
                }
                const state = String(item.state || 'unknown');
                const stateText = stateLabel(state);
                const tone = stateTone(state);
                const trusted = Boolean(item.trusted);
                const trustEligible = item.trust_eligible !== false;
                const family = String(item.interface_family || 'unknown');
                const showArpSuspicious = String(item.session_origin || '') === 'arp_only';
                const showExpectedLinkMismatch = Boolean(item.expected_link_mismatch);
                const meta = classMeta(item);
                const lastSeenRaw = String(item.last_seen || '').trim();
                const lastSeen = lastSeenRaw ? formatHumanDateTime(lastSeenRaw) : '-';
                const chips = [
                    { label: 'ip', value: item.ip || '-' },
                    { label: 'mac', value: item.masked_mac || '-' },
                    { label: 'obs', value: originLabel(item.session_origin || 'unknown') },
                    { label: 'sot', value: item.sot_status || '-' },
                    { label: 'seg', value: item.interface_or_segment || '-' },
                    ...(item.expected_interface_or_segment ? [{ label: 'exp', value: item.expected_interface_or_segment }] : []),
                    { label: 'last', value: lastSeen },
                ];
                return `
                    <article class="client-identity-row row-state-${escapeAttribute(state)} client-class-${escapeAttribute(meta.className)}">
                        <div class="client-identity-row-top">
                            <div class="client-identity-row-name-wrap">
                                <div class="client-identity-row-name">${escapeHtml(item.display_name || '-')}</div>
                                <span class="client-identity-class-badge class-${escapeAttribute(meta.className)}">${escapeHtml(meta.label)}</span>
                                <span class="client-identity-connection-badge connection-${escapeAttribute(family)}">${escapeHtml(connectionLabel(family))}</span>
                                ${showArpSuspicious ? `<span class="client-identity-alert-badge">${escapeHtml(tr('dashboard.client_identity_alert_arp_only', 'UNAPPROVED ARP'))}</span>` : ''}
                                ${showExpectedLinkMismatch ? `<span class="client-identity-alert-badge client-identity-drift-badge">${escapeHtml(tr('dashboard.client_identity_alert_link_drift', 'LINK DRIFT'))}</span>` : ''}
                            </div>
                            <div class="client-identity-row-state ${tone}">${escapeHtml(stateText)}</div>
                        </div>
                        <div class="client-identity-row-actions">
                            <label class="client-identity-trust-toggle ${trustEligible ? '' : 'is-disabled'}">
                                <input
                                    type="checkbox"
                                    class="client-trust-checkbox"
                                    data-session-key="${escapeAttribute(item.session_key || '')}"
                                    data-ip="${escapeAttribute(item.ip || '')}"
                                    data-mac="${escapeAttribute(item.mac || '')}"
                                    data-hostname="${escapeAttribute(item.hostname || '')}"
                                    data-display-name="${escapeAttribute(item.display_name || '')}"
                                    data-segment="${escapeAttribute(item.interface_or_segment || '')}"
                                    data-expected-segment="${escapeAttribute(item.expected_interface_or_segment || '')}"
                                    data-note="${escapeAttribute(item.note || '')}"
                                    data-allowed-networks="${escapeAttribute((item.allowed_networks || []).join(','))}"
                                    data-trusted="${trusted ? 'true' : 'false'}"
                                    ${trusted ? 'checked' : ''}
                                    ${trustEligible ? '' : 'disabled'}
                                >
                                <span>${escapeHtml(tr('dashboard.client_trust_label', 'Trusted endpoint'))}</span>
                            </label>
                            <div class="client-identity-inline-actions">
                                ${showArpSuspicious ? `
                                    <button
                                        type="button"
                                        class="client-ignore-button"
                                        data-session-key="${escapeAttribute(item.session_key || '')}"
                                        data-ip="${escapeAttribute(item.ip || '')}"
                                        data-mac="${escapeAttribute(item.mac || '')}"
                                        data-hostname="${escapeAttribute(item.hostname || '')}"
                                        data-display-name="${escapeAttribute(item.display_name || '')}"
                                        data-segment="${escapeAttribute(item.interface_or_segment || '')}"
                                        data-expected-segment="${escapeAttribute(item.expected_interface_or_segment || '')}"
                                        data-note="${escapeAttribute(item.note || '')}"
                                        data-allowed-networks="${escapeAttribute((item.allowed_networks || []).join(','))}"
                                        data-trusted="${trusted ? 'true' : 'false'}"
                                    >${escapeHtml(tr('dashboard.client_ignore_button', 'Hide from client view'))}</button>
                                ` : ''}
                                ${trustEligible ? '' : `<span class="client-identity-trust-note">${escapeHtml(tr('dashboard.client_trust_ineligible', 'Requires MAC or private IP'))}</span>`}
                            </div>
                        </div>
                        <div class="client-identity-chip-grid">
                            ${chips.map((chip) => `
                                <span class="client-identity-chip">
                                    <span class="client-identity-chip-label">${escapeHtml(chip.label)}</span>
                                    <span>${escapeHtml(chip.value)}</span>
                                </span>
                            `).join('')}
                        </div>
                        <details class="client-profile-editor">
                            <summary>${escapeHtml(tr('dashboard.client_profile_show', 'Edit endpoint profile'))}</summary>
                            <form
                                class="client-profile-form"
                                data-session-key="${escapeAttribute(item.session_key || '')}"
                                data-ip="${escapeAttribute(item.ip || '')}"
                                data-mac="${escapeAttribute(item.mac || '')}"
                                data-hostname="${escapeAttribute(item.hostname || '')}"
                                data-display-name="${escapeAttribute(item.display_name || '')}"
                                data-segment="${escapeAttribute(item.interface_or_segment || '')}"
                                data-trusted="${trusted ? 'true' : 'false'}"
                            >
                                <label class="client-profile-field">
                                    <span>${escapeHtml(tr('dashboard.client_profile_name', 'Name'))}</span>
                                    <input type="text" name="hostname" value="${escapeAttribute(item.display_name || item.hostname || '')}" maxlength="80">
                                </label>
                                <label class="client-profile-field">
                                    <span>${escapeHtml(tr('dashboard.client_profile_note', 'Note'))}</span>
                                    <input type="text" name="note" value="${escapeAttribute(item.note || '')}" maxlength="240">
                                </label>
                                <label class="client-profile-field">
                                    <span>${escapeHtml(tr('dashboard.client_profile_expected_link', 'Expected link'))}</span>
                                    <select name="expected_interface_or_segment">
                                        <option value="" ${!item.expected_interface_or_segment ? 'selected' : ''}>${escapeHtml(tr('dashboard.client_profile_expected_auto', 'Auto'))}</option>
                                        <option value="eth0" ${String(item.expected_interface_or_segment || '') === 'eth0' ? 'selected' : ''}>eth0</option>
                                        <option value="wlan0" ${String(item.expected_interface_or_segment || '') === 'wlan0' ? 'selected' : ''}>wlan0</option>
                                    </select>
                                </label>
                                <label class="client-profile-field client-profile-field-wide">
                                    <span>${escapeHtml(tr('dashboard.client_profile_allowed_networks', 'Allowed networks'))}</span>
                                    <input type="text" name="allowed_networks" value="${escapeAttribute((item.allowed_networks || []).join(','))}" placeholder="lan-main">
                                </label>
                                <div class="client-profile-form-actions">
                                    <button type="submit" class="client-profile-save-button">${escapeHtml(tr('dashboard.client_profile_save', 'Save profile'))}</button>
                                </div>
                            </form>
                        </details>
                    </article>
                `;
            };
            listEl.innerHTML = ['eth', 'wlan', 'unknown', 'other']
                .filter((family) => grouped.get(family)?.length)
                .map((family) => `
                    <section class="client-identity-group">
                        <div class="client-identity-group-title">
                            <span>${escapeHtml(familyLabel(family))}</span>
                            <strong>${grouped.get(family).length}</strong>
                        </div>
                        <div class="client-identity-group-list">
                            ${grouped.get(family).map((item) => renderRow(item)).join('')}
                        </div>
                    </section>
                `)
                .join('');
        }
    }
    updateToggleSummary(
        'clientIdentityDetailsToggle',
        tr(
            'dashboard.client_identity_details_summary',
            'ETH {eth} | WLAN {wlan} | unknown seg {unknown} | ARP-only {arp_only} | link drift {link_drift} | hidden infra {hidden} | ignored {ignored}',
            { count: rows.length, anomaly: anomalyCount, unidentified: unidentifiedCount, eth: ethCount, wlan: wlanCount, unknown: unknownSegmentCount + otherCount, arp_only: arpOnlyCount, link_drift: expectedLinkMismatchCount, hidden: infraFilteredCount, ignored: ignoredFilteredCount },
        ),
        anomalyCount > 0 ? 'status-danger' : ((staleCount > 0 || expectedLinkMismatchCount > 0) ? 'status-caution' : (unidentifiedCount > 0 ? 'status-neutral' : 'status-safe')),
    );

    const remoteToggleTone = Number(remotePeers?.count || 0) > 0 ? 'status-safe' : 'status-neutral';
    updateToggleSummary(
        'remotePeersDetailsToggle',
        tr(
            'dashboard.remote_peers_summary',
            'Remote peers {count} | top {top}',
            {
                count: Number(remotePeers?.count || 0),
                top: Array.isArray(remotePeers?.items) && remotePeers.items.length ? String(remotePeers.items[0]?.label || '-') : '-',
            },
        ),
        remoteToggleTone,
    );
    const remoteList = document.getElementById('remotePeersList');
    if (remoteList) {
        const remoteItems = Array.isArray(remotePeers?.items) ? remotePeers.items : [];
        if (!remoteItems.length) {
            remoteList.innerHTML = `<div class="client-identity-empty">${escapeHtml(tr('dashboard.remote_peers_empty', 'No remote peers in the current top talkers.'))}</div>`;
        } else {
            remoteList.innerHTML = remoteItems.map((item) => `
                <article class="remote-peer-row">
                    <div class="remote-peer-row-top">
                        <div class="client-identity-row-name">${escapeHtml(item.label || '-')}</div>
                        <div class="client-identity-row-state status-safe">${escapeHtml(tr('dashboard.remote_peer_label', 'REMOTE'))}</div>
                    </div>
                    <div class="client-identity-chip-grid">
                        <span class="client-identity-chip"><span class="client-identity-chip-label">bytes</span><span>${escapeHtml(String(item.bytes || 0))}</span></span>
                        <span class="client-identity-chip"><span class="client-identity-chip-label">pkts</span><span>${escapeHtml(String(item.packets || 0))}</span></span>
                        <span class="client-identity-chip"><span class="client-identity-chip-label">flows</span><span>${escapeHtml(String(item.flows || 0))}</span></span>
                    </div>
                </article>
            `).join('');
        }
    }
}

function setPillTone(valueId, tone) {
    const valueEl = document.getElementById(valueId);
    const pill = valueEl ? valueEl.closest('.strip-pill, .freshness-pill') : null;
    if (!pill) return;
    pill.classList.remove('pill-safe', 'pill-caution', 'pill-danger');
    if (tone === 'safe' || tone === 'caution' || tone === 'danger') {
        pill.classList.add(`pill-${tone}`);
    }
}

function setHeatTone(cellId, tone, value) {
    const cell = document.getElementById(cellId);
    if (cell) {
        cell.className = `command-heat-cell ${tone || 'status-neutral'}`;
    }
    updateElement(`${cellId}Value`, value);
}

function tonePriority(tone) {
    if (tone === 'status-danger') return 3;
    if (tone === 'status-caution') return 2;
    if (tone === 'status-neutral') return 1;
    return 0;
}

function strongestTone(...tones) {
    return tones.reduce((best, current) => (
        tonePriority(current) > tonePriority(best) ? current : best
    ), 'status-safe');
}

function setGlanceCell(cellId, tone, value) {
    const cell = document.getElementById(cellId);
    if (cell) {
        cell.className = `split-glance-cell ${tone || 'status-neutral'}`;
    }
    updateElement(`${cellId}Value`, value);
}

function setGlanceCard(cardId, stateId, tone, value) {
    const card = document.getElementById(cardId);
    if (card) {
        card.className = `split-glance-card ${tone || 'status-neutral'}`;
    }
    updateElement(stateId, value);
}

function summarizeServiceState(serviceSummary) {
    const entries = Object.values(serviceSummary || {}).map((value) => String(value || '').toLowerCase());
    const offCount = entries.filter((value) => ['off', 'fail', 'failed', 'error', 'critical', 'unreachable'].includes(value)).length;
    const unknownCount = entries.filter((value) => !value || value === 'unknown').length;
    if (offCount > 0) {
        return { tone: 'status-danger', value: tr('dashboard.heat_service_off', '{count} OFF', { count: offCount }) };
    }
    if (unknownCount > 0) {
        return { tone: 'status-caution', value: tr('dashboard.heat_service_unknown', '{count} UNKNOWN', { count: unknownCount }) };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_all_on', 'ALL ON') };
}

function summarizeClientState(summary) {
    const inventory = summary.noc_focus?.client_inventory || {};
    const unauthorized = Number(inventory.unauthorized_client_count || 0);
    const mismatch = Number(inventory.inventory_mismatch_count || 0);
    const unknown = Number(inventory.unknown_client_count || 0);
    const stale = Number(inventory.stale_session_count || 0);
    const anomaly = unauthorized + mismatch;
    if (anomaly > 0) {
        return { tone: 'status-danger', value: tr('dashboard.heat_client_anomaly', '{count} ANOM', { count: anomaly }) };
    }
    if (stale > 0) {
        return { tone: 'status-caution', value: tr('dashboard.heat_client_stale', '{count} STALE', { count: stale }) };
    }
    if (unknown > 0) {
        return { tone: 'status-neutral', value: tr('dashboard.heat_client_unidentified', '{count} UNID', { count: unknown }) };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_client_clear', 'CLEAR') };
}

function summarizeTelemetryState(summary, health, failures = []) {
    const stale = health.stale_flags || {};
    if (failures.length > 0 || stale.snapshot) {
        return { tone: 'status-danger', value: tr('dashboard.heat_stale', 'STALE') };
    }
    if (stale.ai_metrics || stale.ai_activity || stale.runbook_events || summary.command_strip?.stale_warning) {
        return { tone: 'status-caution', value: tr('dashboard.heat_partial', 'PARTIAL') };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_live', 'LIVE') };
}

function summarizeAiState(summary, health) {
    const stale = health.stale_flags || {};
    const idle = health.idle_flags || {};
    const fallbackRate = Number(health.llm?.fallback_rate || 0);
    const secondPass = String(summary.decision_path?.second_pass_status || '').toLowerCase();
    const threat = String(summary.soc_focus?.threat_level || '').toLowerCase();
    const threatActive = ['critical', 'high', 'elevated', 'watch'].includes(threat) || Number(summary.command_strip?.direct_critical_count || 0) > 0;
    if (stale.ai_metrics || fallbackRate >= 50) {
        return { tone: 'status-danger', value: tr('dashboard.heat_ai_stale', 'STALE') };
    }
    if (fallbackRate > 0 || ((idle.ai_activity || secondPass === 'pending') && threatActive)) {
        return { tone: 'status-caution', value: tr('dashboard.heat_ai_idle', 'IDLE') };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_ai_ready', 'READY') };
}

function summarizeThreatState(summary) {
    const threat = String(summary.soc_focus?.threat_level || '').toLowerCase();
    if (['critical', 'high'].includes(threat) || Number(summary.command_strip?.direct_critical_count || 0) > 0) {
        return { tone: 'status-danger', value: tr('dashboard.heat_threat_critical', 'CRITICAL') };
    }
    if (['elevated', 'watch'].includes(threat) || Number(summary.soc_focus?.warning_count || 0) > 0) {
        return { tone: 'status-caution', value: threat === 'watch' ? tr('dashboard.heat_threat_watch', 'WATCH') : tr('dashboard.heat_threat_elevated', 'ELEVATED') };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_threat_quiet', 'QUIET') };
}

function summarizePathState(summary) {
    const path = summary.noc_focus?.path_health || {};
    const internet = String(path.internet_check || summary.command_strip?.internet_reachability || '').toLowerCase();
    const status = String(path.status || '').toLowerCase();
    if (internet === 'fail' || ['down', 'critical', 'failed'].includes(status)) {
        return { tone: 'status-danger', value: tr('dashboard.heat_path_down', 'DOWN') };
    }
    if (internet && internet !== 'ok' && internet !== 'pass') {
        return { tone: 'status-caution', value: tr('dashboard.heat_path_degraded', 'DEGRADED') };
    }
    if (['degraded', 'warning', 'warn'].includes(status)) {
        return { tone: 'status-caution', value: tr('dashboard.heat_path_degraded', 'DEGRADED') };
    }
    return { tone: 'status-safe', value: tr('dashboard.heat_path_up', 'UP') };
}

function summarizeCorrelationState(correlation) {
    const status = String(correlation?.status || 'unknown').toLowerCase();
    const reasonCount = Array.isArray(correlation?.reasons) ? correlation.reasons.length : 0;
    if (['confirmed', 'correlated', 'active', 'matched'].includes(status)) {
        return { tone: 'status-danger', value: reasonCount > 0 ? `${status.toUpperCase()} ${reasonCount}` : status.toUpperCase() };
    }
    if (['partial', 'watch', 'review'].includes(status)) {
        return { tone: 'status-caution', value: reasonCount > 0 ? `${status.toUpperCase()} ${reasonCount}` : status.toUpperCase() };
    }
    if (['none', 'clear', 'normal', 'idle'].includes(status)) {
        return { tone: 'status-safe', value: status.toUpperCase() };
    }
    return { tone: 'status-neutral', value: status.toUpperCase() };
}

function summarizeTriageState(triage) {
    const status = String(triage?.status || 'unknown').toLowerCase();
    const nowCount = Array.isArray(triage?.now) ? triage.now.length : 0;
    const watchCount = Array.isArray(triage?.watch) ? triage.watch.length : 0;
    const backlogCount = Array.isArray(triage?.backlog) ? triage.backlog.length : 0;
    if (status === 'now' || nowCount > 0) {
        return { tone: 'status-danger', value: `NOW ${nowCount}` };
    }
    if (status === 'watch' || watchCount > 0) {
        return { tone: 'status-caution', value: `WATCH ${watchCount}` };
    }
    if (status === 'backlog' || backlogCount > 0) {
        return { tone: 'status-neutral', value: `BACKLOG ${backlogCount}` };
    }
    if (['idle', 'none', 'clear'].includes(status)) {
        return { tone: 'status-safe', value: status.toUpperCase() };
    }
    return { tone: 'status-neutral', value: status.toUpperCase() };
}

function summarizeVisibilityState(visibility) {
    const status = String(visibility?.status || 'unknown').toLowerCase();
    if (['blind', 'missing', 'failed'].includes(status)) {
        return { tone: 'status-danger', value: status.toUpperCase() };
    }
    if (['partial', 'degraded'].includes(status)) {
        return { tone: 'status-caution', value: status.toUpperCase() };
    }
    if (['full', 'good', 'healthy', 'clear'].includes(status)) {
        return { tone: 'status-safe', value: status.toUpperCase() };
    }
    return { tone: status === 'unknown' ? 'status-neutral' : 'status-neutral', value: status.toUpperCase() };
}

function summarizeCapacityState(capacity) {
    const status = String(capacity?.state || 'unknown').toLowerCase();
    const util = capacity?.utilization_pct;
    if (['critical', 'constrained', 'exhausted', 'saturated'].includes(status)) {
        return { tone: 'status-danger', value: util != null && util !== '' ? `${status.toUpperCase()} ${util}%` : status.toUpperCase() };
    }
    if (['elevated', 'warning', 'warn', 'busy'].includes(status)) {
        return { tone: 'status-caution', value: util != null && util !== '' ? `${status.toUpperCase()} ${util}%` : status.toUpperCase() };
    }
    if (['normal', 'clear', 'stable'].includes(status)) {
        return { tone: 'status-safe', value: util != null && util !== '' ? `${util}%` : status.toUpperCase() };
    }
    return { tone: 'status-neutral', value: util != null && util !== '' ? `${util}%` : status.toUpperCase() };
}

function splitHeadlineForTone(tone) {
    if (tone === 'status-danger') return tr('dashboard.glance_attention', 'ATTENTION');
    if (tone === 'status-caution') return tr('dashboard.glance_watch', 'WATCH');
    if (tone === 'status-safe') return tr('dashboard.glance_normal', 'NORMAL');
    return tr('dashboard.glance_unsettled', 'UNSETTLED');
}

function updateCommandGlance(summary, health, failures = []) {
    const threat = summarizeThreatState(summary);
    const path = summarizePathState(summary);
    const services = summarizeServiceState(summary.service_health_summary || {});
    const clients = summarizeClientState(summary);
    const telemetry = summarizeTelemetryState(summary, health, failures);
    const ai = summarizeAiState(summary, health);
    const clientBaselineTone = clients.tone === 'status-neutral' ? 'status-safe' : clients.tone;
    const tones = [threat.tone, path.tone, services.tone, clientBaselineTone, telemetry.tone, ai.tone];
    const overallTone = strongestTone(...tones);
    const hero = document.getElementById('commandGlanceHero');
    if (hero) {
        hero.className = `command-glance-hero ${overallTone}`;
    }
    updateElement('commandGlanceHeadline', splitHeadlineForTone(overallTone));
    updateElement(
        'commandGlanceSummary',
        overallTone === 'status-danger'
            ? tr('dashboard.visual_summary_attention', 'One or more priority areas need immediate checking.')
            : (overallTone === 'status-caution'
                ? tr('dashboard.visual_summary_watch', 'The baseline is mostly intact, but one or more areas should stay under watch.')
                : (overallTone === 'status-neutral'
                    ? tr('dashboard.visual_summary_unsettled', 'No immediate danger is visible, but identification or context is still unsettled.')
                    : tr('dashboard.visual_summary_normal', 'Threat, path, services, clients, telemetry, and AI all look normal.')))
    );
    setHeatTone('commandHeatThreat', threat.tone, threat.value);
    setHeatTone('commandHeatPath', path.tone, path.value);
    setHeatTone('commandHeatServices', services.tone, services.value);
    setHeatTone('commandHeatClients', clients.tone, clients.value);
    setHeatTone('commandHeatTelemetry', telemetry.tone, telemetry.value);
    setHeatTone('commandHeatAi', ai.tone, ai.value);
}

function updateCommandStrip(summary, health, failures = []) {
    const strip = summary.command_strip || {};
    const idleFlags = health.idle_flags || {};
    updateElement('stripMode', String(strip.current_mode || '--').toUpperCase());
    updateElement('stripRisk', summary.risk?.user_state || '--');
    updateElement('stripUplink', strip.current_uplink || '--');
    updateElement('stripInternet', strip.internet_reachability || '--');
    updateElement('stripCritical', String(strip.direct_critical_count ?? 0));
    updateElement('stripDeferred', String(strip.deferred_count ?? 0));
    updateElement('stripQueue', `${health.queue?.depth ?? 0} / ${health.queue?.capacity ?? 0}`);
    updateElement('stripStale', strip.stale_warning ? 'YES' : 'NO');
    const baseNote = strip.stale_warning
        ? (CURRENT_LANG === 'ja'
            ? 'ダッシュボード入力の一部が stale です。操作前に control-plane の鮮度を確認してください。'
            : 'One or more dashboard inputs are stale. Verify control-plane freshness before acting.')
        : (CURRENT_LANG === 'ja'
            ? 'ダッシュボード入力は live で、現在の control-plane 状態と同期しています。'
            : 'Dashboard inputs are live and in sync with current control-plane state.');
    updateElement('commandStripNote', failures.length > 0 ? `${baseNote} Degraded APIs: ${failures.join(' | ')}` : baseNote);
    updateElement('freshnessSnapshot', formatFreshness(health.ages_sec?.snapshot, health.timestamps?.snapshot_at, health.stale_flags?.snapshot));
    updateElement('freshnessAiMetrics', formatFreshness(health.ages_sec?.ai_metrics, health.timestamps?.ai_metrics_at, health.stale_flags?.ai_metrics));
    updateElement('freshnessAiActivity', formatFreshness(health.ages_sec?.ai_activity, health.timestamps?.last_ai_activity_at, health.stale_flags?.ai_activity, idleFlags.ai_activity));
    updateElement('freshnessRunbook', formatFreshness(health.ages_sec?.runbook_events, health.timestamps?.last_runbook_event_at, health.stale_flags?.runbook_events, idleFlags.runbook_events));
    updateCommandGlance(summary, health, failures);
    setPillTone('stripRisk', toneForRisk(summary.risk?.user_state, summary.risk?.suspicion).replace('status-', ''));
    setPillTone('stripInternet', summarizePathState(summary).tone.replace('status-', ''));
    setPillTone('stripCritical', Number(strip.direct_critical_count || 0) > 0 ? 'danger' : 'safe');
    setPillTone('stripDeferred', Number(strip.deferred_count || 0) > 0 ? 'caution' : 'safe');
    const queueDepth = Number(health.queue?.depth || 0);
    const queueCapacity = Number(health.queue?.capacity || 0);
    const queueRatio = queueCapacity > 0 ? queueDepth / queueCapacity : 0;
    setPillTone('stripQueue', queueRatio >= 0.8 ? 'danger' : (queueRatio >= 0.4 ? 'caution' : 'safe'));
    setPillTone('stripStale', strip.stale_warning ? 'danger' : 'safe');
    setPillTone('freshnessSnapshot', health.stale_flags?.snapshot ? 'danger' : 'safe');
    setPillTone('freshnessAiMetrics', health.stale_flags?.ai_metrics ? 'danger' : 'safe');
    setPillTone('freshnessAiActivity', health.stale_flags?.ai_activity ? 'danger' : (idleFlags.ai_activity ? 'caution' : 'safe'));
    setPillTone('freshnessRunbook', health.stale_flags?.runbook_events ? 'danger' : (idleFlags.runbook_events ? 'caution' : 'safe'));
}

function updateSituationBoard(summary, state, health, mattermost) {
    const risk = summary.risk || {};
    const postureTone = toneForRisk(risk.user_state, risk.suspicion);
    const postureCard = document.getElementById('postureCard');
    if (postureCard) postureCard.className = `situation-card posture-card ${postureTone}`;

    updateElement('postureState', `${risk.user_state || '--'} / ${risk.state_name || '--'}`);
    updateElement('riskScore', String(risk.suspicion ?? 0));
    updateElement('postureRecommendation', summary.current_recommendation || '-');
    updateElement('postureCurrentRecommendation', summary.current_recommendation || '-');
    updateElement('postureConfidence', summary.situation_board?.threat_posture?.confidence ? `${summary.situation_board.threat_posture.confidence}` : '-');
    updateElement('postureLastAlert', summary.situation_board?.threat_posture?.last_alert || '-');
    updateElement('postureLlmStatus', summary.situation_board?.threat_posture?.llm_status || '-');

    updateElement('networkSsid', `${summary.uplink?.ssid || '-'} (${summary.uplink?.up_ip || '-'})`);
    updateElement('networkGateway', summary.gateway || '-');
    updateElement('networkInternet', summary.uplink?.internet_check || '-');
    updateElement('networkPortal', summary.situation_board?.network_health?.captive_portal || '-');
    updateElement('networkScope', summary.situation_board?.network_health?.monitor_scope?.label || '-');
    updateElement('networkDnsMismatch', String(summary.situation_board?.network_health?.dns_mismatch ?? 0));
    updateElement('networkSignals', joinList(summary.situation_board?.network_health?.signals));

    updateServiceChip('svcSuricata', summary.service_health_summary?.suricata || '--');
    updateServiceChip('svcOpencanary', summary.service_health_summary?.opencanary || '--');
    updateServiceChip('svcNtfy', summary.service_health_summary?.ntfy || '--');
    updateServiceChip('svcAiAgent', summary.service_health_summary?.ai_agent || '--');
    updateServiceChip('svcWeb', summary.service_health_summary?.web || '--');
    updateServiceChip('svcMattermost', mattermost.reachable ? 'ON' : 'OFF');
}

function updateSplitBoard(summary, actions) {
    const soc = summary.soc_focus || {};
    const noc = summary.noc_focus || {};
    const correlation = soc.correlation || {};
    const path = noc.path_health || {};
    const services = noc.service_health || {};
    const serviceAssurance = noc.service_assurance || {};
    const resolutionHealth = noc.resolution_health || {};
    const blastRadius = noc.blast_radius || {};
    const configDrift = noc.config_drift || {};
    const incidentSummary = noc.incident_summary || {};
    const capacity = noc.capacity || {};
    const clientInventory = noc.client_inventory || {};
    const clientImpact = noc.client_impact || {};
    const attackType = soc.attack_type || tr('dashboard.no_attack_type', 'No current attack type');
    const visibility = soc.visibility || {};
    const suppression = soc.suppression || {};
    const criticality = soc.criticality || {};
    const exposure = soc.exposure_change || {};
    const sequence = soc.behavior_sequence || {};
    const triage = soc.triage_priority || {};
    const incidentCampaign = soc.incident_campaign || {};
    const triageNow = Array.isArray(triage.now) ? triage.now : [];
    const triageWatch = Array.isArray(triage.watch) ? triage.watch : [];
    const triageBacklog = Array.isArray(triage.backlog) ? triage.backlog : [];
    const socThreat = summarizeThreatState(summary);
    const socCorrelation = summarizeCorrelationState(correlation);
    const socTriage = summarizeTriageState(triage);
    const socVisibility = summarizeVisibilityState(visibility);
    const nocPath = summarizePathState(summary);
    const nocServices = summarizeServiceState(services);
    const nocCapacity = summarizeCapacityState(capacity);
    const nocClients = summarizeClientState(summary);
    const socTone = strongestTone(socThreat.tone, socCorrelation.tone, socTriage.tone, socVisibility.tone);
    const nocTone = strongestTone(nocPath.tone, nocServices.tone, nocCapacity.tone, nocClients.tone);

    setGlanceCard('socGlanceCard', 'socGlanceState', socTone, splitHeadlineForTone(socTone));
    setGlanceCell('socGlanceThreat', socThreat.tone, socThreat.value);
    setGlanceCell('socGlanceCorrelation', socCorrelation.tone, socCorrelation.value);
    setGlanceCell('socGlanceTriage', socTriage.tone, socTriage.value);
    setGlanceCell('socGlanceVisibility', socVisibility.tone, socVisibility.value);

    setGlanceCard('nocGlanceCard', 'nocGlanceState', nocTone, splitHeadlineForTone(nocTone));
    setGlanceCell('nocGlancePath', nocPath.tone, nocPath.value);
    setGlanceCell('nocGlanceServices', nocServices.tone, nocServices.value);
    setGlanceCell('nocGlanceCapacity', nocCapacity.tone, nocCapacity.value);
    setGlanceCell('nocGlanceClients', nocClients.tone, nocClients.value);
    updateToggleSummary(
        'splitBoardDetailsToggle',
        tr('dashboard.split_board_details_summary', 'SOC {soc} | NOC {noc}', {
            soc: splitHeadlineForTone(socTone),
            noc: splitHeadlineForTone(nocTone),
        }),
        strongestTone(socTone, nocTone),
    );

    updateElement('socThreatLevel', String(soc.threat_level || 'quiet').toUpperCase());
    updateElement(
        'socThreatSummary',
        tr(
            'dashboard.soc_threat_summary_line',
            '{attack_type} | src={source} | dst={destination} | triage={triage}',
            {
                attack_type: attackType,
                source: soc.top_source || '-',
                destination: soc.top_destination || '-',
                triage: String(triage.status || 'idle'),
            },
        ),
    );
    updateElement('socAttackType', attackType);
    updateElement('socTopSource', soc.top_source || '-');
    updateElement('socTopDestination', soc.top_destination || '-');
    updateElement('socTopSignature', `${soc.top_sid || '-'} / ${soc.top_severity || '-'}`);
    updateElement('socAlertCounts', `${soc.critical_count || 0} / ${soc.warning_count || 0}`);
    updateElement('socConfidenceSignal', soc.confidence_signal || '-');
    updateElement('socCorrelationStatus', correlation.status || '-');
    renderList('socCorrelationReasons', correlation.reasons || [], (item) => item);
    renderList(
        'socKnowledgeList',
        [
            ...(soc.attack_candidates || []),
            ...((soc.ti_matches || []).map((item) => typeof item === 'string' ? item : `${item.indicator_type || 'ti'}:${item.value || '-'}`)),
            ...((soc.sigma_hits || []).map((item) => typeof item === 'string' ? item : `sigma:${item.rule_id || '-'}`)),
            ...((soc.yara_hits || []).map((item) => typeof item === 'string' ? item : `yara:${item.rule_id || '-'}`)),
        ],
        (item) => item,
    );
    updateElement('socVisibilityStatus', String(visibility.status || 'unknown').toUpperCase());
    updateElement(
        'socSuppressionStatus',
        `${String(suppression.status || 'normal').toUpperCase()} / ${Number(suppression.suppressed_count || 0)}`,
    );
    updateElement(
        'socIncidentStatus',
        `${String(incidentCampaign.status || 'none').toUpperCase()} / ${Number(incidentCampaign.incident_count || 0)}`,
    );
    updateElement(
        'socCriticalityStatus',
        `${String(criticality.status || 'unknown').toUpperCase()} / ${Number(criticality.critical_target_count || 0)}`,
    );
    updateElement('socExposureStatus', String(exposure.status || 'stable').toUpperCase());
    updateElement('socSequenceStatus', String(sequence.status || 'none').toUpperCase());
    updateElement('socTriageStatus', String(triage.status || 'idle').toUpperCase());
    updateElement('socTriageCounts', `${triageNow.length} / ${triageWatch.length} / ${triageBacklog.length}`);
    renderList(
        'socTriageQueueList',
        [
            ...triageNow.slice(0, 4).map((item) =>
                `${tr('dashboard.triage_now_prefix', 'now')}: ${item.id || '-'} (${item.score || 0})`
            ),
            ...triageWatch.slice(0, 3).map((item) =>
                `${tr('dashboard.triage_watch_prefix', 'watch')}: ${item.id || '-'} (${item.score || 0})`
            ),
            ...triageBacklog.slice(0, 2).map((item) =>
                `${tr('dashboard.triage_backlog_prefix', 'backlog')}: ${item.id || '-'} (${item.score || 0})`
            ),
            ...((Array.isArray(triage.top_priority_ids) ? triage.top_priority_ids : []).slice(0, 3).map((id) =>
                `${tr('dashboard.priority_id_prefix', 'priority-id')}: ${id}`
            )),
        ],
        (item) => item,
    );

    updateElement('nocPathStatus', String(incidentSummary.probable_cause || path.status || 'unknown').toUpperCase());
    updateElement('nocIncidentCause', incidentSummary.probable_cause || '-');
    updateElement('nocIncidentConfidence', incidentSummary.confidence ? String(incidentSummary.confidence) : '-');
    updateElement('nocPathUplink', path.uplink || '-');
    updateElement('nocPathGateway', path.gateway || '-');
    updateElement('nocPathInternet', path.internet_check || '-');
    updateElement('nocBlastSegments', (blastRadius.affected_segments || []).join(', ') || '-');
    updateElement('nocBlastClients', String(blastRadius.affected_client_count ?? 0));
    renderList('nocPathSignals', path.signals || [], (item) => item);
    renderList(
        'nocServiceList',
        Object.entries(services).map(([name, value]) => `${name}: ${value}`),
        (item) => item,
    );
    updateElement('nocServiceAssurance', String(serviceAssurance.status || 'unknown').toUpperCase());
    updateElement('nocResolutionHealth', String(resolutionHealth.status || 'unknown').toUpperCase());
    updateElement('nocBlastTargets', (blastRadius.related_service_targets || []).join(', ') || '-');
    updateElement('nocConfigDrift', `${String(configDrift.status || 'unknown').toUpperCase()} / ${String(configDrift.baseline_state || 'unknown').toUpperCase()}`);
    const utilization = capacity.utilization_pct == null || capacity.utilization_pct === ''
        ? '-'
        : `${capacity.utilization_pct}%`;
    updateElement('nocCapacityState', String(capacity.state || 'unknown').toUpperCase());
    updateElement('nocCapacityUtilization', utilization);
    updateElement('nocCapacityMode', capacity.mode || '-');
    updateElement('nocCapacityTopTalker', capacity.top_talker || '-');
    updateElement('nocClientCurrent', String(clientInventory.current_client_count ?? 0));
    updateElement('nocClientUnknown', String(clientInventory.unknown_client_count ?? 0));
    updateElement('nocClientUnauthorized', String(clientInventory.unauthorized_client_count ?? 0));
    updateElement('nocClientMismatch', String(clientInventory.inventory_mismatch_count ?? 0));

    renderList(
        'rejectedStrongerActionsList',
        actions.rejected_stronger_actions || [],
        (item) => `${item.action || '-'}: ${item.reason || '-'}`,
    );
}

function updateActionBoard(actions, state) {
    const whyNowItems = actions.why_now || [];
    const nextItems = actions.do_next || actions.current_operator_actions || [];
    const doNotDoItems = actions.do_not_do || [];
    const escalateItems = actions.escalate_if || [];
    renderList('whyNowList', whyNowItems, (item) => item);
    renderList('nextActionsList', nextItems, (item) => item);
    renderList('doNotDoList', doNotDoItems, (item) => item);
    renderList('escalateIfList', escalateItems, (item) => item);
    updateElement('userGuidanceText', actions.current_user_guidance || '-');

    const runbook = actions.suggested_runbook || {};
    const primaryAction = (actions.do_next || actions.current_operator_actions || [])[0] || actions.current_user_guidance || tr('dashboard.no_immediate_action', 'No immediate action synthesized.');
    const socPriority = actions.soc_priority || {};
    const triageSummary = socPriority.status
        ? `SOC triage=${socPriority.status} now=${(socPriority.now || []).length} watch=${(socPriority.watch || []).length}`
        : '';
    const primarySummary = (actions.why_now || [])[0]
        || (triageSummary || tr('dashboard.waiting_stronger_evidence', 'The dashboard is waiting for stronger causal evidence.'));
    updateElement('priorityActionTitle', primaryAction);
    updateElement('priorityActionSummary', primarySummary);
    updateElement('runbookTitle', runbook.title || '-');
    updateElement('runbookId', runbook.id || '-');
    updateElement('runbookEffect', runbook.effect || '-');
    const approvalLabel = actions.approval_required ? tr('dashboard.review_required', 'Required') : tr('dashboard.review_not_required', 'Not required');
    updateElement('runbookApproval', approvalLabel);
    const runbookSteps = runbook.steps || [];
    renderList('runbookSteps', runbookSteps, (item) => item);
    const decisionPath = actions.decision_path || {};
    const trustCapsule = actions.decision_trust_capsule || {};
    updateElement(
        'trustCapsuleSummary',
        currentAudience === 'temporary'
            ? (trustCapsule.beginner_summary || tr('dashboard.trust_summary_waiting', 'Waiting for trust synthesis.'))
            : (trustCapsule.professional_summary || trustCapsule.beginner_summary || tr('dashboard.trust_summary_waiting', 'Waiting for trust synthesis.')),
    );
    updateElement('trustCapsuleConfidence', trustCapsule.confidence_label || '-');
    updateElement('trustCapsuleConfidenceSource', trustCapsule.confidence_source || '-');
    updateElement('trustCapsuleEvidence', String(trustCapsule.evidence_count ?? 0));
    renderList(
        'trustCapsuleWhyList',
        Array.isArray(trustCapsule.why_this) && trustCapsule.why_this.length
            ? trustCapsule.why_this
            : [tr('dashboard.waiting_causal_summary_ui', 'Waiting for causal summary.')],
        (item) => item,
    );
    renderList(
        'trustCapsuleUnknownList',
        Array.isArray(trustCapsule.unknowns) && trustCapsule.unknowns.length
            ? trustCapsule.unknowns
            : [tr('dashboard.trust_unknown_none', 'No material unknowns right now.')],
        (item) => item,
    );
    const trustCapsuleEl = document.getElementById('decisionTrustCapsule');
    if (trustCapsuleEl) {
        trustCapsuleEl.classList.remove('trust-tone-safe', 'trust-tone-neutral', 'trust-tone-caution', 'trust-tone-danger');
        const trustTone = String(trustCapsule.tone || 'neutral').toLowerCase();
        const confidenceEl = document.getElementById('trustCapsuleConfidence');
        if (confidenceEl) {
            confidenceEl.className = `assistant-status ${
                trustTone === 'safe'
                    ? 'status-safe'
                    : (trustTone === 'danger'
                        ? 'status-danger'
                        : (trustTone === 'caution' ? 'status-caution' : 'status-neutral'))
            }`;
        }
        trustCapsuleEl.classList.add(
            trustTone === 'safe'
                ? 'trust-tone-safe'
                : (trustTone === 'danger'
                    ? 'trust-tone-danger'
                    : (trustTone === 'caution' ? 'trust-tone-caution' : 'trust-tone-neutral')),
        );
    }
    updateElement('decisionFirstPass', `${decisionPath.first_pass_engine || '-'} | ${decisionPath.first_pass_role || '-'}`);
    updateElement('decisionSecondPass', `${decisionPath.second_pass_engine || '-'} | ${decisionPath.second_pass_role || '-'}`);
    const secondPassBits = [decisionPath.second_pass_status || '-'];
    if (decisionPath.second_pass_evidence_count !== undefined) secondPassBits.push(`evidence=${decisionPath.second_pass_evidence_count}`);
    if (decisionPath.second_pass_flow_support_count !== undefined) secondPassBits.push(`flow=${decisionPath.second_pass_flow_support_count}`);
    if (decisionPath.soc_status) secondPassBits.push(`soc=${decisionPath.soc_status}`);
    updateElement('decisionSecondPassStatus', secondPassBits.join(' | '));
    updateElement('decisionAiRole', decisionPath.ai_role || '-');

    const mode = latestState.mode || {};
    updateElement('modeLastChange', formatHumanDateTime(mode.last_change));
    updateElement('modeRequestedBy', mode.requested_by || '-');

    const portalBtn = document.getElementById('portalAssistBtn');
    if (portalBtn) {
        const portalViewer = latestState.portal_viewer || {};
        portalBtn.disabled = !portalViewer.url;
        portalBtn.textContent = portalViewer.ready ? 'Portal Assist' : tr('dashboard.portal_assist_prep', 'Portal Assist (prep)');
    }
    updateToggleSummary(
        'actionBoardPrimaryDetailsToggle',
        tr('dashboard.action_board_primary_details_summary', 'Why {why} | Next {next}', { why: whyNowItems.length, next: nextItems.length }),
        nextItems.length > 0 ? 'status-caution' : (whyNowItems.length > 0 ? 'status-neutral' : 'status-safe'),
    );
    updateGuidanceToggleSummary(doNotDoItems.length);
    updateToggleSummary(
        'actionBoardRunbookDetailsToggle',
        tr('dashboard.action_board_runbook_details_summary', 'Steps {steps} | Approval {approval}', {
            steps: runbookSteps.length,
            approval: approvalLabel,
        }),
        actions.approval_required ? 'status-caution' : (runbookSteps.length > 0 ? 'status-neutral' : 'status-safe'),
    );
    updateToggleSummary(
        'actionBoardDecisionDetailsToggle',
        tr('dashboard.action_board_decision_details_summary', '2nd pass {status}', {
            status: decisionPath.second_pass_status || '-',
        }),
        ['failed', 'error'].includes(String(decisionPath.second_pass_status || '').toLowerCase())
            ? 'status-danger'
            : (['pending', 'running'].includes(String(decisionPath.second_pass_status || '').toLowerCase()) ? 'status-caution' : 'status-safe'),
    );
    updateToggleSummary(
        'actionBoardRejectedDetailsToggle',
        tr('dashboard.action_board_rejected_details_summary', 'Rejected {count}', {
            count: Array.isArray(actions.rejected_stronger_actions) ? actions.rejected_stronger_actions.length : 0,
        }),
        (Array.isArray(actions.rejected_stronger_actions) ? actions.rejected_stronger_actions.length : 0) > 0 ? 'status-neutral' : 'status-safe',
    );
    updateToggleSummary(
        'actionBoardControlDetailsToggle',
        tr('dashboard.action_board_control_details_summary', 'Mode {mode}', {
            mode: String(mode.current_mode || 'shield').toUpperCase(),
        }),
        String(mode.current_mode || 'shield').toLowerCase() === 'shield'
            ? 'status-safe'
            : (String(mode.current_mode || '').toLowerCase() === 'scapegoat' ? 'status-caution' : 'status-neutral'),
    );
}

function updateProgressChecklist(progress) {
    const payload = progress && typeof progress === 'object' ? progress : {};
    const items = Array.isArray(payload.items) ? payload.items : [];
    const nextItem = payload.next_item && typeof payload.next_item === 'object' ? payload.next_item : null;
    updateElement(
        'progressChecklistSummary',
        tr('dashboard.progress_checklist_summary', 'Done {done}/{total} | Next {next}', {
            done: Number(payload.done_count || 0),
            total: Number(payload.total_count || 0),
            next: nextItem?.label || tr('dashboard.progress_next_none', 'All clear'),
        }),
    );
    const list = document.getElementById('progressChecklistList');
    if (list) {
        if (!items.length) {
            list.innerHTML = `<div>${escapeHtml(tr('dashboard.progress_checklist_waiting', 'Waiting for progress state.'))}</div>`;
        } else {
            list.innerHTML = items.map((item) => `
                <div class="progress-checklist-item ${item.done ? 'done' : ''}">
                    <input type="checkbox" class="progress-checklist-checkbox" data-item-id="${escapeAttribute(item.id || '')}" ${item.done ? 'checked' : ''}>
                    <label>
                        <strong>${escapeHtml(item.label || '-')}</strong>
                        <span>${escapeHtml(item.detail || '-')}</span>
                    </label>
                </div>
            `).join('');
        }
    }
    const blockedReason = document.getElementById('progressBlockedReason');
    if (blockedReason && document.activeElement !== blockedReason) {
        blockedReason.value = payload.blocked_reason || '';
    }
    updateElement('progressBlockedPrompt', payload.blocked_prompt || tr('dashboard.progress_blocked_prompt_default', 'Ask what changed first, when it started, and whether this is one device or many.'));
}

function updateHandoffPack(handoff) {
    const payload = handoff && typeof handoff === 'object' ? handoff : {};
    const summary = payload.current_posture
        ? tr('dashboard.handoff_summary_ready', 'Ready | {posture}', { posture: payload.current_posture })
        : tr('dashboard.handoff_waiting', 'Preparing handoff pack.');
    updateElement('handoffPackSummary', summary);
    updateElement('handoffPreview', payload.brief_text || tr('dashboard.handoff_waiting', 'Preparing handoff pack.'));
    const opsCommBtn = document.getElementById('handoffOpsCommBtn');
    if (opsCommBtn) opsCommBtn.href = payload.ops_comm_url || '/ops-comm';
    const mattermostBtn = document.getElementById('handoffMattermostBtn');
    if (mattermostBtn) mattermostBtn.disabled = !payload.mattermost_available;
    updateToggleSummary(
        'handoffDetailsToggle',
        tr('dashboard.handoff_details_summary', 'Clients {clients} | Done {done} | stale {stale}', {
            clients: Array.isArray(payload.affected_clients) ? payload.affected_clients.length : 0,
            done: Array.isArray(payload.actions_done) ? payload.actions_done.length : 0,
            stale: payload.stale_flags?.snapshot || payload.stale_flags?.ai_metrics ? 'yes' : 'no',
        }),
        payload.stale_flags?.snapshot || payload.stale_flags?.ai_metrics
            ? 'status-caution'
            : ((Array.isArray(payload.affected_clients) && payload.affected_clients.length > 0) ? 'status-neutral' : 'status-safe'),
    );
}

function onboardingSteps() {
    return [
        {
            targetId: 'commandGlanceHero',
            title: tr('dashboard.beginner_onboarding_step1_title', 'Start with Visual Baseline'),
            body: tr('dashboard.beginner_onboarding_step1_body', 'If this block says NORMAL, the overall baseline is holding. If it says WATCH or ATTENTION, begin from the highlighted heat cell.'),
        },
        {
            targetId: 'splitGlanceGrid',
            title: tr('dashboard.beginner_onboarding_step2_title', 'Then compare SOC and NOC'),
            body: tr('dashboard.beginner_onboarding_step2_body', 'SOC tells you whether the security side moved first. NOC tells you whether path, services, or client-side health moved first.'),
        },
        {
            targetId: 'clientIdentityCurrentTile',
            title: tr('dashboard.beginner_onboarding_step3_title', 'Finish with affected clients'),
            body: tr('dashboard.beginner_onboarding_step3_body', 'Client Identity tells you who is affected now, whether the client is trusted, and whether the issue is wired or wireless.'),
        },
    ];
}

function syncOnboardingBanner() {
    const banner = document.getElementById('beginnerOnboarding');
    if (!banner) return;
    const dismissed = localStorage.getItem(ONBOARDING_DISMISSED_KEY) === '1';
    const visible = !dismissed;
    banner.hidden = !visible;
    document.querySelectorAll('.onboarding-highlight').forEach((el) => el.classList.remove('onboarding-highlight'));
    if (!visible) return;
    const steps = onboardingSteps();
    const step = steps[onboardingStepIndex % steps.length];
    updateElement('onboardingTitle', step.title);
    updateElement('onboardingBody', step.body);
    updateElement('onboardingStepLabel', tr('dashboard.beginner_onboarding_step', 'Step {current} / {total}', {
        current: (onboardingStepIndex % steps.length) + 1,
        total: steps.length,
    }));
    const target = document.getElementById(step.targetId);
    if (target) target.classList.add('onboarding-highlight');
}

function updateEvidenceBoard(evidence, health, trends) {
    const currentTriggers = Array.isArray(evidence.current_triggers) && evidence.current_triggers.length
        ? evidence.current_triggers
        : [{
            ts_iso: latestState.timestamps?.snapshot_at || '-',
            kind: 'state',
            title: tr('dashboard.no_active_trigger_title', 'No active trigger'),
            detail: tr('dashboard.no_active_trigger_detail', 'No current trigger is keeping the dashboard outside normal monitoring.'),
        }];
    renderTimeline('currentTriggersTimeline', currentTriggers, (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    renderTimeline('decisionChangesTimeline', evidence.decision_changes || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    renderTimeline('operatorInteractionsTimeline', evidence.operator_interactions || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    renderTimeline('backgroundHistoryTimeline', evidence.background_history || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));
    renderTimeline('triageAuditTimeline', evidence.triage_audit || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));
    const syntheticTopology = Array.isArray(evidence.synthetic_story?.topology) ? evidence.synthetic_story.topology : [];
    renderTimeline('topoliteSyntheticTopology', syntheticTopology, (item) => ({
        metaLeft: evidence.data_source === 'synthetic' ? 'synthetic' : '-',
        metaRight: item.kind || '-',
        title: item.label || item.id || '-',
        detail: `state=${item.state || '-'}`,
    }));
    const alertQueues = evidence.alert_queues || {};
    const queueItems = [];
    const nowCount = Number(alertQueues.now?.count || 0);
    const watchCount = Number(alertQueues.watch?.count || 0);
    const backlogCount = Number(alertQueues.backlog?.count || 0);
    queueItems.push({
        ts_iso: '-',
        kind: 'queue',
        title: tr('dashboard.alert_queue_counts', 'now={now} watch={watch} backlog={backlog}', {
            now: nowCount,
            watch: watchCount,
            backlog: backlogCount,
        }),
        detail: tr('dashboard.alert_queue_counts_detail', 'Alert pressure split by deterministic risk bands.'),
    });
    const topNow = Array.isArray(alertQueues.now?.items) ? alertQueues.now.items.slice(0, 2) : [];
    const topEsc = Array.isArray(alertQueues.escalation_candidates) ? alertQueues.escalation_candidates.slice(0, 2) : [];
    topNow.forEach((item) => {
        queueItems.push({
            ts_iso: item.ts_iso || '-',
            kind: 'now',
            title: `${item.attack_type || '-'} (${item.risk_score || 0})`,
            detail: `src=${item.src_ip || '-'} dst=${item.dst_ip || '-'} sid=${item.sid || 0}`,
        });
    });
    topEsc.forEach((item) => {
        queueItems.push({
            ts_iso: item.ts_iso || '-',
            kind: 'escalate',
            title: tr('dashboard.alert_queue_escalation', 'Escalation candidate'),
            detail: `${item.attack_type || '-'} | ${item.recommendation || '-'}`,
        });
    });
    renderTimeline('alertQueuesTimeline', queueItems, (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    const trendPoints = Array.isArray(trends?.points) ? trends.points : [];
    const trendSummary = trends?.summary || {};
    const trendRows = [];
    trendRows.push({
        ts_iso: '-',
        kind: 'summary',
        title: tr('dashboard.trend_samples', 'samples={samples} window={window}s', {
            samples: Number(trendSummary.samples || 0),
            window: Number(trendSummary.window_sec || 0),
        }),
        detail: tr('dashboard.trend_fallback_avg', 'fallback avg={avg}', {
            avg: Number(trendSummary.llm_fallback_rate?.avg || 0).toFixed(3),
        }),
    });
    const latestTrend = trendPoints.length ? trendPoints[trendPoints.length - 1] : null;
    if (latestTrend) {
        trendRows.push({
            ts_iso: latestTrend.ts_iso || '-',
            kind: 'latest',
            title: tr('dashboard.trend_latest_queue', 'queue={depth}/{capacity}', {
                depth: Number(latestTrend.queue_depth || 0),
                capacity: Number(latestTrend.queue_capacity || 0),
            }),
            detail: `latency_ema=${Number(latestTrend.llm_latency_ms_ema || 0).toFixed(1)}ms stale(snapshot=${latestTrend.stale_snapshot ? 'yes' : 'no'}, ai=${latestTrend.stale_ai_metrics ? 'yes' : 'no'})`,
        });
    }
    renderTimeline('dashboardTrendsTimeline', trendRows, (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    const stale = health.stale_flags || {};
    const idle = health.idle_flags || {};
    updateElement('healthSummaryLine', tr('dashboard.health_summary_line', 'Queue {depth}/{capacity} | fallback {fallback} | stale snapshot={snapshot} ai={ai} | idle ai={ai_idle} runbook={runbook_idle}', {
        depth: health.queue?.depth ?? 0,
        capacity: health.queue?.capacity ?? 0,
        fallback: health.llm?.fallback_rate ?? 0,
        snapshot: stale.snapshot ? 'yes' : 'no',
        ai: stale.ai_metrics ? 'yes' : 'no',
        ai_idle: idle.ai_activity ? 'yes' : 'no',
        runbook_idle: idle.runbook_events ? 'yes' : 'no',
    }));
    updateToggleSummary(
        'evidenceTimelineDetailsToggle',
        tr('dashboard.evidence_timeline_details_summary', 'Triggers {triggers} | Changes {changes} | Audit {audit}', {
            triggers: currentTriggers.length,
            changes: Array.isArray(evidence.decision_changes) ? evidence.decision_changes.length : 0,
            audit: Array.isArray(evidence.triage_audit) ? evidence.triage_audit.length : 0,
        }),
        stale.snapshot
            ? 'status-danger'
            : ((Array.isArray(evidence.decision_changes) ? evidence.decision_changes.length : 0) > 0 || currentTriggers.length > 1
                ? 'status-caution'
                : 'status-safe'),
    );
}

function updateTopoliteSingleScreen(summary, evidence, actions) {
    const threat = String(summary?.soc_focus?.threat_level || 'unknown').toUpperCase();
    const pathState = String(summary?.noc_focus?.path_health?.status || 'unknown').toUpperCase();
    const actionName = String(actions?.current_action?.action || summary?.current_recommendation || 'observe').toUpperCase();
    updateElement('topoliteThreatBadge', `THREAT:${threat}`);
    updateElement('topolitePathBadge', `PATH:${pathState}`);
    updateElement('topoliteActionBadge', `ACTION:${actionName}`);

    const overview = [
        `risk=${summary?.risk?.user_state || '-'} / suspicion=${summary?.risk?.suspicion ?? 0}`,
        `uplink=${summary?.uplink?.up_if || '-'} gateway=${summary?.gateway || '-'}`,
        `clients=${summary?.noc_focus?.client_inventory?.current ?? 0} affected=${summary?.noc_focus?.blast_radius?.affected_client_count ?? 0}`,
    ];
    renderList('topoliteOverviewList', overview, (item) => item);

    const topology = Array.isArray(evidence?.synthetic_story?.topology)
        ? evidence.synthetic_story.topology
        : ((summary?.noc_focus?.blast_radius?.affected_segments || []).map((seg) => ({ kind: 'segment', label: String(seg), state: 'watch' })));
    renderTimeline('topoliteTopologyTimeline', topology, (item) => ({
        metaLeft: item.kind || 'node',
        metaRight: item.state || '-',
        title: item.label || item.id || '-',
        detail: item.state ? `state=${item.state}` : '-',
    }));

    const timelineItems = Array.isArray(evidence?.current_triggers) ? evidence.current_triggers.slice(0, 6) : [];
    renderTimeline('topoliteIncidentTimeline', timelineItems, (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }));

    updateElement(
        'topoliteSingleScreenSummary',
        `Threat ${threat} | Path ${pathState} | Action ${actionName} | Source ${String(evidence?.data_source || 'live').toUpperCase()}`,
    );
}

function updateAssistant(actions, mattermost, capabilities) {
    const mio = actions.mio || {};
    const surfaceMessages = mio.surface_messages && typeof mio.surface_messages === 'object' ? mio.surface_messages : {};
    const dashboardSurface = surfaceMessages.dashboard || mio.surface_message || mio.answer || actions.current_recommendation || '-';
    updateElement('mioCurrentAnswer', dashboardSurface);
    updateElement('mioRecommendation', actions.current_recommendation || '-');
    const askedAt = mio.asked_at ? formatHumanDateTime(mio.asked_at) : '';
    const lastAsk = mio.question
        ? `${mio.question}${askedAt ? ` | ${askedAt}` : ''}${mio.source ? ` | ${mio.source}` : ''}`
        : tr('dashboard.no_manual_query', 'No manual query executed yet.');
    updateElement('mioLastAsk', lastAsk);
    const mioRunbook = mio.runbook || actions.suggested_runbook || {};
    const runbookSummary = mioRunbook.title
        ? `${mioRunbook.title}${mioRunbook.id ? ` | ${mioRunbook.id}` : ''}${mioRunbook.effect ? ` | ${mioRunbook.effect}` : ''}`
        : tr('dashboard.no_runbook_selected', 'No runbook selected.');
    updateElement('mioRunbookSummary', runbookSummary);
    renderList('mioRationaleList', mio.rationale || [], (item) => item);
    updateElement('mioUserGuidance', actions.current_user_guidance || '-');
    updateElement('mioReview', mio.review?.final_status || tr('dashboard.no_review_data', 'No review data'));
    updateElement('mattermostState', mattermost.reachable ? tr('dashboard.state_reachable', 'reachable') : tr('dashboard.state_unreachable', 'unreachable'));
    updateElement('mattermostTriggers', joinList(mattermost.command_triggers || capabilities.mattermost_triggers || []));
    const opsCommLink = document.getElementById('assistantOpsCommLink');
    if (opsCommLink) opsCommLink.href = mio.handoff?.ops_comm || '/ops-comm';
    const mattermostLink = document.getElementById('assistantMattermostLink');
    if (mattermostLink) mattermostLink.href = mio.handoff?.mattermost || mattermost.open_url || '/ops-comm';

    const statusBadge = document.getElementById('mioStatusBadge');
    if (statusBadge) {
        const status = String(mio.status || 'idle').toUpperCase();
        statusBadge.textContent = status;
        statusBadge.className = `assistant-status ${toneForStatus(status)}`;
    }
    updateToggleSummary(
        'mioAssistDetailsToggle',
        tr('dashboard.mio_details_summary', 'Rationale {count} | Review {review}', {
            count: Array.isArray(mio.rationale) ? mio.rationale.length : 0,
            review: mio.review?.final_status || tr('dashboard.no_review_data', 'No review data'),
        }),
        ['failed', 'error', 'rejected'].includes(String(mio.review?.final_status || '').toLowerCase())
            ? 'status-danger'
            : (Array.isArray(mio.rationale) && mio.rationale.length > 0 ? 'status-neutral' : 'status-safe'),
    );
}

function updateControlButtons(summary) {
    const currentMode = String(summary.mode?.current_mode || 'shield').toLowerCase();
    ['portal', 'shield', 'scapegoat'].forEach((mode) => {
        document.getElementById(`mode${capitalize(mode)}Btn`)?.classList.toggle('active', currentMode === mode);
    });
    applyAudienceControlPolicy();
}

async function switchMode(mode) {
    const currentMode = String(latestState.mode?.current_mode || '').toLowerCase();
    if (currentMode === mode) {
        showToast(`Already in ${mode.toUpperCase()}`, 'info');
        return;
    }
    const confirmed = window.confirm(`Switch mode ${currentMode || '-'} -> ${mode}?`);
    if (!confirmed) return;

    try {
        await fetchJson('/api/mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode, requested_by: 'dashboard' }),
        });
        showToast(`Mode switched to ${mode.toUpperCase()}`, 'success');
        refreshDashboard();
    } catch (error) {
        showToast(`Mode switch failed: ${error.message}`, 'error');
    }
}

async function openPortalViewer() {
    try {
        const result = await fetchJson('/api/portal-viewer/open', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timeout_sec: 18 }),
        });
        if (result.url) {
            window.open(result.url, '_blank', 'noopener,noreferrer');
        }
        showToast('Portal viewer requested', 'success');
    } catch (error) {
        showToast(`Portal assist failed: ${error.message}`, 'error');
    }
}

async function executeAction(action) {
    try {
        const result = await fetchJson(`/api/action/${action}`, { method: 'POST' });
        showToast(result.message || `${action} executed`, 'success');
        refreshDashboard();
    } catch (error) {
        showToast(`${action} failed: ${error.message}`, 'error');
    }
}

async function updateClientTrust(input) {
    const trusted = Boolean(input.checked);
    const result = await submitClientRecognition({
        trusted,
        ignored: false,
        session_key: String(input.dataset.sessionKey || ''),
        ip: String(input.dataset.ip || ''),
        mac: String(input.dataset.mac || ''),
        hostname: String(input.dataset.hostname || ''),
        display_name: String(input.dataset.displayName || ''),
        interface_or_segment: String(input.dataset.segment || ''),
        expected_interface_or_segment: String(input.dataset.expectedSegment || ''),
        note: String(input.dataset.note || ''),
        allowed_networks: String(input.dataset.allowedNetworks || ''),
    });
    showToast(
        trusted
            ? tr('dashboard.client_trust_saved', 'Endpoint trust saved')
            : tr('dashboard.client_trust_revoked', 'Endpoint trust removed'),
        'success',
    );
    await refreshDashboard();
    return result;
}

async function submitClientRecognition(payload) {
    return fetchJson('/api/clients/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
}

function recognitionPayloadFromElement(element, overrides = {}) {
    const dataset = element?.dataset || {};
    const trusted = String(dataset.trusted || 'false') === 'true';
    return {
        trusted,
        ignored: false,
        session_key: String(dataset.sessionKey || ''),
        ip: String(dataset.ip || ''),
        mac: String(dataset.mac || ''),
        hostname: String(dataset.hostname || ''),
        display_name: String(dataset.displayName || ''),
        interface_or_segment: String(dataset.segment || ''),
        expected_interface_or_segment: String(dataset.expectedSegment || ''),
        note: String(dataset.note || ''),
        allowed_networks: String(dataset.allowedNetworks || ''),
        ...overrides,
    };
}

async function ignoreClientCandidate(button) {
    await submitClientRecognition(recognitionPayloadFromElement(button, { trusted: false, ignored: true }));
    showToast(tr('dashboard.client_ignore_saved', 'Endpoint hidden from client view'), 'success');
    await refreshDashboard();
}

async function saveClientProfile(form) {
    const trustedInput = form.closest('.client-identity-row')?.querySelector('.client-trust-checkbox');
    const trusted = trustedInput instanceof HTMLInputElement ? trustedInput.checked : String(form.dataset.trusted || 'false') === 'true';
    const expectedSelect = form.querySelector('[name="expected_interface_or_segment"]');
    const hostnameInput = form.querySelector('[name="hostname"]');
    const noteInput = form.querySelector('[name="note"]');
    const allowedInput = form.querySelector('[name="allowed_networks"]');
    await submitClientRecognition({
        trusted,
        ignored: false,
        session_key: String(form.dataset.sessionKey || ''),
        ip: String(form.dataset.ip || ''),
        mac: String(form.dataset.mac || ''),
        hostname: hostnameInput instanceof HTMLInputElement ? hostnameInput.value.trim() : String(form.dataset.hostname || ''),
        display_name: String(form.dataset.displayName || ''),
        interface_or_segment: String(form.dataset.segment || ''),
        expected_interface_or_segment: expectedSelect instanceof HTMLSelectElement ? expectedSelect.value.trim() : '',
        note: noteInput instanceof HTMLInputElement ? noteInput.value.trim() : '',
        allowed_networks: allowedInput instanceof HTMLInputElement ? allowedInput.value.trim() : '',
    });
    showToast(tr('dashboard.client_profile_saved', 'Endpoint profile saved'), 'success');
    await refreshDashboard();
}

async function askMio(question) {
    return askMioWithOptions(question, {});
}

async function askMioWithOptions(question, options = {}) {
    const submit = document.getElementById('mioAskSubmit');
    const responseBox = document.getElementById('mioAskResponse');
    const silent = Boolean(options.silent);
    const extraContext = options.context && typeof options.context === 'object' ? options.context : {};
    if (submit) submit.disabled = true;
    if (responseBox) responseBox.textContent = tr('dashboard.mio_analyzing', 'M.I.O. is analyzing...');

    try {
        const result = await fetchJson('/api/ai/ask', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                question,
                lang: CURRENT_LANG,
                sender: 'Dashboard',
                source: options.source || 'dashboard',
                context: Object.assign({ audience: currentAudience, lang: CURRENT_LANG }, extraContext),
            }),
        });
        if (responseBox) {
            responseBox.textContent = formatAssistResponse(result);
        }
        const surfaceMessages = result.surface_messages && typeof result.surface_messages === 'object' ? result.surface_messages : {};
        updateElement('mioCurrentAnswer', surfaceMessages.dashboard || result.surface_message || result.answer || '-');
        updateElement('mioUserGuidance', result.user_message || '-');
        updateElement('mioReview', result.runbook_review?.final_status || tr('dashboard.no_review_data', 'No review data'));
        renderList('mioRationaleList', result.rationale || [], (item) => item);
        const askedAt = new Date().toISOString();
        updateElement('mioLastAsk', `${question}${askedAt ? ` | ${formatHumanDateTime(askedAt)}` : ''} | dashboard`);
        updateElement('mioRunbookSummary', result.runbook_id || tr('dashboard.no_runbook_selected', 'No runbook selected.'));
        const opsCommLink = document.getElementById('assistantOpsCommLink');
        if (opsCommLink) opsCommLink.href = result.handoff?.ops_comm || '/ops-comm';
        const mattermostLink = document.getElementById('assistantMattermostLink');
        if (mattermostLink) mattermostLink.href = result.handoff?.mattermost || latestMattermost.open_url || '/ops-comm';
        const statusBadge = document.getElementById('mioStatusBadge');
        if (statusBadge) {
            statusBadge.textContent = String(result.status || 'completed').toUpperCase();
            statusBadge.className = `assistant-status ${toneForStatus(result.status || 'completed')}`;
        }
        if (!silent) showToast(tr('dashboard.mio_response_received', 'M.I.O. response received'), 'success');
        return result;
    } catch (error) {
        if (responseBox) responseBox.textContent = `${tr('dashboard.mio_request_failed', 'M.I.O. request failed')}: ${error.message}`;
        if (!silent) showToast(`${tr('dashboard.mio_request_failed', 'M.I.O. request failed')}: ${error.message}`, 'error');
        throw error;
    } finally {
        if (submit) submit.disabled = false;
    }
}

function buildDemoMioQuestion(result) {
    const scenarioId = result?.scenario_id || 'demo';
    const nocStatus = result?.noc?.summary?.status || '-';
    const socStatus = result?.soc?.summary?.status || '-';
    const action = result?.arbiter?.action || '-';
    const reason = result?.arbiter?.reason || '-';
    return `Demo scenario ${scenarioId}: NOC status ${nocStatus}, SOC status ${socStatus}, selected action ${action}, reason ${reason}. Explain this choice for an operator and give the next checks.`;
}

async function openAuthenticatedJson(path, title) {
    const popup = window.open('', '_blank', 'noopener,noreferrer');
    if (popup) {
        popup.document.title = title;
        popup.document.body.innerHTML = '<pre>Loading...</pre>';
    }
    try {
        const payload = await fetchJson(path);
        const content = JSON.stringify(payload, null, 2);
        if (popup) {
            popup.document.title = title;
            popup.document.body.innerHTML = `<pre>${escapeHtml(content)}</pre>`;
        }
    } catch (error) {
        if (popup) {
            popup.document.title = `${title} (error)`;
            popup.document.body.innerHTML = `<pre>${escapeHtml(String(error.message || error))}</pre>`;
        }
        showToast(`${title}: ${error.message || error}`, 'error');
    }
}

function formatDemoBoolean(value) {
    return value ? 'yes' : 'no';
}

function formatCapabilityBoundarySummary(boundary) {
    if (!boundary || typeof boundary !== 'object') {
        return tr('dashboard.demo_boundary_summary', 'Deterministic replay path. This does not replace the live Tactical first-pass path, and AI is not used in the core demo decision loop.');
    }
    const implemented = Array.isArray(boundary.implemented_now) ? boundary.implemented_now.length : 0;
    const demoOnly = Array.isArray(boundary.demo_only) ? boundary.demo_only.length : 0;
    const experimental = Array.isArray(boundary.experimental) ? boundary.experimental.length : 0;
    return tr(
        'dashboard.demo_boundary_summary_verbose',
        'Deterministic replay path. It does not replace the live Tactical first-pass path. implemented={implemented}, demo_only={demo_only}, experimental={experimental}. AI is not used in the core demo decision loop.',
        { implemented, demo_only: demoOnly, experimental }
    );
}

function applyDemoDerivedFields(source) {
    const raw = source && typeof source === 'object' ? source : {};
    const execution = raw.execution && typeof raw.execution === 'object' ? raw.execution : {};
    const actionProfile = raw.action_profile && typeof raw.action_profile === 'object'
        ? raw.action_profile
        : (raw.arbiter?.action_profile && typeof raw.arbiter.action_profile === 'object' ? raw.arbiter.action_profile : {});
    const decisionTrace = raw.decision_trace && typeof raw.decision_trace === 'object'
        ? raw.decision_trace
        : (raw.arbiter?.decision_trace && typeof raw.arbiter.decision_trace === 'object' ? raw.arbiter.decision_trace : {});
    const capabilityBoundary = raw.capability_boundary && typeof raw.capability_boundary === 'object' ? raw.capability_boundary : {};
    const scenarioId = String(raw.scenario_id || '-').trim();
    const eventCount = Number(raw.event_count || 0);

    updateElement('demoScenarioId', scenarioId || '-');
    updateElement('demoEventCount', Number.isFinite(eventCount) ? String(eventCount) : '-');
    updateElement('demoExecutionMode', String(execution.mode || 'deterministic_replay'));
    updateElement('demoAiCore', execution.ai_used ? 'used' : 'not-used');
    updateElement('demoSafetyReversible', formatDemoBoolean(Boolean(actionProfile.reversible)));
    updateElement('demoSafetyApproval', actionProfile.approval_required ? 'required' : 'not-required');
    updateElement('demoSafetyAudited', formatDemoBoolean(Boolean(actionProfile.audited)));
    updateElement('demoSafetyEffect', String(actionProfile.effect || '-'));
    updateElement('demoTraceNocFragile', formatDemoBoolean(Boolean(decisionTrace.noc_fragile)));
    updateElement('demoTraceStrongSoc', formatDemoBoolean(Boolean(decisionTrace.strong_soc)));
    updateElement(
        'demoTraceBlastConfidence',
        `${Number(decisionTrace.blast_score || 0)}/${Number(decisionTrace.confidence_score || 0)}`,
    );
    updateElement(
        'demoTraceClientImpact',
        `${Number(decisionTrace.client_impact_score || 0)} / critical=${Number(decisionTrace.critical_client_count || 0)}`,
    );
    updateElement('demoBoundaryMode', execution.live_telemetry ? 'LIVE TELEMETRY' : 'DETERMINISTIC REPLAY');
    updateElement('demoBoundarySummary', formatCapabilityBoundarySummary(capabilityBoundary));
}

function updateReviewReadiness(healthEntry, demoCapabilitiesEntry, demoOverlay) {
    const healthOk = Boolean(healthEntry?.ok);
    const demoCapabilitiesOk = Boolean(demoCapabilitiesEntry?.ok);
    const health = healthEntry?.data || {};
    const demoCapabilities = demoCapabilitiesEntry?.data || {};
    const boundary = demoOverlay?.capability_boundary || demoCapabilities?.boundary || {};
    const execution = demoOverlay?.execution || {
        mode: demoCapabilities?.execution_mode || 'deterministic_replay',
        ai_used: Boolean(demoCapabilities?.ai_used_in_core_path),
        live_telemetry: Boolean(demoCapabilities?.live_telemetry_required),
        local_only: Boolean(demoCapabilities?.local_only_in_core_path),
    };
    const implemented = Array.isArray(boundary.implemented_now) ? boundary.implemented_now : [];
    const demoOnly = Array.isArray(boundary.demo_only) ? boundary.demo_only : [];
    const experimental = Array.isArray(boundary.experimental) ? boundary.experimental : [];
    const nonGoals = Array.isArray(boundary.non_goals) ? boundary.non_goals : [];
    const staleFlags = health?.stale_flags || {};
    const queue = health?.queue || {};
    const llm = health?.llm || {};
    const badge = document.getElementById('reviewStatusBadge');
    const capabilityBtn = document.getElementById('reviewOpenCapabilitiesBtn');
    const explanationBtn = document.getElementById('reviewOpenExplanationBtn');
    const hasBoundaryData = Boolean(demoOverlay?.capability_boundary) || demoCapabilitiesOk;
    const hasHealthData = healthOk;
    const overlayActive = Boolean(demoOverlay);
    const healthy = hasBoundaryData
        && hasHealthData
        && !staleFlags.snapshot
        && !staleFlags.ai_metrics
        && Number(queue.capacity ?? 0) > 0
        && Number(queue.depth ?? 0) <= Number(queue.capacity ?? 0);
    const status = (!hasBoundaryData || !hasHealthData) ? 'UNKNOWN' : (healthy ? 'BOUNDED' : 'CHECK');

    updateElement('reviewExecutionMode', hasBoundaryData ? String(execution.mode || 'deterministic_replay') : 'unknown');
    updateElement('reviewAiCore', hasBoundaryData ? (execution.ai_used ? 'used' : 'not-used') : 'unknown');
    updateElement('reviewLocalOnly', hasBoundaryData ? (execution.local_only ? 'yes' : 'no') : 'unknown');
    updateElement('reviewLiveTelemetry', hasBoundaryData ? (execution.live_telemetry ? 'required' : 'not-required') : 'unknown');
    updateElement('reviewDemoState', overlayActive ? 'overlay-active' : 'overlay-inactive');
    updateElement('reviewBoundaryCounts', hasBoundaryData ? `${implemented.length} / ${experimental.length}` : 'unknown');
    renderList(
        'reviewImplementedList',
        hasBoundaryData && implemented.length ? implemented : [tr('dashboard.no_data', 'No data')],
        (item) => item,
    );
    renderList(
        'reviewExperimentalList',
        hasBoundaryData
            ? [
                ...experimental.map((item) => `experimental: ${item}`),
                ...demoOnly.map((item) => `demo-only: ${item}`),
            ]
            : [tr('dashboard.no_data', 'No data')],
        (item) => item,
    );
    renderList(
        'reviewNonGoalsList',
        hasBoundaryData && nonGoals.length ? nonGoals.map((item) => `non-goal: ${item}`) : [tr('dashboard.no_data', 'No data')],
        (item) => item,
    );

    updateElement('reviewStatusBadge', status);
    if (badge) {
        badge.className = `assistant-status ${
            status === 'BOUNDED' ? 'status-safe' : (status === 'CHECK' ? 'status-caution' : 'status-neutral')
        }`;
    }
    if (capabilityBtn) capabilityBtn.disabled = !hasBoundaryData;
    if (explanationBtn) explanationBtn.disabled = !overlayActive;
    updateElement(
        'reviewSummary',
        tr(
            'dashboard.review_summary_default',
            'Deterministic edge pipeline, bounded controls, local-first operation, auditable outputs.',
        ),
    );
    updateElement(
        'reviewSummaryDetail',
        !hasBoundaryData || !hasHealthData
            ? tr(
                'dashboard.review_summary_unavailable',
                'Reviewer-proof summary is incomplete because capability or health data is unavailable.',
            )
            : tr(
                'dashboard.review_summary_runtime',
                'Execution={execution} | local_only={local_only} | demo_state={demo_state} | bounded={bounded}',
                {
                    execution: execution.mode || 'deterministic_replay',
                    local_only: execution.local_only ? 'yes' : 'no',
                    demo_state: overlayActive ? 'overlay-active' : 'overlay-inactive',
                    bounded: healthy ? 'yes' : 'check',
                },
            ),
    );
}

function updateOperationalResourceGuard(health) {
    const queue = health?.queue || {};
    const llm = health?.llm || {};
    const staleFlags = health?.stale_flags || {};
    const depth = Number(queue.depth ?? 0);
    const capacity = Number(queue.capacity ?? 0);
    const maxSeen = Number(queue.max_seen ?? 0);
    const deferred = Number(queue.deferred_count ?? 0);
    const fallbackRate = Number(llm.fallback_rate ?? 0);
    const latencyLast = Number(llm.latency_ms_last ?? 0);
    const latencyEma = Number(llm.latency_ms_ema ?? 0);
    const requests = Number(llm.requests ?? 0);
    const failed = Number(llm.failed ?? 0);
    const staleCount = [Boolean(staleFlags.snapshot), Boolean(staleFlags.ai_metrics), Boolean(staleFlags.ai_activity)].filter(Boolean).length;
    const queuePct = capacity > 0 ? Math.min(100, Math.max(0, (depth / capacity) * 100)) : 0;
    const fallbackPct = Math.min(100, Math.max(0, fallbackRate * 100));
    const latencyPct = Math.min(100, Math.max(0, (latencyEma / 1500) * 100));
    const headline = document.getElementById('resourceGuardHeadline');
    const queueTone = queuePct >= 90 || (capacity > 0 && depth > capacity) ? 'status-danger' : (queuePct >= 65 ? 'status-caution' : 'status-safe');
    const fallbackTone = fallbackPct >= 50 ? 'status-danger' : (fallbackPct >= 20 ? 'status-caution' : 'status-safe');
    const latencyTone = latencyPct >= 85 ? 'status-danger' : (latencyPct >= 55 ? 'status-caution' : 'status-safe');
    let overallStatus = 'status-safe';
    let summary = tr('dashboard.resource_guard_summary_stable', 'Runtime looks stable.');
    if (Boolean(staleFlags.snapshot) || (capacity > 0 && depth > capacity) || fallbackPct >= 50 || latencyPct >= 85) {
        overallStatus = 'status-danger';
        summary = tr('dashboard.resource_guard_summary_degraded', 'Runtime degraded. Verify live state first.');
    } else if (staleCount > 0 || queuePct >= 65 || fallbackPct >= 20 || latencyPct >= 55 || deferred > 0) {
        overallStatus = 'status-caution';
        summary = tr('dashboard.resource_guard_summary_caution', 'Watch queue, stale data, or fallback before acting.');
    }

    const reasons = [
        tr(
            overallStatus === 'status-danger'
                ? 'dashboard.resource_guard_reason_degraded'
                : (overallStatus === 'status-caution'
                    ? 'dashboard.resource_guard_reason_caution'
                    : 'dashboard.resource_guard_reason_stable'),
            overallStatus === 'status-danger'
                ? 'Trust is reduced: queue {queue_pct}%, fallback {fallback_pct}%, stale {stale_count}/3.'
                : (overallStatus === 'status-caution'
                    ? 'Guardrails are drifting: queue {queue_pct}%, fallback {fallback_pct}%, stale {stale_count}/3.'
                    : 'Guardrails are within bounds: queue {queue_pct}%, fallback {fallback_pct}%, stale {stale_count}/3.'),
            {
                queue_pct: Math.round(queuePct),
                fallback_pct: Math.round(fallbackPct),
                stale_count: staleCount,
            },
        ),
        tr(
            'dashboard.resource_guard_reason_latency',
            'Latency last {last} ms; EMA {ema} ms.',
            { last: latencyLast, ema: latencyEma },
        ),
        tr(
            'dashboard.resource_guard_reason_queue_window',
            'Queue depth {depth}/{capacity}; max seen {max_seen}.',
            { depth, capacity: capacity || 0, max_seen: maxSeen },
        ),
    ];
    const flags = [
        tr('dashboard.resource_guard_flag_policy', 'Policy: {value}', { value: String(health?.policy_mode || '-') }),
        tr('dashboard.resource_guard_flag_stale', 'Stale flags: {count}/3', { count: staleCount }),
        tr('dashboard.resource_guard_flag_deferred', 'Deferred work: {count}', { count: deferred }),
    ];
    const indicators = [
        tr('dashboard.resource_guard_indicator_queue', 'Queue pressure: {pct}%', { pct: Math.round(queuePct) }),
        tr(
            'dashboard.resource_guard_indicator_fallback',
            'Fallback rate: {pct}% ({failed}/{requests})',
            { pct: Math.round(fallbackPct), failed, requests },
        ),
        tr(
            'dashboard.resource_guard_indicator_latency',
            'Latency: last {last} ms / EMA {ema} ms',
            { last: latencyLast, ema: latencyEma },
        ),
    ];

    updateElement('resourceGuardSummary', summary);
    renderList('resourceGuardReasonList', reasons, (item) => item);
    renderList('resourceGuardFlagList', flags, (item) => item);
    renderList('resourceGuardIndicatorList', indicators, (item) => item);
    updateElement('resourceGuardQueueValue', `${Math.round(queuePct)}%`);
    updateElement('resourceGuardQueueDetail', `${depth} / ${capacity || 0} | max ${maxSeen}`);
    updateElement('resourceGuardFallbackValue', `${Math.round(fallbackPct)}%`);
    updateElement('resourceGuardFallbackDetail', `${failed} / ${requests} fallback`);
    updateElement('resourceGuardLatencyValue', `${latencyLast} ms`);
    updateElement('resourceGuardLatencyDetail', `EMA ${latencyEma} ms`);
    setMeterFill('resourceGuardQueueBar', queuePct, queueTone);
    setMeterFill('resourceGuardFallbackBar', fallbackPct, fallbackTone);
    setMeterFill('resourceGuardLatencyBar', latencyPct, latencyTone);
    if (headline) {
        headline.textContent = overallStatus === 'status-danger' ? 'DEGRADED' : (overallStatus === 'status-caution' ? 'WATCH' : 'STABLE');
    }
}

function updateAIGovernanceSnapshot(governance) {
    const status = String(governance?.status || 'unknown').toUpperCase();
    const rates = governance?.rates || {};
    const stale = Boolean(governance?.stale);
    const unknown = Boolean(governance?.unknown);
    const contributionPct = Math.round(Number(rates.ai_contribution ?? 0) * 100);
    const fallbackPct = Math.round(Number(rates.fallback ?? 0) * 100);
    const manualRoutePct = Math.round(Number(rates.manual_route ?? 0) * 100);
    const updatedAt = String(governance?.updated_at || '-');
    const age = governance?.age_sec;
    let summary = tr(
        'dashboard.ai_governance_summary_ok',
        'Updated {updated} | AI contribution {contrib}% | fallback {fallback}% | manual route {manual}%',
        { updated: updatedAt, contrib: contributionPct, fallback: fallbackPct, manual: manualRoutePct },
    );
    if (unknown) {
        summary = tr('dashboard.ai_governance_summary_unknown', 'No AI governance sample yet.');
    } else if (stale) {
        summary = tr(
            'dashboard.ai_governance_summary_stale',
            'Governance metrics are stale ({age}s old).',
            { age: Math.round(Number(age || 0)) },
        );
    }
    updateElement('aiGovernanceStatus', status);
    updateElement('aiGovernanceSummary', summary);
    updateElement('aiGovernanceContribution', `${contributionPct}%`);
    updateElement('aiGovernanceFallback', `${fallbackPct}%`);
    updateElement('aiGovernanceManualRoute', `${manualRoutePct}%`);
}

function renderList(id, items, formatter) {
    const el = document.getElementById(id);
    if (!el) return;
    const rows = Array.isArray(items) && items.length ? items : ['No data'];
    el.innerHTML = rows.map((item) => `<li>${escapeHtml(formatter(item))}</li>`).join('');
}

function summaryBadgeLabel(tone) {
    return splitHeadlineForTone(tone);
}

function updateToggleSummary(id, text, tone = 'status-neutral') {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = `
        <span class="toggle-summary-badge ${tone}">${escapeHtml(summaryBadgeLabel(tone))}</span>
        <span class="toggle-summary-text ${tone}">${escapeHtml(text)}</span>
    `;
}

function updateGuidanceToggleSummary(doNotDoCount = null) {
    const askCount = Array.from(document.querySelectorAll('#temporaryAskList li')).filter((item) => (item.textContent || '').trim()).length;
    const tellCount = Array.from(document.querySelectorAll('#temporaryTellList li')).filter((item) => (item.textContent || '').trim()).length;
    const avoidCount = doNotDoCount == null
        ? Array.from(document.querySelectorAll('#doNotDoList li')).filter((item) => (item.textContent || '').trim()).length
        : doNotDoCount;
    updateToggleSummary(
        'actionBoardGuidanceDetailsToggle',
        tr('dashboard.action_board_guidance_details_summary', 'Ask {ask} | Tell {tell} | Avoid {avoid}', {
            ask: askCount,
            tell: tellCount,
            avoid: avoidCount,
        }),
        avoidCount > 0 ? 'status-caution' : ((askCount + tellCount) > 0 ? 'status-neutral' : 'status-safe'),
    );
}

function escapeAttribute(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('"', '&quot;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');
}

function renderTimeline(id, items, formatter) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!Array.isArray(items) || items.length === 0) {
        el.innerHTML = '<li><div class="timeline-title">No recent entries</div></li>';
        return;
    }
    el.innerHTML = items.map((item) => {
        const row = formatter(item);
        return `
            <li>
                <div class="timeline-meta"><span>${escapeHtml(row.metaLeft || '-')}</span><span>${escapeHtml(row.metaRight || '-')}</span></div>
                <div class="timeline-title">${escapeHtml(row.title || '-')}</div>
                <div class="timeline-detail">${escapeHtml(row.detail || '-')}</div>
            </li>
        `;
    }).join('');
}

function updateServiceChip(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value;
    el.className = toneForStatus(value);
}

function updateElement(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setMeterFill(id, pct, tone) {
    const el = document.getElementById(id);
    if (!el) return;
    const width = Math.max(0, Math.min(100, Number(pct) || 0));
    el.style.width = `${width}%`;
    el.className = `resource-guard-meter-fill ${tone || 'status-safe'}`;
}

function joinList(items) {
    return Array.isArray(items) && items.length ? items.join(', ') : '-';
}

function toneForRisk(userState, suspicion) {
    const state = String(userState || '').toUpperCase();
    const score = Number(suspicion || 0);
    if (state === 'DECEPTION' || state === 'CONTAINED' || score >= 80) return 'status-danger';
    if (state === 'LIMITED' || state === 'CHECKING' || score >= 40) return 'status-caution';
    return 'status-safe';
}

function toneForStatus(status) {
    const text = String(status || '').toLowerCase();
    if (['on', 'ok', 'active', 'connected', 'reachable', 'completed', 'routed'].includes(text)) return 'status-safe';
    if (['off', 'fail', 'failed', 'error', 'critical', 'unreachable'].includes(text)) return 'status-danger';
    if (['warning', 'deferred', 'queued', 'checking', 'preparing', 'reconnecting'].includes(text)) return 'status-caution';
    return 'status-neutral';
}

function capitalize(value) {
    const text = String(value || '');
    return text.charAt(0).toUpperCase() + text.slice(1);
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    window.setTimeout(() => {
        toast.className = 'toast';
    }, 3200);
}
