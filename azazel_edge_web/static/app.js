const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const AUDIENCE_KEY = 'azazel_dashboard_audience';
const LANG_KEY = 'azazel_lang';
const POLL_INTERVAL_MS = 4000;
const CURRENT_LANG = window.AZAZEL_LANG || localStorage.getItem(LANG_KEY) || 'ja';
const I18N = window.AZAZEL_I18N || {};

let dashboardTimer = null;
let currentAudience = localStorage.getItem(AUDIENCE_KEY) || 'professional';
let latestState = {};
let latestMattermost = {};
let lastRefreshWarning = '';
let demoScenarioItems = [];
let demoOverlayResult = null;

function tr(key, fallback, vars = null) {
    const base = I18N[key] || fallback || key;
    if (!vars || typeof base !== 'string') return base;
    return base.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, name) => {
        return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`;
    });
}

function authHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Auth-Token': AUTH_TOKEN,
        'X-AZAZEL-LANG': CURRENT_LANG,
    };
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
    document.body.classList.toggle('demo-overlay-active', !!active);
}

function resetDemoOverlayPresentation() {
    setDemoOverlayVisualState(false);
    updateElement('demoStatusBadge', tr('dashboard.demo_ready', 'READY'));
    const badge = document.getElementById('demoStatusBadge');
    if (badge) badge.className = 'assistant-status status-neutral';
    updateElement('demoNocStatus', '-');
    updateElement('demoSocStatus', '-');
    updateElement('demoAction', '-');
    updateElement('demoReason', '-');
    updateElement('demoOperatorWording', tr('dashboard.no_demo', 'No demo overlay is active.'));
    updateElement('demoResponse', tr('dashboard.no_demo_response', 'Run a scenario to preview the deterministic pipeline.'));
    renderList('demoNextChecks', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
    renderList('demoEvidenceIds', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
    renderList('demoRejectedAlternatives', [tr('dashboard.no_demo_overlay_active', 'No demo overlay is active.')], (item) => item);
}

const shortcutQuestions = {
    wifi: CURRENT_LANG === 'ja' ? 'Wi-Fi に繋がらない利用者へどう案内するか' : 'How should I guide a user who cannot connect to Wi-Fi?',
    reconnect: CURRENT_LANG === 'ja' ? '再接続できない利用者へどう案内するか' : 'How should I guide a user who cannot reconnect?',
    onboarding: CURRENT_LANG === 'ja' ? '初回接続の利用者へどう案内するか' : 'How should I guide a first-time onboarding user?',
    dns: CURRENT_LANG === 'ja' ? 'DNS が引けない時に何を確認するか' : 'What should I verify when DNS lookup fails?',
    route: CURRENT_LANG === 'ja' ? 'gateway と uplink の異常時に何を確認するか' : 'What should I verify when the gateway or uplink looks unhealthy?',
    service: CURRENT_LANG === 'ja' ? 'service の異常時に何を確認するか' : 'What should I verify when a service appears unhealthy?',
    portal: CURRENT_LANG === 'ja' ? 'ポータルが表示されない利用者へどう案内するか' : 'How should I guide a user when the portal does not appear?',
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
    lines.push(result.answer || '-');
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
    setAudience(currentAudience);
    refreshDashboard();
    dashboardTimer = window.setInterval(refreshDashboard, POLL_INTERVAL_MS);
});

window.addEventListener('beforeunload', () => {
    if (dashboardTimer) {
        clearInterval(dashboardTimer);
    }
});

function bindStaticHandlers() {
    document.getElementById('langJaBtn')?.addEventListener('click', () => switchLanguage('ja'));
    document.getElementById('langEnBtn')?.addEventListener('click', () => switchLanguage('en'));
    document.getElementById('audienceProfessional')?.addEventListener('click', () => setAudience('professional'));
    document.getElementById('audienceTemporary')?.addEventListener('click', () => setAudience('temporary'));

    document.getElementById('modePortalBtn')?.addEventListener('click', () => switchMode('portal'));
    document.getElementById('modeShieldBtn')?.addEventListener('click', () => switchMode('shield'));
    document.getElementById('modeScapegoatBtn')?.addEventListener('click', () => switchMode('scapegoat'));
    document.getElementById('portalAssistBtn')?.addEventListener('click', openPortalViewer);
    document.getElementById('containBtn')?.addEventListener('click', () => executeAction('contain'));
    document.getElementById('releaseBtn')?.addEventListener('click', () => executeAction('release'));

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

    document.getElementById('demoScenarioSelect')?.addEventListener('change', updateDemoScenarioDescription);
    document.getElementById('demoRunForm')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await runDemoScenario();
    });
    document.getElementById('demoClearOverlayBtn')?.addEventListener('click', clearDemoOverlay);

    loadDemoScenarios();
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
    currentAudience = audience === 'temporary' ? 'temporary' : 'professional';
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
        if (idle) return `IDLE | ${label}`;
        return stale ? `STALE | ${label}` : label;
    }
    const seconds = Number(ageSec);
    let bucket = `${Math.round(seconds)}s ago`;
    if (seconds >= 3600) {
        bucket = `${Math.round(seconds / 3600)}h ago`;
    } else if (seconds >= 60) {
        bucket = `${Math.round(seconds / 60)}m ago`;
    }
    if (idle) {
        return `IDLE | ${bucket} | ${label}`;
    }
    return `${stale ? 'STALE' : 'LIVE'} | ${bucket} | ${label}`;
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
}

async function refreshDashboard() {
    const requests = [
        ['summary', '/api/dashboard/summary', true],
        ['actions', '/api/dashboard/actions', false],
        ['evidence', '/api/dashboard/evidence', false],
        ['health', '/api/dashboard/health', false],
        ['state', '/api/state', true],
        ['mattermost', '/api/mattermost/status', false],
        ['capabilities', '/api/ai/capabilities', false],
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
    const evidence = resultMap.evidence?.data || {};
    const health = resultMap.health?.data || {};
    const state = resultMap.state?.data || {};
    const mattermost = resultMap.mattermost?.data || { reachable: false, command_triggers: [] };
    const capabilities = resultMap.capabilities?.data || { mattermost_triggers: [] };
    const demoOverlay = resultMap.demoOverlay?.data?.overlay || {};

    latestState = state || {};
    latestMattermost = mattermost || {};
    demoOverlayResult = demoOverlay && demoOverlay.active ? demoOverlay : null;
    setDemoOverlayVisualState(!!demoOverlayResult);
    if (!demoOverlayResult) {
        resetDemoOverlayPresentation();
    }

    try {
        updateHeader(state, mattermost);
        updateCommandStrip(summary, health, failures);
        updateSituationBoard(summary, state, health, mattermost);
        updateSplitBoard(summary, actions);
        updateActionBoard(actions, state);
        updateMissionRow(summary, actions);
        updateTemporaryMission(actions);
        updateEvidenceBoard(evidence, health);
        updateAssistant(actions, mattermost, capabilities);
        updateControlButtons(summary, state);
        if (demoOverlayResult) {
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
    updateElement('nocClientScope', 'demo impact');
    updateElement('nocClientSegment', scenarioId);
    updateElement('nocClientPortal', 'N/A');
    updateElement('nocClientDnsMismatch', '0');
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
    updateElement('runbookTitle', tr('dashboard.demo_runbook_title', 'Demo scenario summary'));
    updateElement('runbookId', scenarioId);
    updateElement('runbookEffect', tr('dashboard.display_only', 'display_only'));
    updateElement('runbookApproval', tr('dashboard.not_applicable', 'Not applicable'));
    renderList('runbookSteps', nextChecks.length ? nextChecks : [tr('dashboard.demo_runbook_step_1', 'Inspect explanation output'), tr('dashboard.demo_runbook_step_2', 'Compare with live telemetry before acting')], (item) => item);

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
    updateElement('headerClock', state.now_time || '--:--:--');
    updateElement('headerCpuUsage', state.cpu_percent != null ? `${state.cpu_percent}%` : '--%');
    updateElement('headerMemUsage', state.mem_percent != null ? `${state.mem_percent}%` : '--%');
    updateElement('headerCpuTemp', state.temp_c != null ? `${state.temp_c}°C` : '--°C');
    const mattermostUrl = mattermost.open_url || '/ops-comm';
    const mmLink = document.getElementById('openMattermostLink');
    if (mmLink) mmLink.href = mattermostUrl;
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
    const clientImpact = noc.client_impact || {};
    const attackType = soc.attack_type || tr('dashboard.no_attack_type', 'No current attack type');

    updateElement('socThreatLevel', String(soc.threat_level || 'quiet').toUpperCase());
    updateElement('socThreatSummary', `${attackType} | src=${soc.top_source || '-'} | dst=${soc.top_destination || '-'}`);
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
            ...(soc.ti_matches || []),
            ...(soc.sigma_hits || []),
            ...(soc.yara_hits || []),
        ],
        (item) => item,
    );

    updateElement('nocPathStatus', String(path.status || 'unknown').toUpperCase());
    updateElement('nocPathUplink', path.uplink || '-');
    updateElement('nocPathGateway', path.gateway || '-');
    updateElement('nocPathInternet', path.internet_check || '-');
    renderList('nocPathSignals', path.signals || [], (item) => item);
    renderList(
        'nocServiceList',
        Object.entries(services).map(([name, value]) => `${name}: ${value}`),
        (item) => item,
    );
    updateElement('nocClientScope', clientImpact.scope || '-');
    updateElement('nocClientSegment', clientImpact.segment_scope || '-');
    updateElement('nocClientPortal', clientImpact.captive_portal || '-');
    updateElement('nocClientDnsMismatch', String(clientImpact.dns_mismatch ?? 0));

    renderList(
        'rejectedStrongerActionsList',
        actions.rejected_stronger_actions || [],
        (item) => `${item.action || '-'}: ${item.reason || '-'}`,
    );
}

function updateActionBoard(actions, state) {
    renderList('whyNowList', actions.why_now || [], (item) => item);
    renderList('nextActionsList', actions.do_next || actions.current_operator_actions || [], (item) => item);
    renderList('doNotDoList', actions.do_not_do || [], (item) => item);
    renderList('escalateIfList', actions.escalate_if || [], (item) => item);
    updateElement('userGuidanceText', actions.current_user_guidance || '-');

    const runbook = actions.suggested_runbook || {};
    const primaryAction = (actions.do_next || actions.current_operator_actions || [])[0] || actions.current_user_guidance || tr('dashboard.no_immediate_action', 'No immediate action synthesized.');
    const primarySummary = (actions.why_now || [])[0] || tr('dashboard.waiting_stronger_evidence', 'The dashboard is waiting for stronger causal evidence.');
    updateElement('priorityActionTitle', primaryAction);
    updateElement('priorityActionSummary', primarySummary);
    updateElement('runbookTitle', runbook.title || '-');
    updateElement('runbookId', runbook.id || '-');
    updateElement('runbookEffect', runbook.effect || '-');
    updateElement('runbookApproval', actions.approval_required ? tr('dashboard.review_required', 'Required') : tr('dashboard.review_not_required', 'Not required'));
    renderList('runbookSteps', runbook.steps || [], (item) => item);

    const mode = latestState.mode || {};
    updateElement('modeLastChange', formatHumanDateTime(mode.last_change));
    updateElement('modeRequestedBy', mode.requested_by || '-');

    const portalBtn = document.getElementById('portalAssistBtn');
    if (portalBtn) {
        const portalViewer = latestState.portal_viewer || {};
        portalBtn.disabled = !portalViewer.url;
        portalBtn.textContent = portalViewer.ready ? 'Portal Assist' : tr('dashboard.portal_assist_prep', 'Portal Assist (prep)');
    }
}

function updateEvidenceBoard(evidence, health) {
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
}

function updateAssistant(actions, mattermost, capabilities) {
    const mio = actions.mio || {};
    updateElement('mioCurrentAnswer', mio.answer || actions.current_recommendation || '-');
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
        updateElement('mioCurrentAnswer', result.answer || '-');
        updateElement('mioUserGuidance', result.user_message || '-');
        updateElement('mioReview', result.runbook_review?.final_status || 'No review data');
        renderList('mioRationaleList', result.rationale || [], (item) => item);
        const askedAt = new Date().toISOString();
        updateElement('mioLastAsk', `${question}${askedAt ? ` | ${formatHumanDateTime(askedAt)}` : ''} | dashboard`);
        updateElement('mioRunbookSummary', result.runbook_id || 'No runbook selected.');
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

function renderList(id, items, formatter) {
    const el = document.getElementById(id);
    if (!el) return;
    const rows = Array.isArray(items) && items.length ? items : ['No data'];
    el.innerHTML = rows.map((item) => `<li>${escapeHtml(formatter(item))}</li>`).join('');
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
