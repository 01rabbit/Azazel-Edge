const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const AUDIENCE_KEY = 'azazel_dashboard_audience';
const POLL_INTERVAL_MS = 4000;

let dashboardTimer = null;
let currentAudience = localStorage.getItem(AUDIENCE_KEY) || 'professional';
let latestState = {};
let latestMattermost = {};
let lastRefreshWarning = '';
let demoScenarioItems = [];
let demoOverlayResult = null;

function setDemoOverlayVisualState(active) {
    document.body.classList.toggle('demo-overlay-active', !!active);
}

const shortcutQuestions = {
    wifi: 'Wi-Fi に繋がらない利用者へどう案内するか',
    reconnect: '再接続できない利用者へどう案内するか',
    onboarding: '初回接続の利用者へどう案内するか',
    dns: 'DNS が引けない時に何を確認するか',
    route: 'gateway と uplink の異常時に何を確認するか',
    service: 'service の異常時に何を確認するか',
    portal: 'ポータルが表示されない利用者へどう案内するか',
};

const temporaryFlows = {
    wifi: {
        ask: [
            'Which device is failing first?',
            'Does the device see the SSID at all?',
            'Is this only one device or multiple devices?'
        ],
        tell: [
            'Do not repeatedly reboot the device yet.',
            'We are checking whether this is a single-device issue or a wider Wi-Fi issue.'
        ],
    },
    reconnect: {
        ask: [
            'Was the user connected successfully before?',
            'Did the failure start after moving location or after a password change?',
            'Is the problem only on one device?'
        ],
        tell: [
            'We are checking whether this is a saved-profile issue or a broader wireless issue.',
            'Please keep the device near the normal usage area and avoid repeated reconnect attempts for the moment.'
        ],
    },
    onboarding: {
        ask: [
            'Is this the first time this device is joining the network?',
            'Can the device see the expected SSID?',
            'Is the user following the standard onboarding steps?'
        ],
        tell: [
            'We are checking the onboarding path first before changing any network settings.',
            'Please prepare the device name and the exact step where the user got stuck.'
        ],
    },
    dns: {
        ask: [
            'Which site or hostname fails to open?',
            'Does access by IP address work?',
            'Is the issue affecting multiple users?'
        ],
        tell: [
            'We are checking name resolution first.',
            'Please keep the device connected while we verify DNS and gateway status.'
        ],
    },
    uplink: {
        ask: [
            'Are all users affected or only one area?',
            'When did the problem start?',
            'Is any external site reachable at all?'
        ],
        tell: [
            'We are checking upstream connectivity and gateway reachability.',
            'Please avoid changing cables or mode settings until the first check completes.'
        ],
    },
    service: {
        ask: [
            'Which function appears unavailable?',
            'Is the UI wrong, or is the function really down?',
            'When was the last successful use?'
        ],
        tell: [
            'We are confirming actual service status before any restart.',
            'Please wait while we check status and journal information.'
        ],
    },
    portal: {
        ask: [
            'Does the device show a browser at all after connecting?',
            'Can the user reach any page by typing a normal website address?',
            'Is this one user or multiple users?'
        ],
        tell: [
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
    lines.push(`Rationale: ${rationale}`);
    lines.push(`User Guidance: ${result.user_message || '-'}`);
    lines.push(`Runbook: ${result.runbook_id || 'no suggestion'}`);
    lines.push(`Review: ${result.runbook_review?.final_status || 'no review data'}`);
    const handoff = result.handoff && typeof result.handoff === 'object' ? result.handoff : {};
    const handoffParts = [];
    if (handoff.ops_comm) handoffParts.push(`Ops Comm ${handoff.ops_comm}`);
    if (handoff.mattermost) handoffParts.push(`Mattermost ${handoff.mattermost}`);
    lines.push(`Continue: ${handoffParts.length ? handoffParts.join(' / ') : '-'}`);
    return lines.join('\n\n');
}

document.addEventListener('DOMContentLoaded', () => {
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

    document.querySelectorAll('.temp-flow-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const symptom = String(btn.dataset.symptom || '').trim();
            applyTemporaryFlow(symptom);
        });
    });

    document.getElementById('mioAskForm')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const area = document.getElementById('mioQuestion');
        const question = String(area?.value || '').trim();
        if (!question) {
            showToast('質問を入力してください。', 'info');
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

function setAudience(audience) {
    currentAudience = audience === 'temporary' ? 'temporary' : 'professional';
    localStorage.setItem(AUDIENCE_KEY, currentAudience);
    document.body.dataset.audience = currentAudience;
    document.getElementById('audienceProfessional')?.classList.toggle('active', currentAudience === 'professional');
    document.getElementById('audienceTemporary')?.classList.toggle('active', currentAudience === 'temporary');
    updateElement('audienceSummary', currentAudience === 'temporary'
        ? 'Temporary mode highlights user guidance, safe next steps, and suppresses dangerous controls'
        : 'Professional mode shows deeper evidence, review status, and operator control context');
    if (currentAudience === 'temporary') {
        applyTemporaryFlow('wifi', false);
    }
    applyAudienceControlPolicy();
}

function applyAudienceControlPolicy() {
    const temporary = currentAudience === 'temporary';
    ['modePortalBtn', 'modeShieldBtn', 'modeScapegoatBtn'].forEach((id) => {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.disabled = temporary;
        btn.title = temporary ? 'Gateway mode changes are disabled in Temporary mode.' : '';
    });
}

function applyTemporaryFlow(symptom, triggerAsk = true) {
    const selected = temporaryFlows[symptom] ? symptom : 'wifi';
    const flow = temporaryFlows[selected];
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
        showToast(`Dashboard refresh failed: ${hardFailures.join(' | ')}`, 'error');
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

    try {
        updateHeader(state, mattermost);
        updateCommandStrip(summary, health, failures);
        updateSituationBoard(summary, state, health, mattermost);
        updateActionBoard(actions, state);
        updateEvidenceBoard(evidence, health);
        updateAssistant(actions, mattermost, capabilities);
        updateControlButtons(summary, state);
        if (demoOverlayResult) {
            applyDemoOverlay(demoOverlayResult);
        }
    } catch (error) {
        console.error('Dashboard render failed:', error);
        showToast(`Dashboard render failed: ${error.message}`, 'error');
        return;
    }

    if (failures.length > 0) {
        const warning = `Partial refresh: ${failures.join(' | ')}`;
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
            select.innerHTML = '<option value="">No scenarios available</option>';
            updateElement('demoScenarioDescription', 'No scenario is currently available.');
            return;
        }
        select.innerHTML = demoScenarioItems
            .map((item) => `<option value="${escapeAttribute(item.scenario_id)}">${escapeHtml(item.scenario_id)}</option>`)
            .join('');
        updateDemoScenarioDescription();
    } catch (error) {
        select.innerHTML = '<option value="">Failed to load scenarios</option>';
        updateElement('demoScenarioDescription', `Failed to load scenarios: ${error.message}`);
    }
}

function updateDemoScenarioDescription() {
    const select = document.getElementById('demoScenarioSelect');
    const selected = String(select?.value || '').trim();
    const item = demoScenarioItems.find((row) => row.scenario_id === selected) || demoScenarioItems[0];
    if (!item) {
        updateElement('demoScenarioDescription', 'No scenario selected.');
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
        showToast('Scenario is required.', 'info');
        return;
    }
    if (submit) submit.disabled = true;
    updateElement('demoResponse', 'Running demo scenario...');
    updateElement('demoOperatorWording', 'Preparing scenario replay...');
    updateElement('demoNocStatus', '-');
    updateElement('demoSocStatus', '-');
    updateElement('demoAction', '-');
    updateElement('demoReason', '-');
    renderList('demoNextChecks', ['Waiting for scenario output'], (item) => item);
    renderList('demoEvidenceIds', ['Waiting for scenario output'], (item) => item);
    renderList('demoRejectedAlternatives', ['Waiting for scenario output'], (item) => item);
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
        updateElement('demoOperatorWording', result.explanation?.operator_wording || 'No explanation returned.');
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
        showToast(`Demo completed: ${scenarioId}`, 'success');
    } catch (error) {
        updateElement('demoResponse', `Demo failed: ${error.message}`);
        updateElement('demoStatusBadge', 'FAILED');
        updateElement('demoOperatorWording', `Scenario replay failed: ${error.message}`);
        if (statusBadge) statusBadge.className = 'assistant-status status-danger';
        showToast(`Demo failed: ${error.message}`, 'error');
    } finally {
        if (submit) submit.disabled = false;
    }
}

async function clearDemoOverlay() {
    if (!demoOverlayResult) {
        showToast('No demo overlay is active.', 'info');
        return;
    }
    try {
        await fetchJson('/api/demo/overlay/clear', { method: 'POST' });
        demoOverlayResult = null;
        setDemoOverlayVisualState(false);
        updateElement('demoStatusBadge', 'READY');
        const statusBadge = document.getElementById('demoStatusBadge');
        if (statusBadge) statusBadge.className = 'assistant-status status-neutral';
        await refreshDashboard();
        showToast('Demo overlay cleared.', 'success');
    } catch (error) {
        showToast(`Failed to clear demo overlay: ${error.message}`, 'error');
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
    updateElement('demoOperatorWording', operatorWording || 'No explanation returned.');
    renderList('demoNextChecks', nextChecks.length ? nextChecks : ['No next checks'], (item) => item);
    renderList('demoEvidenceIds', evidenceIds.length ? evidenceIds : ['No evidence ids'], (item) => item);
    renderList('demoRejectedAlternatives', rejected.length ? rejected : ['No rejected alternatives'], (item) =>
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

    updateElement('commandStripNote', `Demo overlay active: ${scenarioId}. ${description || 'Synthetic scenario replay.'}`);
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
    updateElement('postureRecommendation', `Demo selected ${action} because ${reason}.`);
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

    renderList('whyNowList', [
        `Scenario ${scenarioId} is active.`,
        `NOC status: ${nocStatus}.`,
        `SOC status: ${socStatus}.`,
        `Reason: ${reason}.`,
    ], (item) => item);
    renderList('nextActionsList', nextChecks.length ? nextChecks : [`Review ${action} path for ${scenarioId}.`], (item) => item);
    renderList('doNotDoList', ['Do not treat demo output as live telemetry.', 'Do not change gateway mode based on demo data alone.'], (item) => item);
    renderList('escalateIfList', [`Move to ops review if the same pattern appears in live telemetry.`], (item) => item);
    updateElement('userGuidanceText', `Demo overlay active. Current simulated action is ${action}.`);
    updateElement('runbookTitle', 'Demo scenario summary');
    updateElement('runbookId', scenarioId);
    updateElement('runbookEffect', 'display_only');
    updateElement('runbookApproval', 'Not applicable');
    renderList('runbookSteps', nextChecks.length ? nextChecks : ['Inspect explanation output', 'Compare with live telemetry before acting'], (item) => item);

    renderTimeline('currentTriggersTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'demo',
            title: `Scenario ${scenarioId}`,
            detail: description || 'Synthetic demo scenario replay',
        },
    ], (item) => item);
    renderTimeline('decisionChangesTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'arbiter',
            title: `${action} selected`,
            detail: reason || 'No reason provided',
        },
    ], (item) => item);
    renderTimeline('operatorInteractionsTimeline', [
        {
            ts_iso: result.ts || raw.explanation?.ts || '-',
            kind: 'demo',
            title: 'Demo overlay applied to dashboard',
            detail: 'Display state is synthetic until cleared.',
        },
    ], (item) => item);
    renderTimeline('backgroundHistoryTimeline', rejected, (item) => ({
        ts_iso: result.ts || raw.explanation?.ts || '-',
        kind: 'rejected',
        title: item.action || '-',
        detail: item.reason || '-',
    }));
    updateElement('healthSummaryLine', `Demo overlay active | scenario=${scenarioId} | action=${action} | evidence=${evidenceIds.length}`);

    updateElement('mioCurrentAnswer', `Demo overlay active for ${scenarioId}. ${operatorWording}`.trim());
    updateElement('mioRecommendation', `Demo scenario ${scenarioId} selected ${action}.`);
    updateElement('mioLastAsk', `Demo scenario replay | ${scenarioId}`);
    updateElement('mioRunbookSummary', `Scenario ${scenarioId} | display_only`);
    renderList('mioRationaleList', [
        `Demo scenario: ${scenarioId}`,
        `NOC=${nocStatus}, SOC=${socStatus}`,
        `Arbiter action=${action}`,
        `Reason=${reason}`,
    ], (item) => item);
    updateElement('mioUserGuidance', `This is a demo overlay. Compare it against live telemetry before acting.`);
    updateElement('mioReview', 'demo-overlay');
    const mioStatusBadge = document.getElementById('mioStatusBadge');
    if (mioStatusBadge) {
        mioStatusBadge.textContent = 'DEMO';
        mioStatusBadge.className = 'assistant-status status-demo';
    }
}

async function fetchJson(path, options = {}) {
    const headers = Object.assign({}, options.headers || {}, { 'X-Auth-Token': AUTH_TOKEN });
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
        ? 'One or more dashboard inputs are stale. Verify control-plane freshness before acting.'
        : 'Dashboard inputs are live and in sync with current control-plane state.';
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

function updateActionBoard(actions, state) {
    renderList('whyNowList', actions.why_now || [], (item) => item);
    renderList('nextActionsList', actions.do_next || actions.current_operator_actions || [], (item) => item);
    renderList('doNotDoList', actions.do_not_do || [], (item) => item);
    renderList('escalateIfList', actions.escalate_if || [], (item) => item);
    updateElement('userGuidanceText', actions.current_user_guidance || '-');

    const runbook = actions.suggested_runbook || {};
    updateElement('runbookTitle', runbook.title || '-');
    updateElement('runbookId', runbook.id || '-');
    updateElement('runbookEffect', runbook.effect || '-');
    updateElement('runbookApproval', actions.approval_required ? 'Required' : 'Not required');
    renderList('runbookSteps', runbook.steps || [], (item) => item);

    const mode = latestState.mode || {};
    updateElement('modeLastChange', formatHumanDateTime(mode.last_change));
    updateElement('modeRequestedBy', mode.requested_by || '-');

    const portalBtn = document.getElementById('portalAssistBtn');
    if (portalBtn) {
        const portalViewer = latestState.portal_viewer || {};
        portalBtn.disabled = !portalViewer.url;
        portalBtn.textContent = portalViewer.ready ? 'Portal Assist' : 'Portal Assist (prep)';
    }
}

function updateEvidenceBoard(evidence, health) {
    const currentTriggers = Array.isArray(evidence.current_triggers) && evidence.current_triggers.length
        ? evidence.current_triggers
        : [{
            ts_iso: latestState.timestamps?.snapshot_at || '-',
            kind: 'state',
            title: 'No active trigger',
            detail: 'No current trigger is keeping the dashboard outside normal monitoring.',
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

    const stale = health.stale_flags || {};
    const idle = health.idle_flags || {};
    updateElement('healthSummaryLine', `Queue ${health.queue?.depth ?? 0}/${health.queue?.capacity ?? 0} | fallback ${(health.llm?.fallback_rate ?? 0)} | stale snapshot=${stale.snapshot ? 'yes' : 'no'} ai=${stale.ai_metrics ? 'yes' : 'no'} | idle ai=${idle.ai_activity ? 'yes' : 'no'} runbook=${idle.runbook_events ? 'yes' : 'no'}`);
}

function updateAssistant(actions, mattermost, capabilities) {
    const mio = actions.mio || {};
    updateElement('mioCurrentAnswer', mio.answer || actions.current_recommendation || '-');
    updateElement('mioRecommendation', actions.current_recommendation || '-');
    const askedAt = mio.asked_at ? formatHumanDateTime(mio.asked_at) : '';
    const lastAsk = mio.question
        ? `${mio.question}${askedAt ? ` | ${askedAt}` : ''}${mio.source ? ` | ${mio.source}` : ''}`
        : 'No manual query executed yet.';
    updateElement('mioLastAsk', lastAsk);
    const mioRunbook = mio.runbook || actions.suggested_runbook || {};
    const runbookSummary = mioRunbook.title
        ? `${mioRunbook.title}${mioRunbook.id ? ` | ${mioRunbook.id}` : ''}${mioRunbook.effect ? ` | ${mioRunbook.effect}` : ''}`
        : 'No runbook selected.';
    updateElement('mioRunbookSummary', runbookSummary);
    renderList('mioRationaleList', mio.rationale || [], (item) => item);
    updateElement('mioUserGuidance', actions.current_user_guidance || '-');
    updateElement('mioReview', mio.review?.final_status || 'No review data');
    updateElement('mattermostState', mattermost.reachable ? 'reachable' : 'unreachable');
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
    if (responseBox) responseBox.textContent = 'M.I.O. is analyzing...';

    try {
        const result = await fetchJson('/api/ai/ask', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                question,
                sender: 'Dashboard',
                source: 'dashboard',
                context: Object.assign({ audience: currentAudience }, extraContext),
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
        if (!silent) showToast('M.I.O. response received', 'success');
        return result;
    } catch (error) {
        if (responseBox) responseBox.textContent = `M.I.O. request failed: ${error.message}`;
        if (!silent) showToast(`M.I.O. request failed: ${error.message}`, 'error');
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
