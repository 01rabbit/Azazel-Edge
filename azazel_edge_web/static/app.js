const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const AUDIENCE_KEY = 'azazel_dashboard_audience';
const POLL_INTERVAL_MS = 4000;

let dashboardTimer = null;
let currentAudience = localStorage.getItem(AUDIENCE_KEY) || 'professional';
let latestState = {};
let latestMattermost = {};

const shortcutQuestions = {
    wifi: 'Wi-Fi に繋がらない利用者へどう案内するか',
    dns: 'DNS が引けない時に何を確認するか',
    route: 'gateway と uplink の異常時に何を確認するか',
    service: 'service の異常時に何を確認するか',
};

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
}

async function refreshDashboard() {
    try {
        const [summary, actions, evidence, health, state, mattermost, capabilities] = await Promise.all([
            fetchJson('/api/dashboard/summary'),
            fetchJson('/api/dashboard/actions'),
            fetchJson('/api/dashboard/evidence'),
            fetchJson('/api/dashboard/health'),
            fetchJson('/api/state'),
            fetchJson('/api/mattermost/status'),
            fetchJson('/api/ai/capabilities'),
        ]);

        latestState = state || {};
        latestMattermost = mattermost || {};

        updateHeader(state, mattermost);
        updateCommandStrip(summary, health);
        updateSituationBoard(summary, state, health, mattermost);
        updateActionBoard(actions, state);
        updateEvidenceBoard(evidence, health);
        updateAssistant(actions, mattermost, capabilities);
        updateControlButtons(summary, state);
    } catch (error) {
        console.error('Dashboard refresh failed:', error);
        showToast(`Dashboard refresh failed: ${error.message}`, 'error');
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

function updateCommandStrip(summary, health) {
    const strip = summary.command_strip || {};
    updateElement('stripMode', String(strip.current_mode || '--').toUpperCase());
    updateElement('stripRisk', summary.risk?.user_state || '--');
    updateElement('stripUplink', strip.current_uplink || '--');
    updateElement('stripInternet', strip.internet_reachability || '--');
    updateElement('stripCritical', String(strip.direct_critical_count ?? 0));
    updateElement('stripDeferred', String(strip.deferred_count ?? 0));
    updateElement('stripQueue', `${health.queue?.depth ?? 0} / ${health.queue?.capacity ?? 0}`);
    updateElement('stripStale', strip.stale_warning ? 'YES' : 'NO');
    updateElement('commandStripNote', strip.stale_warning
        ? 'One or more dashboard inputs are stale. Verify control-plane freshness before acting.'
        : 'Dashboard inputs are live and in sync with current control-plane state.');
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
    renderList('nextActionsList', actions.current_operator_actions || [], (item) => item);
    updateElement('userGuidanceText', actions.current_user_guidance || '-');

    const runbook = actions.suggested_runbook || {};
    updateElement('runbookTitle', runbook.title || '-');
    updateElement('runbookId', runbook.id || '-');
    updateElement('runbookEffect', runbook.effect || '-');
    updateElement('runbookApproval', actions.approval_required ? 'Required' : 'Not required');
    renderList('runbookSteps', runbook.steps || [], (item) => item);

    const mode = latestState.mode || {};
    updateElement('modeLastChange', mode.last_change || '-');
    updateElement('modeRequestedBy', mode.requested_by || '-');

    const portalBtn = document.getElementById('portalAssistBtn');
    if (portalBtn) {
        const portalViewer = latestState.portal_viewer || {};
        portalBtn.disabled = !portalViewer.url;
        portalBtn.textContent = portalViewer.ready ? 'Portal Assist' : 'Portal Assist (prep)';
    }
}

function updateEvidenceBoard(evidence, health) {
    renderTimeline('alertsTimeline', evidence.recent_alerts || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: `SID ${item.sid || 0}`,
        title: `${item.attack_type || 'alert'} [${item.risk_level || 'UNKNOWN'}]`,
        detail: `${item.src_ip || '-'} -> ${item.dst_ip || '-'} | score=${item.risk_score ?? 0} | ${item.recommendation || '-'}`,
    }));

    renderTimeline('aiTimeline', evidence.recent_ai_activity || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.status || item.kind || '-',
        title: item.question || item.answer || '-',
        detail: `${item.model || '-'} | runbook=${item.runbook_id || '-'} | ${item.user_message || item.answer || '-'}`,
    }));

    renderTimeline('runbookTimeline', evidence.recent_runbook_events || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.review_status || '-',
        title: `${item.action || '-'} ${item.runbook_id || '-'}`,
        detail: `${item.actor || '-'} | ok=${item.ok} | ${item.effect || '-'}`,
    }));

    renderTimeline('modeTimeline', evidence.recent_mode_changes || [], (item) => ({
        metaLeft: item.last_change || '-',
        metaRight: item.requested_by || '-',
        title: `mode=${item.current_mode || '-'}`,
        detail: item.source || '-',
    }));

    const stale = health.stale_flags || {};
    updateElement('healthSummaryLine', `Queue ${health.queue?.depth ?? 0}/${health.queue?.capacity ?? 0} | fallback ${(health.llm?.fallback_rate ?? 0)} | stale snapshot=${stale.snapshot ? 'yes' : 'no'} ai=${stale.ai_metrics ? 'yes' : 'no'}`);
}

function updateAssistant(actions, mattermost, capabilities) {
    const mio = actions.mio || {};
    updateElement('mioCurrentAnswer', mio.answer || actions.current_recommendation || '-');
    updateElement('mioRecommendation', actions.current_recommendation || '-');
    updateElement('mioUserGuidance', actions.current_user_guidance || '-');
    updateElement('mioReview', mio.review?.final_status || 'No review data');
    updateElement('mattermostState', mattermost.reachable ? 'reachable' : 'unreachable');
    updateElement('mattermostTriggers', joinList(mattermost.command_triggers || capabilities.mattermost_triggers || []));

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
    const submit = document.getElementById('mioAskSubmit');
    const responseBox = document.getElementById('mioAskResponse');
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
                context: { audience: currentAudience },
            }),
        });
        const review = result.runbook_review?.final_status ? ` | review=${result.runbook_review.final_status}` : '';
        const runbook = result.runbook_id ? ` | runbook=${result.runbook_id}` : '';
        if (responseBox) {
            responseBox.textContent = `${result.answer || '-'}${runbook}${review}\n\nUser Guidance: ${result.user_message || '-'}`;
        }
        updateElement('mioCurrentAnswer', result.answer || '-');
        updateElement('mioUserGuidance', result.user_message || '-');
        updateElement('mioReview', result.runbook_review?.final_status || 'No review data');
        const statusBadge = document.getElementById('mioStatusBadge');
        if (statusBadge) {
            statusBadge.textContent = String(result.status || 'completed').toUpperCase();
            statusBadge.className = `assistant-status ${toneForStatus(result.status || 'completed')}`;
        }
        showToast('M.I.O. response received', 'success');
    } catch (error) {
        if (responseBox) responseBox.textContent = `M.I.O. request failed: ${error.message}`;
        showToast(`M.I.O. request failed: ${error.message}`, 'error');
    } finally {
        if (submit) submit.disabled = false;
    }
}

function renderList(id, items, formatter) {
    const el = document.getElementById(id);
    if (!el) return;
    const rows = Array.isArray(items) && items.length ? items : ['No data'];
    el.innerHTML = rows.map((item) => `<li>${escapeHtml(formatter(item))}</li>`).join('');
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
