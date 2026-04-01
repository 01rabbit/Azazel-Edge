const TOPO_BOARD_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const TOPO_BOARD_LANG = window.AZAZEL_LANG || localStorage.getItem('azazel_lang') || 'ja';
const TOPO_BOARD_REFRESH_MS = 5000;

let topoBoardTimer = null;

function topoBoardHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Auth-Token': TOPO_BOARD_TOKEN,
        'X-AZAZEL-LANG': TOPO_BOARD_LANG,
    };
}

async function topoBoardFetch(path) {
    const response = await fetch(path, { headers: topoBoardHeaders() });
    const payload = await response.json().catch(() => ({ ok: false, error: 'invalid_json' }));
    if (!response.ok) {
        throw new Error(payload.error || payload.message || `HTTP ${response.status}`);
    }
    return payload;
}

function updateText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = String(value ?? '-');
}

function renderList(id, items, formatter) {
    const element = document.getElementById(id);
    if (!element) return;
    if (!Array.isArray(items) || !items.length) {
        element.innerHTML = '<li>No data.</li>';
        return;
    }
    element.innerHTML = items.map((item) => formatter(item)).join('');
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderBanner(dataMode) {
    const banner = document.getElementById('topoDataBanner');
    const title = document.getElementById('topoDataBannerTitle');
    const text = document.getElementById('topoDataBannerText');
    if (!banner || !title || !text) return;
    if (!dataMode?.synthetic) {
        banner.hidden = true;
        return;
    }
    banner.hidden = false;
    title.textContent = dataMode.label || 'Synthetic internal LAN sample';
    text.textContent = `Scenario ${dataMode.scenario || '-'} is active. Topology and timeline are deterministic and should not be treated as live evidence.`;
}

function setPillTone(id, tone) {
    const element = document.getElementById(id);
    const pill = element ? element.closest('.strip-pill, .freshness-pill') : null;
    if (!pill) return;
    pill.classList.remove('pill-safe', 'pill-caution', 'pill-danger');
    if (tone === 'safe' || tone === 'caution' || tone === 'danger') {
        pill.classList.add(`pill-${tone}`);
    }
}

function renderRoleSummary(counts) {
    const target = document.getElementById('topoRoleSummary');
    if (!target) return;
    target.innerHTML = [
        { label: 'Network Devices', value: counts.network_device_count },
        { label: 'Servers', value: counts.server_count },
        { label: 'Unknown', value: counts.unknown_count },
    ].map((item) => `
        <div class="strip-pill">
            <span class="strip-label">${escapeHtml(item.label)}</span>
            <strong>${escapeHtml(String(item.value ?? 0))}</strong>
        </div>
    `).join('');
}

function renderSubnets(items) {
    const target = document.getElementById('topoSubnetGrid');
    if (!target) return;
    if (!items.length) {
        target.innerHTML = '<div class="client-identity-empty">No subnet data available.</div>';
        return;
    }
    target.innerHTML = items.map((subnet) => `
        <article class="topo-lite-inline-cluster">
            <div class="topo-lite-inline-cluster-head">
                <strong>${escapeHtml(subnet.subnet)}</strong>
                <span class="client-identity-row-state ${Number(subnet.service_count || 0) > 0 ? 'status-safe' : 'status-neutral'}">${escapeHtml(String(subnet.hosts.length || 0))} hosts</span>
            </div>
            <div class="client-identity-chip-grid">
                ${subnet.hosts.map((host) => `
                    <span class="client-identity-chip">
                        <span class="client-identity-chip-label">${escapeHtml(host.monogram || '--')}</span>
                        <span>${escapeHtml(host.label || host.hostname || host.ip || '-')}</span>
                    </span>
                `).join('')}
            </div>
        </article>
    `).join('');
}

function renderRuns(items) {
    renderList(
        'topoRunList',
        items.length ? items.slice(0, 6).map((item) => `${item.scan_kind || '-'} | ${item.status || '-'} | ${item.started_at || '-'}`) : ['No scan history available.'],
        (item) => `<li>${escapeHtml(item)}</li>`,
    );
}

function renderIrActions(payload) {
    const actions = [];
    if (payload.topo_lite?.data_mode?.synthetic) {
        actions.push('Synthetic mode is active. Confirm UI behavior before switching back to live evidence.');
    }
    if ((payload.topo_lite?.counts?.high_events || 0) > 0) {
        actions.push('Review the highlighted high-severity service changes and confirm whether they are expected internal-LAN transitions.');
    }
    actions.push('Use this page to confirm segment placement, recent change chronology, and operator guidance in one dashboard style.');
    actions.push('If the board looks empty, verify internal-LAN reachability before seeding sample data again.');
    renderList('topoIrActionList', actions, (item) => `<li>${escapeHtml(item)}</li>`);
}

function renderBoard(payload) {
    if (!payload?.ok) {
        updateText('topoOverallHeadline', 'Topo-Lite board unavailable');
        updateText('topoOverallSummary', payload?.summary || payload?.error || 'No payload.');
        return;
    }

    const board = payload.topo_lite || {};
    const counts = board.counts || {};
    const dataMode = board.data_mode || {};
    const freshness = board.freshness || {};
    const severity = board.severity_counts || {};

    renderBanner(dataMode);
    updateText('topoBoardMode', payload.status || '-');
    updateText('topoBoardHosts', `${counts.host_total ?? 0}`);
    updateText('topoBoardFreshness', freshness.started_at || freshness.finished_at || '-');
    updateText('topoBoardFreshnessBody', freshness.started_at || freshness.finished_at || '-');
    updateText('topoBoardSubnet', (board.config?.subnets || []).join(', ') || '-');
    updateText('topoBoardInterface', board.config?.interface || '-');
    updateText('topoBoardDataMode', dataMode.synthetic ? 'synthetic' : 'live');

    updateText('topoOverallHeadline', payload.status === 'synthetic' ? 'Synthetic internal-LAN board' : 'Internal-LAN board ready');
    updateText('topoOverallSummary', payload.summary || '-');
    updateText('topoHostTotal', counts.host_total ?? 0);
    updateText('topoServiceTotal', counts.service_total ?? 0);
    updateText('topoHighEvents', counts.high_events ?? 0);
    updateText('topoSubnetTotal', counts.subnet_total ?? 0);

    setPillTone('topoBoardMode', dataMode.synthetic ? 'caution' : 'safe');
    setPillTone('topoBoardDataMode', dataMode.synthetic ? 'caution' : 'safe');
    setPillTone('topoHighEvents', Number(counts.high_events || 0) > 0 ? 'danger' : (Number(counts.medium_events || 0) > 0 ? 'caution' : 'safe'));

    renderRoleSummary(counts);

    renderList(
        'topoHighEventList',
        (board.high_events || []).length ? board.high_events.slice(0, 6).map((item) => {
            const host = item.host && typeof item.host === 'object' ? item.host : {};
            return `${String(item.severity || 'info').toUpperCase()} | ${item.event_type || '-'} | ${host.hostname || host.ip || '-'} | ${item.summary || '-'}`;
        }) : ['No high-severity events.'],
        (item) => `<li>${escapeHtml(item)}</li>`,
    );

    renderList(
        'topoRecentEventList',
        (board.recent_events || []).length ? board.recent_events.slice(0, 8).map((item) => {
            const host = item.host && typeof item.host === 'object' ? item.host : {};
            return `${item.event_type || '-'} | ${host.hostname || host.ip || '-'} | ${item.created_at || '-'}`;
        }) : ['No recent events.'],
        (item) => `<li>${escapeHtml(item)}</li>`,
    );

    renderSubnets(board.subnets || []);
    renderRuns(board.scan_runs || []);
    renderIrActions(payload);

    renderList(
        'topoAiPromptList',
        (board.ai_support?.prompts || []).length ? board.ai_support.prompts : ['Waiting for board synthesis.'],
        (item) => `<li>${escapeHtml(item)}</li>`,
    );
    renderList(
        'topoAiCaveatList',
        (board.ai_support?.caveats || []).length ? board.ai_support.caveats : ['No caveats yet.'],
        (item) => `<li>${escapeHtml(item)}</li>`,
    );

    updateText('topoSeverityHigh', severity.high ?? counts.high_events ?? 0);
    updateText('topoSeverityMedium', severity.medium ?? counts.medium_events ?? 0);
    updateText('topoSeverityLow', severity.low ?? counts.low_events ?? 0);
}

async function refreshTopoLiteBoard() {
    try {
        const payload = await topoBoardFetch('/api/topo-lite/board');
        renderBoard(payload);
    } catch (error) {
        renderBoard({ ok: false, summary: String(error) });
    }
}

function switchLanguage(lang) {
    const next = lang === 'en' ? 'en' : 'ja';
    localStorage.setItem('azazel_lang', next);
    const url = new URL(window.location.href);
    url.searchParams.set('lang', next);
    window.location.assign(url.toString());
}

function bindLanguageButtons() {
    document.getElementById('langJaBtn')?.addEventListener('click', () => switchLanguage('ja'));
    document.getElementById('langEnBtn')?.addEventListener('click', () => switchLanguage('en'));
}

async function initTopoLiteBoard() {
    bindLanguageButtons();
    await refreshTopoLiteBoard();
    topoBoardTimer = window.setInterval(refreshTopoLiteBoard, TOPO_BOARD_REFRESH_MS);
}

window.addEventListener('beforeunload', () => {
    if (topoBoardTimer) {
        window.clearInterval(topoBoardTimer);
    }
});

initTopoLiteBoard();
