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

function renderRoleSummary(counts) {
    const target = document.getElementById('topoRoleSummary');
    if (!target) return;
    target.innerHTML = [
        { label: 'Network Devices', value: counts.network_device_count },
        { label: 'Servers', value: counts.server_count },
        { label: 'Unknown', value: counts.unknown_count },
    ].map((item) => `
        <div class="strip-pill">
            <span class="strip-label">${item.label}</span>
            <strong>${item.value ?? 0}</strong>
        </div>
    `).join('');
}

function renderHighEvents(items) {
    const target = document.getElementById('topoHighEventList');
    if (!target) return;
    if (!items.length) {
        target.innerHTML = '<article class="topo-lite-event-card"><strong>No high-severity events.</strong></article>';
        return;
    }
    target.innerHTML = items.map((item) => `
        <article class="topo-lite-event-card topo-lite-event-${item.severity}">
            <div class="topo-lite-event-head">
                <span class="topo-lite-severity-ring severity-${item.severity}"></span>
                <div>
                    <strong>${item.event_type}</strong>
                    <p>${item.summary}</p>
                </div>
            </div>
            <div class="panel-note">${item.created_at} · ${(item.host && (item.host.hostname || item.host.ip)) || 'unknown host'}</div>
        </article>
    `).join('');
}

function renderRecentEvents(items) {
    const target = document.getElementById('topoRecentEventList');
    if (!target) return;
    if (!items.length) {
        target.innerHTML = '<article class="topo-lite-event-card"><strong>No recent events.</strong></article>';
        return;
    }
    target.innerHTML = items.map((item) => `
        <article class="topo-lite-event-card topo-lite-event-compact">
            <div class="topo-lite-event-head">
                <span class="topo-lite-severity-ring severity-${item.severity}"></span>
                <div>
                    <strong>${item.event_type}</strong>
                    <p>${item.summary}</p>
                </div>
            </div>
        </article>
    `).join('');
}

function renderSubnets(items) {
    const target = document.getElementById('topoSubnetGrid');
    if (!target) return;
    if (!items.length) {
        target.innerHTML = '<article class="topo-lite-subnet-card"><strong>No subnet data available.</strong></article>';
        return;
    }
    target.innerHTML = items.map((subnet) => `
        <article class="topo-lite-subnet-card">
            <div class="topo-lite-subnet-head">
                <div>
                    <strong>${subnet.subnet}</strong>
                    <p>${subnet.hosts.length} hosts · ${subnet.service_count} visible services</p>
                </div>
            </div>
            <div class="topo-lite-host-grid">
                ${subnet.hosts.map((host) => `
                    <div class="topo-lite-host-tile role-${host.role || 'unknown'}">
                        <div class="topo-lite-host-mark">${host.monogram}</div>
                        <div class="topo-lite-host-copy">
                            <strong>${host.label}</strong>
                            <span>${host.ip}</span>
                            <span>${host.role || 'unknown'} · ${host.status || 'unknown'}</span>
                        </div>
                        <div class="topo-lite-chip-row">
                            ${host.services.map((service) => `<span class="topo-lite-chip">${service}</span>`).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        </article>
    `).join('');
}

function renderRuns(items) {
    const target = document.getElementById('topoRunList');
    if (!target) return;
    if (!items.length) {
        target.innerHTML = '<div class="panel-note">No scan history available.</div>';
        return;
    }
    target.innerHTML = items.map((item) => `
        <article class="topo-lite-run-card">
            <strong>${item.scan_kind}</strong>
            <span>${item.status}</span>
            <span>${item.started_at}</span>
        </article>
    `).join('');
}

function renderPrompts(items, caveats) {
    renderList('topoAiPromptList', items, (item) => `<li>${item}</li>`);
    renderList('topoAiCaveatList', caveats, (item) => `<li>${item}</li>`);
}

function renderIrActions(payload) {
    const actions = [];
    if (payload.topo_lite.data_mode?.synthetic) {
        actions.push('Synthetic mode is active. Confirm UI behavior before switching back to live evidence.');
    }
    if ((payload.topo_lite.counts?.high_events || 0) > 0) {
        actions.push('Review the highlighted high-severity service changes and confirm whether they are expected internal-LAN transitions.');
    }
    actions.push('Use the NOC section to confirm segment placement and the SOC section to confirm event chronology.');
    actions.push('If the board looks unexpectedly empty, verify `br0` reachability and then decide whether to seed the sample dataset.');
    renderList('topoIrActionList', actions, (item) => `<li>${item}</li>`);
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

    renderBanner(dataMode);
    updateText('topoBoardMode', payload.status || '-');
    updateText('topoBoardHosts', `${counts.host_total ?? 0}`);
    updateText('topoBoardFreshness', freshness.started_at || freshness.finished_at || '-');
    updateText('topoBoardSubnet', (board.config?.subnets || []).join(', ') || '-');
    updateText('topoBoardInterface', board.config?.interface || '-');
    updateText('topoBoardDataMode', dataMode.synthetic ? 'synthetic' : 'live');

    updateText('topoOverallHeadline', payload.status === 'synthetic' ? 'Synthetic internal-LAN board' : 'Internal-LAN board ready');
    updateText('topoOverallSummary', payload.summary || '-');
    updateText('topoHostTotal', counts.host_total ?? 0);
    updateText('topoServiceTotal', counts.service_total ?? 0);
    updateText('topoHighEvents', counts.high_events ?? 0);
    updateText('topoSubnetTotal', counts.subnet_total ?? 0);

    renderRoleSummary(counts);
    renderHighEvents(board.high_events || []);
    renderRecentEvents(board.recent_events || []);
    renderSubnets(board.subnets || []);
    renderRuns(board.scan_runs || []);
    renderIrActions(payload);
    renderPrompts(board.ai_support?.prompts || [], board.ai_support?.caveats || []);
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
