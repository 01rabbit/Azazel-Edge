// Azazel-Edge Web UI Frontend
// Polls /api/state every 2 seconds

const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
let updateInterval;
let portalViewerOpening = false;
let portalReprobeRunning = false;
let modeSwitchInFlight = false;
let eventSource = null;
let unreadEventCount = 0;
let lastEventSourceErrorToastAt = 0;
const eventDedupMap = new Map();
const EVENT_DEDUP_WINDOW_MS = 12000;
const EVENT_LOG_MAX_ITEMS = 50;
let caCertificateDownloadUrl = '/api/certs/azazel-webui-local-ca.crt';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    fetchState();
    updateInterval = setInterval(fetchState, 2000); // Poll every 2 seconds
    initLiveNotifications();
    startEventStream();
});

window.addEventListener('beforeunload', () => {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
});

// Fetch state from API
async function fetchState() {
    try {
        const res = await fetch('/api/state', {
            headers: {
                'X-Auth-Token': AUTH_TOKEN
            }
        });
        const data = await res.json();
        
        if (!data.ok) {
            showToast(`Error: ${data.error}`, 'error');
            displayErrorState();
            return;
        }
        
        updateUI(data);
    } catch (e) {
        console.error('Failed to fetch state:', e);
        showToast('Connection error', 'error');
    }
}

// Update UI with state data
function updateUI(state) {
    // Map ui_snapshot.json fields to UI elements
    
    // Header
    updateElement('headerClock', state.now_time || '--:--:--');
    updateModeUI(state.mode || {}, state.mode_runtime || {});
    window.__lastStateMode = state.mode || {};
    
    // Risk Assessment (based on internal state)
    const internal = state.internal || {};
    const suspicion = internal.suspicion || 0;
    const stateVal = (internal.state_name || 'NORMAL').toUpperCase();
    
    // Update score circle
    const scoreCircle = document.getElementById('scoreCircle');
    scoreCircle.textContent = suspicion;
    
    const statusEl = document.getElementById('riskStatus');
    const cardEl = document.getElementById('cardRisk');
    const statusClass = getStatusClass(stateVal);
    
    scoreCircle.className = `score-circle ${statusClass}`;
    statusEl.className = `risk-status ${statusClass}`;
    statusEl.textContent = mapState(stateVal);
    cardEl.className = `card card-risk ${statusClass}`;

    // Toggle Contain/Release buttons based on state
    const containBtn = document.getElementById('containBtn');
    const releaseBtn = document.getElementById('releaseBtn');
    if (containBtn && releaseBtn) {
        if (stateVal === 'CONTAIN') {
            containBtn.style.display = 'none';
            releaseBtn.style.display = 'inline-flex';
        } else {
            containBtn.style.display = 'inline-flex';
            releaseBtn.style.display = 'none';
        }
    }
    
    // Threat level based on suspicion
    let threatLevel = 'LOW';
    if (suspicion >= 50) threatLevel = 'CRITICAL';
    else if (suspicion >= 30) threatLevel = 'HIGH';
    else if (suspicion >= 15) threatLevel = 'MEDIUM';
    updateElement('riskThreatLevel', threatLevel);
    
    updateElement('riskRecommendation', state.recommendation || '-');
    updateElement('riskReason', (state.reasons || [])[0] || '-');

    // Monitoring status
    const monitoring = state.monitoring || {};
    updateBadge('riskSuricata', monitoring.suricata || 'UNKNOWN');
    updateBadge('riskOpenCanary', monitoring.opencanary || 'UNKNOWN');
    updateBadge('riskNtfy', monitoring.ntfy || 'UNKNOWN');
    
    // Connection Info
    updateElement('connSSID', state.ssid || '-');
    updateElement('connBSSID', state.bssid || '-');
    updateElement('connGateway', state.gateway_ip || '-');
    updateElement('connSignal', `${state.signal_dbm || '-'} dBm`);
    
    // Wi-Fi Connection State
    const connection = state.connection || {};
    updateBadge('wifiState', connection.wifi_state || 'DISCONNECTED');
    updateBadge('usbNat', connection.usb_nat || 'OFF');
    updateBadge('internetCheck', connection.internet_check || 'UNKNOWN');
    
    // Captive Portal Warning
    const captivePortal = connection.captive_portal || 'NO';
    const captiveWarning = document.getElementById('captivePortalWarning');
    if (captivePortal === 'SUSPECTED' || captivePortal === 'YES') {
        captiveWarning.style.display = 'block';
    } else {
        captiveWarning.style.display = 'none';
    }

    const portalViewer = state.portal_viewer || {};
    const portalViewerRow = document.getElementById('portalViewerRow');
    const portalViewerBtn = document.getElementById('portalViewerBtn');
    const portalReprobeRow = document.getElementById('portalReprobeRow');
    const portalReprobeBtn = document.getElementById('portalReprobeBtn');
    const shouldShowPortalButton = (
        (captivePortal === 'SUSPECTED' || captivePortal === 'YES') &&
        portalViewer.url
    );
    if (portalViewerRow && portalViewerBtn) {
        if (shouldShowPortalButton) {
            portalViewerRow.style.display = 'flex';
            portalViewerBtn.dataset.url = portalViewer.url;
            if (!portalViewerOpening) {
                portalViewerBtn.disabled = false;
                if (portalViewer.ready) {
                    portalViewerBtn.textContent = '🧭 Open Portal';
                    portalViewerBtn.title = '';
                } else if (portalViewer.active) {
                    portalViewerBtn.textContent = '⏳ Preparing Portal';
                    portalViewerBtn.title = 'Portal viewer is starting';
                } else {
                    portalViewerBtn.textContent = '▶ Start & Open Portal';
                    portalViewerBtn.title = 'Start azazel-portal-viewer.service and open noVNC';
                }
            }
        } else {
            portalViewerRow.style.display = 'none';
            delete portalViewerBtn.dataset.url;
            portalViewerOpening = false;
            portalViewerBtn.disabled = false;
            portalViewerBtn.textContent = '🧭 Open Portal';
            portalViewerBtn.title = '';
        }
    }
    if (portalReprobeRow && portalReprobeBtn) {
        if (captivePortal === 'SUSPECTED' || captivePortal === 'YES') {
            portalReprobeRow.style.display = 'flex';
            if (!portalReprobeRunning) {
                portalReprobeBtn.disabled = false;
                portalReprobeBtn.textContent = '✅ Auth Done & Re-Probe';
                portalReprobeBtn.title = 'Run Re-Probe after portal login';
            }
        } else {
            portalReprobeRow.style.display = 'none';
            portalReprobeRunning = false;
            portalReprobeBtn.disabled = false;
            portalReprobeBtn.textContent = '✅ Auth Done & Re-Probe';
            portalReprobeBtn.title = '';
        }
    }
    
    // Control & Safety
    const degrade = state.degrade || {};
    updateBadge('ctrlDegrade', degrade.on ? 'ON' : 'OFF');
    updateBadge('ctrlQUIC', state.quic || 'ALLOWED');
    updateBadge('ctrlDoH', state.doh || 'BLOCKED');
    const downMbps = degrade.rate_mbps || 0;
    const upMbps = degrade.rate_mbps || 0;
    updateElement('ctrlSpeed', `${downMbps} / ${upMbps}`);
    
    // Security - Probe results
    const probe = state.probe || {};
    const probeStatus = probe.tls_total > 0 
        ? `${probe.tls_ok}/${probe.tls_total} ✓` + (probe.blocked > 0 ? ` (${probe.blocked} blocked)` : '')
        : '-';
    updateElement('ctrlProbe', probeStatus);
    
    // Security - IDS (Suricata alerts)
    const suricataCritical = state.suricata_critical || 0;
    const suricataWarning = state.suricata_warning || 0;
    let idsStatus = '-';
    if (suricataCritical > 0 || suricataWarning > 0) {
        const parts = [];
        if (suricataCritical > 0) parts.push(`${suricataCritical} critical`);
        if (suricataWarning > 0) parts.push(`${suricataWarning} warning`);
        idsStatus = parts.join(', ');
    }
    updateElement('ctrlIDS', idsStatus);

    // Security - Delay-to-Win (targeted canary response slowdown)
    const attack = state.attack || {};
    const delayActive = !!attack.canary_delay_active;
    const delayTargetCount = Number(attack.canary_delay_target_count || 0);
    let delayStatus = 'inactive';
    if (delayActive) {
        delayStatus = `ACTIVE (${delayTargetCount} target${delayTargetCount === 1 ? '' : 's'})`;
    } else if (stateVal === 'DECEPTION') {
        delayStatus = 'armed';
    }
    updateElement('ctrlCanaryDelay', delayStatus);
    
    // Evidence
    updateBadge('evidState', mapState(stateVal));
    updateElement('evidSuspicion', suspicion);
    
    // Scan Results - Channel congestion and AP count
    const channelCongestion = state.channel_congestion || 'unknown';
    const apCount = state.channel_ap_count || 0;
    const scanStatus = apCount > 0 
        ? `${apCount} APs (${channelCongestion})` 
        : '-';
    updateElement('evidScan', scanStatus);
    
    // Decision - State + Suspicion
    const decisionText = `State: ${mapState(stateVal)}, Suspicion: ${suspicion}`;
    updateElement('evidDecision', decisionText);
    
    // System Health Card
    updateElement('sysCPUTemp', `${state.temp_c || '--'}°C`);
    updateElement('sysCPUUsage', `${state.cpu_percent || '--'}%`);
    updateElement('sysMemUsage', `${state.mem_percent || '--'}%`);
    updateElement('headerCpuTemp', `${state.temp_c || '--'}°C`);
    updateElement('headerCpuUsage', `${state.cpu_percent || '--'}%`);
    updateElement('headerMemUsage', `${state.mem_percent || '--'}%`);
}

// Map state names between different systems
function mapState(state) {
    const map = {
        'NORMAL': 'SAFE',
        'PROBE': 'CHECKING',
        'DEGRADED': 'LIMITED',
        'CONTAIN': 'CONTAINED',
        'DECEPTION': 'DECEPTION',
        'INIT': 'CHECKING'
    };
    return map[state] || state;
}

// Get CSS class for status
function getStatusClass(status) {
    const lower = (status || '').toLowerCase();
    if (lower === 'normal') return 'normal';
    if (lower === 'probe') return 'degraded';
    if (lower === 'degraded') return 'degraded';
    if (lower === 'contain') return 'contained';
    if (lower === 'deception') return 'lockdown';
    return 'normal';
}

function formatModeTimestamp(raw) {
    if (!raw) return '-';
    const dt = new Date(raw);
    if (Number.isNaN(dt.getTime())) return String(raw);
    return dt.toLocaleString();
}

function modeDescription(modeName) {
    const mode = String(modeName || '').toLowerCase();
    if (mode === 'portal') return 'Outbound internet enabled; decoy OFF';
    if (mode === 'scapegoat') return 'Decoy ON (isolated), only allowlisted ports exposed';
    return 'Inbound(wlan): DROP ALL, decoy OFF';
}

function setModeBadge(modeName) {
    const el = document.getElementById('modeCurrent');
    if (!el) return;

    const mode = String(modeName || 'shield').toLowerCase();
    el.textContent = mode.toUpperCase();
    el.classList.remove('mode-portal', 'mode-shield', 'mode-scapegoat');
    if (mode === 'portal') el.classList.add('mode-portal');
    else if (mode === 'scapegoat') el.classList.add('mode-scapegoat');
    else el.classList.add('mode-shield');

    const portalBtn = document.getElementById('modePortalBtn');
    const shieldBtn = document.getElementById('modeShieldBtn');
    const scapegoatBtn = document.getElementById('modeScapegoatBtn');
    [portalBtn, shieldBtn, scapegoatBtn].forEach((btn) => {
        if (!btn) return;
        btn.classList.remove('active');
    });
    if (mode === 'portal' && portalBtn) portalBtn.classList.add('active');
    if (mode === 'shield' && shieldBtn) shieldBtn.classList.add('active');
    if (mode === 'scapegoat' && scapegoatBtn) scapegoatBtn.classList.add('active');
}

function updateModeUI(mode, runtime) {
    const current = String((mode || {}).current_mode || 'shield').toLowerCase();
    setModeBadge(current);
    updateElement('modeLastChange', formatModeTimestamp((mode || {}).last_change));
    updateElement('modeNote', modeDescription(current));

    const epdRuntime = (runtime || {}).epd_state || {};
    const switching = String(epdRuntime.mode || '').toLowerCase() === 'switching';
    const target = String(epdRuntime.target_mode || '').toLowerCase();
    const buttons = ['modePortalBtn', 'modeShieldBtn', 'modeScapegoatBtn']
        .map((id) => document.getElementById(id))
        .filter(Boolean);
    buttons.forEach((btn) => {
        btn.disabled = modeSwitchInFlight || switching;
    });

    if (switching && target) {
        updateElement('modeNote', `Switching -> ${target.toUpperCase()} ...`);
    }
}

function modeImpactText(targetMode) {
    const mode = String(targetMode || '').toLowerCase();
    if (mode === 'portal') {
        return 'Portal mode keeps usb0 internet NAT and disables decoy exposure on wlan0.';
    }
    if (mode === 'scapegoat') {
        return 'Scapegoat mode enables isolated OpenCanary exposure on allowlisted ports only.';
    }
    return 'Shield mode drops all inbound on wlan0 and keeps usb0 client internet path.';
}

async function switchMode(targetMode) {
    if (modeSwitchInFlight) {
        return;
    }

    const mode = String(targetMode || '').toLowerCase();
    if (!['portal', 'shield', 'scapegoat'].includes(mode)) {
        showToast(`Unknown mode: ${targetMode}`, 'error');
        return;
    }

    const current = String((window.__lastStateMode || {}).current_mode || '').toLowerCase();
    if (current === mode) {
        showToast(`Already in ${mode.toUpperCase()}`, 'info');
        return;
    }

    const confirmText = `${modeImpactText(mode)}\n\nSwitch ${current.toUpperCase() || '-'} -> ${mode.toUpperCase()} ?`;
    if (!window.confirm(confirmText)) {
        return;
    }

    modeSwitchInFlight = true;
    updateElement('modeNote', `Switching -> ${mode.toUpperCase()} ...`);
    ['modePortalBtn', 'modeShieldBtn', 'modeScapegoatBtn'].forEach((id) => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = true;
    });

    try {
        const res = await fetch('/api/mode', {
            method: 'POST',
            headers: {
                'X-Auth-Token': AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ mode, requested_by: 'webui' })
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            showToast(`Mode switch failed: ${data.error || 'unknown error'}`, 'error');
        } else {
            showToast(`Mode switched to ${mode.toUpperCase()}`, 'success');
        }
    } catch (e) {
        showToast(`Mode switch failed: ${e.message}`, 'error');
    } finally {
        modeSwitchInFlight = false;
        setTimeout(fetchState, 300);
    }
}

// Helper: Update element text
function updateElement(id, text) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = text;
    }
}

// Helper: Update badge with color
function updateBadge(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    
    el.textContent = value;
    
    // Remove all possible classes
    el.classList.remove('allowed', 'blocked', 'on', 'off', 'normal', 'degraded', 'contained', 'lockdown');
    
    // Add appropriate class
    const valueLower = value.toLowerCase();
    if (valueLower === 'allowed') {
        el.classList.add('allowed');
    } else if (valueLower === 'blocked') {
        el.classList.add('blocked');
    } else if (valueLower === 'on') {
        el.classList.add('on');
    } else if (valueLower === 'off') {
        el.classList.add('off');
    } else if (valueLower === 'normal') {
        el.classList.add('normal');
    } else if (valueLower === 'degraded') {
        el.classList.add('degraded');
    } else if (valueLower === 'contained') {
        el.classList.add('contained');
    } else if (valueLower === 'lockdown') {
        el.classList.add('lockdown');
    }
}

async function openPortalViewer() {
    const btn = document.getElementById('portalViewerBtn');
    if (!btn || !btn.dataset.url) {
        showToast('Portal viewer is not ready', 'error');
        return;
    }

    if (portalViewerOpening) {
        return;
    }

    portalViewerOpening = true;
    btn.disabled = true;
    btn.textContent = '⏳ Starting Portal...';

    // Keep user gesture context to reduce popup blocking.
    const popup = window.open('', '_blank');

    try {
        const res = await fetch('/api/portal-viewer/open', {
            method: 'POST',
            headers: {
                'X-Auth-Token': AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ timeout_sec: 18 })
        });
        const data = await res.json();
        if (!res.ok || !data.ok || !data.url) {
            if (popup && !popup.closed) popup.close();
            showToast(`Portal open failed: ${data.error || 'unknown error'}`, 'error');
            return;
        }

        if (popup && !popup.closed) {
            popup.opener = null;
            popup.location.href = data.url;
        } else {
            window.open(data.url, '_blank', 'noopener,noreferrer');
        }
        showToast('Portal viewer ready', 'success');
    } catch (e) {
        if (popup && !popup.closed) popup.close();
        showToast(`Portal open failed: ${e.message}`, 'error');
    } finally {
        portalViewerOpening = false;
        btn.disabled = false;
        setTimeout(fetchState, 400);
    }
}

async function completePortalAuthReprobe() {
    const btn = document.getElementById('portalReprobeBtn');
    if (!btn || portalReprobeRunning) {
        return;
    }

    portalReprobeRunning = true;
    btn.disabled = true;
    btn.textContent = '⏳ Re-Probing...';

    try {
        const data = await postAction('reprobe');
        if (data.ok) {
            showToast('🔍 Re-Probe started', 'success');
        } else {
            showToast(`❌ Re-Probe failed: ${data.error || 'unknown error'}`, 'error');
        }
    } catch (e) {
        showToast(`❌ Re-Probe failed: ${e.message}`, 'error');
    } finally {
        portalReprobeRunning = false;
        btn.disabled = false;
        btn.textContent = '✅ Auth Done & Re-Probe';
        setTimeout(fetchState, 600);
    }
}

// Display error state when API unavailable
function displayErrorState() {
    const scoreCircle = document.getElementById('scoreCircle');
    if (scoreCircle) scoreCircle.textContent = '?';
    
    const statusEl = document.getElementById('riskStatus');
    if (statusEl) statusEl.textContent = 'ERROR';
    
    updateElement('headerClock', '--:--:--');
}

// Execute action via API
async function executeAction(action) {
    try {
        if (action === 'release') {
            showToast('⏳ Releasing...', 'info');
        }

        const data = await postAction(action);
        
        if (data.ok) {
            // Special handling for details action
            if (action === 'details') {
                showDetailsModal(data);
                return;
            }
            if (action === 'shutdown') {
                showToast('🛑 Shutdown requested. Device will power off in a few seconds.', 'success');
                return;
            }
            if (action === 'reboot') {
                showToast('♻️ Reboot requested. Device will restart in a few seconds.', 'success');
                return;
            }
            showToast(`✅ ${action} executed successfully`, 'success');
            // Immediately refresh state
            setTimeout(fetchState, 500);
        } else {
            showToast(`❌ ${action} failed: ${data.error}`, 'error');
        }
    } catch (e) {
        console.error(`Action ${action} failed:`, e);
        showToast(`❌ ${action} failed: ${e.message}`, 'error');
    }
}

async function executeShutdown() {
    const firstConfirm = window.confirm('⚠️ This will shut down Azazel-Edge now. Continue?');
    if (!firstConfirm) return;

    const typed = window.prompt('Type SHUTDOWN to confirm power off');
    if (typed !== 'SHUTDOWN') {
        showToast('ℹ️ Shutdown canceled', 'info');
        return;
    }

    await executeAction('shutdown');
}

async function executeReboot() {
    const firstConfirm = window.confirm('⚠️ This will reboot Azazel-Edge now. Continue?');
    if (!firstConfirm) return;

    const typed = window.prompt('Type REBOOT to confirm restart');
    if (typed !== 'REBOOT') {
        showToast('ℹ️ Reboot canceled', 'info');
        return;
    }

    await executeAction('reboot');
}

// POST /api/action/<action>
async function postAction(action) {
    const res = await fetch(`/api/action/${action}`, {
        method: 'POST',
        headers: {
            'X-Auth-Token': AUTH_TOKEN,
            'Content-Type': 'application/json'
        }
    });
    
    return res.json();
}

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    
    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

function initLiveNotifications() {
    unreadEventCount = 0;
    updateUnreadBadge();
    updateBrowserNotificationStatus();
    setLiveBadge('ntfyStreamStatus', 'CONNECTING', 'degraded');
    setLiveBadge('caCertStatus', 'CHECKING', 'degraded');
    loadCACertificateMeta();

    const logEl = document.getElementById('ntfyEventLog');
    if (logEl) {
        logEl.addEventListener('click', () => {
            unreadEventCount = 0;
            updateUnreadBadge();
        });
    }
}

async function loadCACertificateMeta() {
    try {
        const res = await fetch('/api/certs/azazel-webui-local-ca/meta');
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setLiveBadge('caCertStatus', 'MISSING', 'blocked');
            setCACertFingerprint('SHA256: not available');
            toggleCACertificateButton(false);
            return;
        }

        caCertificateDownloadUrl = data.download_url || '/api/certs/azazel-webui-local-ca.crt';
        setLiveBadge('caCertStatus', 'AVAILABLE', 'on');
        setCACertFingerprint(`SHA256: ${data.sha256 || '-'}`);
        toggleCACertificateButton(true);
    } catch (e) {
        console.warn('Failed to load CA certificate metadata:', e);
        setLiveBadge('caCertStatus', 'ERROR', 'blocked');
        setCACertFingerprint('SHA256: lookup failed');
        toggleCACertificateButton(false);
    }
}

function toggleCACertificateButton(enabled) {
    const btn = document.getElementById('downloadCaBtn');
    if (!btn) return;
    btn.disabled = !enabled;
}

function setCACertFingerprint(text) {
    const el = document.getElementById('caCertFingerprint');
    if (!el) return;
    el.textContent = text;
}

function downloadCACertificate() {
    window.location.href = caCertificateDownloadUrl;
    showToast('📥 Downloading CA certificate...', 'info');
}

function startEventStream() {
    if (eventSource) {
        eventSource.close();
    }

    const streamUrl = `/api/events/stream?token=${encodeURIComponent(AUTH_TOKEN)}`;
    eventSource = new EventSource(streamUrl);
    setLiveBadge('ntfyStreamStatus', 'CONNECTING', 'degraded');

    eventSource.addEventListener('open', () => {
        setLiveBadge('ntfyStreamStatus', 'CONNECTED', 'on');
    });

    eventSource.addEventListener('azazel', (event) => {
        try {
            const payload = JSON.parse(event.data);
            handleLiveEvent(payload);
        } catch (e) {
            console.warn('Failed to parse SSE event payload:', e);
        }
    });

    eventSource.addEventListener('error', () => {
        setLiveBadge('ntfyStreamStatus', 'RECONNECTING', 'degraded');
        const now = Date.now();
        if (now - lastEventSourceErrorToastAt > 15000) {
            showToast('⚠️ Event stream reconnecting...', 'info');
            lastEventSourceErrorToastAt = now;
        }
    });
}

function handleLiveEvent(payload) {
    if (!payload || typeof payload !== 'object') return;

    if (payload.kind === 'bridge_status') {
        handleBridgeStatus(payload);
        return;
    }

    const dedupKey = payload.dedup_key
        || `ntfy:${payload.id || ''}:${payload.topic || ''}:${payload.title || ''}:${payload.message || ''}`;
    if (isDuplicateLiveEvent(dedupKey)) {
        return;
    }

    unreadEventCount += 1;
    updateUnreadBadge();
    appendLiveEventLog(payload);

    const title = payload.title || 'Azazel Notification';
    const message = payload.message || '';
    const toastType = payload.severity === 'error' ? 'error' : 'info';
    const toastMessage = message ? `🔔 ${title}: ${message}` : `🔔 ${title}`;
    showToast(toastMessage, toastType);

    const shown = showBrowserNotification(payload);
    if (!shown) {
        // UI toast/log are already shown; this keeps behavior explicit on fallback path.
        return;
    }
}

function handleBridgeStatus(payload) {
    const status = (payload.status || '').toUpperCase();
    if (status.includes('CONNECTED')) {
        setLiveBadge('ntfyStreamStatus', 'CONNECTED', 'on');
        return;
    }
    if (status.includes('RECONNECT')) {
        setLiveBadge('ntfyStreamStatus', 'RECONNECTING', 'degraded');
        return;
    }
    if (status.includes('CONNECTING')) {
        setLiveBadge('ntfyStreamStatus', 'CONNECTING', 'degraded');
    }
}

function isDuplicateLiveEvent(dedupKey) {
    const now = Date.now();
    for (const [key, ts] of eventDedupMap.entries()) {
        if (now - ts > EVENT_DEDUP_WINDOW_MS) {
            eventDedupMap.delete(key);
        }
    }

    const lastSeen = eventDedupMap.get(dedupKey);
    if (lastSeen && (now - lastSeen) < EVENT_DEDUP_WINDOW_MS) {
        return true;
    }
    eventDedupMap.set(dedupKey, now);
    return false;
}

function appendLiveEventLog(payload) {
    const logEl = document.getElementById('ntfyEventLog');
    if (!logEl) return;

    const li = document.createElement('li');
    li.className = 'event-log-item';

    const ts = payload.timestamp ? String(payload.timestamp).replace('T', ' ').slice(0, 19) : '--:--:--';
    const topic = payload.topic || 'unknown';
    const title = payload.title || 'Azazel Notification';
    const message = payload.message || '';
    li.textContent = `[${ts}] [${topic}] ${title}${message ? ` - ${message}` : ''}`;

    if (payload.severity === 'error') {
        li.classList.add('error');
    } else if (payload.severity === 'warning') {
        li.classList.add('warning');
    }

    logEl.prepend(li);
    while (logEl.children.length > EVENT_LOG_MAX_ITEMS) {
        logEl.removeChild(logEl.lastChild);
    }
}

function updateUnreadBadge() {
    const countLabel = unreadEventCount > 99 ? '99+' : String(unreadEventCount);
    const style = unreadEventCount > 0 ? 'contained' : 'off';
    setLiveBadge('ntfyUnreadBadge', countLabel, style);
}

function setLiveBadge(id, label, styleClass) {
    const el = document.getElementById(id);
    if (!el) return;

    el.textContent = label;
    el.classList.remove('allowed', 'blocked', 'on', 'off', 'normal', 'degraded', 'contained', 'lockdown');
    if (styleClass) {
        el.classList.add(styleClass);
    }
}

function isBrowserNotificationSupported() {
    return typeof window !== 'undefined' && 'Notification' in window;
}

function isBrowserNotificationContextAllowed() {
    // Notification API generally requires secure context (HTTPS or localhost)
    return window.isSecureContext === true;
}

function updateBrowserNotificationStatus() {
    const btn = document.getElementById('enableNotificationsBtn');
    if (!btn) return;

    if (!isBrowserNotificationSupported()) {
        setLiveBadge('browserNotifyStatus', 'UNSUPPORTED', 'off');
        btn.disabled = true;
        btn.textContent = '🔕 未対応ブラウザ';
        return;
    }

    if (!isBrowserNotificationContextAllowed()) {
        setLiveBadge('browserNotifyStatus', 'HTTP_ONLY', 'degraded');
        btn.disabled = false;
        btn.textContent = '🔔 通知を有効化';
        return;
    }

    const permission = Notification.permission;
    if (permission === 'granted') {
        setLiveBadge('browserNotifyStatus', 'GRANTED', 'on');
        btn.disabled = true;
        btn.textContent = '✅ 通知は有効です';
    } else if (permission === 'denied') {
        setLiveBadge('browserNotifyStatus', 'DENIED', 'blocked');
        btn.disabled = false;
        btn.textContent = '🔔 通知を有効化';
    } else {
        setLiveBadge('browserNotifyStatus', 'DEFAULT', 'degraded');
        btn.disabled = false;
        btn.textContent = '🔔 通知を有効化';
    }
}

async function enableBrowserNotifications() {
    if (!isBrowserNotificationSupported()) {
        showToast('ℹ️ Browser notifications are not supported on this browser', 'info');
        updateBrowserNotificationStatus();
        return;
    }

    if (!isBrowserNotificationContextAllowed()) {
        showToast('ℹ️ OS通知は HTTPS/localhost でのみ利用できます。画面内通知で継続します。', 'info');
        updateBrowserNotificationStatus();
        return;
    }

    try {
        const permission = await Notification.requestPermission();
        updateBrowserNotificationStatus();
        if (permission === 'granted') {
            showToast('✅ Browser notifications enabled', 'success');
        } else {
            showToast('ℹ️ Browser notifications not granted. Using in-app notifications only.', 'info');
        }
    } catch (e) {
        console.warn('Notification permission request failed:', e);
        showToast('ℹ️ Browser notifications unavailable. Using in-app notifications only.', 'info');
        updateBrowserNotificationStatus();
    }
}

function showBrowserNotification(payload) {
    if (!isBrowserNotificationSupported()) return false;
    if (!isBrowserNotificationContextAllowed()) return false;
    if (Notification.permission !== 'granted') return false;

    try {
        const title = payload.title || 'Azazel Notification';
        const message = payload.message || '';
        const topic = payload.topic ? `[${payload.topic}] ` : '';
        const notification = new Notification(title, {
            body: `${topic}${message}`.trim(),
            tag: payload.dedup_key || payload.id || undefined,
            renotify: false,
        });
        notification.onclick = () => {
            window.focus();
            notification.close();
        };
        return true;
    } catch (e) {
        console.warn('Failed to show browser notification:', e);
        return false;
    }
}

// Show more menu (mobile)
function showMoreMenu() {
    const menu = document.getElementById('moreMenu');
    menu.style.display = 'flex';
}

// Hide more menu
function hideMoreMenu() {
    const menu = document.getElementById('moreMenu');
    menu.style.display = 'none';
}

// Close more menu when clicking outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('moreMenu');
    const moreBtn = document.querySelector('.mobile-more');
    
    if (menu && moreBtn && 
        !menu.contains(e.target) && 
        !moreBtn.contains(e.target)) {
        hideMoreMenu();
    }
});

// Show Details Modal
function showDetailsModal(data) {
    const modal = document.getElementById('detailsModal');
    const body = document.getElementById('detailsBody');
    
    let html = '<div class="details-section">';
    
    // Current State
    html += '<h4>Current State</h4>';
    html += `<p><strong>Stage:</strong> ${data.state || 'UNKNOWN'}</p>`;
    html += `<p><strong>Suspicion Score:</strong> ${data.suspicion || 0}</p>`;
    html += `<p><strong>Reason:</strong> ${data.reason || '-'}</p>`;
    
    // Probe Details
    if (data.details) {
        html += '<h4>Probe Results</h4>';
        
        // TLS checks
        if (data.details.tls && Array.isArray(data.details.tls)) {
            html += '<p><strong>TLS Verification:</strong></p><ul>';
            data.details.tls.forEach(item => {
                const status = item.ok ? '✅' : '❌';
                html += `<li>${status} ${item.site || 'Unknown'}</li>`;
            });
            html += '</ul>';
        }
        
        // DNS checks
        if (data.details.dns !== undefined) {
            const dnsStatus = data.details.dns ? '❌ Mismatch detected' : '✅ OK';
            html += `<p><strong>DNS:</strong> ${dnsStatus}</p>`;
        }
        
        // Captive Portal
        if (data.details.captive_portal !== undefined) {
            const cpStatus = data.details.captive_portal ? '⚠️ Detected' : '✅ None';
            html += `<p><strong>Captive Portal:</strong> ${cpStatus}</p>`;
        }
        
        // Route Anomaly
        if (data.details.route_anomaly !== undefined) {
            const routeStatus = data.details.route_anomaly ? '⚠️ Anomaly detected' : '✅ OK';
            html += `<p><strong>Route:</strong> ${routeStatus}</p>`;
        }
    } else {
        html += '<p>No probe details available</p>';
    }
    
    html += '</div>';
    
    body.innerHTML = html;
    modal.style.display = 'flex';
}

// Close Details Modal
function closeDetailsModal() {
    const modal = document.getElementById('detailsModal');
    modal.style.display = 'none';
}

// ========== Wi-Fi Control Functions ==========

let selectedSSID = '';
let selectedSecurity = 'UNKNOWN';
let selectedSaved = false;

// Scan Wi-Fi networks
async function scanWiFi() {
    try {
        showToast('🔍 Scanning Wi-Fi networks...', 'info');
        
        const res = await fetch('/api/wifi/scan', {
            method: 'GET'
        });
        
        const data = await res.json();
        
        if (data.ok && data.aps) {
            displayWiFiResults(data.aps);
            showToast(`✅ Found ${data.aps.length} networks`, 'success');
        } else {
            showToast(`❌ Scan failed: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (e) {
        console.error('Wi-Fi scan failed:', e);
        showToast(`❌ Scan failed: ${e.message}`, 'error');
    }
}

// Display Wi-Fi scan results
function displayWiFiResults(aps) {
    const resultsDiv = document.getElementById('wifiScanResults');
    const apList = document.getElementById('wifiAPList');
    
    // Clear existing results
    apList.innerHTML = '';
    
    // Populate AP list
    aps.forEach(ap => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid #333';
        row.style.cursor = 'pointer';
        
        const ssidCell = document.createElement('td');
        ssidCell.textContent = ap.ssid;
        if (ap.saved) {
            ssidCell.textContent += ' ★';
            ssidCell.style.color = '#4CAF50';
        }
        
        const signalCell = document.createElement('td');
        signalCell.textContent = `${ap.signal_dbm} dBm`;
        signalCell.style.textAlign = 'center';
        
        // Color code signal strength
        if (ap.signal_dbm >= -50) {
            signalCell.style.color = '#4CAF50';
        } else if (ap.signal_dbm >= -70) {
            signalCell.style.color = '#FFC107';
        } else {
            signalCell.style.color = '#F44336';
        }
        
        const securityCell = document.createElement('td');
        securityCell.textContent = ap.security;
        securityCell.style.textAlign = 'center';
        
        if (ap.security === 'OPEN') {
            securityCell.style.color = '#ff6b35';
        }
        
        const actionCell = document.createElement('td');
        actionCell.style.textAlign = 'center';
        
        const selectBtn = document.createElement('button');
        selectBtn.textContent = 'Select';
        selectBtn.className = 'btn-small';
        selectBtn.onclick = () => selectAP(ap.ssid, ap.security, ap.saved);
        
        actionCell.appendChild(selectBtn);
        
        row.appendChild(ssidCell);
        row.appendChild(signalCell);
        row.appendChild(securityCell);
        row.appendChild(actionCell);
        
        apList.appendChild(row);
    });
    
    // Show results section
    resultsDiv.style.display = 'block';
}

// Select AP from list
function selectAP(ssid, security, saved) {
    selectedSSID = ssid;
    selectedSecurity = security;
    selectedSaved = !!saved;
    
    // Populate manual SSID field
    document.getElementById('manualSSID').value = ssid;
    
    // Show/hide passphrase section based on security
    const passphraseSection = document.getElementById('passphraseSection');
    if (security === 'OPEN' || selectedSaved) {
        passphraseSection.style.display = 'none';
        document.getElementById('wifiPassphrase').value = '';
    } else {
        passphraseSection.style.display = 'block';
    }
    
    const savedLabel = selectedSaved ? ' (saved)' : '';
    showToast(`✅ Selected: ${ssid} (${security})${savedLabel}`, 'info');
}

// Connect to Wi-Fi
async function connectWiFi() {
    const manualSSID = document.getElementById('manualSSID').value.trim();
    const passphrase = document.getElementById('wifiPassphrase').value;
    
    // Use manual SSID if provided, else selected SSID
    const ssid = manualSSID || selectedSSID;
    
    if (!ssid) {
        showToast('❌ Please select or enter an SSID', 'error');
        return;
    }
    
    // Determine security if manually entered
    let security = selectedSecurity;
    if (manualSSID && manualSSID !== selectedSSID) {
        security = passphrase ? 'WPA2' : 'OPEN';
    }

    const isSavedSelection = !!(selectedSaved && ssid === selectedSSID);
    
    // Validate passphrase for protected networks
    if (security !== 'OPEN' && !passphrase && !isSavedSelection) {
        showToast('❌ Passphrase required for protected network', 'error');
        return;
    }
    
    try {
        showToast(`🔗 Connecting to ${ssid}...`, 'info');
        
        const body = {
            ssid: ssid,
            security: security,
            persist: security !== 'OPEN',
            saved: isSavedSelection
        };
        
        // Add passphrase only for protected networks
        if (security !== 'OPEN' && passphrase) {
            body.passphrase = passphrase;
        }
        
        const res = await fetch('/api/wifi/connect', {
            method: 'POST',
            headers: {
                'X-Auth-Token': AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });
        
        const data = await res.json();
        
        if (data.ok) {
            showToast(`✅ Connected to ${ssid}!`, 'success');
            
            // Clear passphrase field
            document.getElementById('wifiPassphrase').value = '';
            
            // Refresh state immediately
            setTimeout(fetchState, 1000);
        } else {
            showToast(`❌ Connection failed: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (e) {
        console.error('Wi-Fi connect failed:', e);
        showToast(`❌ Connection failed: ${e.message}`, 'error');
    }
}
