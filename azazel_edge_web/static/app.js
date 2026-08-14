const AUTH_TOKEN = String(localStorage.getItem('azazel_token') || '').trim();
const LANG_KEY = 'azazel_lang';
const PROGRESS_SESSION_KEY = 'azazel_operator_progress_session';
const ONBOARDING_DISMISSED_KEY = 'azazel_dashboard_onboarding_v3_dismissed';
const FOLD_STATE_KEY = 'azazel_dashboard_folds_v1';
const WORKSPACE_KEY = 'azazel_dashboard_workspace';
const POLL_INTERVAL_MS = Number(window.AZAZEL_POLL_MS) > 0 ? Number(window.AZAZEL_POLL_MS) : 4000;
const CURRENT_LANG = window.AZAZEL_LANG || localStorage.getItem(LANG_KEY) || 'en';
const I18N = window.AZAZEL_I18N || {};
const CURRENT_PAGE = document.body?.dataset?.page || 'dashboard';

let dashboardTimer = null;
let currentWorkspace = resolveInitialWorkspace();
let latestState = {};
let latestSummary = {};
let latestMattermost = {};
let lastSuccessfulPollMs = null;
let azConnConsecutiveFailures = 0;
let showNormalClients = false;
let headerClockTimer = null;
let headerClockBaseMs = null;
let headerClockSeedMs = null;
let currentHandoff = {};
let onboardingStepIndex = 0;
let pollingPaused = false;

// Evidence timeline filter + show-more state. Timeline renders keep their full
// row set here so the filter and the "+N more" expanders can repaint without
// waiting for the next poll.
let evidenceFilterText = '';
const timelineLastRows = new Map(); // timeline element id -> { rows, maxVisible }
const timelineExpanded = new Set(); // timeline element ids the operator expanded
const EVIDENCE_FILTER_IDS = new Set([
    'alertQueuesTimeline',
    'dashboardTrendsTimeline',
    'topoliteSyntheticTopology',
    'currentTriggersTimeline',
    'decisionChangesTimeline',
    'operatorInteractionsTimeline',
    'backgroundHistoryTimeline',
    'triageAuditTimeline',
]);

// az-attn: status-transition attention system (Issue #300, item 1)
const AZ_ATTN_DANGER_MS = 5000;   // must equal CSS .az-attn-pulse-danger animation-duration
const AZ_ATTN_CAUTION_MS = 2000;  // must equal CSS .az-attn-pulse-caution animation-duration
const azAttnToneMemory = new Map();    // elementId -> last-seen normalized tone
const azAttnActivePulses = new Map();  // elementId -> { cls, expiresAt }
const azAttnPendingPulses = new Map(); // elementId -> { el, cls, durationMs }, deferred while inside a closed <details>
let azAttnFirstSnapshotDone = false;   // flips true after refreshDashboard() tick #1 fully renders
let azAttnPrevHeroTone = null;
let azAttnPrevDirectCritical = null;
let azAttnBandTimer = null;
const azAttnReducedMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

// az-spark: lightweight trend sparklines (Issue #300, item 4)
const AZ_SPARK_CAP = 45;
const azSparkHistory = new Map(); // key -> number[]

function azSparkPush(key, value) {
    const v = Number(value);
    if (!Number.isFinite(v)) return;
    let arr = azSparkHistory.get(key);
    if (!arr) { arr = []; azSparkHistory.set(key, arr); }
    arr.push(v);
    if (arr.length > AZ_SPARK_CAP) arr.shift();
}

function azSparkRender(key, slotId, tone) {
    const slot = document.getElementById(slotId);
    if (!slot) return;
    const data = azSparkHistory.get(key) || [];
    if (data.length < 2) {
        slot.textContent = ''; // clear any prior svg; reserved height keeps layout stable
        return;
    }
    const W = 100, H = 30, PAD = 2;
    const min = Math.min(...data);
    const max = Math.max(...data);
    const span = max - min;
    const stepX = W / (data.length - 1);
    const points = data.map((v, i) => {
        const x = i * stepX;
        const y = span === 0
            ? H / 2
            : (H - PAD) - ((v - min) / span) * (H - PAD * 2);
        return [x, y];
    });
    const lineD = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0].toFixed(2)},${p[1].toFixed(2)}`).join(' ');
    const areaD = `${lineD} L${W},${H} L0,${H} Z`;

    let svg = slot.firstElementChild;
    let linePath, areaPath;
    if (!svg || svg.tagName.toLowerCase() !== 'svg') {
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('aria-hidden', 'true');
        areaPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        areaPath.setAttribute('class', 'az-spark-area');
        linePath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        linePath.setAttribute('class', 'az-spark-line');
        svg.appendChild(areaPath);
        svg.appendChild(linePath);
        slot.textContent = '';
        slot.appendChild(svg);
    } else {
        areaPath = svg.querySelector('.az-spark-area');
        linePath = svg.querySelector('.az-spark-line');
    }
    svg.classList.remove('status-safe', 'status-caution', 'status-danger');
    svg.classList.add(tone || 'status-safe');
    areaPath.setAttribute('d', areaD);
    linePath.setAttribute('d', lineD);
}

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

// Workspace axis (docs/architecture/socnoc-workspace-design.md): 'simple' is
// the default three-tile landing view; 'all' is the classic combined board;
// 'noc'/'soc' reorder the panels around that domain's primary objects and
// hide the other domain's detail-only blocks.
function normalizeWorkspace(value) {
    const text = String(value || '').trim().toLowerCase();
    return ['simple', 'all', 'noc', 'soc'].includes(text) ? text : '';
}

function resolveInitialWorkspace() {
    const url = new URL(window.location.href);
    const queryWorkspace = normalizeWorkspace(url.searchParams.get('workspace'));
    const savedWorkspace = normalizeWorkspace(localStorage.getItem(WORKSPACE_KEY));
    return queryWorkspace || savedWorkspace || 'simple';
}

// Fold ids opened by default per workspace. Applied only when the operator has
// never explicitly toggled that fold — explicit choices are persisted by the
// fold-state mechanism and always win.
const WORKSPACE_FOLD_DEFAULTS = {
    soc: ['splitBoardDetails', 'evidenceTimelineDetails'],
    noc: ['splitBoardDetails', 'clientIdentityDetails'],
};

function setWorkspace(workspace) {
    currentWorkspace = normalizeWorkspace(workspace) || 'simple';
    localStorage.setItem(WORKSPACE_KEY, currentWorkspace);
    document.body.dataset.workspace = currentWorkspace;
    [['workspaceSimpleBtn', 'simple'], ['workspaceAllBtn', 'all'], ['workspaceNocBtn', 'noc'], ['workspaceSocBtn', 'soc']].forEach(([id, ws]) => {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.classList.toggle('active', currentWorkspace === ws);
        btn.setAttribute('aria-pressed', currentWorkspace === ws ? 'true' : 'false');
    });
    const saved = readFoldState();
    (WORKSPACE_FOLD_DEFAULTS[currentWorkspace] || []).forEach((foldId) => {
        if (Object.prototype.hasOwnProperty.call(saved, foldId)) return;
        const details = document.getElementById(foldId);
        if (details) details.open = true;
    });
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
        jaBtn.setAttribute('aria-pressed', CURRENT_LANG === 'ja' ? 'true' : 'false');
    }
    if (enBtn) {
        enBtn.classList.toggle('active', CURRENT_LANG === 'en');
        enBtn.classList.toggle('lang-active-en', CURRENT_LANG === 'en');
        enBtn.classList.remove('lang-active-ja');
        enBtn.setAttribute('aria-pressed', CURRENT_LANG === 'en' ? 'true' : 'false');
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
        toggle.textContent = isSynthetic
            ? tr('dashboard.switch_to_live', 'Switch to Live')
            : tr('dashboard.switch_to_synthetic', 'Switch to Synthetic');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.lang = CURRENT_LANG;
    syncLanguageUi();
    bindStaticHandlers();
    bindFoldPersistence();
    azAttnBindFoldCatchup();
    bindSectionNav();
    bindBackToTop();
    startHeaderClock();
    setWorkspace(currentWorkspace);
    refreshDashboard();
    dashboardTimer = window.setInterval(refreshDashboard, POLL_INTERVAL_MS);
    // Chromium/Brave throttle setInterval in unfocused or backgrounded windows,
    // so a side-by-side dashboard can lag minutes behind the backend while the
    // operator drives commands from a terminal. Force an immediate refresh the
    // moment the page regains focus or visibility, so clicking the dashboard
    // shows the current control-plane state at once instead of on the next
    // (throttled) tick.
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshDashboard(); });
    window.addEventListener('focus', refreshDashboard);
});

window.addEventListener('beforeunload', () => {
    if (dashboardTimer) {
        clearInterval(dashboardTimer);
    }
    if (headerClockTimer) {
        clearInterval(headerClockTimer);
    }
});

// Persist <details> fold state across reloads. Without this every page refresh
// re-collapsed all 13 disclosure folds, losing whatever depth the operator had
// opened mid-incident.
function readFoldState() {
    try {
        const parsed = JSON.parse(localStorage.getItem(FOLD_STATE_KEY) || '{}');
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (e) {
        return {};
    }
}

function bindFoldPersistence() {
    const saved = readFoldState();
    document.querySelectorAll('details[id]').forEach((details) => {
        if (Object.prototype.hasOwnProperty.call(saved, details.id)) {
            details.open = Boolean(saved[details.id]);
        }
        // Persist on summary click (covers keyboard activation too — browsers
        // synthesize a click for Enter/Space on <summary>), NOT on 'toggle':
        // programmatic opens (saved-state restore, workspace fold defaults)
        // also fire 'toggle', and recording those would turn a default into a
        // fake "explicit operator choice".
        details.querySelector('summary')?.addEventListener('click', () => {
            window.setTimeout(() => {
                const current = readFoldState();
                current[details.id] = details.open;
                try {
                    localStorage.setItem(FOLD_STATE_KEY, JSON.stringify(current));
                } catch (e) { /* storage unavailable: fold state simply stays session-local */ }
            }, 0);
        });
    });
}

// Sticky section navigation: measures the sticky topbar stack so anchor jumps
// land below it, and highlights the section currently in view.
function bindSectionNav() {
    const nav = document.getElementById('sectionNav');
    if (!nav) return;
    const stack = document.querySelector('.topbar-attn-stack');
    const syncStickyOffset = () => {
        if (!stack) return;
        document.documentElement.style.setProperty('--az-sticky-offset', `${stack.offsetHeight + 14}px`);
    };
    syncStickyOffset();
    window.addEventListener('resize', syncStickyOffset);

    const links = Array.from(nav.querySelectorAll('.section-nav-link'));
    const linkById = new Map();
    links.forEach((link) => {
        const targetId = String(link.getAttribute('href') || '').replace(/^#/, '');
        if (targetId) linkById.set(targetId, link);
    });
    if (!('IntersectionObserver' in window)) return;
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            const link = linkById.get(entry.target.id);
            if (!link) return;
            links.forEach((candidate) => candidate.classList.toggle('active', candidate === link));
        });
    }, { rootMargin: '-25% 0px -65% 0px' });
    linkById.forEach((_link, targetId) => {
        const target = document.getElementById(targetId);
        if (target) observer.observe(target);
    });
}

function bindBackToTop() {
    const btn = document.getElementById('backToTopBtn');
    if (!btn) return;
    const sync = () => { btn.hidden = window.scrollY < 600; };
    window.addEventListener('scroll', sync, { passive: true });
    sync();
    btn.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: azAttnReducedMotion ? 'auto' : 'smooth' });
    });
}

function bindStaticHandlers() {
    document.getElementById('langJaBtn')?.addEventListener('click', () => switchLanguage('ja'));
    document.getElementById('langEnBtn')?.addEventListener('click', () => switchLanguage('en'));
    document.getElementById('workspaceSimpleBtn')?.addEventListener('click', () => setWorkspace('simple'));
    document.getElementById('workspaceAllBtn')?.addEventListener('click', () => setWorkspace('all'));
    document.getElementById('workspaceNocBtn')?.addEventListener('click', () => setWorkspace('noc'));
    document.getElementById('workspaceSocBtn')?.addEventListener('click', () => setWorkspace('soc'));
    // Simple-view drill-downs.
    document.getElementById('simpleOverallTile')?.addEventListener('click', () => setWorkspace('all'));
    document.getElementById('simpleSocTile')?.addEventListener('click', () => setWorkspace('soc'));
    document.getElementById('simpleNocTile')?.addEventListener('click', () => setWorkspace('noc'));
    document.getElementById('showGuideBtn')?.addEventListener('click', reopenOnboardingGuide);
    document.getElementById('globalAlertBandDismiss')?.addEventListener('click', azAttnHideAlertBand);
    document.getElementById('refreshNowBtn')?.addEventListener('click', async (event) => {
        const btn = event.currentTarget;
        btn.classList.add('meta-action-busy');
        try {
            await refreshDashboard(true);
        } finally {
            btn.classList.remove('meta-action-busy');
        }
    });
    document.getElementById('pollPauseBtn')?.addEventListener('click', () => setPollingPaused(!pollingPaused));
    document.getElementById('evidenceFilterInput')?.addEventListener('input', (event) => {
        evidenceFilterText = String(event.target.value || '').trim();
        EVIDENCE_FILTER_IDS.forEach((id) => paintTimeline(id));
    });
    document.getElementById('triageFilterInput')?.addEventListener('input', (event) => {
        triageTextFilter = String(event.target.value || '').trim();
        paintTriageTable();
    });
    document.querySelectorAll('.triage-band-chip').forEach((chip) => {
        chip.addEventListener('click', () => {
            triageBandFilter = String(chip.dataset.band || 'all');
            document.querySelectorAll('.triage-band-chip').forEach((candidate) => {
                const active = candidate === chip;
                candidate.classList.toggle('active', active);
                candidate.setAttribute('aria-pressed', active ? 'true' : 'false');
            });
            paintTriageTable();
        });
    });
    // "+N more" expanders are rebuilt with each timeline repaint, so handle them
    // via delegation instead of per-button listeners.
    document.addEventListener('click', (event) => {
        const btn = event.target instanceof Element ? event.target.closest('.timeline-more-btn') : null;
        if (!btn) return;
        const id = String(btn.dataset.timelineId || '');
        if (!id) return;
        if (timelineExpanded.has(id)) timelineExpanded.delete(id);
        else timelineExpanded.add(id);
        paintTimeline(id);
    });

    document.getElementById('modePortalBtn')?.addEventListener('click', () => switchMode('portal'));
    document.getElementById('modeShieldBtn')?.addEventListener('click', () => switchMode('shield'));
    document.getElementById('modeScapegoatBtn')?.addEventListener('click', () => switchMode('scapegoat'));
    document.getElementById('topoliteSyntheticToggleBtn')?.addEventListener('click', toggleTopoliteSyntheticMode);
    document.getElementById('portalAssistBtn')?.addEventListener('click', openPortalViewer);
    document.getElementById('containBtn')?.addEventListener('click', () => executeAction('contain'));
    document.getElementById('releaseBtn')?.addEventListener('click', () => executeAction('release'));
    document.getElementById('clientIdentityToggle')?.addEventListener('click', (event) => {
        showNormalClients = !showNormalClients;
        event.currentTarget.setAttribute('aria-pressed', showNormalClients ? 'true' : 'false');
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
    const candidateMs = now.getTime();
    // Never step the displayed clock backwards. Snapshots are cached for a few
    // seconds server-side, so consecutive renders can carry the SAME (older)
    // now_time; re-seeding from it used to rewind the clock by the elapsed
    // interval on every render — the visible "clock jumps back" bug. Accept
    // forward seeds, ignore backward ones (tolerating day-wrap).
    if (headerClockBaseMs != null && headerClockSeedMs != null) {
        const displayedMs = headerClockBaseMs + Math.max(0, Date.now() - headerClockSeedMs);
        const rewindMs = displayedMs - candidateMs;
        if (rewindMs > 0 && rewindMs < 6 * 3600 * 1000) {
            return;
        }
    }
    headerClockBaseMs = candidateMs;
    headerClockSeedMs = Date.now();
    renderHeaderClock();
}

function startHeaderClock() {
    if (headerClockTimer) {
        clearInterval(headerClockTimer);
    }
    seedHeaderClock('');
    headerClockTimer = window.setInterval(() => {
        renderHeaderClock();
        renderFreshnessAge();
    }, 1000);
}

function updateMissionRow(summary, actions) {
    const recommendation = String(summary.current_recommendation || '-').trim();
    const doNext = Array.isArray(actions.do_next) ? actions.do_next : [];
    const whyNow = Array.isArray(actions.why_now) ? actions.why_now : [];
    const doNotDo = Array.isArray(actions.do_not_do) ? actions.do_not_do : [];

    const headline = doNext[0] || recommendation || tr('dashboard.mission_headline_professional_fallback', 'Review current operator action.');
    const summaryLine = tr('dashboard.mission_summary_professional', 'Professional mode compresses the first operator action, the current reason, and the non-negotiable safety rails.');
    const focusItems = doNext.slice(0, 3);
    const safetyItems = doNotDo.length ? doNotDo.slice(0, 3) : [tr('dashboard.mission_safety_default', 'Do not act on stale data without confirming freshness.')];

    updateElement('missionHeadline', headline || '-');
    updateElement('missionSummary', summaryLine);
    renderList('missionReasonList', whyNow.length ? whyNow.slice(0, 3) : [tr('dashboard.waiting_causal_summary_ui', 'Waiting for causal summary.')], (item) => item);
    renderList('missionFocusList', focusItems.length ? focusItems : [tr('dashboard.waiting_next_checks_ui', 'Waiting for next checks.')], (item) => item);
    renderList('missionSafetyList', safetyItems, (item) => item);
}

// Single-flight + ordering guards. The poll interval fires unconditionally, so
// one slow cycle (e.g. /api/dashboard/evidence under load) used to overlap with
// the next ones: dozens of concurrent request batches piled up (up to
// net::ERR_INSUFFICIENT_RESOURCES), and cycles completed out of order, so an
// OLDER snapshot rendered after a newer one — the board stalled for minutes and
// the header clock visibly jumped backwards. Guard all three failure modes:
// never start a cycle while one is in flight, bound each request with a
// timeout, and never render a snapshot older than the last one shown.
let refreshInFlight = false;
let lastRenderedSnapshotEpoch = 0;
const REQUEST_TIMEOUT_MS = 8000;

function requestTimeoutSignal() {
    try {
        return AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    } catch (e) {
        return undefined; // very old browser: no timeout, previous behavior
    }
}

// forceArg must be compared with === true: this function is also bound directly
// as a focus/visibilitychange handler, where the first argument is an Event.
async function refreshDashboard(forceArg = false) {
    const force = forceArg === true;
    if (pollingPaused && !force) return;
    if (refreshInFlight) return;
    refreshInFlight = true;
    try {
        await refreshDashboardOnce();
    } finally {
        refreshInFlight = false;
    }
}

function setPollingPaused(paused) {
    pollingPaused = Boolean(paused);
    const btn = document.getElementById('pollPauseBtn');
    if (btn) {
        btn.setAttribute('aria-pressed', pollingPaused ? 'true' : 'false');
        btn.classList.toggle('active', pollingPaused);
        const label = pollingPaused
            ? tr('dashboard.resume_updates', 'Resume auto-refresh')
            : tr('dashboard.pause_updates', 'Pause auto-refresh');
        btn.setAttribute('aria-label', label);
        btn.title = label;
        btn.innerHTML = pollingPaused ? '&#x25b6;' : '&#x23f8;';
    }
    azConnRenderChip();
    if (!pollingPaused) {
        // Resume with an immediate refresh so the board catches up at once
        // instead of waiting for the next interval tick.
        refreshDashboard(true);
    }
}

async function refreshDashboardOnce() {
    fetchAggregatorStatus();
    // One request per tick (GET /api/dashboard/bundle) instead of the former
    // ~11 parallel fetches. The fan-out used to let the heavy evidence build
    // hold a worker and starve /api/state, flapping the LINK chip OFFLINE;
    // the bundle reads shared inputs once server-side and returns one atomic
    // snapshot, so a poll either fully succeeds or fully fails.
    const bundleUrl = new URL('/api/dashboard/bundle', window.location.origin);
    bundleUrl.searchParams.set('session_id', ensureProgressSessionId());
    bundleUrl.searchParams.set('surface', 'dashboard');
    bundleUrl.searchParams.set('trends_limit', '60');

    let bundle;
    try {
        bundle = await fetchJson(bundleUrl.pathname + bundleUrl.search, { signal: requestTimeoutSignal() });
    } catch (error) {
        const message = error.message || String(error);
        console.error('Dashboard refresh failed:', message);
        azConnSetState(false);
        // Tolerate a single transient slow poll before alarming, so a one-cycle
        // blip does not flicker a toast onto the booth screen.
        if (azConnConsecutiveFailures >= 2) {
            showToast(tr('dashboard.refresh_failed', 'Dashboard refresh failed: {error}', { error: message }), 'error');
        }
        return;
    }

    // Ordering guard: even with the single-flight gate, never let an older
    // control-plane snapshot overwrite a newer one on screen (this is what made
    // the header clock jump backwards). snapshot_epoch is wall-clock seconds.
    const incomingSnapshotEpoch = Number(bundle.state?.snapshot_epoch || 0);
    if (incomingSnapshotEpoch && incomingSnapshotEpoch < lastRenderedSnapshotEpoch) {
        return;
    }
    if (incomingSnapshotEpoch) {
        lastRenderedSnapshotEpoch = incomingSnapshotEpoch;
    }

    const summary = bundle.summary || {};
    const actions = bundle.actions || {};
    const handoff = bundle.handoff_brief_pack || {};
    const evidence = bundle.evidence || {};
    const health = bundle.health || {};
    const trends = bundle.trends || {};
    const activity = bundle.activity || {};
    const decisionFocus = bundle.decision_focus || {};
    const state = bundle.state || {};
    const mattermost = bundle.mattermost || { reachable: false, command_triggers: [] };
    const topoliteMode = bundle.topolite_seed_mode || {};

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
    currentHandoff = handoff || {};
    updateSyntheticModeBanner(summary, evidence);

    try {
        updateHeader(state, mattermost);
        updateClientIdentityView(summary);
        updateCommandStrip(summary, health, []);
        updateOperationalResourceGuard(health, true);
        updateAIGovernanceSnapshot(health.ai_governance || {});
        updateSituationBoard(summary, state, health, mattermost);
        updateSplitBoard(summary, actions);
        updateActionBoard(actions, state);
        updateTopoliteSingleScreen(summary, evidence, actions);
        updateMissionRow(summary, actions);
        updateHandoffPack(handoff);
        syncOnboardingBanner();
        updateEvidenceBoard(evidence, health, trends);
        updateCommStatus(mattermost);
        updateControlButtons(summary, state);
        // Must run after updateCommandStrip: the Overall tile reuses the
        // hero summary wording rendered there.
        updateSimpleView(summary, health, actions, [], evidence, activity, state);
        updateSocFocus(summary, evidence, actions, activity, state, decisionFocus);
        updateNocFocus(summary, health, state, decisionFocus);
        azAttnFirstSnapshotDone = true;
        document.body.classList.remove('az-boot');
        azConnSetState(true);
    } catch (error) {
        console.error('Dashboard render failed:', error);
        showToast(tr('dashboard.render_failed', 'Dashboard render failed: {error}', { error: error.message }), 'error');
        // The bundle fetch already succeeded, so the connection itself is live
        // even though this render pass hit a bug. Clear the boot dimming and
        // reflect that live state instead of leaving az-boot/the conn chip
        // stuck at their initial INIT values on every render-failing poll.
        document.body.classList.remove('az-boot');
        azConnSetState(true);
    }
}

function buildAggregatorNodeRow(node) {
    const freshness = String(node?.freshness || 'offline').toLowerCase();
    const status = String(node?.status || 'active').toLowerCase();
    const label = String(node?.node_label || node?.node_id || '-');
    const site = String(node?.site_id || '');
    const posture = String(node?.summary?.posture || '');
    const action = String(node?.summary?.last_action || '');
    const freshnessClass = freshness === 'fresh'
        ? 'status-ok'
        : freshness === 'stale'
            ? 'status-warn'
            : 'status-crit';
    const quarantineTag = status === 'quarantined'
        ? `<span class="agg-tag agg-tag-quarantine">${escapeHtml(tr('dashboard.aggregator_quarantined', 'Quarantined'))}</span>`
        : '';
    const lastSeen = node?.last_seen_epoch
        ? new Date(Number(node.last_seen_epoch) * 1000).toLocaleTimeString()
        : '--';
    return `<li class="aggregator-node-row ${freshnessClass}">
        <div class="agg-node-identity">
            <strong class="agg-node-label">${escapeHtml(label)}</strong>
            <span class="agg-node-site">${escapeHtml(site)}</span>
            ${quarantineTag}
        </div>
        <div class="agg-node-status">
            <span class="agg-freshness-badge agg-freshness-${escapeAttribute(freshness)}">${escapeHtml(freshness)}</span>
            ${posture ? `<span class="agg-posture">${escapeHtml(posture)}</span>` : ''}
            ${action ? `<span class="agg-action">${escapeHtml(action)}</span>` : ''}
            <span class="agg-lastseen">${escapeHtml(lastSeen)}</span>
        </div>
    </li>`;
}

function renderAggregatorPanel(data) {
    const counts = data?.counts || {};
    const items = Array.isArray(data?.items) ? data.items : [];
    const fresh = Number(counts.fresh || 0);
    const stale = Number(counts.stale || 0);
    const offline = Number(counts.offline || 0);

    updateElement('aggFreshNum', String(fresh));
    updateElement('aggStaleNum', String(stale));
    updateElement('aggOfflineNum', String(offline));

    const list = document.getElementById('aggregatorNodeList');
    if (list) {
        if (!items.length) {
            list.innerHTML = `<li class="aggregator-node-placeholder" id="aggregatorPlaceholder">${escapeHtml(tr('dashboard.aggregator_no_nodes', 'No nodes registered. Use /api/aggregator/nodes/register to add a node.'))}</li>`;
        } else {
            list.innerHTML = items.map((node) => buildAggregatorNodeRow(node)).join('');
        }
    }
    const stamp = new Date().toLocaleString();
    updateElement(
        'aggregatorLastUpdated',
        tr('dashboard.aggregator_last_polled', 'Last polled: {ts}', { ts: stamp }),
    );
}

async function fetchAggregatorStatus() {
    const panel = document.getElementById('aggregatorPanel');
    if (!panel) return;
    const fleetNavLink = document.getElementById('sectionNavFleet');
    try {
        const resp = await fetch('/api/aggregator/nodes', { headers: authHeaders() });
        if (!resp.ok) {
            if (resp.status === 401 || resp.status === 403 || resp.status === 500) {
                panel.hidden = true;
                if (fleetNavLink) fleetNavLink.hidden = true;
            }
            return;
        }
        panel.hidden = false;
        if (fleetNavLink) fleetNavLink.hidden = false;
        const data = await resp.json();
        renderAggregatorPanel(data);
    } catch (_err) {
        // network error: keep last rendered state
    }
}






async function fetchJson(path, options = {}) {
    const headers = Object.assign({}, options.headers || {}, { 'X-Auth-Token': AUTH_TOKEN, 'X-AZAZEL-LANG': CURRENT_LANG });
    // Never let the browser serve a cached snapshot of live dashboard state:
    // Brave/Chromium otherwise replay a stale /api/state for minutes, freezing
    // the board and rewinding the header clock. Force a fresh network fetch.
    const response = await fetch(path, { cache: 'no-store', ...options, headers });
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
        azAttnNotePanelTone(tileId, tile, tone);
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
    azAttnNotePanelTone(valueId, pill, tone);
}

function setHeatTone(cellId, tone, value) {
    const cell = document.getElementById(cellId);
    if (cell) {
        cell.className = `command-heat-cell ${tone || 'status-neutral'}`;
        azAttnNotePanelTone(cellId, cell, tone);
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
        azAttnNotePanelTone(cellId, cell, tone);
    }
    updateElement(`${cellId}Value`, value);
}

function setGlanceCard(cardId, stateId, tone, value) {
    const card = document.getElementById(cardId);
    if (card) {
        card.className = `split-glance-card ${tone || 'status-neutral'}`;
        azAttnNotePanelTone(cardId, card, tone);
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
    const hasData = !!correlation && typeof correlation === 'object' && Object.keys(correlation).length > 0;
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
    // FIX C: no correlation data at all (empty/missing correlation object, or
    // an explicit "unknown" status - the two are indistinguishable from the
    // caller) means "no correlation among threats", which is a GOOD state on
    // a benign board, not an unknown/degraded one. Read it as SAFE/NONE so a
    // fully benign board can settle the SOC glance to NORMAL instead of being
    // stuck at neutral forever. This does not hide real attacks: threat_level
    // elevated/critical drives socThreat to status-danger/caution, which
    // still wins strongestTone(socThreat.tone, socCorrelation.tone, ...) in
    // the SOC glance headline regardless of what this cell reads.
    if (!hasData || status === 'unknown') {
        return { tone: 'status-safe', value: 'NONE' };
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
        azAttnNotePanelTone('commandGlanceHero', hero, overallTone);
        azAttnCheckHeroForBand(overallTone);
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

// ---- Simple view: three verdict tiles (Overall / SOC / NOC) --------------
// Verdicts reuse the SAME deterministic summarize* helpers and strongestTone
// aggregation as the Command Strip hero and the SOC/NOC glance cards, so the
// Simple tile can never disagree with the full board. When inputs are stale
// the verdict is withheld (UNKNOWN) instead of showing a possibly false green.

function simpleVerdictForTone(tone) {
    if (tone === 'status-danger') return tr('dashboard.simple_bad', 'BAD');
    if (tone === 'status-caution') return tr('dashboard.simple_watch', 'WATCH');
    if (tone === 'status-safe') return tr('dashboard.simple_good', 'GOOD');
    return tr('dashboard.simple_checking', 'CHECKING');
}

function setSimpleTile(tileId, verdictId, tone, verdict) {
    const tile = document.getElementById(tileId);
    if (tile) {
        tile.classList.remove('status-safe', 'status-caution', 'status-danger', 'status-neutral');
        tile.classList.add(tone || 'status-neutral');
    }
    updateElement(verdictId, verdict);
}

function simpleChip(label, tone = '') {
    return `<span class="simple-chip ${escapeAttribute(tone)}">${escapeHtml(label)}</span>`;
}

function updateSimpleView(summary, health, actions, failures = [], evidence = {}, activity = {}, state = {}) {
    if (!document.getElementById('simpleViewPanel')) return;
    const stale = Boolean(summary.command_strip?.stale_warning);
    const strip = summary.command_strip || {};
    const soc = summary.soc_focus || {};
    const noc = summary.noc_focus || {};
    const triage = soc.triage_priority || {};

    const threat = summarizeThreatState(summary);
    const path = summarizePathState(summary);
    const services = summarizeServiceState(summary.service_health_summary || {});
    const clients = summarizeClientState(summary);
    const telemetry = summarizeTelemetryState(summary, health, failures);
    const ai = summarizeAiState(summary, health);
    const clientBaselineTone = clients.tone === 'status-neutral' ? 'status-safe' : clients.tone;
    const overallTone = strongestTone(threat.tone, path.tone, services.tone, clientBaselineTone, telemetry.tone, ai.tone);

    const socVisibility = summarizeVisibilityState(soc.visibility || {});
    const socTone = strongestTone(
        threat.tone,
        summarizeCorrelationState(soc.correlation || {}).tone,
        summarizeTriageState(triage).tone,
        socVisibility.tone,
    );
    const nocServices = summarizeServiceState(noc.service_health || {});
    const nocCapacity = summarizeCapacityState(noc.capacity || {});
    const nocParts = [
        { label: tr('dashboard.heat_path', 'Path'), state: path },
        { label: tr('dashboard.heat_services', 'Services'), state: nocServices },
        { label: tr('dashboard.capacity', 'Capacity'), state: nocCapacity },
        { label: tr('dashboard.heat_clients', 'Clients'), state: clients },
    ];
    const nocTone = strongestTone(...nocParts.map((part) => part.state.tone));

    const unknownVerdict = tr('dashboard.simple_unknown', 'UNKNOWN (STALE)');
    const staleReason = tr('dashboard.simple_stale_reason', 'Inputs are stale; verdict withheld. Check freshness first.');

    // Overall tile
    if (stale) {
        setSimpleTile('simpleOverallTile', 'simpleOverallVerdict', 'status-neutral', unknownVerdict);
        updateElement('simpleOverallReason', staleReason);
    } else {
        setSimpleTile('simpleOverallTile', 'simpleOverallVerdict', overallTone, simpleVerdictForTone(overallTone));
        // Same wording as the Command Strip hero summary, already rendered
        // earlier in this refresh pass.
        updateElement('simpleOverallReason', document.getElementById('commandGlanceSummary')?.textContent || '-');
    }
    const doNext = Array.isArray(actions.do_next) ? actions.do_next : [];
    updateElement('simpleOverallAction', doNext[0] || summary.current_recommendation || '-');

    // SOC tile
    const nowCount = Array.isArray(triage.now) ? triage.now.length : 0;
    const watchCount = Array.isArray(triage.watch) ? triage.watch.length : 0;
    const backlogCount = Array.isArray(triage.backlog) ? triage.backlog.length : 0;
    if (stale) {
        setSimpleTile('simpleSocTile', 'simpleSocVerdict', 'status-neutral', unknownVerdict);
        updateElement('simpleSocReason', staleReason);
    } else {
        setSimpleTile('simpleSocTile', 'simpleSocVerdict', socTone, simpleVerdictForTone(socTone));
        updateElement('simpleSocReason', socTone === 'status-safe'
            ? tr('dashboard.simple_soc_ok', 'No active threat evidence.')
            : `${soc.attack_type || tr('dashboard.no_attack_type', 'No current attack type')} | ${soc.top_source || '-'} → ${soc.top_destination || '-'}`);
    }
    const socChips = document.getElementById('simpleSocChips');
    if (socChips) {
        socChips.innerHTML = [
            simpleChip(`NOW ${nowCount}`, nowCount > 0 ? 'status-danger' : 'status-safe'),
            simpleChip(`WATCH ${watchCount}`, watchCount > 0 ? 'status-caution' : ''),
            simpleChip(`BACKLOG ${backlogCount}`),
            simpleChip(`${tr('dashboard.visibility_label', 'Visibility')} ${socVisibility.value}`, socVisibility.tone),
        ].join('');
    }

    // NOC tile
    if (stale) {
        setSimpleTile('simpleNocTile', 'simpleNocVerdict', 'status-neutral', unknownVerdict);
        updateElement('simpleNocReason', staleReason);
    } else {
        setSimpleTile('simpleNocTile', 'simpleNocVerdict', nocTone, simpleVerdictForTone(nocTone));
        const degraded = nocParts
            .filter((part) => part.state.tone === 'status-caution' || part.state.tone === 'status-danger')
            .map((part) => `${part.label}: ${part.state.value}`);
        updateElement('simpleNocReason', degraded.length
            ? degraded.join(' | ')
            : tr('dashboard.simple_noc_ok', 'Path, services, capacity, and clients look normal.'));
    }
    const nocChips = document.getElementById('simpleNocChips');
    if (nocChips) {
        nocChips.innerHTML = [
            simpleChip(`${tr('dashboard.uplink', 'Uplink')} ${strip.current_uplink || '--'}`),
            simpleChip(`${tr('dashboard.internet', 'Internet')} ${strip.internet_reachability || '--'}`, path.tone),
            simpleChip(`${tr('dashboard.heat_services', 'Services')} ${nocServices.value}`, nocServices.tone),
            simpleChip(`${tr('dashboard.heat_clients', 'Clients')} ${clients.value}`, clients.tone),
        ].join('');
    }

    // KPI strip (Splunk-style key indicators with ~1min trend arrows).
    const aq = evidence.alert_queues || {};
    const suspicion = Number(summary.risk?.suspicion ?? 0);
    updateElement('simpleKpiRiskValue', String(Math.round(suspicion)));
    renderKpiDelta('simpleKpiRiskDelta', azKpiDelta('simple.risk', suspicion));
    updateElement('simpleKpiRiskDetail', String(summary.risk?.user_state || '-'));
    setKpiTone('simpleKpiRisk', toneForRisk(summary.risk?.user_state, suspicion));

    const queueNow = Number(aq.now?.count || 0);
    const queueWatch = Number(aq.watch?.count || 0);
    const queueBacklog = Number(aq.backlog?.count || 0);
    updateElement('simpleKpiNowValue', String(queueNow));
    renderKpiDelta('simpleKpiNowDelta', azKpiDelta('simple.now', queueNow));
    updateElement('simpleKpiNowDetail', tr('dashboard.kpi_now_queue_detail', 'watch {watch} · backlog {backlog}', { watch: queueWatch, backlog: queueBacklog }));
    setKpiTone('simpleKpiNow', queueNow > 0 ? 'status-danger' : (queueWatch > 0 ? 'status-caution' : 'status-safe'));

    const critical = Number(strip.direct_critical_count ?? 0);
    const warning = Number(state.suricata_warning ?? 0);
    updateElement('simpleKpiCriticalValue', String(critical));
    renderKpiDelta('simpleKpiCriticalDelta', azKpiDelta('simple.critical', critical));
    updateElement('simpleKpiCriticalDetail', tr('dashboard.kpi_warning_detail', 'warning {count}', { count: warning }));
    setKpiTone('simpleKpiCritical', critical > 0 ? 'status-danger' : (warning > 0 ? 'status-caution' : 'status-safe'));

    const inventory = noc.client_inventory || {};
    const impacted = Number(noc.blast_radius?.affected_client_count || 0);
    updateElement('simpleKpiClientsValue', String(impacted));
    renderKpiDelta('simpleKpiClientsDelta', azKpiDelta('simple.impacted', impacted));
    updateElement('simpleKpiClientsDetail', tr('dashboard.kpi_of_current', 'of {count} current', { count: Number(inventory.current_client_count || 0) }));
    setKpiTone('simpleKpiClients', impacted > 0 ? 'status-caution' : 'status-safe');

    updateElement('simpleKpiUplinkValue', String(strip.current_uplink || '--').toUpperCase());
    updateElement('simpleKpiUplinkDetail', `${tr('dashboard.internet', 'Internet')} ${strip.internet_reachability || '--'}`);
    setKpiTone('simpleKpiUplink', path.tone);

    const svc = serviceCounts(summary.service_health_summary || {});
    updateElement('simpleKpiServicesValue', svc.total ? `${svc.on}/${svc.total}` : '-');
    updateElement('simpleKpiServicesDetail', nocServices.value);
    setKpiTone('simpleKpiServices', nocServices.tone);

    // Activity strip + deterministic pipeline funnel (events → signals →
    // queued → action) over the last hour.
    renderActivityBars('simpleActivityBars', activity?.h1);
    const h1 = activity?.h1 || {};
    updateElement('pipelineEvents', String(Number(h1.events ?? 0)));
    updateElement('pipelineSignals', String(Number(h1.signals ?? 0)));
    updateElement('pipelineQueued', String(queueNow + queueWatch));
    const recommendation = String(summary.current_recommendation || '').trim();
    updateElement('pipelineAction', recommendation ? '1' : '0');
    updateElement('pipelineNote', tr('dashboard.pipeline_note_action', 'evidence → evaluators → arbiter → {action}', {
        action: recommendation ? (recommendation.length > 48 ? `${recommendation.slice(0, 48)}…` : recommendation) : '-',
    }));
}

// ---- Focus-screen building blocks (Simple+/SOC/NOC screens) ---------------

// KPI deltas: current value vs ~60s ago, session-local memory. Purely a
// display affordance (Splunk-style trend arrows); resets on reload.
const azKpiHistory = new Map(); // key -> [{t, v}]

function azKpiDelta(key, value) {
    const now = Date.now();
    const v = Number(value);
    if (!Number.isFinite(v)) return null;
    let arr = azKpiHistory.get(key);
    if (!arr) { arr = []; azKpiHistory.set(key, arr); }
    arr.push({ t: now, v });
    while (arr.length && now - arr[0].t > 150000) arr.shift();
    const ref = arr.find((sample) => now - sample.t >= 55000);
    if (!ref) return null;
    return v - ref.v;
}

function renderKpiDelta(id, delta) {
    const el = document.getElementById(id);
    if (!el) return;
    if (delta === null || delta === undefined) {
        el.textContent = '';
        el.className = 'focus-kpi-delta delta-flat';
        return;
    }
    if (delta === 0) {
        el.textContent = '—';
        el.className = 'focus-kpi-delta delta-flat';
        return;
    }
    el.textContent = `${delta > 0 ? '▲' : '▼'}${Math.abs(Math.round(delta))}`;
    el.className = `focus-kpi-delta ${delta > 0 ? 'delta-up' : 'delta-down'}`;
}

function setKpiTone(id, tone) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('status-safe', 'status-caution', 'status-danger', 'status-neutral');
    el.classList.add(tone || 'status-neutral');
}

// Band-colored bucket bars from the bundle's activity aggregation.
function renderActivityBars(containerId, windowPayload) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const buckets = Array.isArray(windowPayload?.buckets) ? windowPayload.buckets : [];
    if (!buckets.length) {
        el.innerHTML = '';
        return;
    }
    const totals = buckets.map((b) => Number(b.normal || 0) + Number(b.watch || 0) + Number(b.critical || 0));
    const max = Math.max(1, ...totals);
    el.innerHTML = buckets.map((b, i) => {
        const total = totals[i];
        const cls = Number(b.critical || 0) > 0 ? 'band-critical' : (Number(b.watch || 0) > 0 ? 'band-watch' : '');
        const pct = total > 0 ? Math.max(6, Math.round((total / max) * 100)) : 0;
        return `<i class="${cls}" style="height:${pct}%"></i>`;
    }).join('');
}

function formatBytesShort(value) {
    const n = Number(value) || 0;
    if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (n >= 1024 * 1024) return `${Math.round(n / (1024 * 1024))} MB`;
    if (n >= 1024) return `${Math.round(n / 1024)} KB`;
    return `${n} B`;
}

function serviceCounts(serviceSummary) {
    const entries = Object.entries(serviceSummary || {});
    const on = entries.filter(([, value]) => ['on', 'ok', 'active'].includes(String(value || '').toLowerCase())).length;
    return { on, total: entries.length };
}

// ---- SOC focus screen -----------------------------------------------------

let triageBandFilter = 'all';
let triageTextFilter = '';
let triageRows = [];

function paintTriageTable() {
    const body = document.getElementById('triageTableBody');
    if (!body) return;
    const query = triageTextFilter.toLowerCase();
    const rows = triageRows.filter((row) => {
        if (triageBandFilter !== 'all' && row.band !== triageBandFilter) return false;
        if (!query) return true;
        return [row.ts_iso, row.src_ip, row.dst_ip, String(row.sid), row.attack_type]
            .some((v) => String(v || '').toLowerCase().includes(query));
    });
    if (!rows.length) {
        body.innerHTML = `<tr><td colspan="5">${escapeHtml(tr('dashboard.triage_table_empty', 'No queued alerts in this view.'))}</td></tr>`;
        return;
    }
    const bandTone = { now: 'status-danger', watch: 'status-caution', backlog: 'status-neutral' };
    body.innerHTML = rows.map((row) => {
        const riskTone = row.band === 'now' ? 'status-danger' : (row.band === 'watch' ? 'status-caution' : 'status-neutral');
        const timeText = String(row.ts_iso || '-').replace('T', ' ').slice(11, 19) || '-';
        return `<tr>
            <td>${escapeHtml(timeText)}</td>
            <td><span class="focus-badge ${bandTone[row.band] || 'status-neutral'}">${escapeHtml(row.band.toUpperCase())}</span></td>
            <td><strong>${escapeHtml(row.src_ip || '-')}</strong> → ${escapeHtml(row.dst_ip || '-')}</td>
            <td>${escapeHtml(String(row.sid || '-'))} · ${escapeHtml(row.attack_type || '-')}</td>
            <td><span class="focus-badge ${riskTone}">${escapeHtml(String(row.risk_score ?? '-'))}</span></td>
        </tr>`;
    }).join('');
}

// BHUSA 2026 audit-walkthrough line: trace / policy profile / config hash /
// evidence ids / enforcement mode from the v2 decision-explanation record —
// the same artifacts the audit-review CLI reads (read-only projection).
function renderDecisionAudit(metaId, decisionFocus) {
    const audit = decisionFocus?.audit || {};
    const safety = decisionFocus?.safety || {};
    const decision = decisionFocus?.decision || {};
    const evidence = Array.isArray(decision.evidence_ids) ? decision.evidence_ids : [];
    updateElement(metaId, tr('dashboard.decision_audit_meta', 'trace {trace} · policy {policy} · cfg {config} · evidence {evidence} · {enforcement}', {
        trace: audit.trace_id || '-',
        policy: audit.policy_profile || '-',
        config: String(audit.config_hash || '-').slice(0, 12),
        evidence: evidence.length ? evidence.join(', ') : '-',
        enforcement: safety.dry_run === false ? tr('dashboard.enforced_label', 'ENFORCED') : 'DRY RUN',
    }));
}

function updateSocFocus(summary, evidence, actions, activity, state, decisionFocus) {
    if (!document.getElementById('socFocusPanel')) return;
    const aq = evidence.alert_queues || {};
    const nowCount = Number(aq.now?.count || 0);
    const watchCount = Number(aq.watch?.count || 0);
    const backlogCount = Number(aq.backlog?.count || 0);
    updateElement('socKpiNowValue', String(nowCount));
    renderKpiDelta('socKpiNowDelta', azKpiDelta('soc.now', nowCount));
    setKpiTone('socKpiNow', nowCount > 0 ? 'status-danger' : 'status-safe');
    updateElement('socKpiWatchValue', String(watchCount));
    setKpiTone('socKpiWatch', watchCount > 0 ? 'status-caution' : 'status-safe');
    updateElement('socKpiBacklogValue', String(backlogCount));
    setKpiTone('socKpiBacklog', 'status-neutral');

    const critical = Number(summary.command_strip?.direct_critical_count ?? 0);
    const warning = Number(state.suricata_warning ?? 0);
    updateElement('socKpiCriticalValue', `${critical}/${warning}`);
    setKpiTone('socKpiCritical', critical > 0 ? 'status-danger' : (warning > 0 ? 'status-caution' : 'status-safe'));

    const visibility = summarizeVisibilityState(summary.soc_focus?.visibility || {});
    updateElement('socKpiVisibilityValue', visibility.value);
    setKpiTone('socKpiVisibility', visibility.tone);

    // Oldest unhandled NOW alert (MTTA-style pressure signal).
    const nowItems = Array.isArray(aq.now?.items) ? aq.now.items : [];
    let oldestMs = null;
    nowItems.forEach((item) => {
        const t = Date.parse(String(item.ts_iso || ''));
        if (Number.isFinite(t) && (oldestMs === null || t < oldestMs)) oldestMs = t;
    });
    if (oldestMs === null) {
        updateElement('socKpiOldestValue', '-');
        updateElement('socKpiOldestDetail', tr('dashboard.kpi_oldest_none', 'no NOW alerts'));
        setKpiTone('socKpiOldest', 'status-safe');
    } else {
        const ageMin = Math.max(0, Math.floor((Date.now() - oldestMs) / 60000));
        updateElement('socKpiOldestValue', ageMin < 60 ? `${ageMin}m` : `${Math.floor(ageMin / 60)}h${ageMin % 60}m`);
        updateElement('socKpiOldestDetail', tr('dashboard.kpi_oldest_since', 'unhandled since {time}', {
            time: new Date(oldestMs).toLocaleTimeString().slice(0, 5),
        }));
        setKpiTone('socKpiOldest', ageMin >= 30 ? 'status-danger' : (ageMin >= 10 ? 'status-caution' : 'status-safe'));
    }

    // Triage table rows from the deterministic queue bands.
    triageRows = [];
    [['now', aq.now?.items], ['watch', aq.watch?.items], ['backlog', aq.backlog?.items]].forEach(([band, items]) => {
        (Array.isArray(items) ? items : []).forEach((item) => {
            triageRows.push({ band, ...item });
        });
    });
    paintTriageTable();

    // Decision card: the BHUSA 2026 v2 explanation fields — the arbiter's
    // pick with the SOC jurisdiction's evaluator rationale. Falls back to the
    // live actions payload when no explanation record exists yet.
    const decisionAvailable = Boolean(decisionFocus?.available);
    const decision = decisionFocus?.decision || {};
    const socReasons = Array.isArray(decisionFocus?.domains?.soc?.reasons) ? decisionFocus.domains.soc.reasons : [];
    const doNext = Array.isArray(actions.do_next) ? actions.do_next : [];
    updateElement('socDecisionAction', decisionAvailable
        ? (decision.action || '-')
        : (doNext[0] || summary.current_recommendation || '-'));
    updateElement('socDecisionReason', decisionAvailable
        ? (decision.reason || '-')
        : tr('dashboard.decision_no_record', 'No decision explanation recorded yet.'));
    const socWhy = socReasons.length
        ? socReasons
        : ((Array.isArray(actions.why_now) && actions.why_now.length)
            ? actions.why_now.slice(0, 3)
            : [tr('dashboard.waiting_causal_summary_ui', 'Waiting for causal summary.')]);
    renderList('socDecisionWhyList', socWhy, (item) => item);
    const whyNot = (Array.isArray(decision.why_not_others) && decision.why_not_others.length)
        ? decision.why_not_others
        : (Array.isArray(actions.rejected_stronger_actions) ? actions.rejected_stronger_actions : []);
    renderList('socDecisionRejectedList',
        whyNot.length ? whyNot.slice(0, 3) : [tr('dashboard.no_stronger_rejection_summary', 'No stronger-action rejection summary.')],
        (item) => (typeof item === 'object' && item !== null) ? `${item.action || '-'} — ${item.reason || '-'}` : String(item));
    updateElement('socDecisionRelease', decisionAvailable ? (decision.release_condition || '-') : '-');
    if (decisionAvailable) {
        renderDecisionAudit('socDecisionMeta', decisionFocus);
    } else {
        const capsule = actions.decision_trust_capsule || {};
        updateElement('socDecisionMeta', tr('dashboard.decision_card_meta', 'confidence {confidence} · evidence {evidence} · AI role: {ai}', {
            confidence: capsule.confidence_label || '-',
            evidence: Number(capsule.evidence_count ?? 0),
            ai: actions.decision_path?.ai_role || '-',
        }));
    }

    renderActivityBars('socActivityBars', activity?.h6);
}

// ---- NOC focus screen -----------------------------------------------------

function updateNocFocus(summary, health, state, decisionFocus) {
    if (!document.getElementById('nocFocusPanel')) return;
    // Decision rationale — NOC jurisdiction (same v2 explanation record as
    // the SOC card; NOC health preempts engagement value in the doctrine).
    const decisionAvailable = Boolean(decisionFocus?.available);
    const decision = decisionFocus?.decision || {};
    const nocReasons = Array.isArray(decisionFocus?.domains?.noc?.reasons) ? decisionFocus.domains.noc.reasons : [];
    updateElement('nocDecisionAction', decisionAvailable
        ? (decision.action || '-')
        : (summary.current_recommendation || '-'));
    renderList('nocDecisionRationaleList',
        nocReasons.length ? nocReasons : [tr('dashboard.no_path_signal_summary', 'No path signal summary.')],
        (item) => item);
    updateElement('nocDecisionRelease', decisionAvailable ? (decision.release_condition || '-') : '-');
    if (decisionAvailable) {
        renderDecisionAudit('nocDecisionMeta', decisionFocus);
    } else {
        updateElement('nocDecisionMeta', tr('dashboard.decision_no_record', 'No decision explanation recorded yet.'));
    }
    const strip = summary.command_strip || {};
    const noc = summary.noc_focus || {};
    const pathHealth = noc.path_health || {};
    const inventory = noc.client_inventory || {};
    const blast = noc.blast_radius || {};
    const capacity = noc.capacity || {};
    const path = summarizePathState(summary);
    const clients = summarizeClientState(summary);
    const clientBaselineTone = clients.tone === 'status-neutral' ? 'status-safe' : clients.tone;
    const services = summarizeServiceState(summary.service_health_summary || {});
    const svc = serviceCounts(summary.service_health_summary || {});

    updateElement('nocKpiUplinkValue', String(strip.current_uplink || '--').toUpperCase());
    updateElement('nocKpiUplinkDetail', `${tr('dashboard.gateway', 'Gateway')} ${state.gateway_ip || '-'}`);
    setKpiTone('nocKpiUplink', toneForStatus(pathHealth.uplink) === 'status-neutral' ? path.tone : toneForStatus(pathHealth.uplink));
    updateElement('nocKpiInternetValue', String(strip.internet_reachability || '--').toUpperCase());
    updateElement('nocKpiInternetDetail', `${tr('dashboard.captive_portal', 'Captive Portal')} ${state.connection?.captive_portal || '-'}`);
    setKpiTone('nocKpiInternet', path.tone);

    const utilization = Number(capacity.utilization_pct);
    const capState = summarizeCapacityState(capacity);
    updateElement('nocKpiCapacityValue', Number.isFinite(utilization) ? `${Math.round(utilization)}%` : capState.value);
    renderKpiDelta('nocKpiCapacityDelta', Number.isFinite(utilization) ? azKpiDelta('noc.capacity', utilization) : null);
    updateElement('nocKpiCapacityDetail', String(capacity.state || 'unknown'));
    setKpiTone('nocKpiCapacity', capState.tone);

    const current = Number(inventory.current_client_count || 0);
    updateElement('nocKpiClientsValue', String(current));
    updateElement('nocKpiClientsDetail', tr('dashboard.kpi_clients_detail', '{unknown} unknown · {unauthorized} unauthorized', {
        unknown: Number(inventory.unknown_client_count || 0),
        unauthorized: Number(inventory.unauthorized_client_count || 0),
    }));
    setKpiTone('nocKpiClients', clientBaselineTone);

    const impacted = Number(blast.affected_client_count || 0);
    updateElement('nocKpiImpactedValue', String(impacted));
    updateElement('nocKpiImpactedDetail', joinList(blast.affected_segments));
    setKpiTone('nocKpiImpacted', impacted > 0 ? 'status-caution' : 'status-safe');

    updateElement('nocKpiServicesValue', svc.total ? `${svc.on}/${svc.total}` : '-');
    updateElement('nocKpiServicesDetail', services.value);
    setKpiTone('nocKpiServices', services.tone);

    // Path strip: the edge-local topology answer to a geo map.
    const stripEl = document.getElementById('nocPathStrip');
    if (stripEl) {
        const hops = [
            { title: tr('dashboard.hop_clients', 'Clients ×{count}', { count: current }), state: clients.value, tone: clientBaselineTone },
            { title: 'Azazel-Edge', state: String(summary.mode?.current_mode || state.mode?.current_mode || '-').toUpperCase(), tone: 'status-safe' },
            { title: tr('dashboard.uplink', 'Uplink'), state: String(pathHealth.uplink || strip.current_uplink || '-').toUpperCase(), tone: toneForStatus(pathHealth.uplink) },
            { title: `GW ${state.gateway_ip || '-'}`, state: String(pathHealth.gateway || '-').toUpperCase(), tone: toneForStatus(pathHealth.gateway) },
            { title: tr('dashboard.internet', 'Internet'), state: String(pathHealth.internet || strip.internet_reachability || '-').toUpperCase(), tone: toneForStatus(pathHealth.internet) },
        ];
        const rank = { 'status-safe': 0, 'status-neutral': 1, 'status-caution': 2, 'status-danger': 3 };
        stripEl.innerHTML = hops.map((hop, i) => {
            const hopHtml = `<div class="path-hop ${hop.tone}"><div class="path-hop-title">${escapeHtml(hop.title)}</div><div class="path-hop-state">${escapeHtml(hop.state || '-')}</div></div>`;
            if (i === hops.length - 1) return hopHtml;
            const linkTone = rank[hop.tone] >= rank[hops[i + 1].tone] ? hop.tone : hops[i + 1].tone;
            return hopHtml + `<span class="path-link ${linkTone === 'status-safe' ? '' : linkTone}"></span>`;
        }).join('');
    }

    // Top talkers joined with the client identity view. The per-source list
    // lives on the raw snapshot (state.noc_capacity.top_sources); the summary
    // projection only carries the single top_talker string.
    const talkersBody = document.getElementById('topTalkersBody');
    if (talkersBody) {
        const rawSources = state.noc_capacity?.top_sources || capacity.top_sources;
        const sources = Array.isArray(rawSources) ? rawSources.slice(0, 6) : [];
        const identityItems = Array.isArray(noc.client_identity_view?.items) ? noc.client_identity_view.items : [];
        const byIp = new Map(identityItems.map((item) => [String(item.ip || ''), item]));
        const maxBytes = Math.max(1, ...sources.map((s) => Number(s.bytes) || 0));
        if (!sources.length) {
            talkersBody.innerHTML = `<tr><td colspan="4">${escapeHtml(tr('dashboard.top_talkers_empty', 'No top-talker telemetry in the current window.'))}</td></tr>`;
        } else {
            talkersBody.innerHTML = sources.map((src) => {
                const ip = String(src.src_ip || src.id || '-');
                const identity = byIp.get(ip);
                const name = identity?.display_name && identity.display_name !== ip ? ` ${identity.display_name}` : '';
                const stateText = identity ? String(identity.state || (identity.trusted ? 'trusted' : 'unknown')) : '-';
                const stateTone = ['unauthorized', 'mismatch', 'missing'].includes(stateText)
                    ? 'status-danger'
                    : (stateText === 'unknown' ? 'status-neutral' : 'status-safe');
                const share = Math.max(3, Math.round(((Number(src.bytes) || 0) / maxBytes) * 100));
                const shareTone = share >= 60 ? ' status-caution' : '';
                return `<tr>
                    <td><strong>${escapeHtml(ip)}</strong>${escapeHtml(name)}</td>
                    <td>${escapeHtml(formatBytesShort(src.bytes))}</td>
                    <td><span class="share-bar${shareTone}" style="width:${Math.min(90, share)}px"></span></td>
                    <td><span class="focus-badge ${stateTone}">${escapeHtml(stateText)}</span></td>
                </tr>`;
            }).join('');
        }
    }

    // Runtime meters (same math as the resource guard).
    const queue = health.queue || {};
    const llm = health.llm || {};
    const depth = Number(queue.depth ?? 0);
    const cap = Number(queue.capacity ?? 0);
    const queuePct = cap > 0 ? Math.min(100, (depth / cap) * 100) : 0;
    const fallbackPct = Math.min(100, Math.max(0, Number(llm.fallback_rate ?? 0) * 100));
    const latencyEma = Number(llm.latency_ms_ema ?? 0);
    const latencyPct = Math.min(100, Math.max(0, (latencyEma / 1500) * 100));
    updateElement('nocMeterQueueLabel', `${tr('dashboard.queue', 'Queue')} ${depth}/${cap}`);
    setMeterFill('nocMeterQueueBar', queuePct, queuePct >= 90 ? 'status-danger' : (queuePct >= 65 ? 'status-caution' : 'status-safe'));
    updateElement('nocMeterFallbackLabel', `${tr('dashboard.fallback_rate', 'Fallback Rate')} ${Math.round(fallbackPct)}%`);
    setMeterFill('nocMeterFallbackBar', fallbackPct, fallbackPct >= 50 ? 'status-danger' : (fallbackPct >= 20 ? 'status-caution' : 'status-safe'));
    updateElement('nocMeterLatencyLabel', `${tr('dashboard.latency', 'Latency')} ${Math.round(latencyEma)} ms`);
    setMeterFill('nocMeterLatencyBar', latencyPct, latencyPct >= 85 ? 'status-danger' : (latencyPct >= 55 ? 'status-caution' : 'status-safe'));

    const chips = document.getElementById('nocServiceChips');
    if (chips) {
        const entries = Object.entries(summary.service_health_summary || {});
        chips.innerHTML = entries.length
            ? entries.map(([name, value]) => {
                const tone = toneForStatus(value);
                const cls = tone === 'status-safe' ? 'status-safe' : (tone === 'status-danger' ? 'status-danger' : (tone === 'status-caution' ? 'status-caution' : ''));
                return `<span class="simple-chip ${cls}">${escapeHtml(name)} ${escapeHtml(String(value || '-').toUpperCase())}</span>`;
            }).join('')
            : `<span class="simple-chip">${escapeHtml(tr('dashboard.no_data', 'No data'))}</span>`;
    }
}

function updateCommandStrip(summary, health, failures = []) {
    const strip = summary.command_strip || {};
    const idleFlags = health.idle_flags || {};
    updateElement('stripMode', String(strip.current_mode || '--').toUpperCase());
    updateElement('stripRisk', summary.risk?.user_state || '--');
    updateElement('stripUplink', strip.current_uplink || '--');
    updateElement('stripInternet', strip.internet_reachability || '--');
    updateElement('stripCritical', String(strip.direct_critical_count ?? 0));
    azAttnCheckCriticalForBand(Number(strip.direct_critical_count ?? 0));
    updateElement('stripDeferred', String(strip.deferred_count ?? 0));
    updateElement('stripQueue', `${health.queue?.depth ?? 0} / ${health.queue?.capacity ?? 0}`);
    const aiContributionPct = Math.round(Number(strip.ai_contribution_rate ?? 0) * 100);
    const aiFallbackPct = Math.round(Number(strip.ai_fallback_rate ?? 0) * 100);
    updateElement('stripAiContribution', `${aiContributionPct}%`);
    updateElement('stripAiFallback', `${aiFallbackPct}%`);
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
    // FIX A: deferred_count is a lifetime monotonic counter (never decreases),
    // so keying tone off it would pin this pill to caution forever after the
    // first LLM-queue-full event. deferred_recent is the windowed/decaying
    // view of the same signal (agent.py `_update_ui_snapshot`); it ages back
    // to zero once queue-full pressure stops, so the pill reflects CURRENT
    // pressure, not history. deferred_count is still shown as text for audit.
    setPillTone('stripDeferred', Number(strip.deferred_recent || 0) > 0 ? 'caution' : 'safe');
    const queueDepth = Number(health.queue?.depth || 0);
    const queueCapacity = Number(health.queue?.capacity || 0);
    const queueRatio = queueCapacity > 0 ? queueDepth / queueCapacity : 0;
    setPillTone('stripQueue', queueRatio >= 0.8 ? 'danger' : (queueRatio >= 0.4 ? 'caution' : 'safe'));
    setPillTone('stripAiContribution', aiContributionPct >= 40 ? 'safe' : 'caution');
    setPillTone('stripAiFallback', aiFallbackPct >= 50 ? 'danger' : (aiFallbackPct >= 20 ? 'caution' : 'safe'));
    setPillTone('stripStale', strip.stale_warning ? 'danger' : 'safe');
    setPillTone('freshnessSnapshot', health.stale_flags?.snapshot ? 'danger' : 'safe');
    setPillTone('freshnessAiMetrics', health.stale_flags?.ai_metrics ? 'danger' : 'safe');
    setPillTone('freshnessAiActivity', health.stale_flags?.ai_activity ? 'danger' : (idleFlags.ai_activity ? 'caution' : 'safe'));
    setPillTone('freshnessRunbook', health.stale_flags?.runbook_events ? 'danger' : (idleFlags.runbook_events ? 'caution' : 'safe'));
    azFoldUpdateCommandStripBadge();
}

// az-strip-fold: worst-tone aggregation badge for the collapsed runtime-pills fold (Issue #300, item 2)
function azFoldUpdateCommandStripBadge() {
    const hiddenPillIds = ['stripDeferred', 'stripQueue', 'stripAiContribution', 'stripAiFallback',
        'freshnessSnapshot', 'freshnessAiMetrics', 'freshnessAiActivity', 'freshnessRunbook'];
    let worst = 'status-safe';
    let flagged = 0;
    hiddenPillIds.forEach((id) => {
        const valueEl = document.getElementById(id);
        const pill = valueEl ? valueEl.closest('.strip-pill, .freshness-pill') : null;
        if (!pill) return;
        let tone = 'status-safe';
        if (pill.classList.contains('pill-danger')) tone = 'status-danger';
        else if (pill.classList.contains('pill-caution')) tone = 'status-caution';
        if (tone !== 'status-safe') flagged += 1;
        worst = strongestTone(worst, tone);
    });
    const badge = document.getElementById('commandStripFoldBadge');
    if (badge) {
        badge.className = `toggle-summary-badge ${worst}`;
        badge.textContent = summaryBadgeLabel(worst);
    }
    const text = document.getElementById('commandStripFoldText');
    if (text) {
        text.className = `toggle-summary-text ${worst}`;
        text.textContent = flagged > 0
            ? tr('dashboard.command_strip_fold_summary', '{count} hidden | worst {tone}', { count: flagged, tone: summaryBadgeLabel(worst) })
            : tr('dashboard.command_strip_details_show', 'Show runtime pills');
    }
}

function updateSituationBoard(summary, state, health, mattermost) {
    const risk = summary.risk || {};
    const postureTone = toneForRisk(risk.user_state, risk.suspicion);
    const postureCard = document.getElementById('postureCard');
    if (postureCard) {
        postureCard.className = `situation-card posture-card ${postureTone}`;
        azAttnNotePanelTone('postureCard', postureCard, postureTone);
    }

    updateElement('postureState', `${risk.user_state || '--'} / ${risk.state_name || '--'}`);
    azAttnUpdateRiskScore(risk.suspicion ?? 0, postureTone);
    azSparkPush('risk', risk.suspicion ?? 0);
    azSparkRender('risk', 'azSparkRisk', postureTone);
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
        trustCapsule.professional_summary || trustCapsule.beginner_summary || tr('dashboard.trust_summary_waiting', 'Waiting for trust synthesis.'),
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
    }), { maxVisible: 6 });

    renderTimeline('decisionChangesTimeline', evidence.decision_changes || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }), { maxVisible: 6 });

    renderTimeline('operatorInteractionsTimeline', evidence.operator_interactions || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }), { maxVisible: 6 });

    renderTimeline('backgroundHistoryTimeline', evidence.background_history || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }), { maxVisible: 6 });
    renderTimeline('triageAuditTimeline', evidence.triage_audit || [], (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }), { maxVisible: 6 });
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
    // Keep more context available than the initial view shows: paintTimeline caps
    // the visible rows and offers a "+N more" expander for the rest.
    const topNow = Array.isArray(alertQueues.now?.items) ? alertQueues.now.items.slice(0, 8) : [];
    const topEsc = Array.isArray(alertQueues.escalation_candidates) ? alertQueues.escalation_candidates.slice(0, 4) : [];
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
    }), { maxVisible: 5 });

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

    const timelineItems = Array.isArray(evidence?.current_triggers) ? evidence.current_triggers.slice(0, 12) : [];
    renderTimeline('topoliteIncidentTimeline', timelineItems, (item) => ({
        metaLeft: item.ts_iso || '-',
        metaRight: item.kind || '-',
        title: item.title || '-',
        detail: item.detail || '-',
    }), { maxVisible: 6 });

    updateElement(
        'topoliteSingleScreenSummary',
        `Threat ${threat} | Path ${pathState} | Action ${actionName} | Source ${String(evidence?.data_source || 'live').toUpperCase()}`,
    );
}

// Comm status in the handoff rail: Mattermost reachability + link targets.
function updateCommStatus(mattermost) {
    updateElement('mattermostState', mattermost.reachable ? tr('dashboard.state_reachable', 'reachable') : tr('dashboard.state_unreachable', 'unreachable'));
    const mattermostLink = document.getElementById('assistantMattermostLink');
    if (mattermostLink) mattermostLink.href = mattermost.open_url || '/ops-comm';
}

function updateControlButtons(summary) {
    const currentMode = String(summary.mode?.current_mode || 'shield').toLowerCase();
    ['portal', 'shield', 'scapegoat'].forEach((mode) => {
        const btn = document.getElementById(`mode${capitalize(mode)}Btn`);
        if (!btn) return;
        btn.classList.toggle('active', currentMode === mode);
        btn.setAttribute('aria-pressed', currentMode === mode ? 'true' : 'false');
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


function updateOperationalResourceGuard(health, healthOk = true) {
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
    if (healthOk) {
        azSparkPush('queue', queuePct);
        azSparkPush('fallback', fallbackPct);
        azSparkPush('latency', latencyPct);
    }
    azSparkRender('queue', 'azSparkQueue', queueTone);
    azSparkRender('fallback', 'azSparkFallback', fallbackTone);
    azSparkRender('latency', 'azSparkLatency', latencyTone);
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
    const rows = Array.isArray(items) && items.length ? items : [tr('dashboard.no_data', 'No data')];
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

function updateGuidanceToggleSummary(doNotDoCount = 0) {
    updateToggleSummary(
        'actionBoardGuidanceDetailsToggle',
        tr('dashboard.action_board_guidance_details_summary_v2', 'Avoid {avoid}', { avoid: doNotDoCount }),
        doNotDoCount > 0 ? 'status-caution' : 'status-safe',
    );
}

function escapeAttribute(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('"', '&quot;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');
}

function renderTimeline(id, items, formatter, opts = {}) {
    const rows = Array.isArray(items) ? items.map((item) => formatter(item)) : [];
    timelineLastRows.set(id, { rows, maxVisible: Number(opts.maxVisible) > 0 ? Number(opts.maxVisible) : null });
    paintTimeline(id);
}

// Repaint a timeline from its stored rows, applying the evidence keyword filter
// (evidence-board timelines only) and the "+N more" cap without refetching.
function paintTimeline(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const entry = timelineLastRows.get(id) || { rows: [], maxVisible: null };
    const filterActive = Boolean(evidenceFilterText) && EVIDENCE_FILTER_IDS.has(id);
    let rows = entry.rows;
    if (filterActive) {
        const query = evidenceFilterText.toLowerCase();
        rows = rows.filter((row) => [row.metaLeft, row.metaRight, row.title, row.detail]
            .some((value) => String(value || '').toLowerCase().includes(query)));
    }
    if (rows.length === 0) {
        const message = filterActive
            ? tr('dashboard.evidence_filter_no_match', 'No entries match the filter.')
            : tr('dashboard.no_recent_entries', 'No recent entries');
        el.innerHTML = `<li><div class="timeline-title">${escapeHtml(message)}</div></li>`;
        return;
    }
    // A filtered view already shows only matches, so the cap is not applied there.
    const cap = filterActive ? null : entry.maxVisible;
    const collapsible = Boolean(cap) && rows.length > cap;
    const expanded = timelineExpanded.has(id);
    const visible = collapsible && !expanded ? rows.slice(0, cap) : rows;
    let html = visible.map((row) => `
            <li>
                <div class="timeline-meta"><span>${escapeHtml(row.metaLeft || '-')}</span><span>${escapeHtml(row.metaRight || '-')}</span></div>
                <div class="timeline-title">${escapeHtml(row.title || '-')}</div>
                <div class="timeline-detail">${escapeHtml(row.detail || '-')}</div>
            </li>
        `).join('');
    if (collapsible) {
        const label = expanded
            ? tr('dashboard.timeline_show_less', 'Show less')
            : tr('dashboard.timeline_show_more', 'Show {count} more', { count: rows.length - visible.length });
        html += `<li class="timeline-more"><button type="button" class="timeline-more-btn" data-timeline-id="${escapeAttribute(id)}" aria-expanded="${expanded ? 'true' : 'false'}">${escapeHtml(label)}</button></li>`;
    }
    el.innerHTML = html;
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

// ---- az-attn: status-transition attention system (Issue #300, item 1) ----

function azAttnNormalizeTone(tone) {
    const t = String(tone || '').trim();
    if (!t) return 'status-neutral';
    return t.startsWith('status-') ? t : `status-${t}`;
}

function azAttnCancelPulse(elId, el) {
    azAttnPendingPulses.delete(elId);
    const entry = azAttnActivePulses.get(elId);
    if (entry) {
        azAttnActivePulses.delete(elId);
        if (el) {
            el.classList.remove(entry.cls);
            // Must mirror the listener attached in azAttnStartPulse: if a pulse is pre-empted
            // (e.g. a new tone change arrives before the old pulse's animation-duration
            // elapses) before 'animationend' ever fires, that listener would otherwise stay
            // bound to el forever.
            if (entry.onEnd) el.removeEventListener('animationend', entry.onEnd);
        }
    }
    // Defensive: strip any stale pulse class even if the map entry was already lost/expired
    // (e.g. via azAttnReapply's own expiry check), so a stuck pulse can never survive a tone
    // change back to safe.
    if (el) el.classList.remove('az-attn-pulse-caution', 'az-attn-pulse-danger');
}

function azAttnStartPulse(elId, el, cls, durationMs) {
    if (!el || azAttnReducedMotion) return;
    azAttnCancelPulse(elId, el);
    const details = el.closest('details');
    if (details && !details.open) {
        // CSS animations never run on content inside a closed <details> (browsers hide its
        // contents much like display:none), so 'animationend' would never fire and the pulse
        // class + map entry would sit dormant indefinitely. Defer: replay the pulse fresh once
        // the fold is opened (see azAttnBindFoldCatchup), instead of leaving a stuck class or
        // firing a misleading replay later disconnected from the tone change.
        azAttnPendingPulses.set(elId, { el, cls, durationMs });
        return;
    }
    const onEnd = (ev) => {
        if (ev.target !== el) return;
        el.classList.remove(cls);
        azAttnActivePulses.delete(elId);
        el.removeEventListener('animationend', onEnd);
    };
    azAttnActivePulses.set(elId, { cls, expiresAt: Date.now() + durationMs, onEnd });
    el.classList.add(cls);
    el.addEventListener('animationend', onEnd);
}

// Replay any pulses deferred by azAttnStartPulse while their element sat inside a closed
// <details> fold, once that fold is opened — otherwise the "something changed" cue never
// reaches the operator for pills tucked away in a collapsed fold (Issue #300 round-3 regression).
function azAttnBindFoldCatchup() {
    document.querySelectorAll('details.panel-fold-details').forEach((details) => {
        details.addEventListener('toggle', () => {
            if (!details.open) return;
            azAttnPendingPulses.forEach((pending, elId) => {
                if (!details.contains(pending.el)) return;
                azAttnPendingPulses.delete(elId);
                azAttnStartPulse(elId, pending.el, pending.cls, pending.durationMs);
            });
        });
    });
}

// Re-attach an in-flight pulse class after the caller has just overwritten el.className wholesale.
// Calling classList.add with the SAME class name here, in the same synchronous tick as the caller's
// className overwrite (no forced reflow in between), does NOT restart the CSS animation — browsers
// coalesce same-tick class mutations into one style recalc, so a still-running animation continues
// uninterrupted instead of retriggering every 4s poll.
function azAttnReapply(elId, el) {
    if (!el) return;
    const entry = azAttnActivePulses.get(elId);
    if (!entry) return;
    if (Date.now() >= entry.expiresAt) { azAttnActivePulses.delete(elId); return; }
    el.classList.add(entry.cls);
}

// Call AFTER el.className has already been (re)assigned by the caller.
function azAttnNotePanelTone(elId, el, rawTone) {
    const tone = azAttnNormalizeTone(rawTone);
    const prev = azAttnToneMemory.get(elId);
    azAttnToneMemory.set(elId, tone);
    if (!el || !azAttnFirstSnapshotDone) return; // suppress on initial '-' -> real-value population
    if (prev === tone) { azAttnReapply(elId, el); return; }
    if (tone === 'status-danger') azAttnStartPulse(elId, el, 'az-attn-pulse-danger', AZ_ATTN_DANGER_MS);
    else if (tone === 'status-caution') azAttnStartPulse(elId, el, 'az-attn-pulse-caution', AZ_ATTN_CAUTION_MS);
    else azAttnCancelPulse(elId, el);
}

// Connection-state chip (Issue #300, item 5): distinguishes booting/waiting from an unreachable API.
let azConnLastOk = null; // null until the first poll completes

function azConnSetState(ok) {
    if (ok) {
        azConnConsecutiveFailures = 0;
        lastSuccessfulPollMs = Date.now();
    } else {
        azConnConsecutiveFailures += 1;
    }
    azConnLastOk = ok;
    azConnRenderChip();
    renderFreshnessAge();
}

function azConnRenderChip() {
    const chip = document.getElementById('connStateChip');
    const valueEl = document.getElementById('connStateChipValue');
    const descEl = document.getElementById('connStateChipDesc');
    if (!chip || !valueEl) return;
    const hadPriorSuccess = lastSuccessfulPollMs !== null;
    // Mirror the tooltip into a visible-on-focus sr-only node: `title` only ever surfaces on
    // mouse hover, which keyboard and touch/kiosk operators can never trigger.
    const lastSuccessText = hadPriorSuccess
        ? tr('dashboard.conn_state.last_success', 'Last successful update: {time}', { time: new Date(lastSuccessfulPollMs).toLocaleTimeString() })
        : '';
    chip.classList.remove('status-safe', 'status-caution', 'status-danger');
    if (pollingPaused) {
        chip.classList.add('status-caution');
        valueEl.textContent = tr('dashboard.conn_state.paused', 'PAUSED');
        chip.title = lastSuccessText;
        if (descEl) descEl.textContent = lastSuccessText;
        return;
    }
    if (azConnLastOk === null) return; // still booting: keep the INIT placeholder
    if (azConnLastOk) {
        chip.classList.add('status-safe');
        valueEl.textContent = tr('dashboard.conn_state.live', 'LIVE');
        chip.title = '';
        if (descEl) descEl.textContent = '';
        return;
    }
    // Tolerate a single transient failure after a prior success: keep the last-good
    // LIVE chip for one blip so a one-cycle slow poll (dev web server briefly starving
    // /api/state while /api/dashboard/evidence holds a worker) doesn't flap the link
    // indicator OFFLINE on the booth screen. Escalate to OFFLINE only once the failure
    // persists (>=2 consecutive), or immediately if we've never had a successful snapshot.
    if (hadPriorSuccess && azConnConsecutiveFailures < 2) {
        chip.classList.add('status-safe');
        return;
    }
    chip.classList.add('status-danger');
    valueEl.textContent = tr('dashboard.conn_state.offline', 'OFFLINE');
    chip.title = lastSuccessText;
    if (descEl) descEl.textContent = lastSuccessText;
}

// "UPD" freshness chip: seconds since the last successful poll, re-rendered by
// the shared 1s header-clock interval so the age visibly counts up between polls.
function renderFreshnessAge() {
    const el = document.getElementById('freshnessAgeValue');
    if (!el) return;
    if (lastSuccessfulPollMs === null) {
        el.textContent = '-';
        return;
    }
    const ageMs = Math.max(0, Date.now() - lastSuccessfulPollMs);
    const sec = Math.round(ageMs / 1000);
    el.textContent = sec < 60
        ? `${sec}s`
        : `${Math.floor(sec / 60)}m${String(sec % 60).padStart(2, '0')}s`;
    const chipEl = document.getElementById('freshnessChip');
    if (chipEl) {
        chipEl.classList.remove('status-caution');
        // Flag visibly stale data once several poll intervals have passed with
        // no successful refresh (also counts up while paused, on purpose).
        if (ageMs >= Math.max(POLL_INTERVAL_MS * 3, 15000)) {
            chipEl.classList.add('status-caution');
        }
    }
}

// Two band-trigger conditions can fire within the same synchronous refresh tick (e.g. a single
// correlated incident both flips the hero to danger AND bumps the direct-critical count).
// Buffer messages that arrive before the microtask flush instead of letting the second call
// unconditionally overwrite the first, so neither alert is silently lost.
let azAttnBandPendingMessages = [];
let azAttnBandFlushQueued = false;

function azAttnShowAlertBand(message) {
    if (!message) return;
    azAttnBandPendingMessages.push(message);
    if (azAttnBandFlushQueued) return;
    azAttnBandFlushQueued = true;
    Promise.resolve().then(azAttnFlushAlertBand);
}

function azAttnFlushAlertBand() {
    azAttnBandFlushQueued = false;
    const messages = azAttnBandPendingMessages;
    azAttnBandPendingMessages = [];
    if (messages.length === 0) return;
    const band = document.getElementById('globalAlertBand');
    const msgEl = document.getElementById('globalAlertBandMessage');
    if (!band || !msgEl) return;
    msgEl.textContent = messages.join('  •  ');
    band.classList.add('az-attn-band-show');
    if (azAttnBandTimer) window.clearTimeout(azAttnBandTimer);
    azAttnBandTimer = window.setTimeout(azAttnHideAlertBand, 12000);
}

function azAttnHideAlertBand() {
    const band = document.getElementById('globalAlertBand');
    if (band) band.classList.remove('az-attn-band-show');
    if (azAttnBandTimer) { window.clearTimeout(azAttnBandTimer); azAttnBandTimer = null; }
}

// Scope: band fires ONLY on (a) hero transition into danger, (b) direct-critical count increasing.
// (Per-panel pulses above already cover every other watched element generically.)
function azAttnCheckHeroForBand(overallTone) {
    const tone = azAttnNormalizeTone(overallTone);
    const prev = azAttnPrevHeroTone;
    azAttnPrevHeroTone = tone;
    if (!azAttnFirstSnapshotDone || prev === tone || tone !== 'status-danger') return;
    const area = tr('dashboard.alert_band.area_overall', 'Overall status');
    azAttnShowAlertBand(tr('dashboard.alert_band.transition', '{area} just changed to DANGER — check immediately.', { area }));
}

function azAttnCheckCriticalForBand(count) {
    const prev = azAttnPrevDirectCritical;
    azAttnPrevDirectCritical = count;
    if (!azAttnFirstSnapshotDone || prev === null || !(count > prev)) return;
    const label = tr('dashboard.direct_critical', 'Direct Critical');
    azAttnShowAlertBand(tr('dashboard.alert_band.critical_increase', '{label} increased to {count}.', { label, count }));
}

function azAttnUpdateRiskScore(value, tone) {
    const el = document.getElementById('riskScore');
    if (!el) return;
    const target = Number(value) || 0;
    const toneCls = azAttnNormalizeTone(tone);
    el.classList.remove('status-safe', 'status-caution', 'status-danger', 'status-neutral');
    el.classList.add(toneCls);

    const previous = Number(el.dataset.azAttnValue ?? target);
    el.dataset.azAttnValue = String(target);

    if (!azAttnFirstSnapshotDone || azAttnReducedMotion || previous === target) {
        el.textContent = String(target);
        return;
    }
    if (!azAttnReducedMotion) {
        el.classList.remove('az-attn-riskscore-bump');
        void el.offsetWidth; // force reflow so the bump can retrigger on consecutive changes
        el.classList.add('az-attn-riskscore-bump');
    }
    const start = performance.now();
    const DURATION = 450; // ms; short + terminating rAF, no continuous loop
    function step(now) {
        const p = Math.min(1, (now - start) / DURATION);
        const eased = 1 - Math.pow(1 - p, 2);
        el.textContent = String(Math.round(previous + (target - previous) * eased));
        if (p < 1) window.requestAnimationFrame(step);
        else el.textContent = String(target);
    }
    window.requestAnimationFrame(step);
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
