/* =============================================================================
   Azazel-Edge touch console (/touch) — kiosk front end for a touch display.
   -----------------------------------------------------------------------------
   - Reads and operates ONLY through the existing Web UI API with the existing
     token and roles (no new endpoint, no new permission). See API below.
   - Secrets: the access token and a Wi-Fi passphrase live in page memory only.
     Nothing secret is written to localStorage/sessionStorage/cookies, put in a
     URL, or logged. A token query parameter in the address is removed, NOT used.
   - Honesty: absent data renders as "—"/unknown, stale data is never green,
     and an operation result is shown as success only when the API answered
     ok: true. not_implemented / undelivered / delivery_unknown /
     status_api_error and transport failures are shown as what they are.
   - AI (M.I.O.) output is labelled advisory; the Defensive State shown is the
     deterministic arbiter's selected action.
   Pure logic is exported for tests/touch_console_logic.test.js (node).
   ========================================================================== */
(function (root, factory) {
    var api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.AzazelTouch = api;
        api.boot();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* The complete list of endpoints this page calls. Each one already exists
       in azazel_edge_web/app.py; tests/test_touch_console_v1.py checks that
       this file calls nothing else. */
    var API = {
        bundle: '/api/dashboard/bundle',
        stateStream: '/api/state/stream',
        wifiScan: '/api/wifi/scan',
        wifiConnect: '/api/wifi/connect',
        runbookGet: '/api/runbooks/',
        runbookAct: '/api/runbooks/act'
    };

    var SNAPSHOT_STALE_SEC = 30;   // app.py DASHBOARD_SNAPSHOT_STALE_SEC default
    var STREAM_IDLE_MS = 10000;    // no SSE event for this long -> reconnect
    /* Load on the Edge: every open /api/state/stream runs the monitoring
       checks (systemctl) and a mode_status query once a second on the
       server. The kiosk therefore keeps the stream open only while someone
       is using the panel; otherwise the dashboard's own bundle poll (>= 4 s)
       carries the data, and nothing runs while the page is hidden. */
    var STREAM_USER_IDLE_MS = 5 * 60 * 1000;   // no touch for 5 min -> close the stream
    var STREAM_BACKOFF_MAX_MS = 60000;
    var STREAM_ERROR_HOLDOFF_MS = 5 * 60 * 1000; // after 3 stream_error in a row
    var POST_TIMEOUT_MS = 40000;   // daemon socket timeout is 30 s
    var GET_TIMEOUT_MS = 12000;
    var HOLD_MS = 1200;            // press-and-hold to confirm
    var SECRET_MAX = 128;

    /* ------------------------------------------------------------------ */
    /* Pure logic                                                          */
    /* ------------------------------------------------------------------ */
    var OK_WORDS = ['healthy', 'normal', 'safe', 'ok', 'good', 'quiet', 'low', 'up', 'on', 'ready', 'clear', 'stable', 'connected'];
    var WATCH_WORDS = ['watch', 'elevated', 'caution', 'degraded', 'partial', 'suspected', 'drift', 'limited', 'pending', 'stale', 'checking', 'warn', 'warning', 'medium'];
    var CRIT_WORDS = ['critical', 'danger', 'alert', 'down', 'outage', 'compromised', 'failed', 'fail', 'high', 'disconnected'];

    function toneOf(word) {
        var w = String(word == null ? '' : word).trim().toLowerCase();
        if (!w) return 'unknown';
        if (CRIT_WORDS.indexOf(w) !== -1) return 'crit';
        if (WATCH_WORDS.indexOf(w) !== -1) return 'watch';
        if (OK_WORDS.indexOf(w) !== -1) return 'ok';
        return 'unknown';
    }

    // UNKNOWN ranks above OK: an unverified input never yields green.
    function worstTone() {
        var order = { ok: 0, neutral: 0, unknown: 1, stale: 1, watch: 2, crit: 3 };
        var worst = null;
        for (var i = 0; i < arguments.length; i++) {
            var t = arguments[i];
            if (!(t in order)) continue;
            if (worst === null || order[t] > order[worst]) worst = t;
        }
        return worst || 'unknown';
    }

    // Stale data must not read as healthy: a green tone becomes "stale".
    function staleTone(tone, stale) {
        return (stale && (tone === 'ok' || tone === 'neutral')) ? 'stale' : tone;
    }

    // Canonical Defensive State vocabulary (docs/architecture/decision-loop.md).
    var DEFENSIVE_TONES = { OBSERVE: 'ok', NOTIFY: 'watch', THROTTLE: 'watch', REDIRECT: 'crit', ISOLATE: 'crit' };
    function defensiveTone(action) {
        return DEFENSIVE_TONES[String(action || '').toUpperCase()] || 'unknown';
    }

    function num(v) {
        if (v === null || v === undefined || v === '') return null;
        var n = Number(v);
        return isFinite(n) ? n : null;
    }

    function obj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
    function arr(v) { return Array.isArray(v) ? v : []; }
    function str(v) { return v == null ? '' : String(v).trim(); }

    /* Classify an operation response. Success only for an HTTP 2xx whose body
       says ok: true (or the legacy status: "ok"). transportError is set when
       no HTTP answer was read (network error, abort/timeout): the request may
       or may not have reached the daemon, so it is delivery_unknown. */
    function classifyResult(httpStatus, payload, transportError, method) {
        var p = obj(payload);
        var structured = !!payload && typeof payload === 'object' && (p.ok !== undefined || p.error !== undefined || p.status !== undefined);
        var msg = str(p.error || p.message).slice(0, 240);
        if (transportError) return { kind: 'delivery_unknown', message: str(transportError).slice(0, 120) };
        if (httpStatus === 401 || httpStatus === 403) return { kind: 'unauthorized', message: msg };
        if (p.delivery_unknown === true) return { kind: 'delivery_unknown', message: msg };
        if (p.not_implemented === true || msg === 'not_implemented') return { kind: 'not_implemented', message: msg };
        if (p.undelivered === true) return { kind: 'undelivered', message: msg };
        if (p.status_api_error === true) return { kind: 'failed', message: msg || 'status_api_error' };
        if (httpStatus === 409) return { kind: 'rejected', message: msg };
        var ok2xx = httpStatus >= 200 && httpStatus < 300;
        if (ok2xx && (p.ok === true || (p.ok === undefined && p.status === 'ok'))) return { kind: 'ok', message: msg };
        // app.py _send_control_command_socket: the request was sent but no
        // (complete) reply came back -> it may have run.
        if (/daemon timeout|timed? ?out|empty response from daemon|connection reset|broken pipe/i.test(msg)) return { kind: 'delivery_unknown', message: msg };
        // Never reached the daemon: socket file missing or connect refused.
        if (/daemon not running|no such file|connection refused/i.test(msg)) return { kind: 'undelivered', message: msg };
        // The daemon refused before running anything (busy, rate limit, peer table).
        if (/^busy$|connect busy|rate limit|^forbidden$/i.test(msg)) return { kind: 'busy', message: msg };
        // A POST answered 5xx without the API's JSON (proxy error page, worker
        // killed mid-request): it may have run.
        if (method === 'POST' && httpStatus >= 500 && !structured) return { kind: 'delivery_unknown', message: 'HTTP ' + httpStatus };
        if (ok2xx && p.ok === undefined && !msg) return { kind: 'failed', message: 'invalid response' };
        return { kind: 'failed', message: msg || ('HTTP ' + httpStatus) };
    }

    /* Minimal text/event-stream parser (event, data, retry; comments ignored). */
    function createSseParser(onEvent) {
        var buf = '';
        var evName = '';
        var dataLines = [];
        var retry = null;
        function dispatch() {
            if (dataLines.length) onEvent({ event: evName || 'message', data: dataLines.join('\n'), retry: retry });
            evName = '';
            dataLines = [];
        }
        return {
            feed: function (chunk) {
                buf += String(chunk || '');
                if (buf.length > 4 * 1024 * 1024) { buf = ''; dataLines = []; evName = ''; return; }
                var m;
                while ((m = /\r\n|\n|\r/.exec(buf)) !== null) {
                    var line = buf.slice(0, m.index);
                    buf = buf.slice(m.index + m[0].length);
                    if (line === '') { dispatch(); continue; }
                    if (line.charAt(0) === ':') continue;
                    var c = line.indexOf(':');
                    var field = c < 0 ? line : line.slice(0, c);
                    var val = c < 0 ? '' : line.slice(c + 1);
                    if (val.charAt(0) === ' ') val = val.slice(1);
                    if (field === 'event') evName = val;
                    else if (field === 'data') dataLines.push(val);
                    else if (field === 'retry' && /^\d+$/.test(val)) retry = Number(val);
                }
            },
            retryMs: function () { return retry; }
        };
    }

    /* A secret typed on the on-screen keyboard: kept as single characters so
       it is never one long-lived string, and wiped right after use. JS cannot
       promise the engine overwrote every copy; it drops every reference. */
    function createSecretBuffer(max) {
        var chars = [];
        var limit = max || SECRET_MAX;
        return {
            push: function (ch) { if (chars.length < limit) chars.push(String(ch).charAt(0)); },
            pop: function () { if (chars.length) chars[chars.length - 1] = ''; chars.pop(); },
            clear: function () { for (var i = 0; i < chars.length; i++) chars[i] = ''; chars.length = 0; },
            length: function () { return chars.length; },
            reveal: function () { return chars.join(''); },
            take: function () { var s = chars.join(''); this.clear(); return s; }
        };
    }

    /* Press-and-hold progress. Each frame adds at most HOLD_FRAME_CAP_MS, so a
       stalled tab (throttled timers, a long frame, a suspended display) can
       never jump to "done" in one step: it needs HOLD_MS of observed frames. */
    var HOLD_FRAME_CAP_MS = 100;
    function advanceHold(state, nowMs) {
        var st = state || {};
        var last = num(st.lastMs);
        var elapsed = num(st.elapsedMs) || 0;
        var step = last === null ? 0 : Math.max(0, Math.min(HOLD_FRAME_CAP_MS, nowMs - last));
        elapsed += step;
        return { lastMs: nowMs, elapsedMs: elapsed, progress: Math.min(1, elapsed / HOLD_MS), done: elapsed >= HOLD_MS };
    }

    /* On-screen keyboard: one key press against { shift, sym } and a secret
       buffer. Returns the new modifier state and whether keys must be redrawn. */
    function applyKey(kbState, key, buffer) {
        var st = { shift: !!(kbState && kbState.shift), sym: !!(kbState && kbState.sym) };
        if (key === '{shift}') { if (!st.sym) st.shift = !st.shift; return { shift: st.shift, sym: st.sym, redraw: true }; }
        if (key === '{sym}') return { shift: false, sym: !st.sym, redraw: true };
        if (key === '{bksp}') { buffer.pop(); return { shift: st.shift, sym: st.sym, redraw: false }; }
        if (key === '{clear}') { buffer.clear(); return { shift: st.shift, sym: st.sym, redraw: false }; }
        if (key === '{space}') { buffer.push(' '); return { shift: st.shift, sym: st.sym, redraw: false }; }
        var ch = String(key || '');
        if (ch.length !== 1) return { shift: st.shift, sym: st.sym, redraw: false };
        buffer.push(st.shift && !st.sym ? ch.toUpperCase() : ch);
        return { shift: false, sym: st.sym, redraw: st.shift };
    }

    /* SSID for display only (the value sent is the original): no control or
       bidi-override characters, at most 32 characters. */
    function displaySsid(value) {
        var cleaned = String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '');
        return cleaned.length > 32 ? cleaned.slice(0, 31) + '…' : cleaned;
    }

    /* Whether the state stream should be open now. */
    function streamWanted(o) {
        o = o || {};
        if (o.hidden || o.authProblem || o.unsupported) return false;
        if (num(o.nowMs) === null) return false;
        if (o.holdOffUntilMs && o.nowMs < o.holdOffUntilMs) return false;
        return (o.nowMs - (num(o.lastInteractionMs) || 0)) < STREAM_USER_IDLE_MS;
    }

    /* Delay before reconnecting after the stream ended. The server's retry
       hint (sent with stream_error, 15 s on main) is a floor; transport
       failures back off exponentially up to a minute. */
    function nextStreamDelay(o) {
        o = o || {};
        var backoff = Math.min(STREAM_BACKOFF_MAX_MS, Math.max(2000, num(o.backoffMs) || 2000));
        var hint = num(o.retryHintMs);
        if (o.ended === 'stream_error') return Math.max(hint || 15000, backoff);
        if (o.ended === 'auth') return STREAM_BACKOFF_MAX_MS;
        return hint ? Math.max(hint, backoff) : backoff;
    }

    function fmtAge(sec, trf) {
        var tr = trf || function (k, d, v) { return d.replace(/\{(\w+)\}/g, function (_, n) { return v[n]; }); };
        if (sec === null || sec === undefined || !isFinite(sec)) return '—';
        var s = Math.max(0, Math.round(sec));
        if (s < 60) return tr('touch.age_sec', '{n}s ago', { n: s });
        if (s < 3600) return tr('touch.age_min', '{n} min ago', { n: Math.floor(s / 60) });
        return tr('touch.age_hour', '{n} h ago', { n: Math.floor(s / 3600) });
    }

    // The newer of the bundle's state and the live (SSE) state.
    function pickState(bundleState, liveState) {
        var b = obj(bundleState);
        var l = liveState ? obj(liveState) : null;
        if (!l) return b;
        var be = num(b.snapshot_epoch);
        var le = num(l.snapshot_epoch);
        if (le !== null && (be === null || le >= be)) return l;
        if (le === null && be === null) return l;
        return b;
    }

    /* Everything the status pane shows, derived from existing API payloads.
       input: { bundle, live, nowSec, skewSec, linkLost } */
    function deriveView(input) {
        input = input || {};
        var b = obj(input.bundle);
        var summary = obj(b.summary);
        var health = obj(b.health);
        var focus = obj(b.decision_focus);
        var evidence = obj(b.evidence);
        var actions = obj(b.actions);
        var hasBundle = !!input.bundle;
        var state = pickState(b.state, input.live);
        var modeRuntime = obj(state.mode_runtime);
        var connection = obj(state.connection);
        var nowSec = num(input.nowSec);
        var skew = num(input.skewSec) || 0;

        var epoch = num(state.snapshot_epoch);
        var age = (epoch !== null && nowSec !== null) ? Math.max(0, nowSec - skew - epoch) : null;
        var snapshotStale = age !== null ? age > SNAPSHOT_STALE_SEC : !!obj(health.stale_flags).snapshot;
        var bootstrap = state.bootstrap === true;
        var stateSource = str(state.source);
        var daemonDown = modeRuntime.ok === false || /^FILE:/.test(stateSource) || stateSource === 'NONE' || stateSource === 'ERROR';
        // Not green unless fresh AND read through the control daemon.
        var stale = snapshotStale || !!input.linkLost || age === null || daemonDown || bootstrap;

        // Defensive State: the arbiter's selected action from the decision record.
        var decision = obj(focus.decision);
        var defAction = focus.available === true ? str(decision.action).toUpperCase() : '';
        var def = {
            value: defAction || '—',
            tone: staleTone(defAction ? defensiveTone(defAction) : 'unknown', stale),
            reason: str(decision.reason),
            release: str(decision.release_condition),
            available: !!defAction,
            replay: obj(focus.mode).kind === 'deterministic_replay',
            // true / false / null (not reported): never guess "enforced".
            dryRun: obj(focus.safety).dry_run === true ? true : (obj(focus.safety).dry_run === false ? false : null)
        };

        var soc = obj(summary.soc_focus);
        var noc = obj(obj(summary.noc_focus).path_health);
        var socWord = str(soc.threat_level).toUpperCase();
        var nocWord = str(noc.status).toUpperCase();
        var domains = obj(focus.domains);
        var socReason = focus.available === true ? str(arr(obj(domains.soc).reasons)[0]) : '';
        var nocReason = focus.available === true ? str(arr(obj(domains.noc).reasons)[0]) : '';

        var strip = obj(summary.command_strip);
        var p0 = num(strip.direct_critical_count);
        if (p0 === null) p0 = num(soc.critical_count);
        var liveCrit = input.live ? num(obj(input.live).suricata_critical) : null;
        if (liveCrit !== null && state === input.live) p0 = liveCrit;

        var queues = obj(evidence.alert_queues);
        var qNow = obj(queues.now);
        var qWatch = obj(queues.watch);
        var qBacklog = obj(queues.backlog);

        // The legacy concept mode (portal/shield/scapegoat) is deliberately not
        // shown or offered here (#340). mode_runtime is read only to tell
        // whether the control daemon answered.
        var audit = obj(focus.audit);
        var trace = {
            id: focus.available === true ? str(audit.trace_id) : '',
            policy: focus.available === true ? str(audit.policy_profile) : '',
            format: focus.available === true ? str(audit.format_version) : ''
        };

        var inet = str(connection.internet_check).toUpperCase();
        var upIf = str(state.up_if);
        var upType = str(connection.uplink_type);
        var uplinkTone = inet === 'OK' ? 'ok' : (inet === 'FAIL' ? 'crit' : 'unknown');
        var uplink = {
            value: (upIf && upIf !== '-' ? upIf : '—') + (upType && upType !== 'unknown' ? ' · ' + upType : ''),
            internet: inet || '—',
            tone: staleTone(uplinkTone, stale),
            ssid: str(state.ssid),
            gateway: str(state.gateway_ip),
            upIp: str(state.up_ip),
            captive: str(connection.captive_portal),
            wifiState: str(connection.wifi_state),
            dnsMismatch: num(obj(state.network_health).dns_mismatch)
        };

        var svc = obj(summary.service_health_summary);
        var aiSvc = str(svc.ai_agent).toUpperCase();
        var aiStale = !!obj(health.stale_flags).ai_metrics;
        var ai;
        if (!hasBundle || !aiSvc) ai = { value: '—', tone: 'unknown', state: 'unknown' };
        else if (aiSvc === 'ON' && !aiStale) ai = { value: 'ON', tone: 'ok', state: 'on' };
        else if (aiSvc === 'ON') ai = { value: 'STALE', tone: 'watch', state: 'stale' };
        else ai = { value: 'OFF', tone: 'neutral', state: 'off' };
        ai.tone = staleTone(ai.tone, stale);

        var mio = obj(actions.mio);
        var topolite = obj(summary.topolite);

        return {
            hasData: hasBundle || !!input.live,
            stale: stale,
            staleReason: snapshotStale || age === null || !!input.linkLost ? 'stale' : (daemonDown || bootstrap ? 'unverified' : ''),
            snapshotStale: snapshotStale,
            snapshotAgeSec: age,
            bootstrap: bootstrap,
            daemonDown: daemonDown,
            synthetic: str(topolite.data_source) === 'synthetic' || str(evidence.data_source) === 'synthetic',
            defensive: def,
            soc: { value: socWord || '—', tone: staleTone(toneOf(socWord), stale), reason: socReason },
            noc: { value: nocWord || '—', tone: staleTone(toneOf(nocWord), stale), reason: nocReason },
            p0: { value: p0, tone: staleTone(p0 === null ? 'unknown' : (p0 > 0 ? 'crit' : 'ok'), stale) },
            queues: {
                now: num(qNow.count), watch: num(qWatch.count), backlog: num(qBacklog.count),
                items: arr(qNow.items).map(function (x) { return Object.assign({ queue: 'now' }, obj(x)); })
                    .concat(arr(qWatch.items).map(function (x) { return Object.assign({ queue: 'watch' }, obj(x)); }))
            },
            trace: trace,
            uplink: uplink,
            ai: ai,
            mioText: str(mio.surface_message || actions.current_user_guidance),
            runbook: obj(actions.suggested_runbook)
        };
    }

    /* ------------------------------------------------------------------ */
    /* Browser side                                                        */
    /* ------------------------------------------------------------------ */
    function boot() {
        if (typeof document === 'undefined') return;
        var CFG = window.AZAZEL_TOUCH || {};
        var CATALOGS = obj(CFG.catalogs);
        // The server-side language (?lang=, X-AZAZEL-LANG, azazel_lang cookie) wins.
        var lang = CFG.lang === 'ja' ? 'ja' : 'en';
        var pollMs = Math.max(4000, Number(CFG.pollMs) || 4000);

        // Secrets: page memory only.
        var token = '';
        try {
            // Same origin key the existing dashboard pages read; read only.
            token = str(window.localStorage.getItem('azazel_token'));
        } catch (_e) { token = ''; }
        stripTokenFromUrl();

        var bundle = null;
        var live = null;
        var skewSec = 0;
        var lastDataMs = 0;
        var lastBundleMs = 0;
        var authProblem = false;
        var pollFailures = 0;
        var pollBusy = false;
        var stream = { status: 'connecting', reason: '', ctrl: null, lastEventMs: 0, retryTimer: null, backoff: 2000, errors: 0, holdOffUntilMs: 0 };
        var lastInteractionMs = Date.now();
        var alertPage = 0;
        var apPage = 0;
        var aps = [];
        var wifiBusy = false;
        var opBusy = false;
        var results = [];
        var runbookDetail = { id: '', requiredArgs: null };
        var currentTab = 'status';

        var $ = function (id) { return document.getElementById(id); };

        function tr(key, fallback, vars) {
            var cat = obj(CATALOGS[lang]);
            var base = (key in cat) ? cat[key] : (key in obj(CATALOGS.en) ? CATALOGS.en[key] : (fallback || key));
            return String(base).replace(/\{(\w+)\}/g, function (_, n) { return (vars && n in vars) ? String(vars[n]) : '{' + n + '}'; });
        }

        function readPref(key, fallback) {
            try { var v = window.localStorage.getItem(key); return v || fallback; } catch (_e) { return fallback; }
        }
        function writePref(key, value) {
            // Non-secret display preferences only (language, theme).
            try { window.localStorage.setItem(key, value); } catch (_e) { /* ignore */ }
        }

        function stripTokenFromUrl() {
            try {
                var url = new URL(window.location.href);
                if (url.searchParams.has('token')) {
                    url.searchParams.delete('token');
                    window.history.replaceState(null, '', url.pathname + (url.search || '') + url.hash);
                    setTimeout(function () { showBanner('url-token', 'watch', tr('touch.url_token_ignored', 'A token in the address was removed and not used. Enter it on the Settings tab.')); }, 0);
                }
            } catch (_e) { /* ignore */ }
        }

        function headers(json) {
            var h = { 'X-AZAZEL-LANG': lang };
            if (json) h['Content-Type'] = 'application/json';
            if (token) h['X-Auth-Token'] = token;
            return h;
        }

        function timeoutSignal(ms) {
            var ctrl = new AbortController();
            var t = setTimeout(function () { ctrl.abort(); }, ms);
            return { signal: ctrl.signal, done: function () { clearTimeout(t); } };
        }

        // Returns { status, payload, transportError }. Never throws.
        function request(method, path, body, timeoutMs) {
            var ts = timeoutSignal(timeoutMs || (method === 'GET' ? GET_TIMEOUT_MS : POST_TIMEOUT_MS));
            var init = { method: method, headers: headers(body !== undefined), cache: 'no-store', credentials: 'same-origin', signal: ts.signal };
            if (body !== undefined) init.body = JSON.stringify(body);
            return fetch(path, init).then(function (res) {
                return res.text().then(function (text) {
                    var payload = null;
                    try { payload = text ? JSON.parse(text) : null; } catch (_e) { payload = null; }
                    return { status: res.status, payload: payload, transportError: '' };
                });
            }).catch(function (err) {
                return { status: 0, payload: null, transportError: (err && err.name === 'AbortError') ? 'timeout' : 'network' };
            }).then(function (r) { ts.done(); return r; });
        }

        /* ---------------- rendering helpers ---------------- */
        var ICON = { ok: 'i-ok', watch: 'i-watch', crit: 'i-crit', unknown: 'i-unknown', stale: 'i-stale', neutral: 'i-neutral' };
        var TONES = ['tone-ok', 'tone-watch', 'tone-crit', 'tone-unknown', 'tone-stale', 'tone-neutral'];

        function setTone(el, tone, keepIcon) {
            if (!el) return;
            TONES.forEach(function (c) { el.classList.remove(c); });
            el.classList.add('tone-' + (tone || 'unknown'));
            if (keepIcon) return;
            var use = el.querySelector('.t-ico use');
            if (use) use.setAttribute('href', '#' + (ICON[tone] || 'i-unknown'));
        }
        // While a sheet is open, the page behind it takes no touch or focus.
        function setInert(on) {
            var app = $('tApp');
            if (!app) return;
            if (on) app.setAttribute('inert', ''); else app.removeAttribute('inert');
        }
        function setText(id, value) {
            var e = $(id);
            if (!e) return;
            e.textContent = value ? String(value) : '';
            e.hidden = !value;
        }
        function text(id, value) {
            var el = $(id);
            if (el) el.textContent = (value === null || value === undefined || value === '') ? '—' : String(value);
        }
        function el(tag, cls, content) {
            var e = document.createElement(tag);
            if (cls) e.className = cls;
            if (content !== undefined && content !== null) e.textContent = String(content);
            return e;
        }

        /* ---------------- banners ---------------- */
        var banners = {};
        var BANNER_ORDER = ['auth', 'link', 'daemon', 'stale', 'synthetic', 'replay', 'url-token'];
        function showBanner(id, tone, message) {
            var cur = banners[id];
            if (cur && cur.tone === tone && cur.message === message) return;
            banners[id] = { tone: tone, message: message };
            paintBanners();
        }
        function clearBanner(id) {
            if (banners[id]) { delete banners[id]; paintBanners(); }
        }
        function paintBanners() {
            var box = $('tBanners');
            if (!box) return;
            box.textContent = '';
            // At most two lines so the panes keep their room; most important first.
            BANNER_ORDER.filter(function (id) { return banners[id]; }).slice(0, 2).forEach(function (id) {
                var b = banners[id];
                var div = el('div', 't-banner tone-' + b.tone);
                var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('class', 't-ico');
                var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                use.setAttribute('href', '#' + (ICON[b.tone] || 'i-unknown'));
                svg.appendChild(use);
                div.appendChild(svg);
                div.appendChild(el('span', '', b.message));
                box.appendChild(div);
            });
            document.body.classList.toggle('t-has-banner', Object.keys(banners).length > 0);
        }

        /* ---------------- status pane ---------------- */
        function currentView() {
            var nowMs = Date.now();
            var limit = Math.max(3 * pollMs, 15000);
            var linkLost = lastDataMs > 0 && (nowMs - lastDataMs) > limit;
            // SOC/NOC/alerts come from the bundle only: an old bundle is stale
            // even while the state stream keeps the snapshot age fresh.
            var bundleOld = lastBundleMs > 0 && (nowMs - lastBundleMs) > limit;
            return deriveView({ bundle: bundle, live: live, nowSec: nowMs / 1000, skewSec: skewSec, linkLost: linkLost || bundleOld || (lastDataMs === 0 && pollFailures > 1) });
        }

        function paint() {
            var v = currentView();
            paintTopBar(v);
            paintStatus(v);
            paintAlerts(v);
            paintNetworkFacts(v);
            paintRunbook(v);
        }

        function paintTopBar(v) {
            var chip = $('tLinkChip');
            var tone, label;
            var nowMs = Date.now();
            var pollOk = lastDataMs > 0 && (nowMs - lastDataMs) <= Math.max(3 * pollMs, 15000);
            if (authProblem) { tone = 'crit'; label = tr('touch.link_auth', 'Token required'); }
            else if (stream.status === 'live' && (nowMs - stream.lastEventMs) < STREAM_IDLE_MS) { tone = 'ok'; label = tr('touch.link_live', 'Live'); }
            else if (pollOk && stream.status === 'paused') { tone = 'ok'; label = tr('touch.link_paused', 'Periodic update'); }
            else if (pollOk) { tone = 'watch'; label = tr('touch.link_polling', 'Polling (stream down)'); }
            else if (lastDataMs === 0 && pollFailures === 0) { tone = 'unknown'; label = tr('touch.link_connecting', 'Connecting'); }
            else { tone = 'crit'; label = tr('touch.link_lost', 'Disconnected — retrying'); }
            setTone(chip, tone);
            text('tLinkText', label);

            var fresh = $('tFreshChip');
            if (v.snapshotAgeSec === null) { setTone(fresh, 'unknown'); text('tFreshText', tr('touch.fresh_unknown', 'Age unknown')); }
            else if (v.snapshotStale || v.staleReason === 'stale') { setTone(fresh, 'stale'); text('tFreshText', tr('touch.fresh_stale', 'STALE {age}', { age: fmtAge(v.snapshotAgeSec, tr) })); }
            else if (v.stale) { setTone(fresh, 'stale'); text('tFreshText', tr('touch.unverified_tag', 'UNVERIFIED') + ' ' + fmtAge(v.snapshotAgeSec, tr)); }
            else { setTone(fresh, 'ok'); text('tFreshText', fmtAge(v.snapshotAgeSec, tr)); }

            var dry = $('tDryChip');
            if (dry) {
                dry.hidden = !v.defensive.available;
                text('tDryText', v.defensive.dryRun === true ? 'DRY RUN' : (v.defensive.dryRun === false ? tr('touch.enforced', 'ENFORCED') : tr('touch.dry_unknown', 'Enforcement unknown')));
                dry.classList.toggle('is-enforced', v.defensive.dryRun === false);
            }

            // Banners derived from the view.
            if (authProblem) showBanner('auth', 'crit', tr('touch.banner_auth', 'The API refused this screen (token missing, wrong or role too low). Enter a token on the Settings tab.'));
            else clearBanner('auth');
            if (tone === 'crit' && !authProblem) showBanner('link', 'crit', tr('touch.banner_link', 'Connection to the Web UI lost. Showing the last data received; retrying.'));
            else clearBanner('link');
            if (v.hasData && v.daemonDown) showBanner('daemon', 'watch', tr('touch.banner_daemon', 'Control daemon not answering: state may come from a file fallback and operations may not be delivered.'));
            else clearBanner('daemon');
            if (v.hasData && v.snapshotStale) showBanner('stale', 'stale', tr('touch.banner_stale', 'Snapshot is stale ({age}). Do not treat this screen as current.', { age: fmtAge(v.snapshotAgeSec, tr) }));
            else if (tone !== 'crit' && lastBundleMs > 0 && (Date.now() - lastBundleMs) > Math.max(3 * pollMs, 15000)) showBanner('stale', 'stale', tr('touch.banner_bundle_old', 'SOC/NOC summary is not being refreshed (last {age}). Do not treat it as current.', { age: fmtAge((Date.now() - lastBundleMs) / 1000, tr) }));
            else clearBanner('stale');
            if (v.synthetic) showBanner('synthetic', 'watch', 'SYNTHETIC DATA - NOT LIVE EVIDENCE');
            else clearBanner('synthetic');
            if (v.defensive.replay) showBanner('replay', 'neutral', 'DETERMINISTIC REPLAY — LOCAL / OFFLINE');
            else clearBanner('replay');
        }

        function paintStatus(v) {
            var def = $('cardDef');
            setTone(def, v.defensive.tone);
            text('defValue', v.defensive.value);
            text('defSub', v.defensive.available ? v.defensive.reason : (v.bootstrap ? tr('touch.initializing', 'Initializing — waiting for the first snapshot') : tr('touch.no_decision', 'No decision record yet')));
            setText('defRelease', v.defensive.available && v.defensive.release ? tr('touch.release', 'Release condition') + ': ' + v.defensive.release : '');
            setText('socReason', v.soc.reason);
            setText('nocReason', v.noc.reason);

            setTone($('cardSoc'), v.soc.tone);
            text('socValue', v.soc.value);
            setTone($('cardNoc'), v.noc.tone);
            text('nocValue', v.noc.value);

            setTone($('cardP0'), v.p0.tone);
            text('p0Value', v.p0.value === null ? '—' : v.p0.value);
            text('p0Sub', v.p0.value === null ? tr('touch.unknown', 'Unknown') : (v.p0.value > 0 ? tr('touch.p0_present', 'Critical evidence present') : tr('touch.p0_none', 'None reported')));

            setTone($('cardAi'), v.ai.tone, true);
            var aiWords = { on: tr('touch.ai_on', 'ON'), off: tr('touch.ai_off', 'OFF'), stale: tr('touch.ai_stale', 'STALE') };
            text('aiValue', aiWords[v.ai.state] || '—');

            setTone($('tileTrace'), v.trace.id ? staleTone('neutral', v.stale) : 'unknown', true);
            text('traceValue', v.trace.id);
            text('traceSub', v.trace.id ? ['policy ' + (v.trace.policy || '—'), v.trace.format].filter(Boolean).join(' · ') : tr('touch.no_decision', 'No decision record yet'));
            setTone($('tileUplink'), v.uplink.tone, true);
            text('uplinkValue', v.uplink.value);
            text('uplinkSub', tr('touch.internet', 'Internet') + ': ' + v.uplink.internet);
            setTone($('tileFresh'), v.snapshotAgeSec === null ? 'unknown' : (v.stale ? 'stale' : 'ok'), true);
            text('freshValue', v.snapshotAgeSec === null ? tr('touch.unknown', 'Unknown') : (v.snapshotStale ? tr('touch.fresh_stale', 'STALE {age}', { age: fmtAge(v.snapshotAgeSec, tr) }) : fmtAge(v.snapshotAgeSec, tr)));
            text('freshSub', v.daemonDown ? tr('touch.source_fallback', 'Source: file fallback (daemon not answering)') : (v.bootstrap ? tr('touch.initializing', 'Initializing — waiting for the first snapshot') : tr('touch.source_daemon', 'Source: control daemon')));
            text('mioText', v.mioText || tr('touch.mio_none', 'No advisory at the moment.'));

            ['cardSoc', 'cardNoc', 'cardP0', 'cardDef', 'cardAi'].forEach(function (id) {
                var c = $(id);
                if (c) c.setAttribute('data-stale', v.staleReason === 'stale' ? tr('touch.stale_tag', 'STALE') : (v.staleReason === 'unverified' ? tr('touch.unverified_tag', 'UNVERIFIED') : ''));
            });
        }

        /* ---------------- paging ---------------- */
        function pageSize(listEl, rowGuessPx) {
            if (!listEl) return 4;
            var h = listEl.clientHeight;
            var first = listEl.firstElementChild;
            var rowH = first ? first.getBoundingClientRect().height : rowGuessPx;
            var gap = 8;
            return Math.max(1, Math.floor((h + gap) / (rowH + gap)) || 1);
        }

        /* ---------------- alerts pane ---------------- */
        function paintAlerts(v) {
            var cells = [['cntP0', v.p0.value, v.p0.tone], ['cntNow', v.queues.now, v.queues.now > 0 ? 'crit' : 'ok'],
                ['cntWatch', v.queues.watch, v.queues.watch > 0 ? 'watch' : 'ok'], ['cntBacklog', v.queues.backlog, 'neutral']];
            cells.forEach(function (c) {
                var box = $(c[0]);
                if (!box) return;
                var known = c[1] !== null && c[1] !== undefined;
                setTone(box, known ? staleTone(c[2], v.stale) : 'unknown', true);
                box.querySelector('strong').textContent = known ? String(c[1]) : '—';
            });
            var badge = $('tAlertBadge');
            // P0 and the NOW queue overlap (both come from the same alerts): show the larger.
            var urgent = Math.max(v.p0.value || 0, v.queues.now || 0);
            if (badge) { badge.hidden = !(urgent > 0); badge.textContent = String(urgent); }

            var list = $('alertList');
            if (!list) return;
            var items = v.queues.items;
            list.textContent = '';
            if (!items.length) {
                list.appendChild(el('li', 't-empty', bundle ? tr('touch.alerts_empty', 'No alerts in the NOW or WATCH queue.') : tr('touch.waiting', 'Waiting for data')));
                text('alertPage', '—');
                return;
            }
            // Measure one row, then fill the visible height.
            list.appendChild(alertRow(items[0]));
            var per = pageSize(list, 64);
            var pages = Math.max(1, Math.ceil(items.length / per));
            alertPage = Math.min(alertPage, pages - 1);
            list.textContent = '';
            items.slice(alertPage * per, alertPage * per + per).forEach(function (it) { list.appendChild(alertRow(it)); });
            text('alertPage', (alertPage + 1) + ' / ' + pages);
            $('alertPrev').disabled = alertPage <= 0;
            $('alertNext').disabled = alertPage >= pages - 1;
        }

        function alertRow(it) {
            var li = el('li', 't-alert tone-' + (it.queue === 'now' ? 'crit' : 'watch'));
            var q = el('span', 't-alert-q', it.queue === 'now' ? tr('touch.queue_now', 'Now') : tr('touch.queue_watch', 'Watch'));
            var main = el('div', 't-alert-main');
            main.appendChild(el('strong', '', str(it.attack_type) || ('SID ' + (it.sid || '—'))));
            main.appendChild(el('span', 't-alert-meta', [str(it.ts_iso).replace('T', ' ').slice(0, 19) || '—', (str(it.src_ip) || '—') + ' → ' + (str(it.dst_ip) || '—')].join(' · ')));
            var risk = el('b', 't-alert-risk', String(num(it.risk_score) === null ? '—' : it.risk_score));
            li.appendChild(q); li.appendChild(main); li.appendChild(risk);
            return li;
        }

        /* ---------------- network pane ---------------- */
        function paintNetworkFacts(v) {
            var dl = $('netFacts');
            if (!dl) return;
            var u = v.uplink;
            var rows = [
                [tr('touch.net_interface', 'Interface'), u.value],
                [tr('touch.internet', 'Internet'), u.internet],
                ['SSID', u.ssid],
                [tr('touch.net_wifi_state', 'Wi-Fi state'), u.wifiState],
                [tr('touch.net_address', 'Address'), u.upIp],
                [tr('touch.net_gateway', 'Gateway'), u.gateway],
                [tr('touch.net_captive', 'Captive portal'), u.captive],
                [tr('touch.net_dns_mismatch', 'DNS mismatch'), u.dnsMismatch === null ? '' : u.dnsMismatch],
                ['NOC', v.noc.value]
            ];
            dl.textContent = '';
            rows.forEach(function (r) {
                var d = el('div', 't-fact');
                d.appendChild(el('dt', '', r[0]));
                d.appendChild(el('dd', '', (r[1] === '' || r[1] === null || r[1] === undefined || r[1] === '-') ? '—' : r[1]));
                dl.appendChild(d);
            });
            dl.classList.toggle('is-stale', v.stale);
        }

        function signalBars(dbm) {
            var n = num(dbm);
            if (n === null) return '—';
            var bars = n >= -55 ? 4 : n >= -67 ? 3 : n >= -78 ? 2 : 1;
            return '▮▮▮▮'.slice(0, bars) + '▯▯▯▯'.slice(0, 4 - bars) + ' ' + n + ' dBm';
        }

        function paintAps() {
            var list = $('apList');
            if (!list) return;
            list.textContent = '';
            if (!aps.length) {
                text('apPage', '—');
                $('apPrev').disabled = true;
                $('apNext').disabled = true;
                return;
            }
            list.appendChild(apRow(aps[0], 0));
            var per = pageSize(list, 64);
            var pages = Math.max(1, Math.ceil(aps.length / per));
            apPage = Math.min(apPage, pages - 1);
            list.textContent = '';
            aps.slice(apPage * per, apPage * per + per).forEach(function (ap, i) { list.appendChild(apRow(ap, apPage * per + i)); });
            text('apPage', (apPage + 1) + ' / ' + pages);
            $('apPrev').disabled = apPage <= 0;
            $('apNext').disabled = apPage >= pages - 1;
        }

        function apRow(ap, index) {
            var li = el('li', 't-ap');
            var btn = el('button', 't-btn t-ap-btn');
            btn.type = 'button';
            btn.disabled = !str(ap.ssid);
            btn.setAttribute('data-ap', String(index));
            var name = el('strong', '', displaySsid(ap.ssid) || tr('touch.wifi_hidden', '(hidden network)'));
            var sec = str(ap.security).toUpperCase() || 'UNKNOWN';
            var meta = el('span', 't-ap-meta', [sec === 'OPEN' ? tr('touch.wifi_open', 'OPEN (no encryption)') : sec, signalBars(ap.signal_dbm), ap.saved ? tr('touch.wifi_saved', 'Saved') : ''].filter(Boolean).join(' · '));
            btn.appendChild(name);
            btn.appendChild(meta);
            li.appendChild(btn);
            return li;
        }

        function scanWifi() {
            if (wifiBusy) return;
            wifiBusy = true;
            var btn = $('wifiScanBtn');
            btn.disabled = true;
            text('wifiNote', tr('touch.wifi_scanning', 'Scanning…'));
            request('GET', API.wifiScan, undefined, POST_TIMEOUT_MS).then(function (r) {
                var res = classifyResult(r.status, r.payload, '');
                if (r.transportError) {
                    aps = [];
                    text('wifiNote', tr('touch.res_no_answer', 'No answer from the Web UI.'));
                } else if (res.kind === 'ok') {
                    aps = arr(obj(r.payload).aps).filter(function (ap) { return ap && typeof ap === 'object'; });
                    apPage = 0;
                    text('wifiNote', aps.length ? tr('touch.wifi_found', '{n} networks. Tap one to connect.', { n: aps.length }) : tr('touch.wifi_none', 'No networks found.'));
                } else {
                    aps = [];
                    text('wifiNote', resultTitle(res.kind) + (res.message ? ' — ' + res.message : ''));
                }
                paintAps();
            }).then(function () { wifiBusy = false; btn.disabled = false; });
        }

        /* ---------------- operate pane ---------------- */
        function paintRunbook(v) {
            var rb = v.runbook;
            var id = str(rb.id);
            text('rbName', id ? (str(rb.title) || id) : tr('touch.runbook_none', 'No runbook suggested right now.'));
            text('rbMeta', id ? [id, tr('touch.runbook_effect', 'effect') + ': ' + (str(rb.effect) || '—'), rb.requires_approval ? tr('touch.runbook_approval', 'approval required') : ''].filter(Boolean).join(' · ') : '');
            var ol = $('rbSteps');
            ol.textContent = '';
            arr(rb.steps).slice(0, 3).forEach(function (s) { ol.appendChild(el('li', '', s)); });
            if (id && runbookDetail.id !== id) loadRunbookDetail(id);
            var execOk = !!id && runbookDetail.id === id && runbookDetail.requiredArgs !== null && runbookDetail.requiredArgs.length === 0
                && (str(rb.effect) === 'read_only' || str(rb.effect) === 'controlled_exec');
            $('rbPreviewBtn').disabled = !id || opBusy;
            $('rbExecBtn').disabled = !execOk || opBusy;
            var note;
            if (!id) note = '';
            else if (runbookDetail.id !== id || runbookDetail.requiredArgs === null) note = tr('touch.runbook_checking', 'Checking the runbook definition…');
            else if (runbookDetail.requiredArgs.length) note = tr('touch.runbook_needs_args', 'Needs input ({args}); run it from Ops Comm on a full keyboard.', { args: runbookDetail.requiredArgs.join(', ') });
            else if (!(str(rb.effect) === 'read_only' || str(rb.effect) === 'controlled_exec')) note = tr('touch.runbook_guidance_only', 'Guidance only: follow the steps; there is nothing to execute.');
            else note = tr('touch.runbook_exec_note', 'Execute asks for confirmation and runs with the existing operator role check and runbook review.');
            text('rbNote', note);
        }

        function loadRunbookDetail(id) {
            runbookDetail = { id: id, requiredArgs: null };
            request('GET', API.runbookGet + encodeURIComponent(id)).then(function (r) {
                if (runbookDetail.id !== id) return;
                var rb = obj(obj(r.payload).runbook);
                if (r.status === 200 && obj(r.payload).ok === true) {
                    runbookDetail.requiredArgs = arr(obj(rb.args_schema).required).map(String);
                } else {
                    runbookDetail.requiredArgs = ['?'];
                    // Retry later (e.g. after a token is entered) instead of sticking.
                    setTimeout(function () { if (runbookDetail.id === id && runbookDetail.requiredArgs && runbookDetail.requiredArgs[0] === '?') runbookDetail.id = ''; }, 30000);
                }
                paintRunbook(currentView());
            });
        }

        var RESULT_TONE = { ok: 'ok', failed: 'crit', rejected: 'crit', unauthorized: 'crit', not_implemented: 'watch', undelivered: 'crit', delivery_unknown: 'watch', busy: 'watch' };
        function resultTitle(kind) {
            var map = {
                ok: tr('touch.res_ok', 'Done (API answered ok)'),
                failed: tr('touch.res_failed', 'Failed'),
                rejected: tr('touch.res_rejected', 'Refused by review or approval rule'),
                unauthorized: tr('touch.res_unauthorized', 'Not allowed (token or role)'),
                busy: tr('touch.res_busy', 'Refused by the control daemon (busy, rate limit or not allowed); nothing was run'),
                not_implemented: tr('touch.res_not_implemented', 'Not implemented on this device'),
                undelivered: tr('touch.res_undelivered', 'Not delivered (daemon not reachable)'),
                delivery_unknown: tr('touch.res_delivery_unknown', 'No answer — it may have run. Check the state before retrying.')
            };
            return map[kind] || map.failed;
        }

        function recordResult(label, res) {
            results.unshift({ label: label, kind: res.kind, message: res.message, at: new Date() });
            results = results.slice(0, 4);
            paintResults();
        }

        function paintResults() {
            var ol = $('resList');
            if (!ol) return;
            ol.textContent = '';
            if (!results.length) ol.appendChild(el('li', 't-empty', tr('touch.results_empty', 'No operation from this screen yet.')));
            results.forEach(function (r) {
                var li = el('li', 't-res tone-' + (RESULT_TONE[r.kind] || 'crit'));
                li.appendChild(el('strong', '', r.label));
                li.appendChild(el('span', '', resultTitle(r.kind) + (r.message && r.kind !== 'ok' ? ' — ' + r.message : '')));
                li.appendChild(el('time', '', r.at.toTimeString().slice(0, 8)));
                ol.appendChild(li);
            });
        }

        /* ---------------- confirmation sheet ---------------- */
        var confirmCtx = null;
        function openConfirm(ctx) {
            // ctx: { title, facts: [[k, v]], run: () => Promise<{kind,message}>, label }
            confirmCtx = ctx;
            text('confirmTitle', ctx.title);
            var dl = $('confirmFacts');
            dl.textContent = '';
            ctx.facts.forEach(function (f) {
                var d = el('div', 't-fact');
                d.appendChild(el('dt', '', f[0]));
                d.appendChild(el('dd', '', f[1] === '' || f[1] == null ? '—' : f[1]));
                dl.appendChild(d);
            });
            $('confirmResult').hidden = true;
            $('confirmHold').hidden = false;
            $('confirmHold').disabled = false;
            text('confirmCancel', tr('touch.cancel', 'Cancel'));
            $('confirmSheet').hidden = false;
            setInert(true);
            $('confirmCancel').focus();
        }
        function closeConfirm() {
            if (opBusy) return;
            confirmCtx = null;
            $('confirmSheet').hidden = true;
            setInert(!$('kbSheet').hidden);
        }
        function showConfirmResult(res) {
            var box = $('confirmResult');
            setTone(box, RESULT_TONE[res.kind] || 'crit');
            text('confirmResultTitle', resultTitle(res.kind));
            setText('confirmResultDetail', res.kind === 'ok' ? '' : res.message);
            box.hidden = false;
            $('confirmHold').hidden = true;
            text('confirmCancel', tr('touch.close', 'Close'));
        }
        function runConfirmed() {
            if (!confirmCtx || opBusy) return;
            var ctx = confirmCtx;
            opBusy = true;
            $('confirmHold').disabled = true;
            $('confirmCancel').disabled = true;
            var box = $('confirmResult');
            setTone(box, 'unknown');
            text('confirmResultTitle', tr('touch.sending', 'Sending…'));
            setText('confirmResultDetail', '');
            box.hidden = false;
            ctx.run().then(function (res) {
                opBusy = false;
                $('confirmCancel').disabled = false;
                showConfirmResult(res);
                recordResult(ctx.label, res);
                paint();
                pollSoon();
            });
        }

        /* Press-and-hold button: fires after HOLD_MS of continuous press. */
        var holdResets = [];
        function resetAllHolds() { holdResets.forEach(function (fn) { fn(true); }); }

        function bindHold(button, onDone) {
            var start = 0;
            var hold = null;
            var raf = 0;
            var fill = button.querySelector('.t-hold-fill');
            var label = button.querySelector('.t-hold-label');
            var hintTimer = 0;
            function reset(silent) {
                // Released before the bar filled: say how to confirm (a tap never runs it).
                if (start && label && silent !== true) {
                    var key = label.getAttribute('data-i18n');
                    label.textContent = tr('touch.hold_hint', 'Keep pressing until the bar fills');
                    clearTimeout(hintTimer);
                    hintTimer = setTimeout(function () { label.textContent = tr(key, label.textContent); }, 1800);
                }
                start = 0;
                hold = null;
                cancelAnimationFrame(raf);
                if (fill) fill.style.transform = 'scaleX(0)';
                button.classList.remove('is-holding');
            }
            holdResets.push(reset);
            function tick() {
                if (!start) return;
                hold = advanceHold(hold, performance.now());
                if (fill) fill.style.transform = 'scaleX(' + hold.progress + ')';
                if (hold.done) { start = 0; reset(); onDone(); return; }
                raf = requestAnimationFrame(tick);
            }
            button.addEventListener('pointerdown', function (e) {
                if (button.disabled || e.button > 0) return;
                try { button.setPointerCapture(e.pointerId); } catch (_e) { /* ignore */ }
                start = performance.now();
                hold = advanceHold(null, start);
                button.classList.add('is-holding');
                raf = requestAnimationFrame(tick);
            });
            ['pointerup', 'pointercancel', 'lostpointercapture'].forEach(function (ev) { button.addEventListener(ev, reset); });
            // Keyboard users: Enter/Space held is not a hold; require the same hold time.
            button.addEventListener('keydown', function (e) {
                if ((e.key === 'Enter' || e.key === ' ') && !start && !e.repeat) { e.preventDefault(); start = performance.now(); hold = advanceHold(null, start); raf = requestAnimationFrame(tick); }
            });
            button.addEventListener('keyup', function (e) { if (e.key === 'Enter' || e.key === ' ') reset(); });
        }

        /* ---------------- operations (existing APIs only) ---------------- */
        function opRequest(method, path, body) {
            return request(method, path, body, POST_TIMEOUT_MS).then(function (r) {
                return classifyResult(r.status, r.payload, r.transportError, method);
            });
        }

        function confirmRunbook(action) {
            var rb = currentView().runbook;
            var id = str(rb.id);
            if (!id) return;
            var preview = action === 'preview';
            var body = { runbook_id: id, action: preview ? 'preview' : 'execute', approved: !preview, args: {}, actor: 'touch-console', lang: lang, note: 'touch' };
            if (preview) {
                // A dry run has no effect: run it straight away, show the result.
                opBusy = true;
                paint();
                opRequest('POST', API.runbookAct, body).then(function (res) {
                    opBusy = false;
                    recordResult(tr('touch.runbook_preview', 'Preview (dry run)') + ' · ' + id, res);
                    paint();
                });
                return;
            }
            openConfirm({
                label: tr('touch.runbook_execute', 'Execute…') + ' · ' + id,
                title: tr('touch.confirm_runbook_title', 'Execute this runbook?'),
                facts: [
                    [tr('touch.runbook_title', 'Suggested runbook'), str(rb.title) || id],
                    ['ID', id],
                    [tr('touch.runbook_effect', 'effect'), str(rb.effect)],
                    [tr('touch.note', 'Note'), tr('touch.runbook_exec_note', 'Execute asks for confirmation and runs with the existing operator role check and runbook review.')]
                ],
                run: function () { return opRequest('POST', API.runbookAct, body); }
            });
        }

        /* ---------------- on-screen keyboard ---------------- */
        var secret = createSecretBuffer(SECRET_MAX);
        var kb = { purpose: '', ap: null, shift: false, sym: false, reveal: false, persist: false };
        var KB_ROWS = [
            ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
            ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
            ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', '-'],
            ['{shift}', 'z', 'x', 'c', 'v', 'b', 'n', 'm', '.', '{bksp}'],
            ['{sym}', '{space}', '{clear}']
        ];
        var KB_SYM = [
            ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'],
            ['_', '=', '+', '[', ']', '{', '}', '\\', '|', '~'],
            [';', ':', '\'', '"', ',', '<', '>', '/', '?', '`'],
            ['{shift}', '1', '2', '3', '4', '5', '6', '7', '8', '{bksp}'],
            ['{sym}', '{space}', '{clear}']
        ];

        function buildKeys() {
            var box = $('kbKeys');
            box.textContent = '';
            (kb.sym ? KB_SYM : KB_ROWS).forEach(function (row) {
                var r = el('div', 't-kb-row');
                row.forEach(function (k) {
                    var b = el('button', 't-key');
                    b.type = 'button';
                    if (k === '{shift}') { b.textContent = '⇧ Shift'; b.className += ' t-key-wide' + (kb.shift ? ' is-on' : ''); b.setAttribute('aria-pressed', kb.shift ? 'true' : 'false'); b.disabled = kb.sym; }
                    else if (k === '{bksp}') { b.textContent = '⌫'; b.className += ' t-key-wide'; b.setAttribute('aria-label', tr('touch.kb_backspace', 'Backspace')); }
                    else if (k === '{sym}') { b.textContent = kb.sym ? 'ABC' : '#+='; b.className += ' t-key-wide'; }
                    else if (k === '{space}') { b.textContent = tr('touch.kb_space', 'Space'); b.className += ' t-key-space'; }
                    else if (k === '{clear}') { b.textContent = tr('touch.kb_clear', 'Clear'); b.className += ' t-key-wide'; }
                    else { b.textContent = kb.shift && !kb.sym ? k.toUpperCase() : k; }
                    b.setAttribute('data-key', k);
                    r.appendChild(b);
                });
                box.appendChild(r);
            });
        }

        function paintKbValue() {
            var out = $('kbValue');
            var n = secret.length();
            if (!n) { out.textContent = ''; out.setAttribute('data-empty', tr('touch.kb_empty', 'Type with the keys below')); }
            else { out.removeAttribute('data-empty'); out.textContent = kb.reveal ? secret.reveal() : new Array(n + 1).join('●'); }
            var rv = $('kbReveal');
            rv.setAttribute('aria-pressed', kb.reveal ? 'true' : 'false');
            rv.querySelector('use').setAttribute('href', kb.reveal ? '#i-eye-off' : '#i-eye');
            rv.setAttribute('aria-label', kb.reveal ? tr('touch.kb_hide', 'Hide') : tr('touch.kb_show', 'Show'));
            var ready = n > 0;
            $('kbSubmit').disabled = !ready;
            $('kbHold').disabled = !ready || opBusy;
        }

        function onKey(k) {
            var next = applyKey(kb, k, secret);
            kb.shift = next.shift;
            kb.sym = next.sym;
            if (next.redraw) buildKeys();
            paintKbValue();
        }

        function openKeyboard(purpose, ap) {
            secret.clear();
            kb = { purpose: purpose, ap: ap || null, shift: false, sym: false, reveal: false, persist: false };
            var isWifi = purpose === 'wifi';
            text('kbTitle', isWifi ? tr('touch.wifi_pass_title', 'Passphrase for {ssid}', { ssid: displaySsid(ap.ssid) || '—' }) : tr('touch.token_enter', 'Enter token'));
            text('kbSub', isWifi ? [str(ap.security), tr('touch.wifi_pass_note', 'Cleared from memory right after sending.')].join(' · ') : tr('touch.token_note', 'Kept in this page’s memory only. Not stored, not put in the URL. Reloading the page forgets it.'));
            $('kbSubmit').hidden = isWifi;
            text('kbSubmit', tr('touch.token_set', 'Use this token'));
            $('kbHold').hidden = !isWifi;
            $('kbPersist').hidden = !isWifi;
            $('kbPersist').setAttribute('aria-pressed', 'false');
            $('kbPersist').classList.remove('is-on');
            buildKeys();
            paintKbValue();
            $('kbSheet').hidden = false;
            setInert(true);
        }

        function closeKeyboard() {
            if (opBusy) return;
            secret.clear();
            kb.reveal = false;
            $('kbValue').textContent = '';
            $('kbSheet').hidden = true;
            setInert(!$('confirmSheet').hidden);
        }

        function submitToken() {
            token = secret.take();
            runbookDetail = { id: '', requiredArgs: null };
            closeKeyboard();
            authProblem = false;
            paintTokenState();
            restartStream();
            pollSoon();
        }

        function wifiConnectWithPassphrase() {
            if (opBusy || !kb.ap) return;
            var ap = kb.ap;
            var body = { ssid: str(ap.ssid), security: str(ap.security) || 'UNKNOWN', passphrase: secret.take(), saved: false, persist: !!kb.persist };
            paintKbValue();
            opBusy = true;
            $('kbHold').disabled = true;
            $('kbCancel').disabled = true;
            text('kbSub', tr('touch.sending', 'Sending…'));
            var pending = opRequest('POST', API.wifiConnect, body);
            body.passphrase = '';
            body = null;
            pending.then(function (res) {
                opBusy = false;
                $('kbCancel').disabled = false;
                closeKeyboard();
                var label = 'Wi-Fi → ' + (displaySsid(ap.ssid) || '—');
                recordResult(label, res);
                openConfirm({ label: label, title: label, facts: [], run: function () { return Promise.resolve(res); } });
                showConfirmResult(res);
                pollSoon();
            });
        }

        function chooseAp(ap) {
            if (!str(ap.ssid)) return;   // a hidden network needs its name typed: not offered here
            var sec = str(ap.security).toUpperCase();
            if (sec === 'OPEN' || ap.saved) {
                var label = 'Wi-Fi → ' + (displaySsid(ap.ssid) || '—');
                openConfirm({
                    label: label,
                    title: tr('touch.wifi_confirm_title', 'Connect the uplink to this network?'),
                    facts: [
                        ['SSID', displaySsid(ap.ssid)],
                        [tr('touch.wifi_security', 'Security'), sec === 'OPEN' ? tr('touch.wifi_open', 'OPEN (no encryption)') : sec],
                        [tr('touch.note', 'Note'), sec === 'OPEN' ? tr('touch.wifi_open_note', 'Traffic on an open network is not encrypted.') : tr('touch.wifi_saved_note', 'Uses the saved profile; no passphrase is sent.')],
                        [tr('touch.api', 'API'), 'POST ' + API.wifiConnect + ' (operator)']
                    ],
                    run: function () {
                        return opRequest('POST', API.wifiConnect, { ssid: str(ap.ssid), security: sec || 'UNKNOWN', saved: !!ap.saved && sec !== 'OPEN', persist: false });
                    }
                });
                return;
            }
            openKeyboard('wifi', ap);
        }

        /* ---------------- settings ---------------- */
        function paintTokenState() {
            text('tokenState', token ? tr('touch.token_held', 'Token set (in memory)') : tr('touch.token_none', 'No token'));
            $('tokenForgetBtn').disabled = !token;
        }

        function applyLang(next) {
            lang = next === 'ja' ? 'ja' : 'en';
            writePref('azazel_lang', lang);
            document.documentElement.lang = lang;
            document.querySelectorAll('[data-i18n]').forEach(function (n) {
                var key = n.getAttribute('data-i18n');
                n.textContent = tr(key, n.textContent);
            });
            document.querySelectorAll('[data-lang]').forEach(function (b) {
                var on = b.getAttribute('data-lang') === lang;
                b.classList.toggle('is-on', on);
                b.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
            paintTokenState();
            paintResults();
            paint();
            pollSoon();
        }

        function applyTheme(theme) {
            var t = theme === 'light' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', t);
            writePref('azazel_touch_theme', t);
            document.querySelectorAll('[data-theme-choice]').forEach(function (b) {
                var on = b.getAttribute('data-theme-choice') === t;
                b.classList.toggle('is-on', on);
                b.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
        }

        function selectTab(name) {
            currentTab = name;
            document.querySelectorAll('.t-tab').forEach(function (b) {
                var on = b.getAttribute('data-tab') === name;
                b.setAttribute('aria-selected', on ? 'true' : 'false');
                b.tabIndex = on ? 0 : -1;
            });
            document.querySelectorAll('.t-pane').forEach(function (p) { p.hidden = p.id !== 'pane-' + name; });
            document.body.setAttribute('data-tab', name);
            paint();
            if (name === 'network') paintAps();
        }

        /* ---------------- data: bundle poll + state stream ---------------- */
        var pollTimer = null;
        function pollSoon() {
            clearTimeout(pollTimer);
            pollTimer = setTimeout(poll, 300);
        }
        function poll() {
            clearTimeout(pollTimer);
            if (document.hidden) return;   // resumed by visibilitychange
            if (pollBusy) { pollTimer = setTimeout(poll, pollMs); return; }
            pollBusy = true;
            request('GET', API.bundle + '?surface=dashboard&audience=temporary&trends_limit=1').then(function (r) {
                pollBusy = false;
                var p = obj(r.payload);
                if (r.status === 200 && p.ok === true) {
                    bundle = p;
                    lastDataMs = Date.now();
                    lastBundleMs = lastDataMs;
                    pollFailures = 0;
                    authProblem = false;
                    var epoch = num(obj(p.state).snapshot_epoch);
                    var age = num(obj(obj(p.health).ages_sec).snapshot);
                    if (epoch !== null && age !== null) skewSec = (Date.now() / 1000) - (epoch + age);
                } else {
                    pollFailures += 1;
                    if (r.status === 401 || r.status === 403) authProblem = true;
                }
                paint();
                if (!document.hidden) pollTimer = setTimeout(poll, pollMs);
            });
        }

        function wantStream() {
            return streamWanted({
                hidden: document.hidden, authProblem: authProblem, unsupported: stream.status === 'unsupported',
                nowMs: Date.now(), lastInteractionMs: lastInteractionMs, holdOffUntilMs: stream.holdOffUntilMs
            });
        }

        function closeStream(status) {
            var ctrl = stream.ctrl;
            stream.ctrl = null;
            clearTimeout(stream.retryTimer);
            stream.retryTimer = null;
            stream.status = status || 'paused';
            if (ctrl) { try { ctrl.abort(); } catch (_e) { /* ignore */ } }
        }

        function restartStream() {
            closeStream('connecting');
            stream.backoff = 2000;
            stream.errors = 0;
            stream.holdOffUntilMs = 0;
            if (wantStream()) openStream(); else stream.status = 'paused';
        }

        function scheduleStream(ms) {
            clearTimeout(stream.retryTimer);
            stream.retryTimer = setTimeout(function () {
                stream.retryTimer = null;
                if (wantStream()) openStream(); else stream.status = 'paused';
            }, ms);
        }

        // Called every second and on interaction/visibility: open or close
        // the stream to match wantStream(); never opens while a retry waits.
        function syncStream() {
            var want = wantStream();
            if (!want && stream.ctrl) closeStream('paused');
            else if (!want && stream.status !== 'unsupported') { clearTimeout(stream.retryTimer); stream.retryTimer = null; stream.status = 'paused'; }
            else if (want && !stream.ctrl && !stream.retryTimer) openStream();
        }

        function openStream() {
            if (typeof ReadableStream === 'undefined' || typeof TextDecoder === 'undefined') { stream.status = 'unsupported'; return; }
            var ctrl = new AbortController();
            stream.ctrl = ctrl;
            stream.status = 'connecting';
            stream.lastEventMs = Date.now();
            var retryHint = null;
            var parser = createSseParser(function (ev) {
                stream.lastEventMs = Date.now();
                if (ev.retry) retryHint = ev.retry;
                if (ev.event === 'ready') { stream.status = 'live'; }
                else if (ev.event === 'state') {
                    var data = null;
                    try { data = JSON.parse(ev.data); } catch (_e) { data = null; }
                    if (data && typeof data === 'object') { live = data; lastDataMs = Date.now(); stream.status = 'live'; stream.backoff = 2000; stream.errors = 0; }
                } else if (ev.event === 'stream_error') {
                    var info = null;
                    try { info = JSON.parse(ev.data); } catch (_e) { info = null; }
                    stream.status = 'error';
                    stream.reason = str(obj(info).error || obj(info).reason || 'stream_error');
                }
            });
            var watchdog = setInterval(function () {
                if (Date.now() - stream.lastEventMs > STREAM_IDLE_MS) { try { ctrl.abort(); } catch (_e) { /* ignore */ } }
            }, 2000);
            var authFailed = false;
            fetch(API.stateStream, { headers: headers(false), cache: 'no-store', credentials: 'same-origin', signal: ctrl.signal }).then(function (res) {
                if (res.status === 401 || res.status === 403) { authProblem = true; authFailed = true; throw new Error('auth'); }
                if (!res.ok || !res.body) throw new Error('http ' + res.status);
                var reader = res.body.getReader();
                var decoder = new TextDecoder();
                function pump() {
                    return reader.read().then(function (chunk) {
                        if (chunk.done) return;
                        parser.feed(decoder.decode(chunk.value, { stream: true }));
                        return pump();
                    });
                }
                return pump();
            }).catch(function () { /* handled below */ }).then(function () {
                clearInterval(watchdog);
                if (stream.ctrl !== ctrl) return;   // closed on purpose (idle/hidden) or superseded
                stream.ctrl = null;
                var ended = authFailed ? 'auth' : (stream.status === 'error' ? 'stream_error' : 'closed');
                if (ended === 'stream_error') {
                    stream.errors += 1;
                    if (stream.errors >= 3) stream.holdOffUntilMs = Date.now() + STREAM_ERROR_HOLDOFF_MS;
                } else {
                    stream.status = 'down';
                }
                var wait = nextStreamDelay({ ended: ended, retryHintMs: retryHint, backoffMs: stream.backoff });
                stream.backoff = Math.min(STREAM_BACKOFF_MAX_MS, stream.backoff * 2);
                paint();
                scheduleStream(wait);
            });
        }

        /* ---------------- wiring ---------------- */
        document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
        document.addEventListener('gesturestart', function (e) { e.preventDefault(); });
        document.addEventListener('dblclick', function (e) { e.preventDefault(); });

        document.querySelectorAll('.t-tab').forEach(function (b) {
            b.addEventListener('click', function () { selectTab(b.getAttribute('data-tab')); });
        });
        $('alertPrev').addEventListener('click', function () { alertPage = Math.max(0, alertPage - 1); paintAlerts(currentView()); });
        $('alertNext').addEventListener('click', function () { alertPage += 1; paintAlerts(currentView()); });
        $('apPrev').addEventListener('click', function () { apPage = Math.max(0, apPage - 1); paintAps(); });
        $('apNext').addEventListener('click', function () { apPage += 1; paintAps(); });
        $('wifiScanBtn').addEventListener('click', scanWifi);
        $('apList').addEventListener('click', function (e) {
            var b = e.target instanceof Element ? e.target.closest('[data-ap]') : null;
            if (!b) return;
            var ap = aps[Number(b.getAttribute('data-ap'))];
            if (ap) chooseAp(ap);
        });
        $('rbPreviewBtn').addEventListener('click', function () { confirmRunbook('preview'); });
        $('rbExecBtn').addEventListener('click', function () { confirmRunbook('execute'); });
        $('confirmCancel').addEventListener('click', closeConfirm);
        bindHold($('confirmHold'), runConfirmed);
        bindHold($('kbHold'), wifiConnectWithPassphrase);
        $('kbKeys').addEventListener('click', function (e) {
            var b = e.target instanceof Element ? e.target.closest('[data-key]') : null;
            if (b && !b.disabled) onKey(b.getAttribute('data-key'));
        });
        $('kbReveal').addEventListener('click', function () { kb.reveal = !kb.reveal; paintKbValue(); });
        $('kbPersist').addEventListener('click', function () {
            kb.persist = !kb.persist;
            $('kbPersist').classList.toggle('is-on', kb.persist);
            $('kbPersist').setAttribute('aria-pressed', kb.persist ? 'true' : 'false');
        });
        $('kbCancel').addEventListener('click', closeKeyboard);
        $('kbSubmit').addEventListener('click', function () { if (kb.purpose === 'token' && secret.length()) submitToken(); });
        $('tokenEnterBtn').addEventListener('click', function () { openKeyboard('token'); });
        $('tokenForgetBtn').addEventListener('click', function () { token = ''; runbookDetail = { id: '', requiredArgs: null }; paintTokenState(); restartStream(); pollSoon(); });
        document.querySelectorAll('[data-lang]').forEach(function (b) {
            b.addEventListener('click', function () { applyLang(b.getAttribute('data-lang')); });
        });
        document.querySelectorAll('[data-theme-choice]').forEach(function (b) {
            b.addEventListener('click', function () { applyTheme(b.getAttribute('data-theme-choice')); });
        });
        // Drop the passphrase/token being typed if the page is hidden or left.
        document.addEventListener('visibilitychange', function () {
            if (document.hidden) {
                resetAllHolds();
                if (!opBusy) closeKeyboard();
                clearTimeout(pollTimer);
                closeStream('paused');
            } else {
                lastInteractionMs = Date.now();
                pollSoon();
                syncStream();
            }
        });
        // Any touch counts as use: reopen the live stream if it was idle-closed.
        document.addEventListener('pointerdown', function () {
            lastInteractionMs = Date.now();
            syncStream();
        }, true);
        window.addEventListener('pagehide', function () { resetAllHolds(); secret.clear(); });
        window.addEventListener('blur', resetAllHolds);

        setInterval(function () {
            var d = new Date();
            text('tClock', ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2));
            syncStream();
            paintTopBar(currentView());
        }, 1000);
        var resizeTimer = null;
        window.addEventListener('resize', function () { clearTimeout(resizeTimer); resizeTimer = setTimeout(function () { paint(); paintAps(); }, 150); });

        applyTheme(readPref('azazel_touch_theme', 'dark'));
        paintResults();
        applyLang(lang);
        selectTab('status');
        document.body.classList.remove('t-boot');
        poll();
        syncStream();
    }

    return {
        API: API,
        toneOf: toneOf,
        worstTone: worstTone,
        staleTone: staleTone,
        defensiveTone: defensiveTone,
        classifyResult: classifyResult,
        createSseParser: createSseParser,
        createSecretBuffer: createSecretBuffer,
        fmtAge: fmtAge,
        pickState: pickState,
        advanceHold: advanceHold,
        applyKey: applyKey,
        displaySsid: displaySsid,
        streamWanted: streamWanted,
        nextStreamDelay: nextStreamDelay,
        deriveView: deriveView,
        boot: boot
    };
}));
