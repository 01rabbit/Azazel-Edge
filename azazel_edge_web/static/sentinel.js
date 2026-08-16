/* =============================================================================
   SENTINEL Decision Console — tier navigation + deterministic decision pipeline
   -----------------------------------------------------------------------------
   Progressive enhancement layered on top of the existing dashboard (app.js).
   - Groups the (contract-frozen) panels into OVERVIEW / OPERATIONS / EVIDENCE /
     SYSTEM via the data-tier attributes, with a SOC/NOC sub-filter.
   - Renders the SENSE -> EVALUATE -> DECIDE -> CONTROL -> AUDIT pipeline strip and
     the per-tier status dots from the SAME deterministic payloads app.js already
     fetched (delivered via the 'azazel:refresh' CustomEvent). No extra polling,
     no new decision logic, no fabricated values: absent data renders as unknown.
   ========================================================================== */
(function () {
    'use strict';

    var TIER_KEY = 'azazel_sentinel_tier';
    var OP_KEY = 'azazel_sentinel_op';
    var TIERS = ['overview', 'operations', 'evidence', 'system'];
    var body = (typeof document !== 'undefined') ? document.body : null;

    /* ---- state-word -> tone classifier (mirrors booth_focus.js vocab) ------- */
    var OK_WORDS = ['healthy', 'normal', 'safe', 'ok', 'good', 'quiet', 'low', 'up', 'on', 'ready', 'present', 'clear'];
    var WATCH_WORDS = ['watch', 'elevated', 'caution', 'degraded', 'partial', 'suspected', 'drift', 'limited', 'pending', 'stale'];
    var CRIT_WORDS = ['critical', 'danger', 'alert', 'down', 'off', 'outage', 'compromised', 'failed', 'fail', 'high'];

    function toneOf(word) {
        var w = String(word == null ? '' : word).trim().toLowerCase();
        if (!w) return 'is-unknown';
        if (CRIT_WORDS.indexOf(w) !== -1) return 'is-critical';
        if (WATCH_WORDS.indexOf(w) !== -1) return 'is-watch';
        if (OK_WORDS.indexOf(w) !== -1) return 'is-ok';
        return 'is-unknown';
    }
    // Rank UNKNOWN ABOVE OK so any unverified component blocks a green aggregate —
    // a healthy sibling must never mask an unknown one (false-green law). With no
    // recognised inputs the result is UNKNOWN, never OK.
    function worstTone() {
        var order = { 'is-ok': 0, 'is-unknown': 1, 'is-watch': 2, 'is-critical': 3 };
        var worst = null;
        for (var i = 0; i < arguments.length; i++) {
            var t = arguments[i];
            if (!(t in order)) continue;
            if (worst === null || order[t] > order[worst]) worst = t;
        }
        return worst || 'is-unknown';
    }
    function num(v) { var n = Number(v); return isFinite(n) ? n : 0; }
    function upper(v, fallback) {
        var s = String(v == null ? '' : v).trim();
        return s ? s.toUpperCase() : (fallback || '—');
    }

    /* ------------------------------------------------------------------------
       TIER NAVIGATION
       --------------------------------------------------------------------- */
    function currentAudience() {
        return String(body.getAttribute('data-audience') || 'temporary');
    }

    function tierPanels(tier) {
        return Array.prototype.slice.call(
            document.querySelectorAll('[data-tier~="' + tier + '"]')
        );
    }

    // A panel is effectively visible only if its tier is active AND the audience
    // policy allows it AND it is not explicitly hidden AND (in operations) the
    // SOC/NOC sub-filter allows it.
    function panelVisibleForAudience(panel, op) {
        var aud = currentAudience();
        if (panel.hasAttribute('hidden')) return false;
        if (aud === 'temporary' && panel.classList.contains('pro-only')) return false;
        if (aud === 'professional' && panel.classList.contains('temp-only')) return false;
        var panelOp = panel.getAttribute('data-op');
        if (op && op !== 'both' && panelOp && panelOp !== op) return false;
        return true;
    }

    function updateEmptyNote(tier) {
        var note = document.getElementById('sentinelTierEmpty');
        if (!note) return;
        var op = tier === 'operations' ? (body.getAttribute('data-op-active') || 'both') : 'both';
        var panels = tierPanels(tier);
        var anyVisible = panels.some(function (p) { return panelVisibleForAudience(p, op); });
        note.classList.toggle('is-visible', panels.length > 0 && !anyVisible);
    }

    function setTier(tier, opts) {
        if (TIERS.indexOf(tier) === -1) tier = 'overview';
        body.setAttribute('data-tier-active', tier);
        try { localStorage.setItem(TIER_KEY, tier); } catch (e) { /* ignore */ }
        TIERS.forEach(function (t) {
            var btn = document.querySelector('[data-sentinel-tier="' + t + '"]');
            if (!btn) return;
            var active = t === tier;
            if (active) btn.setAttribute('aria-current', 'page'); else btn.removeAttribute('aria-current');
            btn.classList.toggle('is-active', active);
            btn.tabIndex = active ? 0 : -1;
        });
        updateEmptyNote(tier);
        if (typeof renderActiveTier === 'function') renderActiveTier();
        if (opts && opts.focus) {
            var f = document.querySelector('[data-sentinel-tier="' + tier + '"]');
            if (f) f.focus();
        }
    }

    function setOp(op) {
        if (['soc', 'noc'].indexOf(op) === -1) op = 'soc';
        body.setAttribute('data-op-active', op);
        try { localStorage.setItem(OP_KEY, op); } catch (e) { /* ignore */ }
        ['soc', 'noc'].forEach(function (o) {
            var btn = document.querySelector('[data-sentinel-op="' + o + '"]');
            if (!btn) return;
            var active = o === op;
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
            btn.classList.toggle('is-active', active);
        });
        updateEmptyNote('operations');
    }

    function wireNav() {
        document.querySelectorAll('[data-sentinel-tier]').forEach(function (btn) {
            btn.addEventListener('click', function () { setTier(btn.getAttribute('data-sentinel-tier')); });
        });
        document.querySelectorAll('[data-sentinel-op]').forEach(function (btn) {
            btn.addEventListener('click', function () { setOp(btn.getAttribute('data-sentinel-op')); });
        });
        // Roving arrow-key navigation across the main tier tabs (WAI-ARIA tablist).
        var nav = document.getElementById('sentinelTierNav');
        if (nav) {
            nav.addEventListener('keydown', function (ev) {
                var active = body.getAttribute('data-tier-active') || 'overview';
                var idx = TIERS.indexOf(active);
                if (idx === -1) return;
                var next;
                if (ev.key === 'ArrowRight') next = (idx + 1) % TIERS.length;
                else if (ev.key === 'ArrowLeft') next = (idx - 1 + TIERS.length) % TIERS.length;
                else if (ev.key === 'Home') next = 0;
                else if (ev.key === 'End') next = TIERS.length - 1;
                else return;
                ev.preventDefault();
                setTier(TIERS[next], { focus: true });
            });
        }
        // Re-check the empty-tier note when app.js flips the audience mode.
        var obs = new MutationObserver(function () {
            updateEmptyNote(body.getAttribute('data-tier-active') || 'overview');
        });
        obs.observe(body, { attributes: true, attributeFilter: ['data-audience'] });
    }

    /* ------------------------------------------------------------------------
       DECISION PIPELINE + TIER DOTS  (driven by azazel:refresh)
       --------------------------------------------------------------------- */
    function setStage(id, value, meta, tone) {
        var el = document.getElementById(id);
        if (!el) return;
        var v = document.getElementById(id + 'Value');
        var m = document.getElementById(id + 'Meta');
        if (v) v.textContent = value;
        if (m && meta != null) m.textContent = meta;
        el.classList.remove('is-ok', 'is-watch', 'is-critical', 'is-unknown');
        el.classList.add(tone || 'is-unknown');
    }

    var TONE_WORD = { 'is-ok': 'OK', 'is-watch': 'WATCH', 'is-critical': 'CRITICAL', 'is-unknown': 'UNKNOWN' };

    // State-transition cue: a single (non-repeating, reduced-motion-aware) highlight
    // when a tracked element's tone changes, so a NORMAL->WATCH->CRITICAL shift is
    // visible without blinking. First observation never flashes.
    var toneMemory = {};
    var azReduced = !!(typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    function flashOnChange(key, el, tone) {
        var prev = toneMemory[key];
        toneMemory[key] = tone;
        if (prev === undefined || prev === tone || !el || azReduced) return;
        el.classList.remove('sentinel-flash');
        void el.offsetWidth; // restart the animation
        el.classList.add('sentinel-flash');
        window.setTimeout(function () { el.classList.remove('sentinel-flash'); }, 1300);
    }

    // Update a tier dot AND its screen-reader-only status text, so per-tier health
    // is never conveyed by color alone (accessibility) — the dot also carries a
    // non-color shape cue via CSS (hollow=unknown, ring=watch/critical).
    function setTierDot(tier, tone) {
        var cap = tier.charAt(0).toUpperCase() + tier.slice(1);
        var dot = document.getElementById('sentinelDot' + cap);
        if (dot) {
            dot.classList.remove('is-ok', 'is-watch', 'is-critical', 'is-unknown');
            dot.classList.add(tone || 'is-unknown');
            flashOnChange('dot-' + tier, dot.closest ? dot.closest('.sentinel-tier-btn') : dot, tone);
        }
        var sr = document.getElementById('sentinelStatus' + cap);
        if (sr) sr.textContent = ' (' + (TONE_WORD[tone] || 'UNKNOWN') + ')';
    }

    // Pure derivation of every stage + tier-dot tone from the deterministic
    // payloads. No DOM access, so it is unit-testable in node. The false-green law
    // is enforced here: absent inputs => UNKNOWN, any 'down' service => CRITICAL,
    // any stale signal => at least WATCH, and unknown never masked green.
    function computeConsoleState(detail) {
        detail = detail || {};
        var summary = detail.summary || {};
        var evidence = detail.evidence || {};
        var health = detail.health || {};
        var soc = summary.soc_focus || {};
        var noc = summary.noc_focus || {};
        var pathHealth = noc.path_health || {};
        var dpath = summary.decision_path || {};
        var assurance = summary.normal_assurance || {};
        var mode = summary.mode || {};
        var cmd = summary.command_strip || {};

        var hasAlerts = Array.isArray(evidence.recent_alerts);
        var hasSocCounts = !!(soc && (soc.critical_count != null || soc.warning_count != null || soc.threat_level != null));
        var signalCount = num(soc.critical_count) + num(soc.warning_count);

        // 01 SENSE — never fabricate a green "0 signals" from missing data.
        var sense;
        if (!hasAlerts && !hasSocCounts) {
            sense = { value: '—', meta: dpath.first_pass_engine ? String(dpath.first_pass_engine) : 'evidence intake', tone: 'is-unknown' };
        } else {
            var alertCount = hasAlerts ? evidence.recent_alerts.length : signalCount;
            // Signals present must never render green, even if SOC counts are absent.
            var senseTone = num(soc.critical_count) > 0 ? 'is-critical'
                : (signalCount > 0 || alertCount > 0) ? 'is-watch' : 'is-ok';
            sense = {
                value: alertCount + (alertCount === 1 ? ' signal' : ' signals'),
                meta: dpath.first_pass_engine ? String(dpath.first_pass_engine) : 'evidence intake',
                tone: senseTone
            };
        }

        // 02 EVALUATE — the two independent NOC/SOC evaluators.
        var nocTone = toneOf(pathHealth.status);
        var socTone = toneOf(soc.threat_level);
        var evaluate = {
            value: 'NOC ' + upper(pathHealth.status, 'UNKNOWN') + ' · SOC ' + upper(soc.threat_level, 'UNKNOWN'),
            meta: dpath.second_pass_status ? ('2nd pass: ' + dpath.second_pass_status) : 'NOC / SOC',
            tone: worstTone(nocTone, socTone)
        };

        // 03 DECIDE — arbitrated deterministic assurance verdict.
        var decideTone = assurance.status ? toneOf(assurance.status === 'alert' ? 'critical' : assurance.status) : 'is-unknown';
        var decide = { value: upper(assurance.status, 'UNKNOWN'), meta: 'arbiter', tone: decideTone };

        // 04 CONTROL — active, reversible mode; an abnormal (watch/critical) mode
        // keyword must not read as verified-healthy green.
        var modeTone = toneOf(mode.current_mode);
        var control = {
            value: upper(mode.current_mode, 'UNKNOWN'),
            meta: 'bounded / reversible',
            tone: mode.current_mode ? ((modeTone === 'is-critical' || modeTone === 'is-watch') ? modeTone : 'is-ok') : 'is-unknown'
        };

        // 05 AUDIT — recording state only; trace detail lives in the Evidence tier.
        var auditRows = 0, hasAuditArr = false;
        ['recent_runbook_events', 'recent_mode_changes', 'recent_triage_audit', 'recent_ai_activity'].forEach(function (k) {
            if (Array.isArray(evidence[k])) { hasAuditArr = true; auditRows += evidence[k].length; }
        });
        var audit = hasAuditArr
            ? { value: auditRows > 0 ? 'RECORDED' : 'IDLE', meta: auditRows > 0 ? (auditRows + ' rows · see Evidence') : 'no recent entries', tone: auditRows > 0 ? 'is-ok' : 'is-unknown' }
            : { value: '—', meta: 'trace in Evidence', tone: 'is-unknown' };

        // Tier dots.
        var evTone = (!hasAlerts && !hasSocCounts)
            ? 'is-unknown'
            : (num(soc.critical_count) > 0 ? 'is-critical' : (signalCount > 0 ? 'is-watch' : 'is-ok'));
        var svc = summary.service_health_summary || {};
        var svcTones = Object.keys(svc).map(function (k) { return toneOf(svc[k]); });
        var stale = health.stale_flags || {};
        var anyStale = !!(stale.snapshot || stale.ai_metrics || stale.ai_activity || stale.runbook_events || cmd.stale_warning);
        var sysTone = svcTones.length ? worstTone.apply(null, svcTones) : 'is-unknown';
        if (anyStale) sysTone = worstTone(sysTone, 'is-watch');

        return {
            stages: { sense: sense, evaluate: evaluate, decide: decide, control: control, audit: audit },
            dots: {
                overview: assurance.status ? decideTone : 'is-unknown',
                operations: worstTone(nocTone, socTone),
                evidence: evTone,
                system: sysTone
            }
        };
    }

    function renderPipeline(detail) {
        var st = computeConsoleState(detail);
        setStage('pipelineSense', st.stages.sense.value, st.stages.sense.meta, st.stages.sense.tone);
        setStage('pipelineEvaluate', st.stages.evaluate.value, st.stages.evaluate.meta, st.stages.evaluate.tone);
        setStage('pipelineDecide', st.stages.decide.value, st.stages.decide.meta, st.stages.decide.tone);
        setStage('pipelineControl', st.stages.control.value, st.stages.control.meta, st.stages.control.tone);
        setStage('pipelineAudit', st.stages.audit.value, st.stages.audit.meta, st.stages.audit.tone);
        setTierDot('overview', st.dots.overview);
        setTierDot('operations', st.dots.operations);
        setTierDot('evidence', st.dots.evidence);
        setTierDot('system', st.dots.system);
        updateEmptyNote(body.getAttribute('data-tier-active') || 'overview');
    }

    /* ------------------------------------------------------------------------
       DECISION CONSOLE (bespoke OVERVIEW) — populated from live payloads.
       All writes are textContent only (no innerHTML); absent data -> em-dash.
       --------------------------------------------------------------------- */
    function statusFromTone(tone) {
        return tone === 'is-ok' ? 'status-ok'
            : tone === 'is-watch' ? 'status-warn'
                : tone === 'is-critical' ? 'status-danger' : 'status-neutral';
    }
    function txt(id, value) {
        var el = document.getElementById(id);
        if (el) el.textContent = (value == null || value === '') ? '—' : String(value);
    }
    function setToneClass(id, tone) {
        var el = document.getElementById(id);
        if (!el) return;
        el.classList.remove('status-ok', 'status-safe', 'status-warn', 'status-caution', 'status-danger', 'status-neutral');
        el.classList.add(statusFromTone(tone));
        if (id === 'consolePosture' || id === 'socConsoleCard' || id === 'nocConsoleCard') flashOnChange('tc-' + id, el, tone);
    }
    function fillList(id, pairs) {
        var ul = document.getElementById(id);
        if (!ul) return;
        ul.textContent = '';
        (pairs || []).forEach(function (p) {
            var li = document.createElement('li');
            var s = document.createElement('span');
            s.textContent = p[0];
            var b = document.createElement('b');
            b.textContent = (p[1] == null || p[1] === '') ? '—' : String(p[1]);
            li.appendChild(s); li.appendChild(b);
            ul.appendChild(li);
        });
    }
    function fillLines(id, items, emptyText) {
        var ul = document.getElementById(id);
        if (!ul) return;
        ul.textContent = '';
        (items || []).slice(0, 4).forEach(function (t) {
            var li = document.createElement('li');
            li.textContent = String(t);
            ul.appendChild(li);
        });
        if (!ul.children.length) {
            var li = document.createElement('li');
            li.textContent = emptyText || '—';
            ul.appendChild(li);
        }
    }
    function fillRejected(id, items) {
        var ul = document.getElementById(id);
        if (!ul) return;
        ul.textContent = '';
        (items || []).slice(0, 4).forEach(function (r) {
            var li = document.createElement('li');
            var a = document.createElement('span'); a.className = 'rej-action';
            a.textContent = String((r && r.action) || '—').toUpperCase();
            var rr = document.createElement('span'); rr.className = 'rej-reason';
            rr.textContent = String((r && r.reason) || '');
            li.appendChild(a); li.appendChild(rr);
            ul.appendChild(li);
        });
        if (!ul.children.length) fillLines(id, [], 'No stronger action was justified.');
    }
    function fmtClock(v) {
        if (v == null || v === '') return '—';
        if (typeof v === 'number') { try { return new Date(v * 1000).toTimeString().slice(0, 8); } catch (e) { return '—'; } }
        var m = String(v).match(/(\d{2}:\d{2}:\d{2})/);
        return m ? m[1] : String(v).slice(0, 10);
    }
    function fillEvidence(id, alerts) {
        var ul = document.getElementById(id);
        if (!ul) return;
        ul.textContent = '';
        (alerts || []).slice(0, 5).forEach(function (a) {
            var li = document.createElement('li');
            var t = document.createElement('span'); t.className = 'ev-time';
            t.textContent = fmtClock(a.ts_iso || a.ts);
            var l = document.createElement('span'); l.className = 'ev-label';
            l.textContent = String(a.attack_type || a.recommendation || (a.sid ? ('SID ' + a.sid) : 'event'));
            li.appendChild(t); li.appendChild(l);
            ul.appendChild(li);
        });
        if (!ul.children.length) fillLines(id, [], 'No recent evidence.');
    }
    function confLabel(c) {
        c = Number(c);
        if (!isFinite(c) || c === 0) return '—';
        return c >= 0.75 ? 'HIGH' : (c >= 0.5 ? 'MEDIUM' : 'LOW');
    }
    // Bounded-action severity → tone (deterministic action vocabulary).
    function actionTone(a) {
        a = String(a || '').toUpperCase();
        if (a === 'ISOLATE' || a === 'BLOCK') return 'is-critical';
        if (a === 'THROTTLE' || a === 'REDIRECT' || a === 'DEFER' || a === 'DELAY') return 'is-watch';
        if (a === 'OBSERVE' || a === 'NOTIFY' || a === 'MONITOR') return 'is-ok';
        return '';
    }
    // Inline stroke icons (no external assets). Keyed by bounded action / posture.
    var ICONS = {
        observe: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z'],
        throttle: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z', 'M9 12l2 2 4-4'],
        redirect: ['M4 17v-2a4 4 0 0 1 4-4h9', 'M14 7l4 4-4 4'],
        isolate: ['M7.9 3h8.2L21 7.9v8.2L16.1 21H7.9L3 16.1V7.9Z', 'M9 9l6 6', 'M15 9l-6 6'],
        unknown: ['M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z', 'M12 16h.01', 'M9.6 9a2.5 2.5 0 1 1 3.4 2.3c-.7.4-1 .9-1 1.7']
    };
    function actionIconKey(a) {
        a = String(a || '').toUpperCase();
        if (a === 'ISOLATE' || a === 'BLOCK') return 'isolate';
        if (a === 'REDIRECT') return 'redirect';
        if (a === 'THROTTLE' || a === 'DEFER' || a === 'DELAY') return 'throttle';
        if (a === 'OBSERVE' || a === 'NOTIFY' || a === 'MONITOR') return 'observe';
        return 'unknown';
    }
    function toneIconKey(tone) {
        return tone === 'is-critical' ? 'isolate' : tone === 'is-watch' ? 'throttle' : tone === 'is-ok' ? 'observe' : 'unknown';
    }
    function setIcon(slotId, key, tone) {
        var slot = document.getElementById(slotId);
        if (!slot) return;
        var ns = 'http://www.w3.org/2000/svg';
        var paths = ICONS[key] || ICONS.unknown;
        slot.textContent = '';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '1.6');
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        svg.setAttribute('aria-hidden', 'true');
        paths.forEach(function (d) { var p = document.createElementNS(ns, 'path'); p.setAttribute('d', d); svg.appendChild(p); });
        slot.appendChild(svg);
        slot.classList.remove('tone-ok', 'tone-watch', 'tone-critical', 'tone-unknown');
        slot.classList.add(tone === 'is-ok' ? 'tone-ok' : tone === 'is-watch' ? 'tone-watch' : tone === 'is-critical' ? 'tone-critical' : 'tone-unknown');
    }

    function renderOverviewConsole(detail) {
        detail = detail || {};
        var summary = detail.summary || {};
        var actions = detail.actions || {};
        var evidence = detail.evidence || {};
        var booth = detail.boothFocus || {};
        var soc = summary.soc_focus || {};
        var noc = summary.noc_focus || {};
        var path = noc.path_health || {};
        var assurance = summary.normal_assurance || {};
        var mode = summary.mode || {};
        var tp = (summary.situation_board || {}).threat_posture || {};
        var svc = summary.service_health_summary || {};
        var ci = noc.client_inventory || {};
        var dpath = summary.decision_path || {};
        var audit = booth.audit || {};
        var decision = booth.decision || {};
        var capsule = actions.decision_trust_capsule || {};
        var action = String(decision.action || '').toUpperCase();
        var actTone = actionTone(action);

        // Posture
        var postureTone = assurance.status ? toneOf(assurance.status === 'alert' ? 'critical' : assurance.status) : 'is-unknown';
        txt('consolePostureWord', assurance.status ? upper(assurance.status === 'alert' ? 'critical' : assurance.status, 'UNKNOWN') : 'UNKNOWN');
        txt('consolePostureDesc', tp.recommendation || summary.current_recommendation || '');
        setToneClass('consolePosture', postureTone);
        setIcon('consolePostureIcon', toneIconKey(postureTone), postureTone);

        // Active control = the deterministic bounded action (OBSERVE/THROTTLE/ISOLATE…),
        // falling back to the reversible mode when no decision record is available.
        txt('consoleControlWord', action || upper(mode.current_mode, 'UNKNOWN'));
        txt('consoleControlPolicy', audit.policy_profile || 'deterministic');
        txt('consoleControlMode', mode.current_mode || (action ? 'bounded / reversible' : '—'));
        var ctlTone = actTone || (mode.current_mode ? 'is-ok' : 'is-unknown');
        setToneClass('consoleControl', ctlTone);
        setIcon('consoleControlIcon', action ? actionIconKey(action) : toneIconKey(ctlTone), ctlTone);

        // NOC card
        var svcKeys = Object.keys(svc);
        var svcOn = svcKeys.filter(function (k) { var v = String(svc[k]).toLowerCase(); return v === 'on' || v === 'up'; }).length;
        txt('consoleNocState', upper(path.status, 'UNKNOWN'));
        fillList('consoleNocList', [
            ['Uplink', path.uplink || '—'],
            ['Internet', path.internet_check || '—'],
            ['Services', svcKeys.length ? (svcOn + '/' + svcKeys.length) : '—'],
            ['Clients', ci.current_client_count != null ? ci.current_client_count : '—']
        ]);
        setToneClass('consoleNoc', toneOf(path.status));

        // SOC card
        txt('consoleSocState', upper(soc.threat_level, 'UNKNOWN'));
        var evCount = (soc.critical_count != null || soc.warning_count != null) ? (num(soc.critical_count) + num(soc.warning_count)) : (capsule.evidence_count != null ? capsule.evidence_count : '—');
        fillList('consoleSocList', [
            ['Evidence', evCount],
            ['Critical', soc.critical_count != null ? soc.critical_count : '—'],
            ['Watch', soc.warning_count != null ? soc.warning_count : '—'],
            ['Top source', soc.top_source || '—']
        ]);
        setToneClass('consoleSoc', toneOf(soc.threat_level));

        // Decision card — headline is the selected action (mockup ①/⑤).
        var boothConf = (booth.trust_capsule || {}).confidence;
        txt('consoleDecisionState', action || (assurance.status ? upper(assurance.status === 'alert' ? 'critical' : assurance.status, 'UNKNOWN') : 'UNKNOWN'));
        fillList('consoleDecisionList', [
            ['Confidence', boothConf ? String(boothConf).toUpperCase() : confLabel(tp.confidence)],
            ['Applied', (action || mode.current_mode) ? 'YES' : '—'],
            ['Trust', capsule.tone ? String(capsule.tone).toUpperCase() : '—']
        ]);
        setToneClass('consoleDecision', actTone || postureTone);

        // Why + rejected — prefer the deterministic decision record.
        var whyItems = decision.reason ? [decision.reason] : ((capsule.why_this && capsule.why_this.length) ? capsule.why_this : actions.why_now);
        fillLines('consoleWhyList', whyItems, 'No decision rationale available yet.');
        var rejected = (decision.why_not_others && decision.why_not_others.length) ? decision.why_not_others : actions.rejected_stronger_actions;
        fillRejected('consoleRejectedList', rejected);

        // Recent evidence + audit
        fillEvidence('consoleEvidenceList', evidence.recent_alerts);
        txt('consoleAuditTrace', audit.trace_id || '—');
        txt('consoleAuditPolicy', audit.policy_profile || mode.current_mode || '—');
        txt('consoleAuditConfig', audit.config_hash || dpath.second_pass_engine || dpath.first_pass_engine || '—');
        txt('consoleAuditActor', (booth.decision && booth.decision.actor) || 'arbiter');
    }

    /* ---- lightweight SVG sparkline (no chart library; Pi-friendly) --------- */
    function drawSpark(id, data, tone) {
        var slot = document.getElementById(id);
        if (!slot) return;
        data = (data || []).map(Number).filter(function (v) { return isFinite(v); });
        if (data.length < 2) { slot.textContent = ''; return; }
        var W = 100, H = 30, PAD = 2;
        var min = Math.min.apply(null, data), max = Math.max.apply(null, data), span = max - min;
        var stepX = W / (data.length - 1);
        var pts = data.map(function (v, i) {
            var x = i * stepX;
            var y = span === 0 ? H / 2 : (H - PAD) - ((v - min) / span) * (H - PAD * 2);
            return [x, y];
        });
        var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(2) + ',' + p[1].toFixed(2); }).join(' ');
        var area = line + ' L' + W + ',' + H + ' L0,' + H + ' Z';
        var ns = 'http://www.w3.org/2000/svg';
        var svg = slot.firstElementChild;
        if (!svg || svg.tagName.toLowerCase() !== 'svg') {
            svg = document.createElementNS(ns, 'svg');
            svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
            svg.setAttribute('preserveAspectRatio', 'none');
            svg.setAttribute('aria-hidden', 'true');
            var ap = document.createElementNS(ns, 'path'); ap.setAttribute('class', 'spk-area');
            var lp = document.createElementNS(ns, 'path'); lp.setAttribute('class', 'spk-line');
            svg.appendChild(ap); svg.appendChild(lp);
            slot.textContent = ''; slot.appendChild(svg);
        }
        svg.querySelector('.spk-area').setAttribute('d', area);
        svg.querySelector('.spk-line').setAttribute('d', line);
    }
    // Multi-series line chart (CPU/MEM/TEMP overlaid on a shared auto scale).
    function drawMultiSpark(id, seriesIn) {
        var slot = document.getElementById(id);
        if (!slot) return;
        var series = (seriesIn || []).map(function (s) {
            return { cls: s.cls, data: (s.data || []).map(Number).filter(function (v) { return isFinite(v); }) };
        }).filter(function (s) { return s.data.length >= 2; });
        if (!series.length) { slot.textContent = ''; return; }
        var all = [];
        series.forEach(function (s) { all = all.concat(s.data); });
        var min = Math.min.apply(null, all), max = Math.max.apply(null, all), span = (max - min) || 1;
        var W = 100, H = 30, PAD = 2, ns = 'http://www.w3.org/2000/svg';
        slot.textContent = '';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('aria-hidden', 'true');
        series.forEach(function (s) {
            var n = s.data.length, stepX = W / (n - 1);
            var d = s.data.map(function (v, i) {
                var x = i * stepX, y = (H - PAD) - ((v - min) / span) * (H - PAD * 2);
                return (i ? 'L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2);
            }).join(' ');
            var p = document.createElementNS(ns, 'path');
            p.setAttribute('class', 'spk-line ' + s.cls);
            p.setAttribute('d', d);
            svg.appendChild(p);
        });
        slot.appendChild(svg);
    }
    function fillChips(id, arr) {
        var box = document.getElementById(id);
        if (!box) return;
        box.textContent = '';
        (arr || []).slice(0, 8).forEach(function (t) {
            var s = String(t), m = s.match(/^(T\d{4}(?:\.\d+)?)\s*(.*)$/);
            var chip = document.createElement('span'); chip.className = 'sentinel-chip';
            if (m) { var code = document.createElement('b'); code.textContent = m[1]; chip.appendChild(code); chip.appendChild(document.createTextNode(' ' + m[2])); }
            else chip.textContent = s;
            box.appendChild(chip);
        });
        if (!box.children.length) { var e = document.createElement('span'); e.className = 'sentinel-chip sentinel-chip--empty'; e.textContent = 'none'; box.appendChild(e); }
    }
    function fillEnrich(id, pairs) {
        var box = document.getElementById(id);
        if (!box) return;
        box.textContent = '';
        (pairs || []).forEach(function (p) {
            var b = document.createElement('span'); b.className = 'sentinel-badge';
            b.textContent = p[0] + ' ' + p[1];
            box.appendChild(b);
        });
    }
    function fillCatBars(id, arr) {
        var box = document.getElementById(id);
        if (!box) return;
        box.textContent = '';
        var maxv = arr.reduce(function (m, x) { return Math.max(m, x[1]); }, 1);
        arr.slice(0, 5).forEach(function (x) {
            var row = document.createElement('div'); row.className = 'catbar-row';
            var lab = document.createElement('span'); lab.className = 'catbar-label'; lab.textContent = String(x[0]);
            var track = document.createElement('span'); track.className = 'catbar-track';
            var fill = document.createElement('span'); fill.className = 'catbar-fill'; fill.style.width = Math.round(100 * x[1] / maxv) + '%';
            track.appendChild(fill);
            var c = document.createElement('b'); c.className = 'catbar-count'; c.textContent = String(x[1]);
            row.appendChild(lab); row.appendChild(track); row.appendChild(c);
            box.appendChild(row);
        });
        if (!box.children.length) { var e = document.createElement('div'); e.className = 'catbar-row'; e.textContent = '—'; box.appendChild(e); }
    }

    /* ---- OPERATIONS (SOC + NOC) ------------------------------------------- */
    var socRiskHist = [];
    function renderOperationsConsole(detail) {
        detail = detail || {};
        var summary = detail.summary || {}, evidence = detail.evidence || {};
        var soc = summary.soc_focus || {}, noc = summary.noc_focus || {}, path = noc.path_health || {};

        var socTone = toneOf(soc.threat_level);
        txt('socConsoleStatus', upper(soc.threat_level, 'UNKNOWN'));
        setToneClass('socConsoleCard', socTone);
        var hasSoc = (soc.critical_count != null || soc.warning_count != null);
        var crit = num(soc.critical_count), warn = num(soc.warning_count);
        txt('socMetricEvidence', hasSoc ? (crit + warn) : '—');
        txt('socMetricCritical', soc.critical_count != null ? soc.critical_count : '—');
        txt('socMetricWatch', soc.warning_count != null ? soc.warning_count : '—');
        txt('socMetricSources', soc.top_source ? 1 : (hasSoc ? 0 : '—'));
        var risk = (soc.confidence_provenance || {}).adjusted_score;
        txt('socMetricRisk', risk != null ? (risk + '/100') : '—');
        // Risk over time — real risk scores from the recent alerts, ordered by time.
        var riskSeries = (evidence.recent_alerts || []).slice()
            .sort(function (a, b) { return Number(a.ts) - Number(b.ts); })
            .map(function (a) { return num(a.risk_score); }).filter(function (v) { return v > 0; });
        if (riskSeries.length >= 2) drawSpark('socRiskSpark', riskSeries, socTone);
        else { if (risk != null) { socRiskHist.push(Number(risk)); if (socRiskHist.length > 45) socRiskHist.shift(); } drawSpark('socRiskSpark', socRiskHist, socTone); }
        fillEvidence('socTopEvidenceList', evidence.recent_alerts);
        // MITRE ATT&CK technique chips (adopted SIEM pattern; deterministic input).
        fillChips('socAttackChips', soc.attack_candidates || []);
        // Enrichment context badges: threat-intel / detection-rule hits / correlation.
        var enrich = [];
        if ((soc.ti_matches || []).length) enrich.push(['TI', soc.ti_matches.length]);
        if ((soc.sigma_hits || []).length) enrich.push(['Sigma', soc.sigma_hits.length]);
        if ((soc.yara_hits || []).length) enrich.push(['YARA', soc.yara_hits.length]);
        if (soc.correlation && soc.correlation.status && soc.correlation.status !== 'none') enrich.push(['Correlation', String(soc.correlation.status)]);
        fillEnrich('socEnrich', enrich);
        // Evidence pipeline funnel (Events -> Signals -> Now -> Watch).
        var tri = soc.triage_priority || {};
        var alertsN = Array.isArray(evidence.recent_alerts) ? evidence.recent_alerts.length : null;
        txt('socPipeEvents', alertsN != null ? alertsN : '—');
        txt('socPipeSignals', hasSoc ? (crit + warn) : '—');
        txt('socPipeNow', Array.isArray(tri.now) ? tri.now.length : (tri.status ? 0 : '—'));
        txt('socPipeWatch', Array.isArray(tri.watch) ? tri.watch.length : (tri.status ? 0 : '—'));
        // Threat categories (horizontal bars) — grouped from alert attack types.
        var cats = {};
        (evidence.recent_alerts || []).forEach(function (a) { var t = a.attack_type; if (t) cats[t] = (cats[t] || 0) + 1; });
        (soc.attack_candidates || []).forEach(function (c) { if (!(c in cats)) cats[c] = cats[c] || 1; });
        var catArr = Object.keys(cats).map(function (k) { return [k, cats[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
        fillCatBars('socThreatCats', catArr);
        renderSocTriage(evidence);
        renderDecisionRationale(detail.boothFocus, 'soc', 'soc');

        var nocTone = toneOf(path.status);
        txt('nocConsoleStatus', upper(path.status, 'UNKNOWN'));
        setToneClass('nocConsoleCard', nocTone);
        var svc = summary.service_health_summary || {}; var keys = Object.keys(svc);
        var on = keys.filter(function (k) { var v = String(svc[k]).toLowerCase(); return v === 'on' || v === 'up'; }).length;
        var cap = noc.capacity || {};
        txt('nocMetricUplink', path.uplink || '—');
        txt('nocMetricInternet', path.internet_check || '—');
        txt('nocMetricServices', keys.length ? (on + '/' + keys.length) : '—');
        txt('nocMetricClients', (noc.client_inventory || {}).current_client_count);
        txt('nocMetricCapacity', cap.utilization_pct != null ? (Math.round(cap.utilization_pct) + '%') : '—');
        var sa = noc.service_assurance || {}, rh = noc.resolution_health || {}, cd = noc.config_drift || {}, inc = noc.incident_summary || {}, br = noc.blast_radius || {};
        fillList('nocServiceList', [
            ['Service assurance', sa.status || '—'],
            ['Resolution (DNS)', rh.status || '—'],
            ['Config drift', cd.status || '—'],
            ['Incident cause', inc.probable_cause || '—']
        ]);
        fillList('nocCapacityList', [
            ['Utilization', cap.utilization_pct != null ? (Math.round(cap.utilization_pct) + '%') : '—'],
            ['Top talker', cap.top_talker || '—'],
            ['Affected clients', br.affected_client_count != null ? br.affected_client_count : '—'],
            ['Affected segments', (br.affected_segments || []).length || '—']
        ]);
        renderNocClients(noc);
        renderNocBandwidth(noc);
        renderNocTrafficControl(detail);
        renderNocPathStrip(detail);
        renderNocTopTalkers(detail);
        renderNocMeters(detail.health);
        renderDecisionRationale(detail.boothFocus, 'noc', 'noc');
    }

    // NOC · client roster (real SoT / identity view).
    function clientStateTone(s) {
        s = String(s || '').toLowerCase();
        if (s.indexOf('unauthor') !== -1) return 'is-critical';
        if (s === 'mismatch' || s.indexOf('mismatch') !== -1 || s.indexOf('unknown') !== -1) return 'is-watch';
        if (s === 'normal' || s.indexOf('author') !== -1) return 'is-ok';
        return 'is-unknown';
    }
    function renderNocClients(noc) {
        var view = noc.client_identity_view || {};
        var items = view.items || [];
        txt('nocClientSummary', items.length + ' shown · ' + num(view.attention_count) + ' attention · ' + num(view.normal_count) + ' normal');
        var box = document.getElementById('nocClientRoster');
        if (!box) return;
        box.textContent = '';
        var header = document.createElement('div'); header.className = 'client-row client-head';
        ['State', 'Host / IP', 'MAC', 'Link', 'Trust'].forEach(function (h) { var c = document.createElement('span'); c.textContent = h; header.appendChild(c); });
        box.appendChild(header);
        items.slice(0, 12).forEach(function (it) {
            var row = document.createElement('div'); row.className = 'client-row';
            if (it.requires_attention) row.classList.add('is-attn');
            var st = document.createElement('span'); st.className = 'client-state ' + statusFromTone(clientStateTone(it.state));
            st.textContent = String(it.state || '—');
            var host = document.createElement('span'); host.className = 'client-host';
            host.textContent = String(it.hostname || it.display_name || it.ip || '—') + (it.ip && (it.hostname || it.display_name) ? ('  ' + it.ip) : '');
            var mac = document.createElement('span'); mac.className = 'client-mac'; mac.textContent = String(it.masked_mac || it.mac || '—');
            var link = document.createElement('span'); link.className = 'client-link'; link.textContent = String(it.interface_family || '—') + (it.expected_link_mismatch ? ' ⚠' : '');
            var trust = document.createElement('span'); trust.className = 'client-trust'; trust.textContent = it.trusted ? 'trusted' : (it.trust_eligible ? 'eligible' : '—');
            row.appendChild(st); row.appendChild(host); row.appendChild(mac); row.appendChild(link); row.appendChild(trust);
            box.appendChild(row);
        });
        if (items.length <= 0) { var e = document.createElement('div'); e.className = 'client-row'; e.textContent = 'No managed clients in scope.'; box.appendChild(e); }
    }
    function renderNocBandwidth(noc) {
        var cap = noc.capacity || {}, br = noc.blast_radius || {};
        var box = document.getElementById('nocBandwidth');
        if (box) {
            box.textContent = '';
            var util = cap.utilization_pct;
            var meter = document.createElement('div'); meter.className = 'sentinel-meter';
            var lab = document.createElement('div'); lab.className = 'sentinel-meter__lab';
            lab.textContent = 'Interface utilization';
            var val = document.createElement('b'); val.textContent = util != null ? (Math.round(util) + '%') : '—';
            lab.appendChild(val);
            var track = document.createElement('div'); track.className = 'sentinel-meter__track';
            var fill = document.createElement('div'); fill.className = 'sentinel-meter__fill ' + (num(util) >= 80 ? 'is-critical' : num(util) >= 60 ? 'is-watch' : 'is-ok');
            fill.style.width = (util != null ? Math.max(2, Math.min(100, util)) : 0) + '%';
            track.appendChild(fill); meter.appendChild(lab); meter.appendChild(track);
            box.appendChild(meter);
            var kv = document.createElement('dl'); kv.className = 'sentinel-kv';
            [['Top talker', cap.top_talker || '—'], ['Affected clients', br.affected_client_count != null ? br.affected_client_count : '—'], ['Critical clients', br.critical_client_count != null ? br.critical_client_count : '—']].forEach(function (r) {
                var d = document.createElement('div'); var dt = document.createElement('dt'); dt.textContent = r[0]; var dd = document.createElement('dd'); dd.textContent = String(r[1]); d.appendChild(dt); d.appendChild(dd); kv.appendChild(d);
            });
            box.appendChild(kv);
        }
        var peers = (noc.remote_peers || {}).items || [];
        var tbox = document.getElementById('nocTopTalkers');
        if (tbox) {
            tbox.textContent = '';
            if (peers.length) {
                var k = document.createElement('div'); k.className = 'sentinel-card__kicker'; k.style.marginTop = '10px'; k.textContent = 'External peers'; tbox.appendChild(k);
                peers.slice(0, 5).forEach(function (p) { var li = document.createElement('div'); li.className = 'talker'; li.textContent = String(p.label || p.src_ip || p.value || '—'); tbox.appendChild(li); });
            }
        }
    }
    function renderNocTrafficControl(detail) {
        var booth = detail.boothFocus || {}, summary = detail.summary || {};
        var decision = booth.decision || {}, safety = booth.safety || {};
        var action = String(decision.action || '').toUpperCase();
        var box = document.getElementById('nocTrafficControl');
        if (!box) return;
        box.textContent = '';
        var rows = [
            ['Active control', action || upper((summary.mode || {}).current_mode, 'OBSERVE')],
            ['Effect', action === 'THROTTLE' ? 'traffic shaping (interface-wide)' : action === 'ISOLATE' ? 'segment isolation' : action === 'REDIRECT' ? 'decoy redirect' : 'visibility only'],
            ['Enforcement', booth.available ? (safety.dry_run === false ? 'enforced' : 'dry-run (advisory)') : 'dry-run (advisory)'],
            ['Safety gate', 'auto-downgrade to NOTIFY if critical clients affected']
        ];
        var kv = document.createElement('dl'); kv.className = 'sentinel-kv';
        rows.forEach(function (r) { var d = document.createElement('div'); var dt = document.createElement('dt'); dt.textContent = r[0]; var dd = document.createElement('dd'); dd.textContent = String(r[1]); d.appendChild(dt); d.appendChild(dd); kv.appendChild(d); });
        box.appendChild(kv);
    }

    /* ---- OPERATIONS · folded-in focus content (triage / path / talkers /
       runtime meters / per-domain decision rationale) ---------------------- */
    var socTriageBand = 'all';

    function bytesShort(n) {
        var v = Number(n) || 0;
        if (v >= 1e9) return (v / 1e9).toFixed(1) + ' GB';
        if (v >= 1e6) return (v / 1e6).toFixed(1) + ' MB';
        if (v >= 1e3) return (v / 1e3).toFixed(1) + ' KB';
        return v + ' B';
    }
    function shortTime(iso) {
        if (!iso) return '—';
        var m = String(iso).match(/[T\s](\d{2}:\d{2}:\d{2})/);
        return m ? m[1] : String(iso).slice(0, 19);
    }
    function riskBandTone(band) {
        return band === 'now' ? 'is-critical' : band === 'watch' ? 'is-watch' : 'is-unknown';
    }

    // SOC triage queue — the full filterable table (evidence.alert_queues), the
    // rows the classic SOC workspace rendered. Band filter is client-side only.
    function renderSocTriage(evidence) {
        var box = document.getElementById('socTriageTable');
        if (!box) return;
        var aq = (evidence || {}).alert_queues || {};
        var bands = [['now', aq.now], ['watch', aq.watch], ['backlog', aq.backlog]];
        var rows = [];
        bands.forEach(function (b) {
            if (socTriageBand !== 'all' && socTriageBand !== b[0]) return;
            var items = (b[1] || {}).items || [];
            items.forEach(function (it) { rows.push([b[0], it]); });
        });
        rows.sort(function (a, b) { return num(b[1].risk_score) - num(a[1].risk_score); });
        box.textContent = '';
        var head = document.createElement('div'); head.className = 'tri-row tri-head';
        ['Time', 'Band', 'Source → Dest', 'SID · Attack', 'Risk'].forEach(function (h) { var c = document.createElement('span'); c.textContent = h; head.appendChild(c); });
        box.appendChild(head);
        if (!rows.length) { var e = document.createElement('div'); e.className = 'tri-row tri-empty'; e.textContent = 'No queued alerts in this view.'; box.appendChild(e); return; }
        rows.slice(0, 24).forEach(function (r) {
            var band = r[0], it = r[1];
            var row = document.createElement('div'); row.className = 'tri-row';
            var t = document.createElement('span'); t.className = 'tri-time'; t.textContent = shortTime(it.ts_iso);
            var bd = document.createElement('span'); var badge = document.createElement('b'); badge.className = 'tri-band ' + statusFromTone(riskBandTone(band)); badge.textContent = band.toUpperCase(); bd.appendChild(badge);
            var flow = document.createElement('span'); flow.className = 'tri-flow'; flow.textContent = (it.src_ip || '—') + ' → ' + (it.dst_ip || '—');
            var sid = document.createElement('span'); sid.className = 'tri-sid'; sid.textContent = (it.sid ? ('#' + it.sid) : '—') + (it.attack_type ? (' · ' + it.attack_type) : '');
            var risk = document.createElement('span'); var rb = document.createElement('b'); rb.className = 'tri-risk ' + statusFromTone(num(it.risk_score) >= 80 ? 'is-critical' : num(it.risk_score) >= 50 ? 'is-watch' : 'is-ok'); rb.textContent = num(it.risk_score); risk.appendChild(rb);
            row.appendChild(t); row.appendChild(bd); row.appendChild(flow); row.appendChild(sid); row.appendChild(risk);
            box.appendChild(row);
        });
    }

    // Per-domain (SOC / NOC evaluator jurisdiction) decision rationale, rejected
    // options, release condition and audit refs — from the decision_focus record.
    function renderDecisionRationale(booth, domainKey, prefix) {
        booth = booth || {};
        var decision = booth.decision || {}, domains = booth.domains || {}, audit = booth.audit || {};
        var domainReasons = (domains[domainKey] || {}).reasons;
        var whyItems = (domainReasons && domainReasons.length) ? domainReasons : (decision.reason ? [decision.reason] : []);
        fillLines(prefix + 'WhyList', whyItems, 'No decision rationale available yet.');
        fillRejected(prefix + 'RejectedList', decision.why_not_others || []);
        txt(prefix + 'ReleaseCond', decision.release_condition || '—');
        txt(prefix + 'AuditTrace', audit.trace_id || '—');
        txt(prefix + 'AuditPolicy', audit.policy_profile || '—');
    }

    // NOC path strip: the edge-local topology (Clients -> Edge -> Uplink -> GW ->
    // Internet), tone-ranked. Mirrors the classic 5-hop strip.
    function renderNocPathStrip(detail) {
        var box = document.getElementById('nocPathStrip');
        if (!box) return;
        var summary = detail.summary || {}, state = detail.state || {};
        var noc = summary.noc_focus || {}, path = noc.path_health || {};
        var current = (noc.client_inventory || {}).current_client_count;
        var mode = (summary.mode || {}).current_mode || (state.mode || {}).current_mode;
        var hops = [
            { title: 'Clients' + (current != null ? (' ×' + current) : ''), state: 'MANAGED', tone: 'is-ok' },
            { title: 'Azazel-Edge', state: upper(mode, 'OBSERVE'), tone: 'is-ok' },
            { title: 'Uplink', state: upper(path.uplink, '—'), tone: toneOf(path.uplink) },
            { title: 'GW ' + (state.gateway_ip || '—'), state: upper(path.gateway, '—'), tone: toneOf(path.gateway) },
            { title: 'Internet', state: upper(path.internet_check || path.internet, '—'), tone: toneOf(path.internet_check || path.internet) }
        ];
        var rank = { 'is-ok': 0, 'is-unknown': 1, 'is-watch': 2, 'is-critical': 3 };
        box.textContent = '';
        hops.forEach(function (hop, i) {
            var h = document.createElement('div'); h.className = 'sp-hop ' + hop.tone;
            var ht = document.createElement('div'); ht.className = 'sp-hop__title'; ht.textContent = hop.title;
            var hs = document.createElement('div'); hs.className = 'sp-hop__state'; hs.textContent = hop.state;
            h.appendChild(ht); h.appendChild(hs); box.appendChild(h);
            if (i < hops.length - 1) {
                var link = document.createElement('span');
                var lt = (rank[hop.tone] || 0) >= (rank[hops[i + 1].tone] || 0) ? hop.tone : hops[i + 1].tone;
                link.className = 'sp-link ' + lt; box.appendChild(link);
            }
        });
    }

    // NOC top talkers joined with the client identity view (bytes + share bar +
    // identity state). Source list lives on the raw snapshot state.noc_capacity.
    function renderNocTopTalkers(detail) {
        var box = document.getElementById('nocTopTalkerTable');
        if (!box) return;
        var summary = detail.summary || {}, state = detail.state || {};
        var noc = summary.noc_focus || {}, cap = noc.capacity || {};
        var rawSources = (state.noc_capacity || {}).top_sources || cap.top_sources;
        var sources = Array.isArray(rawSources) ? rawSources.slice(0, 6) : [];
        var identityItems = Array.isArray((noc.client_identity_view || {}).items) ? noc.client_identity_view.items : [];
        var byIp = {}; identityItems.forEach(function (it) { byIp[String(it.ip || '')] = it; });
        var maxBytes = sources.reduce(function (m, s) { return Math.max(m, Number(s.bytes) || 0); }, 1);
        box.textContent = '';
        var head = document.createElement('div'); head.className = 'talker-row talker-head';
        ['Source', 'Volume', 'Share', 'Identity'].forEach(function (h) { var c = document.createElement('span'); c.textContent = h; head.appendChild(c); });
        box.appendChild(head);
        if (!sources.length) { var e = document.createElement('div'); e.className = 'talker-row talker-empty'; e.textContent = 'No top-talker telemetry in the current window.'; box.appendChild(e); return; }
        sources.forEach(function (src) {
            var ip = String(src.src_ip || src.id || '—');
            var identity = byIp[ip];
            var name = (identity && identity.display_name && identity.display_name !== ip) ? (' ' + identity.display_name) : '';
            var stateText = identity ? String(identity.state || (identity.trusted ? 'trusted' : 'unknown')) : '—';
            var stTone = (stateText.indexOf('unauthor') !== -1 || stateText.indexOf('mismatch') !== -1 || stateText.indexOf('missing') !== -1) ? 'is-critical' : (stateText === 'unknown' ? 'is-unknown' : 'is-ok');
            var share = Math.max(4, Math.round(((Number(src.bytes) || 0) / maxBytes) * 100));
            var row = document.createElement('div'); row.className = 'talker-row';
            var s = document.createElement('span'); s.className = 'talker-src'; s.innerHTML = '<b></b>'; s.firstChild.textContent = ip; s.appendChild(document.createTextNode(name));
            var vol = document.createElement('span'); vol.className = 'talker-vol'; vol.textContent = bytesShort(src.bytes);
            var sh = document.createElement('span'); sh.className = 'talker-share'; var bar = document.createElement('span'); bar.className = 'talker-share__bar' + (share >= 60 ? ' is-watch' : ''); bar.style.width = Math.min(100, share) + '%'; sh.appendChild(bar);
            var idn = document.createElement('span'); var ib = document.createElement('b'); ib.className = 'talker-idn ' + statusFromTone(stTone); ib.textContent = stateText; idn.appendChild(ib);
            row.appendChild(s); row.appendChild(vol); row.appendChild(sh); row.appendChild(idn);
            box.appendChild(row);
        });
    }

    // NOC runtime meters (queue depth / LLM fallback rate / latency EMA) — same
    // math as the classic resource guard.
    function renderNocMeters(health) {
        var box = document.getElementById('nocRuntimeMeters');
        if (!box) return;
        health = health || {};
        var queue = health.queue || {}, llm = health.llm || {};
        var depth = num(queue.depth), cap = num(queue.capacity);
        var queuePct = cap > 0 ? Math.min(100, (depth / cap) * 100) : 0;
        var fallbackPct = Math.min(100, Math.max(0, num(llm.fallback_rate) * 100));
        var latency = num(llm.latency_ms_ema);
        var latencyPct = Math.min(100, Math.max(0, (latency / 1500) * 100));
        var meters = [
            ['Queue', depth + '/' + cap, queuePct, queuePct >= 90 ? 'is-critical' : queuePct >= 65 ? 'is-watch' : 'is-ok'],
            ['Fallback rate', Math.round(fallbackPct) + '%', fallbackPct, fallbackPct >= 50 ? 'is-critical' : fallbackPct >= 20 ? 'is-watch' : 'is-ok'],
            ['Latency', Math.round(latency) + ' ms', latencyPct, latencyPct >= 85 ? 'is-critical' : latencyPct >= 55 ? 'is-watch' : 'is-ok']
        ];
        box.textContent = '';
        meters.forEach(function (m) {
            var meter = document.createElement('div'); meter.className = 'sentinel-meter';
            var lab = document.createElement('div'); lab.className = 'sentinel-meter__lab'; lab.textContent = m[0];
            var val = document.createElement('b'); val.textContent = m[1]; lab.appendChild(val);
            var track = document.createElement('div'); track.className = 'sentinel-meter__track';
            var fill = document.createElement('div'); fill.className = 'sentinel-meter__fill ' + m[3]; fill.style.width = Math.max(2, m[2]) + '%';
            track.appendChild(fill); meter.appendChild(lab); meter.appendChild(track); box.appendChild(meter);
        });
    }

    /* ---- EVIDENCE (timeline + list + audit + raw + detail drawer) --------- */
    var evLastSig = null, evSelectedKey = null, evRange = 0;
    function alertKey(a) { return [a.evidence_id || a.trace_id || '', a.ts || a.ts_iso || '', a.sid || '', a.attack_type || ''].join('|'); }
    function alertTag(a) {
        var r = String(a.risk_level || '').toUpperCase();
        if (r === 'HIGH' || r === 'CRITICAL' || num(a.severity) >= 3) return { cls: 'tag-crit', word: 'CRITICAL', row: 'tone-crit' };
        if (r === 'MEDIUM' || num(a.severity) > 0 || num(a.risk_score) > 0) return { cls: '', word: 'WATCH', row: 'tone-warn' };
        return { cls: 'tag-info', word: 'INFO', row: '' };
    }
    var EVD_FIELDS = ['evdTime', 'evdSource', 'evdDest', 'evdProto', 'evdSeverity', 'evdPolicy', 'evdRule', 'evdEid', 'evdTrace'];
    function clearEvidenceDrawer() { EVD_FIELDS.forEach(function (id) { txt(id, '—'); }); }
    function selectEvidence(a, li) {
        evSelectedKey = alertKey(a);
        var tl = document.getElementById('evTimeline');
        if (tl) Array.prototype.forEach.call(tl.children, function (c) { c.classList.remove('is-selected'); });
        if (li) li.classList.add('is-selected');
        txt('evdTime', a.ts_iso || fmtClock(a.ts));
        txt('evdSource', a.src_ip || '—');
        txt('evdDest', a.dst_ip || '—');
        txt('evdProto', a.protocol || '—');
        txt('evdSeverity', a.severity != null ? a.severity : (a.risk_level || '—'));
        txt('evdPolicy', a.policy || '—');
        txt('evdRule', a.sid || '—');
        txt('evdEid', a.evidence_id || '—');
        txt('evdTrace', a.trace_id || '—');
    }
    function renderEvidenceConsole(detail) {
        detail = detail || {};
        var evidence = detail.evidence || {};
        var allAlerts = evidence.recent_alerts || [];
        // Time-range filter (adopted SIEM control). 0 = All.
        var cutoff = evRange > 0 ? ((Date.now() / 1000) - evRange) : 0;
        var alerts = evRange > 0 ? allAlerts.filter(function (a) { return Number(a.ts) >= cutoff; }) : allAlerts;
        // Skip the destructive rebuild when nothing changed, so a poll never wipes
        // the operator's selection or keyboard focus on this drill-down surface.
        var sig = alerts.map(alertKey).join('~') + '@' + evRange + '#' +
            (evidence.recent_mode_changes || []).length + ',' +
            (evidence.recent_runbook_events || []).length + ',' +
            (evidence.recent_triage_audit || []).length;
        if (sig === evLastSig) return;
        evLastSig = sig;
        txt('evCount', alerts.length + ' of ' + allAlerts.length + ' shown');
        var tl = document.getElementById('evTimeline');
        if (tl) {
            var hadFocus = tl.contains(document.activeElement);
            tl.textContent = '';
            var selectedLi = null;
            alerts.slice(0, 20).forEach(function (a) {
                var li = document.createElement('li');
                li.tabIndex = 0; li.setAttribute('role', 'button');
                var tag = alertTag(a); if (tag.row) li.className = tag.row;
                if (alertKey(a) === evSelectedKey) { li.classList.add('is-selected'); selectedLi = li; }
                var t = document.createElement('span'); t.className = 'evt-time'; t.textContent = fmtClock(a.ts_iso || a.ts);
                var l = document.createElement('span'); l.className = 'evt-label'; l.textContent = String(a.attack_type || a.recommendation || 'event');
                var g = document.createElement('span'); g.className = 'evt-tag ' + tag.cls; g.textContent = tag.word;
                li.appendChild(t); li.appendChild(l); li.appendChild(g);
                li.addEventListener('click', function () { selectEvidence(a, li); });
                li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectEvidence(a, li); } });
                tl.appendChild(li);
            });
            if (!tl.children.length) { var li = document.createElement('li'); li.textContent = 'No evidence in the current window.'; tl.appendChild(li); }
            else if (hadFocus) { (selectedLi || tl.firstElementChild).focus(); }
            // Selected alert scrolled out of the window: clear the drawer rather than
            // keep describing an alert that is no longer listed.
            if (evSelectedKey && !selectedLi) { clearEvidenceDrawer(); evSelectedKey = null; }
        }
        var lst = document.getElementById('evList');
        if (lst) {
            lst.textContent = '';
            alerts.slice(0, 30).forEach(function (a) {
                var row = document.createElement('div'); row.className = 'evrow';
                row.textContent = fmtClock(a.ts_iso || a.ts) + '  ' + (a.src_ip || '—') + ' → ' + (a.dst_ip || '—') + '  ' + (a.attack_type || '') + '  SID ' + (a.sid || '—') + '  ' + (a.risk_level || '');
                lst.appendChild(row);
            });
            if (!lst.children.length) lst.textContent = '—';
        }
        var au = document.getElementById('evAudit');
        if (au) {
            au.textContent = '';
            var rows = [];
            (evidence.recent_mode_changes || []).forEach(function (m) { rows.push([fmtClock(m.ts), 'mode → ' + (m.current_mode || '')]); });
            (evidence.recent_runbook_events || []).forEach(function (r) { rows.push([fmtClock(r.ts), 'runbook ' + (r.action || '') + ' ' + (r.runbook_id || '')]); });
            (evidence.recent_triage_audit || []).forEach(function (t) { rows.push([fmtClock(t.ts), String(t.kind || 'triage')]); });
            rows.slice(0, 20).forEach(function (r) {
                var li = document.createElement('li');
                var a = document.createElement('span'); a.className = 'aud-time'; a.textContent = r[0];
                var b = document.createElement('span'); b.textContent = r[1];
                li.appendChild(a); li.appendChild(b); au.appendChild(li);
            });
            if (!au.children.length) { var li = document.createElement('li'); li.textContent = 'No audit entries.'; au.appendChild(li); }
        }
        var raw = document.getElementById('evRaw');
        if (raw) { try { raw.textContent = JSON.stringify(alerts.slice(0, 10), null, 2); } catch (e) { raw.textContent = '—'; } }
    }

    /* ---- SYSTEM (runtime tiles + resource history + services/fleet/config) - */
    function pctTone(v) { v = Number(v); if (!isFinite(v) || v === 0) return 'is-unknown'; if (v >= 95) return 'is-critical'; if (v >= 80) return 'is-watch'; return 'is-ok'; }
    function tempTone(v) { v = Number(v); if (!isFinite(v) || v === 0) return 'is-unknown'; if (v >= 85) return 'is-critical'; if (v >= 70) return 'is-watch'; return 'is-ok'; }
    function renderSystemConsole(detail) {
        detail = detail || {};
        var summary = detail.summary || {}, health = detail.health || {}, trends = detail.trends || {};
        var points = trends.points || [];
        var last = points.length ? points[points.length - 1] : {};
        // A 0/absent reading here means "not sampled" (no psutil), not a real 0% —
        // render it as unknown rather than a misleading green 0%.
        var cpu = last.cpu_percent, mem = last.memory_percent, temp = last.temperature_c;
        txt('sysCpu', cpu ? (Math.round(Number(cpu)) + '%') : '—');
        txt('sysMem', mem ? (Math.round(Number(mem)) + '%') : '—');
        txt('sysDisk', '—');
        txt('sysTemp', temp ? (Math.round(Number(temp)) + '°C') : '—');
        setToneClass('sysCpuTile', pctTone(cpu)); setToneClass('sysMemTile', pctTone(mem)); setToneClass('sysTempTile', tempTone(temp));
        // Non-color state cue for screen readers (tiles otherwise encode state by color).
        function ariaTile(tileId, valId, name, tone) {
            var el = document.getElementById(tileId), v = document.getElementById(valId);
            if (el && v) el.setAttribute('aria-label', name + ' ' + v.textContent + ' (' + (TONE_WORD[tone] || 'UNKNOWN') + ')');
        }
        ariaTile('sysCpuTile', 'sysCpu', 'CPU', pctTone(cpu));
        ariaTile('sysMemTile', 'sysMem', 'Memory', pctTone(mem));
        ariaTile('sysTempTile', 'sysTemp', 'Temperature', tempTone(temp));
        ariaTile('sysDiskTile', 'sysDisk', 'Disk', 'is-unknown');
        var path = (summary.noc_focus || {}).path_health || {};
        txt('sysUplink', path.internet_check || '—');
        var svc = summary.service_health_summary || {}; var keys = Object.keys(svc);
        var on = keys.filter(function (k) { var v = String(svc[k]).toLowerCase(); return v === 'on' || v === 'up'; }).length;
        txt('sysServices', keys.length ? (on + '/' + keys.length) : '—');
        var coreOn = String(svc.web || svc.ai_agent || '').toLowerCase();
        txt('sysCore', (coreOn === 'on' || coreOn === 'up') ? 'RUNNING' : '—');
        var llm = health.llm || {};
        // Absent AI health must read unknown, not a confident STANDBY.
        txt('sysAi', health.llm ? (num(llm.requests) > 0 ? 'READY' : 'STANDBY') : '—');
        // Per-tile sparklines + overlaid resource history from the trend series.
        var cpuSeries = points.map(function (p) { return p.cpu_percent; });
        var memSeries = points.map(function (p) { return p.memory_percent; });
        var tempSeries = points.map(function (p) { return p.temperature_c; });
        drawSpark('sysCpuSpark', cpuSeries.filter(function (v) { return isFinite(Number(v)) && Number(v) > 0; }), 'is-ok');
        drawSpark('sysMemSpark', memSeries.filter(function (v) { return isFinite(Number(v)) && Number(v) > 0; }), 'is-ok');
        drawSpark('sysTempSpark', tempSeries.filter(function (v) { return isFinite(Number(v)) && Number(v) > 0; }), 'is-ok');
        // DISK has no metric source → leave its sparkline empty (honest).
        drawSpark('sysDiskSpark', [], 'is-unknown');
        drawMultiSpark('sysResSpark', [
            { data: cpuSeries, cls: 'spk-cpu' },
            { data: memSeries, cls: 'spk-mem' },
            { data: tempSeries, cls: 'spk-temp' }
        ]);
        renderSystemServices(detail);
        renderSystemFleet(detail);
        renderSystemAz06(detail);
        renderSystemConfig(detail);
    }

    // AZ-06 Azazel-Deception — advisory-only effectiveness/shadow posture. Edge
    // stays the sole engagement authority; nothing here is a decision input.
    function renderSystemAz06(detail) {
        if (!document.getElementById('sysAz06Panel')) return;
        var az = (detail || {}).deceptionAz06 || {};
        var adv = az.effectiveness_advisory || {};
        var badge = document.getElementById('sysAz06Mode');
        if (badge) {
            badge.textContent = az.mode === 'shadow_only' ? 'SHADOW-ONLY' : upper(az.mode, '—');
            badge.className = 'sentinel-az06-badge ' + (az.shadow_evaluator_ready ? 'is-ok' : 'is-unknown');
        }
        txt('sysAz06Shadow', az.shadow_evaluator_ready ? 'ready · Fabric contracts loaded' : 'dark · Fabric contracts not loaded');
        txt('sysAz06Advisory', adv.available ? 'available' : ('unavailable' + (adv.reason ? (' · ' + adv.reason) : '')));
        txt('sysAz06Enforce', az.enforcement_applied ? 'APPLIED' : 'not applied · advisory-only');
        txt('sysAz06Authority', (az.authority || {}).note || 'advisory-only');
        var box = document.getElementById('sysAz06Gate');
        if (box) {
            box.textContent = '';
            (az.live_gate || []).forEach(function (g) {
                var li = document.createElement('li'); li.className = 'gate-row ' + (g.met ? 'is-met' : 'is-pending');
                var mark = document.createElement('span'); mark.className = 'gate-mark'; mark.textContent = g.met ? '✓' : '○';
                var lab = document.createElement('span'); lab.className = 'gate-label'; lab.textContent = String(g.label || '');
                li.appendChild(mark); li.appendChild(lab); box.appendChild(li);
            });
        }
    }

    // SERVICES — per-service cards with role + status (real data only).
    var SVC_META = {
        suricata: ['IDS / EVE monitor', 'suricata.service'],
        opencanary: ['Deception honeypot', 'opencanary@az_canary'],
        ntfy: ['Notifier', 'ntfy.service'],
        ai_agent: ['M.I.O. AI agent (advisory)', 'azazel-edge-ai-agent'],
        web: ['Azazel core / web', 'azazel-edge-web']
    };
    function svcStateTone(v) {
        v = String(v).toLowerCase();
        return (v === 'on' || v === 'up') ? 'is-ok' : (v === 'off' || v === 'down') ? 'is-critical' : 'is-unknown';
    }
    function renderSystemServices(detail) {
        var summary = detail.summary || {}, health = detail.health || {};
        var svc = summary.service_health_summary || {};
        var grid = document.getElementById('sysServicesGrid');
        if (!grid) return;
        grid.textContent = '';
        Object.keys(svc).forEach(function (k) {
            var meta = SVC_META[k] || [k, k];
            var card = document.createElement('article'); card.className = 'sentinel-svc-card ' + statusFromTone(svcStateTone(svc[k]));
            var name = document.createElement('div'); name.className = 'svc-name'; name.textContent = k.toUpperCase().replace('_', ' ');
            var role = document.createElement('div'); role.className = 'svc-role'; role.textContent = meta[0];
            var unit = document.createElement('div'); unit.className = 'svc-unit'; unit.textContent = meta[1];
            var st = document.createElement('div'); st.className = 'svc-state'; st.textContent = String(svc[k]).toUpperCase();
            card.appendChild(name); card.appendChild(role); card.appendChild(unit); card.appendChild(st);
            grid.appendChild(card);
        });
        // Mattermost bridge as a card.
        var mm = health.mattermost || {};
        var mmCard = document.createElement('article'); mmCard.className = 'sentinel-svc-card ' + (mm.reachable ? 'status-ok' : 'status-neutral');
        var n2 = document.createElement('div'); n2.className = 'svc-name'; n2.textContent = 'MATTERMOST';
        var r2 = document.createElement('div'); r2.className = 'svc-role'; r2.textContent = 'Operator chat bridge';
        var u2 = document.createElement('div'); u2.className = 'svc-unit'; u2.textContent = 'ops-comm / /mio';
        var s2 = document.createElement('div'); s2.className = 'svc-state'; s2.textContent = mm.reachable ? 'REACHABLE' : (mm.ping && mm.ping.error ? 'UNREACHABLE' : '—');
        mmCard.appendChild(n2); mmCard.appendChild(r2); mmCard.appendChild(u2); mmCard.appendChild(s2);
        grid.appendChild(mmCard);
    }

    // FLEET — node fabric: this Edge node (live), peer Edge nodes (aggregator,
    // empty by default), and companion nodes with honest provenance tags.
    function fabricNode(name, code, status, tone, kind, lines) {
        var n = document.createElement('article'); n.className = 'fabric-node ' + kind + ' ' + statusFromTone(tone);
        var head = document.createElement('div'); head.className = 'fabric-node__head';
        var c = document.createElement('span'); c.className = 'fabric-node__code'; c.textContent = code;
        var s = document.createElement('span'); s.className = 'fabric-node__status'; s.textContent = status;
        head.appendChild(c); head.appendChild(s);
        var t = document.createElement('div'); t.className = 'fabric-node__name'; t.textContent = name;
        n.appendChild(head); n.appendChild(t);
        (lines || []).forEach(function (ln) { var p = document.createElement('div'); p.className = 'fabric-node__line'; p.textContent = ln; n.appendChild(p); });
        return n;
    }
    function renderSystemFleet(detail) {
        var summary = detail.summary || {}, agg = detail.aggregator || {};
        var soc = summary.soc_focus || {}, svc = summary.service_health_summary || {}, mode = summary.mode || {};
        var fab = document.getElementById('sysFabric');
        if (!fab) return;
        fab.textContent = '';
        // AZ-01 — this Edge node (live).
        var posture = (summary.normal_assurance || {}).status;
        var pTone = posture ? toneOf(posture === 'alert' ? 'critical' : posture) : 'is-unknown';
        fab.appendChild(fabricNode('Azazel-Edge (this node)', 'AZ-01 SENTINEL', 'LIVE', pTone, 'is-self', [
            'Deterministic SOC/NOC + arbiter',
            'Posture: ' + upper(posture, 'UNKNOWN')
        ]));
        // AZ-04 — Knowledge (CTI). Live link is planned (FY2027+); real today = local
        // TI feed + outbound STIX/TAXII publish.
        var tiN = (soc.ti_matches || []).length;
        fab.appendChild(fabricNode('Azazel-Knowledge (CTI)', 'AZ-04', 'ADVISORY · PLANNED LINK', 'is-unknown', 'is-planned', [
            'Local TI feed: ' + (tiN ? (tiN + ' match(es)') : 'no current match'),
            'Edge publishes decisions → STIX/TAXII',
            'Live node link: planned (FY2027+), advisory-only'
        ]));
        // Deception — in-box subsystem (real state).
        var oc = String(svc.opencanary || '').toUpperCase();
        var decActive = (mode.current_mode === 'scapegoat' || mode.current_mode === 'portal');
        fab.appendChild(fabricNode('Deception (in-box)', 'OpenCanary + gateway', decActive ? 'ENGAGED' : 'STANDBY', decActive ? 'is-watch' : 'is-ok', 'is-capability', [
            'Mode: ' + upper(mode.current_mode, 'shield'),
            'OpenCanary service: ' + (oc || 'UNKNOWN'),
            'REDIRECT action decoys suspect traffic'
        ]));
        // Peer Edge nodes from the aggregator.
        var items = agg.items || [];
        items.slice(0, 4).forEach(function (nd) {
            var tone = nd.freshness === 'fresh' ? 'is-ok' : nd.freshness === 'stale' ? 'is-watch' : 'is-critical';
            fab.appendChild(fabricNode(String(nd.node_label || nd.node_id || 'peer'), 'AZ-01 peer', String(nd.freshness || 'offline').toUpperCase(), tone, 'is-peer', [
                'Site: ' + (nd.site_id || '—'),
                'Posture: ' + ((nd.summary || {}).posture || '—')
            ]));
        });
        var note = document.getElementById('sysFabricNote');
        if (note) {
            note.textContent = items.length
                ? (items.length + ' peer node(s) registered.')
                : 'No peer Edge nodes registered (single-node deployment). Dashed nodes are architecture/advisory, not live links.';
        }
    }

    // CONFIGURATION — decision-engine profile, control mode, drift, thresholds.
    function configGroup(title, rows) {
        var g = document.createElement('article'); g.className = 'sentinel-config-group';
        var k = document.createElement('div'); k.className = 'sentinel-card__kicker'; k.textContent = title; g.appendChild(k);
        var dl = document.createElement('dl'); dl.className = 'sentinel-kv';
        rows.forEach(function (r) {
            var d = document.createElement('div');
            var dt = document.createElement('dt'); dt.textContent = r[0];
            var dd = document.createElement('dd'); dd.textContent = (r[1] == null || r[1] === '') ? '—' : String(r[1]);
            d.appendChild(dt); d.appendChild(dd); dl.appendChild(d);
        });
        g.appendChild(dl); return g;
    }
    function renderSystemConfig(detail) {
        var summary = detail.summary || {}, health = detail.health || {}, booth = detail.boothFocus || {};
        var dpath = summary.decision_path || {}, mode = summary.mode || {}, cd = (summary.noc_focus || {}).config_drift || {}, audit = booth.audit || {};
        var box = document.getElementById('sysConfigPanel');
        if (!box) return;
        box.textContent = '';
        box.appendChild(configGroup('Decision engine profile', [
            ['First pass', dpath.first_pass_engine || '—'],
            ['Second pass', dpath.second_pass_engine || '—'],
            ['AI role', dpath.ai_role || 'supplemental_operator_assist'],
            ['Policy profile', audit.policy_profile || '—'],
            ['Config hash', audit.config_hash || '—']
        ]));
        box.appendChild(configGroup('Control mode', [
            ['Current mode', mode.current_mode || '—'],
            ['Last change', mode.last_change || '—'],
            ['Requested by', mode.requested_by || '—'],
            ['Policy mode', health.policy_mode || '—']
        ]));
        box.appendChild(configGroup('Configuration drift', [
            ['Status', cd.status || '—'],
            ['Baseline', cd.baseline_state || '—'],
            ['Changed fields', (cd.changed_fields || []).join(', ') || 'none'],
            ['Rollback hint', cd.rollback_hint || '—']
        ]));
        box.appendChild(configGroup('Alert queue thresholds', [
            ['Now', '80'], ['Watch', '50'], ['Escalate', '90'],
            ['Last error', health.last_error || 'none']
        ]));
    }

    /* ---- sub-tab switching (evidence + system) ---------------------------- */
    function switchSub(view, btnAttr, panelAttr) {
        document.querySelectorAll('[' + btnAttr + ']').forEach(function (b) {
            var on = b.getAttribute(btnAttr) === view;
            b.classList.toggle('is-active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        document.querySelectorAll('[' + panelAttr + ']').forEach(function (p) {
            p.hidden = p.getAttribute(panelAttr) !== view;
        });
    }
    function wireSubtabs() {
        document.querySelectorAll('[data-ev-view]').forEach(function (btn) {
            btn.addEventListener('click', function () { switchSub(btn.getAttribute('data-ev-view'), 'data-ev-view', 'data-ev-panel'); });
        });
        document.querySelectorAll('[data-sys-view]').forEach(function (btn) {
            btn.addEventListener('click', function () { switchSub(btn.getAttribute('data-sys-view'), 'data-sys-view', 'data-sys-panel'); });
        });
        document.querySelectorAll('[data-ev-range]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                evRange = Number(btn.getAttribute('data-ev-range')) || 0;
                document.querySelectorAll('[data-ev-range]').forEach(function (b) {
                    var on = b === btn;
                    b.classList.toggle('is-active', on);
                    b.setAttribute('aria-pressed', on ? 'true' : 'false');
                });
                evLastSig = null; // force re-render with the new range
                try { renderEvidenceConsole(lastDetail); } catch (e) { /* progressive enhancement */ }
            });
        });
        document.querySelectorAll('[data-tri-band]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                socTriageBand = btn.getAttribute('data-tri-band') || 'all';
                document.querySelectorAll('[data-tri-band]').forEach(function (b) {
                    var on = b === btn;
                    b.classList.toggle('is-active', on);
                    b.setAttribute('aria-pressed', on ? 'true' : 'false');
                });
                try { renderSocTriage((lastDetail || {}).evidence); } catch (e) { /* progressive enhancement */ }
            });
        });
    }

    // Render only the console for the active tier (Pi: avoid rebuilding hidden
    // consoles every 4s). The pipeline + tier dots always update. lastDetail lets
    // a tier switch populate immediately from the most recent poll.
    var lastDetail = {};
    function renderActiveTier() {
        var tier = body ? (body.getAttribute('data-tier-active') || 'overview') : 'overview';
        try {
            if (tier === 'overview') renderOverviewConsole(lastDetail);
            else if (tier === 'operations') renderOperationsConsole(lastDetail);
            else if (tier === 'evidence') renderEvidenceConsole(lastDetail);
            else if (tier === 'system') renderSystemConsole(lastDetail);
        } catch (e) { /* progressive enhancement */ }
    }

    function syncTopbarHeight() {
        if (typeof document === 'undefined') return;
        var tb = document.querySelector('.topbar-attn-stack') || document.querySelector('.topbar');
        if (tb) document.documentElement.style.setProperty('--sentinel-topbar-h', tb.offsetHeight + 'px');
    }

    /* ------------------------------------------------------------------------
       INIT
       --------------------------------------------------------------------- */
    function init() {
        var startTier = 'overview';
        var startOp = 'both';
        try { startTier = localStorage.getItem(TIER_KEY) || 'overview'; } catch (e) { /* ignore */ }
        // Allow deep-linking a tier (e.g. from the M.I.O. page sidebar: /?tier=operations).
        try { var qt = new URLSearchParams(location.search).get('tier'); if (qt && TIERS.indexOf(qt) !== -1) startTier = qt; } catch (e) { /* ignore */ }
        try { startOp = localStorage.getItem(OP_KEY) || 'soc'; } catch (e) { /* ignore */ }
        wireNav();
        wireSubtabs();
        setTier(startTier);
        setOp(startOp);
        // The bespoke consoles are the console's face; the classic contract-locked
        // panels stay in the DOM (hidden) so nothing about the render contract or
        // any deterministic value is lost. Progressive disclosure is the tier depth
        // itself (overview -> operations/evidence/system), not a separate toggle.
        if (body) body.classList.add('sentinel-fidelity');
        syncTopbarHeight();
        window.addEventListener('resize', syncTopbarHeight);
        document.addEventListener('azazel:refresh', function (ev) {
            lastDetail = ev.detail || {};
            syncTopbarHeight(); // attention banners can change topbar height without a resize
            try { renderPipeline(lastDetail); } catch (e) { /* progressive enhancement */ }
            renderActiveTier();
        });
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }

    // Expose the pure classifiers for node-based unit tests (no-op in browsers,
    // where `module` is undefined). Does not change runtime behavior.
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { toneOf: toneOf, worstTone: worstTone, computeConsoleState: computeConsoleState };
    }
})();
