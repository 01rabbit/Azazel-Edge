/* Node unit tests for sentinel.js pure logic (no DOM). Run via
   `node tests/sentinel_console_logic.test.js`; exit 0 = pass. Invoked from
   tests/test_sentinel_console_v1.py (skipped if node is unavailable).

   Focus: the "false-green law" — STALE/UNKNOWN/DOWN must never resolve to green
   (is-ok). These are exactly the paths the adversarial review flagged. */
'use strict';
const path = require('path');
const { toneOf, worstTone, computeConsoleState } = require(
    path.join(__dirname, '..', 'azazel_edge_web', 'static', 'sentinel.js'));

let failures = 0;
function ok(cond, msg) { if (!cond) { failures++; console.error('FAIL: ' + msg); } }
function eq(a, b, msg) { ok(a === b, msg + ' (got ' + JSON.stringify(a) + ', want ' + JSON.stringify(b) + ')'); }

// --- toneOf ---------------------------------------------------------------
eq(toneOf('HEALTHY'), 'is-ok', 'healthy -> ok');
eq(toneOf('up'), 'is-ok', 'up -> ok');
eq(toneOf('on'), 'is-ok', 'on -> ok');
eq(toneOf('quiet'), 'is-ok', 'quiet -> ok');
eq(toneOf('elevated'), 'is-watch', 'elevated -> watch');
eq(toneOf('degraded'), 'is-watch', 'degraded -> watch');
eq(toneOf('critical'), 'is-critical', 'critical -> critical');
eq(toneOf('down'), 'is-critical', 'down -> critical');
eq(toneOf('off'), 'is-critical', 'off -> critical');
eq(toneOf(''), 'is-unknown', 'empty -> unknown');
eq(toneOf(null), 'is-unknown', 'null -> unknown');
eq(toneOf('wibble'), 'is-unknown', 'unrecognised -> unknown');

// --- worstTone: UNKNOWN must beat OK (never masked green) ------------------
eq(worstTone('is-ok', 'is-ok'), 'is-ok', 'ok+ok -> ok');
eq(worstTone('is-ok', 'is-unknown'), 'is-unknown', 'ok+unknown -> unknown (not ok!)');
eq(worstTone('is-unknown', 'is-ok'), 'is-unknown', 'unknown+ok -> unknown');
eq(worstTone('is-watch', 'is-critical'), 'is-critical', 'watch+critical -> critical');
eq(worstTone('is-ok', 'is-watch'), 'is-watch', 'ok+watch -> watch');
eq(worstTone(), 'is-unknown', 'no inputs -> unknown');
eq(worstTone('junk'), 'is-unknown', 'only junk -> unknown');

// --- computeConsoleState: empty payload -> everything UNKNOWN (never green)-
const empty = computeConsoleState({});
['sense', 'evaluate', 'decide', 'control', 'audit'].forEach(function (s) {
    eq(empty.stages[s].tone, 'is-unknown', 'empty ' + s + ' -> unknown');
});
['overview', 'operations', 'evidence', 'system'].forEach(function (d) {
    eq(empty.dots[d], 'is-unknown', 'empty dot ' + d + ' -> unknown');
});

// --- SYSTEM dot: a service 'down' is CRITICAL, not green ------------------
const down = computeConsoleState({ summary: { service_health_summary: { web: 'up', suricata: 'down' } } });
eq(down.dots.system, 'is-critical', 'a down service -> system critical');

// --- SYSTEM dot: presence of the summary object is NOT green --------------
const emptySvc = computeConsoleState({ summary: { service_health_summary: {} } });
eq(emptySvc.dots.system, 'is-unknown', 'empty service summary -> unknown (not green)');

// --- SYSTEM dot: stale signals force at least WATCH -----------------------
const stale = computeConsoleState({
    summary: { service_health_summary: { web: 'up', suricata: 'up' } },
    health: { stale_flags: { snapshot: true } },
});
eq(stale.dots.system, 'is-watch', 'stale snapshot -> system watch even with healthy services');
const staleCmd = computeConsoleState({
    summary: { service_health_summary: { web: 'up' }, command_strip: { stale_warning: true } },
});
eq(staleCmd.dots.system, 'is-watch', 'command_strip.stale_warning -> system watch');

// --- EVALUATE: unknown NOC must not be masked green by quiet SOC ----------
const nocUnknown = computeConsoleState({ summary: { soc_focus: { threat_level: 'quiet', warning_count: 0 } } });
eq(nocUnknown.stages.evaluate.tone, 'is-unknown', 'NOC unknown + SOC quiet -> evaluate unknown');

// --- SENSE: absent evidence renders unknown '—', not green "0 signals" -----
eq(empty.stages.sense.value, '—', 'empty sense value -> em-dash');

// --- Full healthy payload -> green where verified -------------------------
const healthy = computeConsoleState({
    summary: {
        soc_focus: { threat_level: 'quiet', critical_count: 0, warning_count: 0 },
        noc_focus: { path_health: { status: 'HEALTHY' } },
        normal_assurance: { status: 'normal' },
        mode: { current_mode: 'shield' },
        service_health_summary: { web: 'up', suricata: 'up' },
    },
    evidence: { recent_alerts: [], recent_mode_changes: [{}] },
    health: { stale_flags: {} },
});
eq(healthy.stages.evaluate.tone, 'is-ok', 'healthy evaluate -> ok');
eq(healthy.dots.system, 'is-ok', 'healthy system -> ok');
eq(healthy.dots.overview, 'is-ok', 'healthy overview -> ok');

// --- Critical payload -----------------------------------------------------
const crit = computeConsoleState({
    summary: {
        soc_focus: { threat_level: 'critical', critical_count: 3, warning_count: 4 },
        noc_focus: { path_health: { status: 'DOWN' } },
        normal_assurance: { status: 'alert' },
        mode: { current_mode: 'shield' },
    },
});
eq(crit.stages.decide.tone, 'is-critical', 'alert -> decide critical');
eq(crit.stages.evaluate.tone, 'is-critical', 'DOWN path -> evaluate critical');

if (failures) { console.error(failures + ' assertion(s) failed'); process.exit(1); }
console.log('sentinel logic: all assertions passed');
