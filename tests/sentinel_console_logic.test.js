/* Node unit tests for sentinel.js pure logic (no DOM). Run via
   `node tests/sentinel_console_logic.test.js`; exit 0 = pass. Invoked from
   tests/test_sentinel_console_v1.py (skipped if node is unavailable).

   Focus: the "false-green law" — STALE/UNKNOWN/DOWN must never resolve to green
   (is-ok). These are exactly the paths the adversarial review flagged.

   The second half (Edge#348) mounts the console's real markup from
   templates/index.html in tests/js_mini_dom.js (a dependency-free DOM; CI has
   no npm install) and drives the bespoke renderers: they must not throw on
   empty/partial/odd payloads, must not paint green from absent data, must keep
   ARIA state and keyboard focus right, and must route sentences through the
   catalog while product terms stay English. */
'use strict';
const path = require('path');
const { toneOf, worstTone, computeConsoleState, alertDecisionTraceId, groupAlertsByDecision, decisionTraceView, diskTileView, managedTalkerRows } = require(
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


// --- Decision-level trace (Edge#341): never fabricated per alert ----------
const TID = 'core-0123456789abcdef0123456789abcdef';
const report = {
    ok: true,
    sources: { chain: { ok: true, verified: true, scope: 'from_genesis' } },
    traces: [{
        trace_id: TID,
        explanation: { status: 'found', segment: 'active', selected_action: 'isolate', not_applied: true,
            applied_state: 'not_applied', applied_label: 'NOT APPLIED - planned only (dry_run)', schema_valid: true },
        chain_record: { status: 'found', segment: 'active', integrity: 'verified', action: 'isolate' },
        consistency: { action_matches: true },
    }],
};
function rowText(view) { return view.rows.map(function (r) { return r[0] + '=' + r[1]; }).join(' | '); }

// An alert without a core decision has no trace, even with id-like fields
// and a report that holds traces.
const plain = { ts: 1, sid: 9, trace_id: TID, evidence_id: 'ev-1', recommendation: 'isolate' };
eq(alertDecisionTraceId(plain), '', 'alert trace_id/evidence_id are never used as a decision trace');
const none = decisionTraceView(alertDecisionTraceId(plain), report, 1);
eq(none.state, 'none', 'no decision -> state none');
eq(none.traceId, '—', 'no decision -> em-dash, never a made-up id');
ok(rowText(none).indexOf('VERIFIED') === -1 && rowText(none).indexOf('isolate'.toUpperCase()) === -1,
    'no decision -> no trace content from the report');
eq(alertDecisionTraceId({ decision_trace_id: 42 }), '', 'non-string decision id -> none');

// One decision, several alerts: one group, one trace.
const alerts = [
    { ts: 1, decision_trace_id: TID }, { ts: 2, decision_trace_id: TID },
    { ts: 3 }, { ts: 4, decision_trace_id: '' },
];
const groups = groupAlertsByDecision(alerts);
eq(groups.length, 1, 'two alerts of one decision + two without -> one decision');
eq(groups[0].traceId, TID, 'the group is the decision');
eq(groups[0].alerts.length, 2, 'the decision covers its two alerts');
eq(groupAlertsByDecision([]).length, 0, 'no alerts -> no decision');
eq(groupAlertsByDecision([{ ts: 1 }]).length, 0, 'alerts without decisions -> no decision (nothing invented)');

// Recorded and verified.
const found = decisionTraceView(TID, report, 2);
eq(found.state, 'recorded', 'explanation found -> recorded');
eq(found.traceId, TID, 'the decision id is shown');
ok(rowText(found).indexOf('Action=ISOLATE · NOT APPLIED') !== -1, 'a dry-run action is labelled NOT APPLIED: ' + rowText(found));
ok(rowText(found).indexOf('Chain record=VERIFIED') !== -1, 'verified chain record: ' + rowText(found));
ok(rowText(found).indexOf('Applied=NOT APPLIED - planned only (dry_run)') !== -1, 'applied label shown: ' + rowText(found));
ok(rowText(found).indexOf('2 alerts in view share this decision') !== -1, 'shared count shown once per decision');

// The report did not carry this decision: not loaded, not made up.
const notLoaded = decisionTraceView(TID, { ok: true, traces: [] }, 1);
eq(notLoaded.state, 'unavailable', 'decision missing from the report -> unavailable');
eq(decisionTraceView(TID, null, 1).state, 'unavailable', 'no report -> unavailable');
eq(decisionTraceView(TID, { ok: false, error: 'x', traces: report.traces }, 1).state, 'unavailable', 'failed report -> unavailable');

// No explanation: "No record".
const noRec = decisionTraceView(TID, { ok: true, sources: { chain: { ok: true, scope: 'empty' } }, traces: [{
    trace_id: TID, explanation: { status: 'not_found', rotated_file_present: true }, chain_record: { status: 'not_found' }, consistency: {} }] }, 1);
eq(noRec.state, 'no_record', 'no explanation -> no_record');
ok(rowText(noRec).indexOf('Explanation=No record (older records may be rotated out)') !== -1, 'no explanation says so: ' + rowText(noRec));
ok(rowText(noRec).indexOf('Chain record=No record (chain holds P0 decisions only)') !== -1, 'no chain record says so');
ok(rowText(noRec).indexOf('Chain=EMPTY (nothing verified)') !== -1, 'empty chain is EMPTY, not verified');
ok(rowText(noRec).indexOf('Action=') === -1, 'no explanation -> no action shown');

// Rotated: in the older file.
const rotated = decisionTraceView(TID, { ok: true, sources: { chain: { ok: true, verified: true, scope: 'from_rotation_boundary' } }, traces: [{
    trace_id: TID, explanation: { status: 'found', segment: 'rotated', selected_action: 'isolate', schema_valid: true },
    chain_record: { status: 'found', segment: 'rotated', integrity: 'verified' }, consistency: { action_matches: true } }] }, 1);
ok(rowText(rotated).indexOf('Explanation=recorded (rotated file .1)') !== -1, 'rotated explanation marked: ' + rowText(rotated));
ok(rowText(rotated).indexOf('Chain record=VERIFIED · rotated file .1') !== -1, 'rotated chain record marked');
ok(rowText(rotated).indexOf('Chain=VERIFIED (from_rotation_boundary)') !== -1, 'scope shown');

// Tampered: never green, never "verified".
const tampered = decisionTraceView(TID, { ok: true, sources: { chain: { ok: false, verified: false, error_kind: 'chain_hash_mismatch_at', error_position: 2 } }, traces: [{
    trace_id: TID, explanation: { status: 'found', segment: 'active', selected_action: 'isolate', schema_valid: true },
    chain_record: { status: 'found', segment: 'active', integrity: 'failed_here', action: 'notify' }, consistency: { action_matches: false } }] }, 1);
ok(rowText(tampered).indexOf('Chain record=TAMPERED') !== -1, 'tampered record marked: ' + rowText(tampered));
ok(rowText(tampered).indexOf('Chain=NOT OK: chain_hash_mismatch_at (record 2)') !== -1, 'chain failure shown: ' + rowText(tampered));
ok(rowText(tampered).indexOf('Consistency=ACTION MISMATCH') !== -1, 'explanation/chain mismatch shown');
ok(rowText(tampered).indexOf('VERIFIED (') === -1, 'a tampered chain never reads as verified');
const elsewhere = decisionTraceView(TID, { ok: true, sources: { chain: { ok: false, verified: false, error_kind: 'chain_hash_mismatch_at', error_position: 9 } }, traces: [{
    trace_id: TID, explanation: { status: 'found', selected_action: 'isolate', schema_valid: true },
    chain_record: { status: 'found', integrity: 'not_verified' }, consistency: {} }] }, 1);
ok(rowText(elsewhere).indexOf('Chain record=NOT VERIFIED') !== -1, 'a record of a failed chain is not verified');
const unknownIntegrity = decisionTraceView(TID, { ok: true, sources: { chain: {} }, traces: [{
    trace_id: TID, explanation: { status: 'found' }, chain_record: { status: 'found', integrity: 'wibble' }, consistency: {} }] }, 1);
ok(rowText(unknownIntegrity).indexOf('Chain record=NOT VERIFIED') !== -1, 'unknown integrity -> NOT VERIFIED, never verified');
ok(rowText(unknownIntegrity).indexOf('Chain=NOT OK') !== -1, 'absent chain verdict -> NOT OK');
const unreadable = decisionTraceView(TID, { ok: true, sources: { chain: { state: 'unreadable' } }, traces: [{
    trace_id: TID, explanation: { status: 'source_unreadable' }, chain_record: { status: 'source_unreadable' }, consistency: {} }] }, 1);
ok(rowText(unreadable).indexOf('Explanation=source unreadable') !== -1 && rowText(unreadable).indexOf('Chain=UNREADABLE') !== -1,
    'unreadable sources say so: ' + rowText(unreadable));


// Re-verifying: an answer from before the chain changed is never verified.
const pendingView = decisionTraceView(TID, { ok: true, sources: { chain: { ok: true, verified: false, recheck_pending: true, scope: 'from_genesis' } }, traces: [{
    trace_id: TID, explanation: { status: 'found', selected_action: 'isolate', schema_valid: true },
    chain_record: { status: 'found', integrity: 'pending' }, consistency: {} }] }, 1);
ok(rowText(pendingView).indexOf('Chain record=RE-VERIFYING') !== -1, 'pending record shown as re-verifying: ' + rowText(pendingView));
ok(rowText(pendingView).indexOf('Chain=RE-VERIFYING') !== -1, 'pending chain shown as re-verifying');
ok(rowText(pendingView).indexOf('VERIFIED (') === -1 && rowText(pendingView).indexOf('=VERIFIED') === -1, 'pending never reads as verified');

// --- DISK tile (Edge#343): null/absent is '—' (unknown), a value is a % ----
[null, undefined, 0, 'n/a', NaN].forEach(function (v) {
    eq(diskTileView(v).text, '—', 'disk ' + String(v) + ' -> dash');
    eq(diskTileView(v).tone, 'is-unknown', 'disk ' + String(v) + ' -> unknown (never green)');
});
eq(diskTileView(42.4).text, '42%', 'disk value -> rounded percent');
eq(diskTileView(42.4).tone, 'is-ok', 'disk 42% -> ok');
eq(diskTileView(85.6).text, '86%', 'disk 85.6 -> 86%');
eq(diskTileView(85.6).tone, 'is-watch', 'disk >= 80 -> watch');
eq(diskTileView(97).tone, 'is-critical', 'disk >= 95 -> critical');

// --- managedTalkerRows (Edge#344): managed-client talkers, flow window --------
eq(managedTalkerRows({}).length, 0, 'no managed_client_talkers -> no rows');
eq(managedTalkerRows({ managed_client_talkers: { items: 'junk' } }).length, 0, 'non-array items -> no rows');
const mrows = managedTalkerRows({ managed_client_talkers: { count: 6, items: [
    { id: 'c1', label: 'c1', bytes: 4000 }, { id: 'c2', label: 'c2', bytes: 1000 }, { id: 'c3', bytes: 0 },
    { id: 'c4', label: 'c4', bytes: 10 }, { id: 'c5', label: 'c5', bytes: 5 }, { id: 'c6', label: 'c6', bytes: 1 }] } });
eq(mrows.length, 5, 'at most five managed talkers in the bandwidth card');
eq(mrows[0].share, 100, 'largest managed talker -> 100%');
eq(mrows[1].share, 25, 'share is relative to the largest');
eq(mrows[2].label, 'c3', 'label falls back to id');
eq(managedTalkerRows({ managed_client_talkers: { items: [{ label: 'z', bytes: 0 }] } })[0].share, 0, 'all-zero bytes -> 0%, no NaN');

// --- rovingIndex: Arrow keys wrap, Home/End jump ---------------------------
const { rovingIndex, tr } = require(path.join(__dirname, '..', 'azazel_edge_web', 'static', 'sentinel.js'));
eq(rovingIndex('ArrowRight', 0, 4), 1, 'right -> next');
eq(rovingIndex('ArrowDown', 3, 4), 0, 'down wraps');
eq(rovingIndex('ArrowLeft', 0, 4), 3, 'left wraps');
eq(rovingIndex('ArrowUp', 2, 4), 1, 'up -> previous');
eq(rovingIndex('Home', 2, 4), 0, 'home -> first');
eq(rovingIndex('End', 0, 4), 3, 'end -> last');
eq(rovingIndex('Enter', 0, 4), -1, 'other keys do not move');
eq(rovingIndex('ArrowRight', -1, 4), -1, 'no current tab -> no move');
eq(rovingIndex('ArrowRight', 0, 0), -1, 'empty row -> no move');
// tr without a catalog (node, es/uk/tl) falls back to the English text.
eq(tr('sentinel.x', 'Hello {who}', { who: 'op' }), 'Hello op', 'tr fallback + vars');
eq(tr('sentinel.x', '{a} {b}', { a: 1 }), '1 {b}', 'unknown var left as is');

// ===========================================================================
// DOM harness over the bespoke renderers (Edge#348)
// ===========================================================================
const fs = require('fs');
const dom = require(path.join(__dirname, 'js_mini_dom.js'));
const SENTINEL = require.resolve(path.join(__dirname, '..', 'azazel_edge_web', 'static', 'sentinel.js'));
const TEMPLATE = fs.readFileSync(path.join(__dirname, '..', 'azazel_edge_web', 'templates', 'index.html'), 'utf8');

function consoleMarkup(catalog) {
    const start = TEMPLATE.indexOf('<nav class="sentinel-tier-nav"');
    const end = TEMPLATE.indexOf('<section class="onboarding-banner"');
    ok(start !== -1 && end > start, 'console markup found in index.html');
    return TEMPLATE.slice(start, end).replace(/\{\{\s*tr\('([\w.-]+)',\s*'((?:[^'\\]|\\.)*)'\)\s*\}\}/g, function (_m, k, fb) {
        return (catalog && catalog[k]) || fb;
    });
}
function mount(opts) {
    opts = opts || {};
    const doc = new dom.Document();
    doc.body.setAttribute('data-audience', 'professional');
    const markup = consoleMarkup(opts.catalog);
    ok(markup.indexOf('{{') === -1 && markup.indexOf('{%') === -1, 'no unrendered template syntax in the console markup');
    dom.parseInto(doc, doc.body, markup);
    dom.install(doc, opts);
    delete require.cache[SENTINEL];
    const S = require(SENTINEL);   // init() runs against this document
    return { doc: doc, S: S, $: function (id) { return doc.getElementById(id); } };
}
function renderAll(S, detail) {
    S.renderPipeline(detail);
    S.renderOverviewConsole(detail);
    S.renderOperationsConsole(detail);
    S.renderEvidenceConsole(detail);
    S.renderSystemConsole(detail);
}
function noThrow(fn, msg) { try { fn(); ok(true, msg); } catch (e) { ok(false, msg + ' threw ' + (e && e.stack)); } }
const GREEN = ['is-ok', 'status-ok', 'status-safe', 'tone-ok'];
function greenNodes(doc) {
    return doc.body.querySelectorAll('[class]').filter(function (el) {
        return GREEN.some(function (c) { return el.classList.contains(c); });
    });
}
function describe(el) { return el.tagName.toLowerCase() + '#' + el.id + '.' + el.className + ' "' + el.textContent.slice(0, 40) + '"'; }

// --- 1. Empty payload: nothing throws, nothing is green, unknowns say so ----
(function () {
    const m = mount();
    noThrow(function () { renderAll(m.S, {}); }, 'renderers on {}');
    noThrow(function () { renderAll(m.S, undefined); }, 'renderers on undefined');
    const green = greenNodes(m.doc);
    eq(green.length, 0, 'empty payload paints nothing green: ' + green.map(describe).join(' | '));
    ['Overview', 'Operations', 'Evidence', 'System'].forEach(function (t) {
        ok(m.$('sentinelDot' + t).classList.contains('is-unknown'), t + ' dot unknown');
        eq(m.$('sentinelStatus' + t).textContent, ' (UNKNOWN)', t + ' dot has SR text, not color only');
    });
    ['Sense', 'Evaluate', 'Decide', 'Control', 'Audit'].forEach(function (st) {
        ok(/\(UNKNOWN\)$/.test(m.$('pipeline' + st).getAttribute('aria-label') || ''), st + ' stage names its state: ' + m.$('pipeline' + st).getAttribute('aria-label'));
    });
    ['Cpu', 'Mem', 'Disk', 'Temp'].forEach(function (t) {
        ok(m.$('sys' + t + 'Tile').classList.contains('status-neutral'), t + ' tile neutral when unsampled');
        ok(/\(UNKNOWN\)$/.test(m.$('sys' + t + 'Tile').getAttribute('aria-label') || ''), t + ' tile aria-label names UNKNOWN');
    });
    eq(m.$('sysDisk').textContent, '—', 'DISK unread -> dash');
    eq(m.$('sysDiskTile').getAttribute('aria-label'), 'Disk — (UNKNOWN)', 'DISK aria-label in English without a catalog');
    eq(m.$('consolePostureWord').textContent, 'UNKNOWN', 'posture unknown, not NORMAL');
    ok(m.$('nocTopTalkers').textContent.indexOf('Managed-client talkers (flow window)') !== -1, 'managed talkers heading (EN)');
    ok(m.$('nocTopTalkers').textContent.indexOf('No managed client in the current top talkers.') !== -1, 'managed talkers empty text (EN)');
    eq(m.$('evCount').textContent, '0 of 0 shown', 'evidence count (EN)');
    eq(m.$('sentinelLiveRegion').textContent, '', 'first observation is not announced');
    dom.uninstall();
})();

// --- 2. Odd/partial payloads: no throw, absent pieces stay unknown ----------
(function () {
    const m = mount();
    const odd = [
        { summary: null, evidence: null, health: null, trends: null, boothFocus: null },
        { summary: { soc_focus: {}, noc_focus: { path_health: null, capacity: null }, service_health_summary: null } },
        { evidence: { recent_alerts: [], alert_queues: { now: null } }, trends: { points: [] } },
        { evidence: { recent_alerts: [{ ts: 'x' }, {}, { sid: 1, attack_type: '<img src=x onerror=alert(1)>' }] } },
        { summary: { noc_focus: { managed_client_talkers: { items: 'junk' }, remote_peers: { items: [{}] } } } },
        { trends: { points: [{ disk_percent: null }, { disk_percent: 'n/a' }] } },
        { aggregator: { items: [{}] }, deceptionAz06: { live_gate: [{}] } }
    ];
    odd.forEach(function (d, i) {
        noThrow(function () { renderAll(m.S, d); }, 'renderers on odd payload #' + i);
        if (i === 3) {
            // A hostile label stays text: no element is created from data.
            eq(m.doc.body.querySelectorAll('img').length, 0, 'data never becomes markup');
            ok(m.$('evList').textContent.indexOf('<img src=x onerror=alert(1)>') !== -1, 'hostile label rendered as literal text');
        }
    });
    renderAll(m.S, {});
    eq(greenNodes(m.doc).length, 0, 'still nothing green after odd payloads: ' + greenNodes(m.doc).map(describe).join(' | '));
    dom.uninstall();
})();

// --- 3. Stale / down / unknown never green; healthy is green where verified --
(function () {
    const m = mount();
    const healthy = {
        summary: {
            soc_focus: { threat_level: 'quiet', critical_count: 0, warning_count: 0 },
            noc_focus: { path_health: { status: 'HEALTHY', uplink: 'up', gateway: 'up', internet_check: 'up' }, client_inventory: { current_client_count: 3 } },
            normal_assurance: { status: 'normal' },
            mode: { current_mode: 'shield' },
            service_health_summary: { web: 'up', suricata: 'up' }
        },
        evidence: { recent_alerts: [], recent_mode_changes: [{ ts: 1, current_mode: 'shield' }] },
        health: { stale_flags: {}, queue: { depth: 1, capacity: 10 }, llm: { fallback_rate: 0, latency_ms_ema: 100 } },
        trends: { points: [{ cpu_percent: 10, memory_percent: 20, temperature_c: 40, disk_percent: 42.4 }] }
    };
    renderAll(m.S, {});
    eq(m.$('sentinelLiveRegion').textContent, '', 'first observation (unknown) is silent');
    renderAll(m.S, healthy);
    ok(m.$('sentinelDotSystem').classList.contains('is-ok'), 'healthy services -> system dot ok');
    ok(m.$('sysDiskTile').classList.contains('status-ok'), 'DISK 42% -> ok tile');
    eq(m.$('sysDisk').textContent, '42%', 'DISK value shown');
    eq(m.$('sentinelLiveRegion').textContent, 'Status changed: OVERVIEW: OK, OPERATIONS: OK, EVIDENCE: OK, SYSTEM: OK',
        'unknown -> ok change announced once');

    const stale = JSON.parse(JSON.stringify(healthy));
    stale.health.stale_flags = { snapshot: true };
    stale.summary.service_health_summary.suricata = 'down';
    stale.trends.points[0].disk_percent = null;
    renderAll(m.S, stale);
    ok(m.$('sentinelDotSystem').classList.contains('is-critical'), 'down service + stale -> system critical');
    eq(m.$('sentinelStatusSystem').textContent, ' (CRITICAL)', 'system SR text critical');
    ok(m.$('sysDiskTile').classList.contains('status-neutral'), 'DISK unread after a reading -> neutral, not the old green');
    eq(m.$('sentinelLiveRegion').textContent, 'Status changed: SYSTEM: CRITICAL', 'only the changed tier is announced');
    m.$('sentinelLiveRegion').textContent = '';
    renderAll(m.S, stale);
    eq(m.$('sentinelLiveRegion').textContent, '', 'an unchanged poll announces nothing');

    // Absent health readings: meters are '—' and not green.
    const noHealth = JSON.parse(JSON.stringify(healthy));
    noHealth.health = {};
    m.S.renderOperationsConsole(noHealth);
    const meters = m.$('nocRuntimeMeters');
    ok(meters.textContent.indexOf('Queue—') !== -1, 'absent queue -> dash: ' + meters.textContent);
    eq(meters.querySelectorAll('.is-ok').length, 0, 'absent runtime health -> no green meter');
    dom.uninstall();
})();

// --- 4. Tabs: ARIA state + keyboard (roving tabindex, Home/End) -------------
(function () {
    const m = mount();
    const evTabs = m.doc.body.querySelectorAll('[data-ev-view]');
    eq(evTabs.length, 5, 'five evidence tabs');
    dom.keydown(evTabs[0], 'ArrowRight');
    eq(evTabs[1].getAttribute('aria-selected'), 'true', 'ArrowRight selects the next evidence tab');
    eq(evTabs[0].getAttribute('aria-selected'), 'false', 'previous tab deselected');
    eq(evTabs[1].tabIndex, 0, 'selected tab is in the tab order');
    eq(evTabs[0].tabIndex, -1, 'other tabs leave the tab order');
    ok(m.doc.activeElement === evTabs[1], 'focus follows the selection');
    ok(m.$('evList').hidden === false && m.$('evPanelTimeline').hidden === true, 'the controlled panel is shown, the other hidden');
    dom.keydown(evTabs[1], 'End');
    eq(evTabs[4].getAttribute('aria-selected'), 'true', 'End -> last tab');
    ok(m.$('evPanelRaw').hidden === false, 'raw panel shown');
    dom.keydown(evTabs[4], 'ArrowRight');
    eq(evTabs[0].getAttribute('aria-selected'), 'true', 'ArrowRight wraps to the first tab');
    dom.keydown(evTabs[0], 'Home');
    eq(evTabs[0].getAttribute('aria-selected'), 'true', 'Home stays on the first tab');
    ok(!dom.keydown(evTabs[0], 'a').defaultPrevented, 'other keys are not swallowed');
    evTabs.forEach(function (t) {
        ok(!t.hasAttribute('aria-pressed'), 'tabs carry aria-selected, not aria-pressed');
        const panel = m.$(t.getAttribute('aria-controls'));
        ok(panel && panel.getAttribute('role') === 'tabpanel' && panel.getAttribute('aria-labelledby') === t.id, 'tab ' + t.id + ' controls a tabpanel labelled by it');
    });

    const sysTabs = m.doc.body.querySelectorAll('[data-sys-view]');
    dom.click(sysTabs[2]);
    eq(sysTabs[2].getAttribute('aria-selected'), 'true', 'click selects a system tab');
    ok(m.$('sysFleetPanel').hidden === false && m.$('sysRuntimePanel').hidden === true, 'fleet panel shown on click');
    dom.keydown(sysTabs[2], 'ArrowLeft');
    eq(sysTabs[1].getAttribute('aria-selected'), 'true', 'ArrowLeft on system tabs');

    const ops = m.doc.body.querySelectorAll('[data-sentinel-op]');
    m.S.setOp('soc');
    dom.keydown(ops[0], 'ArrowRight');
    eq(m.doc.body.getAttribute('data-op-active'), 'noc', 'ArrowRight on SOC selects NOC');
    eq(ops[1].getAttribute('aria-selected'), 'true', 'NOC tab selected');
    eq(ops[0].tabIndex, -1, 'SOC leaves the tab order');

    const tiers = m.doc.body.querySelectorAll('[data-sentinel-tier]');
    m.S.setTier('overview');
    dom.keydown(tiers[0], 'ArrowDown');
    eq(m.doc.body.getAttribute('data-tier-active'), 'operations', 'ArrowDown in the vertical tier nav -> next tier');
    eq(tiers[1].getAttribute('aria-current'), 'page', 'the active tier is aria-current');
    ok(m.doc.activeElement === tiers[1], 'focus moves with the tier');
    dom.keydown(tiers[1], 'End');
    eq(m.doc.body.getAttribute('data-tier-active'), 'system', 'End -> last tier');
    const ask = m.$('sentinelAskMioLink');
    dom.keydown(ask, 'ArrowUp');
    eq(m.doc.body.getAttribute('data-tier-active'), 'system', 'arrows on the Ask M.I.O. link do not switch tiers');
    dom.uninstall();
})();

// --- 5. i18n: sentences from the catalog, product terms stay English --------
(function () {
    const JA = {
        'sentinel.managed_talkers_heading': '管理端末の通信量（フロー集計の期間）',
        'sentinel.managed_talkers_empty': '現在の上位の通信元に管理端末はありません。',
        'sentinel.tile_disk': 'ディスク',
        'sentinel.ev_count': '{total} 件中 {shown} 件を表示',
        'sentinel.live_changed': '状態が変わりました: {changes}',
        'sentinel.tier_empty_title': '専門家詳細の表示が必要です。'
    };
    const m = mount({ catalog: JA });
    renderAll(m.S, {});
    const talkers = m.$('nocTopTalkers').textContent;
    ok(talkers.indexOf(JA['sentinel.managed_talkers_heading']) !== -1, 'managed talkers heading in JA');
    ok(talkers.indexOf(JA['sentinel.managed_talkers_empty']) !== -1, 'managed talkers empty text in JA');
    eq(m.$('sysDiskTile').getAttribute('aria-label'), 'ディスク — (UNKNOWN)', 'DISK aria-label in JA, state word English');
    eq(m.$('evCount').textContent, '0 件中 0 件を表示', 'evidence count in JA');
    ok(m.$('sentinelTierEmpty').textContent.indexOf(JA['sentinel.tier_empty_title']) !== -1, 'template sentence in JA');
    ok(m.doc.body.textContent.indexOf('No recent evidence.') !== -1, 'a key missing from the catalog falls back to English');
    // Product terms are not routed.
    ['OVERVIEW', 'TIMELINE', 'RUNTIME', 'DISK'].forEach(function (term) {
        ok(m.doc.body.textContent.indexOf(term) !== -1, term + ' stays English');
    });
    m.S.renderPipeline({ summary: { normal_assurance: { status: 'alert' } } });
    eq(m.$('sentinelLiveRegion').textContent, '状態が変わりました: OVERVIEW: CRITICAL', 'live region sentence in JA, state word English');
    dom.uninstall();
})();

// --- 6. Display strings with and without data (review of #515) -------------
(function () {
    const m = mount();
    function deceptionNode() {
        const n = m.doc.body.querySelectorAll('.fabric-node').filter(function (x) { return x.textContent.indexOf('Deception (in-box)') !== -1; })[0];
        ok(!!n, 'deception node rendered');
        return n || m.doc.createElement('div');
    }
    function deception(mode) {
        m.S.renderSystemConsole({ summary: mode === undefined ? {} : { mode: { current_mode: mode } } });
        const n = deceptionNode();
        return {
            status: n.querySelector('.fabric-node__status').textContent,
            mode: n.querySelectorAll('.fabric-node__line').map(function (l) { return l.textContent; }).filter(function (t) { return t.indexOf('Mode: ') === 0; })[0],
            green: n.classList.contains('status-ok')
        };
    }
    let d = deception('shield');
    eq(d.status, 'STANDBY', 'deception shield -> STANDBY'); eq(d.mode, 'Mode: SHIELD', 'deception Mode: SHIELD'); ok(d.green, 'shield standby is ok');
    d = deception('scapegoat');
    eq(d.status, 'ENGAGED', 'deception scapegoat -> ENGAGED'); eq(d.mode, 'Mode: SCAPEGOAT', 'deception Mode: SCAPEGOAT'); ok(!d.green, 'engaged is not green');
    d = deception(undefined);
    eq(d.status, 'UNKNOWN', 'deception without mode -> UNKNOWN'); eq(d.mode, 'Mode: UNKNOWN', 'deception Mode: UNKNOWN'); ok(!d.green, 'unknown deception not green');

    function kv(id) {
        const out = {};
        m.$(id).querySelectorAll('dt').forEach(function (dt) { out[dt.textContent] = dt.parentNode.querySelector('dd').textContent; });
        return out;
    }
    function activeControl(detail) { m.S.renderOperationsConsole(detail); return kv('nocTrafficControl')['Active control']; }
    eq(activeControl({ boothFocus: { decision: { action: 'throttle' } } }), 'THROTTLE', 'active control throttle -> THROTTLE');
    eq(activeControl({ boothFocus: { decision: { action: 'observe' } } }), 'OBSERVE', 'active control observe -> OBSERVE');
    eq(activeControl({ summary: { mode: { current_mode: 'observe' } } }), 'OBSERVE', 'active control from the mode -> OBSERVE');
    eq(activeControl({}), 'UNKNOWN', 'active control without decision or mode -> UNKNOWN');

    function hops(detail) {
        m.S.renderOperationsConsole(detail);
        return m.$('nocPathStrip').querySelectorAll('.sp-hop').map(function (h) {
            return { title: h.querySelector('.sp-hop__title').textContent, state: h.querySelector('.sp-hop__state').textContent, tone: ['is-ok', 'is-watch', 'is-critical', 'is-unknown'].filter(function (c) { return h.classList.contains(c); })[0] };
        });
    }
    let h = hops({});
    eq(h[0].title, 'Clients', 'clients hop without count'); eq(h[0].state, '—', 'clients hop state dash'); eq(h[0].tone, 'is-unknown', 'clients hop unknown');
    eq(h[1].title, 'Azazel-Edge', 'edge hop title'); eq(h[1].state, 'UNKNOWN', 'edge hop without mode -> UNKNOWN'); eq(h[1].tone, 'is-unknown', 'edge hop unknown');
    h = hops({ summary: { mode: { current_mode: 'shield' }, noc_focus: { client_inventory: { current_client_count: 3 } } } });
    eq(h[0].title, 'Clients ×3', 'clients hop with count'); eq(h[0].state, 'MANAGED', 'clients hop MANAGED'); eq(h[0].tone, 'is-ok', 'clients hop ok');
    eq(h[1].state, 'SHIELD', 'edge hop shows the mode'); eq(h[1].tone, 'is-ok', 'edge hop ok');

    function meter(label, health) {
        m.S.renderOperationsConsole({ health: health });
        const mt = m.$('nocRuntimeMeters').querySelectorAll('.sentinel-meter').filter(function (x) { return x.textContent.indexOf(label) === 0; })[0];
        ok(!!mt, label + ' meter rendered');
        return { value: mt.querySelector('b').textContent, tone: ['is-ok', 'is-watch', 'is-critical', 'is-unknown'].filter(function (c) { return mt.querySelector('.sentinel-meter__fill').classList.contains(c); })[0] };
    }
    let f = meter('Fallback rate', {});
    eq(f.value, '—', 'fallback rate absent -> dash'); eq(f.tone, 'is-unknown', 'fallback rate absent -> unknown');
    f = meter('Fallback rate', { llm: { fallback_rate: 0.3 } });
    eq(f.value, '30%', 'fallback rate 0.3 -> 30%'); eq(f.tone, 'is-watch', 'fallback rate 30% -> watch');
    f = meter('Fallback rate', { llm: { fallback_rate: 0 } });
    eq(f.value, '0%', 'fallback rate 0 -> 0%'); eq(f.tone, 'is-ok', 'fallback rate 0 -> ok');
    f = meter('Fallback rate', { llm: { fallback_rate: '0.6' } });
    eq(f.value, '60%', 'numeric string accepted'); eq(f.tone, 'is-critical', 'fallback rate 60% -> critical');
    ['', true, 'n/a', null].forEach(function (v) {
        const r = meter('Fallback rate', { llm: { fallback_rate: v } });
        eq(r.value, '—', 'fallback rate ' + JSON.stringify(v) + ' -> dash'); eq(r.tone, 'is-unknown', 'fallback rate ' + JSON.stringify(v) + ' -> unknown');
    });
    const lat = meter('Latency', { llm: { latency_ms_ema: true } });
    eq(lat.value, '—', 'latency true -> dash');
    dom.uninstall();
})();

if (failures) { console.error(failures + ' assertion(s) failed'); process.exit(1); }
console.log('sentinel logic: all assertions passed');
