/* Node unit tests for sentinel.js pure logic (no DOM). Run via
   `node tests/sentinel_console_logic.test.js`; exit 0 = pass. Invoked from
   tests/test_sentinel_console_v1.py (skipped if node is unavailable).

   Focus: the "false-green law" — STALE/UNKNOWN/DOWN must never resolve to green
   (is-ok). These are exactly the paths the adversarial review flagged. */
'use strict';
const path = require('path');
const { toneOf, worstTone, computeConsoleState, alertDecisionTraceId, groupAlertsByDecision, decisionTraceView, diskTileView } = require(
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

if (failures) { console.error(failures + ' assertion(s) failed'); process.exit(1); }
console.log('sentinel logic: all assertions passed');
