/* Node unit tests for the pure logic in azazel_edge_web/static/touch.js (no
   DOM). Run via `node tests/touch_console_logic.test.js`; exit 0 = pass.
   Invoked from tests/test_touch_console_v1.py (skipped if node is missing).

   Focus: an operation is "ok" only when the API said ok: true; failure kinds
   from the control daemon (not_implemented, undelivered, delivery_unknown,
   status_api_error) never read as success; stale/unknown data never reads as
   green; the SSE parser handles stream_error/retry; the secret buffer wipes. */
'use strict';
const path = require('path');
const T = require(path.join(__dirname, '..', 'azazel_edge_web', 'static', 'touch.js'));

let failures = 0;
function ok(cond, msg) { if (!cond) { failures++; console.error('FAIL: ' + msg); } }
function eq(a, b, msg) { ok(a === b, msg + ' (got ' + JSON.stringify(a) + ', want ' + JSON.stringify(b) + ')'); }

// --- classifyResult -------------------------------------------------------
const C = (s, p, e) => T.classifyResult(s, p, e).kind;
eq(C(200, { ok: true }), 'ok', '200 ok:true -> ok');
eq(C(200, { status: 'ok', message: 'x' }), 'ok', 'legacy status ok -> ok');
eq(C(200, {}), 'failed', '200 without ok -> not success');
eq(C(200, null), 'failed', '200 unparsable body -> not success');
eq(C(200, { ok: false, error: 'x' }), 'failed', '200 ok:false -> failed');
eq(C(500, { ok: false, error: 'not_implemented', not_implemented: true }), 'not_implemented', 'not_implemented flag');
eq(C(500, { ok: false, error: 'not_implemented' }), 'not_implemented', 'not_implemented error string');
eq(C(200, { ok: true, not_implemented: true }), 'not_implemented', 'not_implemented beats ok');
eq(C(500, { ok: false, undelivered: true }), 'undelivered', 'undelivered');
eq(C(500, { ok: false, delivery_unknown: true, error: 'no reply' }), 'delivery_unknown', 'delivery_unknown');
eq(C(200, { ok: true, delivery_unknown: true }), 'delivery_unknown', 'delivery_unknown beats ok');
eq(C(500, { ok: false, status_api_error: true, error: 'HTTP 403' }), 'failed', 'status_api_error -> failed');
eq(C(200, { ok: true, status_api_error: true }), 'failed', 'status_api_error beats ok');
eq(C(500, { ok: false, error: 'Daemon timeout' }), 'delivery_unknown', 'daemon timeout -> may have run');
eq(C(500, { ok: false, error: 'Control daemon not running' }), 'undelivered', 'daemon not running -> undelivered');
eq(C(0, null, 'timeout'), 'delivery_unknown', 'transport timeout -> delivery_unknown');
eq(C(0, null, 'network'), 'delivery_unknown', 'network error -> delivery_unknown');
eq(C(401, { ok: false, error: 'Unauthorized' }), 'unauthorized', '401 -> unauthorized');
eq(C(403, { error: 'Unauthorized' }), 'unauthorized', '403 -> unauthorized');
eq(C(409, { ok: false, error: 'approval_required' }), 'rejected', '409 -> rejected');
eq(C(400, { ok: false, error: 'Missing SSID' }), 'failed', '400 -> failed');
eq(T.classifyResult(500, { ok: false, error: 'boom' }).message, 'boom', 'message carried');

// --- tones: unknown/stale never green ------------------------------------
eq(T.toneOf('QUIET'), 'ok', 'quiet ok');
eq(T.toneOf('critical'), 'crit', 'critical crit');
eq(T.toneOf(''), 'unknown', 'empty unknown');
eq(T.toneOf('wibble'), 'unknown', 'unrecognised unknown');
eq(T.worstTone('ok', 'unknown'), 'unknown', 'unknown beats ok');
eq(T.worstTone(), 'unknown', 'no input unknown');
eq(T.staleTone('ok', true), 'stale', 'stale ok -> stale');
eq(T.staleTone('crit', true), 'crit', 'stale crit stays crit');
eq(T.staleTone('ok', false), 'ok', 'fresh ok stays ok');
eq(T.defensiveTone('OBSERVE'), 'ok', 'observe');
eq(T.defensiveTone('isolate'), 'crit', 'isolate');
eq(T.defensiveTone('shield'), 'unknown', 'legacy mode is not a Defensive State');
eq(T.defensiveTone(''), 'unknown', 'absence is not a state');

// --- deriveView ------------------------------------------------------------
const now = 1700000100;
function bundle(over) {
    const b = {
        ok: true,
        summary: {
            soc_focus: { threat_level: 'quiet', critical_count: 0 },
            noc_focus: { path_health: { status: 'healthy' } },
            command_strip: { direct_critical_count: 0 },
            service_health_summary: { ai_agent: 'ON' },
            topolite: { data_source: 'live' }
        },
        health: { stale_flags: { snapshot: false, ai_metrics: false } },
        decision_focus: { available: true, decision: { action: 'OBSERVE', reason: 'r' }, mode: { kind: 'live_test_input' }, safety: { dry_run: true } },
        evidence: { alert_queues: { now: { count: 0, items: [] }, watch: { count: 0, items: [] }, backlog: { count: 0 } } },
        actions: { mio: { surface_message: 'advice' }, suggested_runbook: {} },
        state: { snapshot_epoch: now - 5, mode_runtime: { ok: true, mode: { current_mode: 'shield' } }, connection: { internet_check: 'OK' }, up_if: 'eth0', source: 'CONTROL_PLANE' }
    };
    return Object.assign(b, over || {});
}
let v = T.deriveView({ bundle: bundle(), nowSec: now, skewSec: 0 });
eq(v.stale, false, 'fresh not stale');
eq(v.defensive.value, 'OBSERVE', 'defensive from decision record');
eq(v.defensive.tone, 'ok', 'observe ok when fresh');
eq(v.soc.tone, 'ok', 'soc ok');
eq(v.p0.value, 0, 'p0 zero');
eq(v.ai.state, 'on', 'ai on');
eq(v.mode.value, 'SHIELD', 'legacy mode shown');
eq(v.daemonDown, false, 'daemon up');
eq(v.mioText, 'advice', 'mio text');

v = T.deriveView({ bundle: bundle(), nowSec: now + 120, skewSec: 0 });
eq(v.stale, true, 'old snapshot stale');
eq(v.staleReason, 'stale', 'old snapshot reason');
eq(v.soc.tone, 'stale', 'stale soc not green');
eq(v.defensive.tone, 'stale', 'stale defensive not green');
eq(v.p0.tone, 'stale', 'stale p0 not green');

v = T.deriveView({ bundle: bundle(), nowSec: now, skewSec: 0, linkLost: true });
eq(v.soc.tone, 'stale', 'lost link -> not green');

const noEpoch = bundle();
delete noEpoch.state.snapshot_epoch;
v = T.deriveView({ bundle: noEpoch, nowSec: now });
eq(v.snapshotAgeSec, null, 'no epoch -> unknown age');
eq(v.soc.tone, 'stale', 'unknown age -> not green');

const down = bundle();
down.state.mode_runtime = { ok: false, mode: { current_mode: 'shield' }, error: 'Control daemon not running' };
v = T.deriveView({ bundle: down, nowSec: now });
eq(v.daemonDown, true, 'daemon down detected');
eq(v.mode.value, '—', 'fallback shield is not shown as the mode');
eq(v.mode.known, false, 'mode unknown');
eq(v.soc.tone, 'stale', 'daemon down -> fresh-looking data is not green');
eq(v.staleReason, 'unverified', 'daemon down -> unverified, not stale');

const fileSrc = bundle();
fileSrc.state.source = 'FILE:/x';
eq(T.deriveView({ bundle: fileSrc, nowSec: now }).daemonDown, true, 'file fallback snapshot -> daemon down');

const noDecision = bundle({ decision_focus: { ok: true, available: false, status: 'decision_unavailable' } });
v = T.deriveView({ bundle: noDecision, nowSec: now });
eq(v.defensive.value, '—', 'no record -> em dash');
eq(v.defensive.tone, 'unknown', 'no record -> unknown');

const p0 = bundle();
p0.summary.command_strip.direct_critical_count = 3;
eq(T.deriveView({ bundle: p0, nowSec: now }).p0.tone, 'crit', 'p0 present crit');

const aiStale = bundle();
aiStale.health.stale_flags.ai_metrics = true;
eq(T.deriveView({ bundle: aiStale, nowSec: now }).ai.state, 'stale', 'ai stale');
const aiOff = bundle();
aiOff.summary.service_health_summary.ai_agent = 'OFF';
eq(T.deriveView({ bundle: aiOff, nowSec: now }).ai.state, 'off', 'ai off');

v = T.deriveView({});
eq(v.hasData, false, 'empty -> no data');
eq(v.soc.value, '—', 'empty soc em dash');
eq(v.ai.state, 'unknown', 'empty ai unknown');

// live (SSE) state newer than the bundle wins
const liveState = { snapshot_epoch: now - 1, suricata_critical: 2, mode_runtime: { ok: true, mode: { current_mode: 'portal' } }, connection: {} };
v = T.deriveView({ bundle: bundle(), live: liveState, nowSec: now });
eq(v.mode.value, 'PORTAL', 'newer live state used');
eq(v.p0.value, 2, 'live critical count used');

// --- SSE parser -------------------------------------------------------------
const evs = [];
const parser = T.createSseParser((e) => evs.push(e));
parser.feed('event: ready\ndata: {"ok": true}\n\n');
parser.feed('event: state\ndata: {"a"');
parser.feed(': 1}\n\n: comment\n\n');
parser.feed('retry: 15000\nevent: stream_error\ndata: {"reason": "busy"}\n\n');
eq(evs.length, 3, 'three events');
eq(evs[0].event, 'ready', 'ready');
eq(JSON.parse(evs[1].data).a, 1, 'split chunk joined');
eq(evs[2].event, 'stream_error', 'stream_error');
eq(evs[2].retry, 15000, 'retry captured');
eq(parser.retryMs(), 15000, 'retryMs');

// --- secret buffer ---------------------------------------------------------
const sb = T.createSecretBuffer(8);
'pass word!'.split('').forEach((c) => sb.push(c));
eq(sb.length(), 8, 'limit respected');
sb.pop();
eq(sb.reveal(), 'pass wo', 'pop');
eq(sb.take(), 'pass wo', 'take returns');
eq(sb.length(), 0, 'take clears');
eq(sb.reveal(), '', 'nothing left');

// --- age ---------------------------------------------------------------------
eq(T.fmtAge(5), '5s ago', 'seconds');
eq(T.fmtAge(125), '2 min ago', 'minutes');
eq(T.fmtAge(null), '—', 'unknown age');

if (failures) {
    console.error(failures + ' failure(s)');
    process.exit(1);
}
console.log('touch console logic: all passed');
