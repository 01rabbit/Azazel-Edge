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
eq(C(500, { ok: false, error: '[Errno 111] Connection refused' }), 'undelivered', 'connect refused -> undelivered');
eq(C(500, { ok: false, error: 'Empty response from daemon' }), 'delivery_unknown', 'sent, no reply -> may have run');
eq(C(500, { ok: false, error: '[Errno 104] Connection reset by peer' }), 'delivery_unknown', 'reset after send -> may have run');
eq(C(500, { ok: false, error: 'busy' }), 'busy', 'daemon busy -> refused, not run');
eq(C(500, { ok: false, error: 'forbidden', reason: 'web_ui' }), 'busy', 'peer table refusal -> refused');
eq(C(500, { ok: false, error: 'Rate limit exceeded (1 req/3sec)' }), 'busy', 'rate limit -> refused');
eq(C(500, { ok: false, error: 'Wi-Fi connect busy: another connect is in progress; try again' }), 'busy', 'wifi connect busy -> refused, not run');
// POST answered 5xx without the API's JSON -> may have run
eq(T.classifyResult(502, null, '', 'POST').kind, 'delivery_unknown', 'POST 502 without body -> may have run');
eq(T.classifyResult(500, { html: 'x' }, '', 'POST').kind, 'delivery_unknown', 'POST 500 unstructured -> may have run');
// Flask errorhandler(500) body, and a daemon error passed through as 500:
// neither says nothing ran -> may have run.
eq(T.classifyResult(500, { ok: false, error: 'Server error' }, '', 'POST').kind, 'delivery_unknown', 'POST 500 Server error -> may have run');
eq(T.classifyResult(500, { ok: false, error: 'Connection failed' }, '', 'POST').kind, 'delivery_unknown', 'POST 500 generic error -> may have run');
// ...but explicit "nothing was run" answers stay what they are.
eq(T.classifyResult(500, { ok: false, error: 'not_implemented', not_implemented: true }, '', 'POST').kind, 'not_implemented', 'POST 500 not_implemented');
eq(T.classifyResult(500, { ok: false, error: 'Control daemon not running' }, '', 'POST').kind, 'undelivered', 'POST 500 undelivered');
eq(T.classifyResult(500, { ok: false, error: 'busy' }, '', 'POST').kind, 'busy', 'POST 500 busy');
eq(T.classifyResult(500, { ok: false, status_api_error: true, error: 'HTTP 403' }, '', 'POST').kind, 'failed', 'POST 500 status API refusal');
eq(T.classifyResult(400, { ok: false, error: 'Missing SSID' }, '', 'POST').kind, 'failed', 'POST 400 -> failed (validation, nothing ran)');
eq(T.classifyResult(500, { ok: false, error: 'boom' }, '', 'GET').kind, 'failed', 'GET 500 -> failed');
eq(T.classifyResult(502, null, '', 'GET').kind, 'failed', 'GET 502 -> failed (nothing to run)');
eq(T.classifyResult(503, null, '', 'POST').kind === 'ok', false, 'never ok');
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
        decision_focus: { available: true, decision: { action: 'OBSERVE', reason: 'r' }, mode: { kind: 'live_test_input' }, safety: { dry_run: true }, audit: { trace_id: 'trace-1', policy_profile: 'balanced', format_version: 'v2' } },
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
eq(v.mode, undefined, 'legacy concept mode is not part of the view (#340)');
eq(v.trace.id, 'trace-1', 'decision trace');
eq(v.trace.policy, 'balanced', 'policy profile');
eq(v.daemonDown, false, 'daemon up');
eq(v.defensive.dryRun, true, 'dry run reported');
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
eq(v.mode, undefined, 'no legacy mode even when the daemon is down');
eq(v.soc.tone, 'stale', 'daemon down -> fresh-looking data is not green');
eq(v.staleReason, 'unverified', 'daemon down -> unverified, not stale');

const fileSrc = bundle();
fileSrc.state.source = 'FILE:/x';
eq(T.deriveView({ bundle: fileSrc, nowSec: now }).daemonDown, true, 'file fallback snapshot -> daemon down');

const enforced = bundle();
enforced.decision_focus.safety = { dry_run: false };
eq(T.deriveView({ bundle: enforced, nowSec: now }).defensive.dryRun, false, 'dry_run false -> enforced');

const noSafety = bundle();
delete noSafety.decision_focus.safety;
eq(T.deriveView({ bundle: noSafety, nowSec: now }).defensive.dryRun, null, 'missing dry_run -> unknown, not enforced');

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
eq(v.snapshotAgeSec, 1, 'newer live state used');
eq(v.p0.value, 2, 'live critical count used');

// --- stream policy (load on the Edge) -------------------------------------
const W = (o) => T.streamWanted(Object.assign({ nowMs: 1000000, lastInteractionMs: 999000 }, o));
eq(W({}), true, 'recent touch -> stream wanted');
eq(W({ hidden: true }), false, 'hidden -> no stream');
eq(W({ authProblem: true }), false, 'auth problem -> no stream');
eq(W({ lastInteractionMs: 1000000 - 5 * 60 * 1000 - 1 }), false, 'idle 5 min -> no stream');
eq(W({ holdOffUntilMs: 1000001 }), false, 'hold-off after repeated stream_error');
eq(T.nextStreamDelay({ ended: 'stream_error', retryHintMs: 15000, backoffMs: 2000 }), 15000, 'stream_error honours retry');
eq(T.nextStreamDelay({ ended: 'stream_error', backoffMs: 2000 }), 15000, 'stream_error without hint -> 15 s floor');
eq(T.nextStreamDelay({ ended: 'stream_error', retryHintMs: 15000, backoffMs: 32000 }), 32000, 'backoff above retry');
eq(T.nextStreamDelay({ ended: 'closed', backoffMs: 2000 }), 2000, 'first transport retry');
eq(T.nextStreamDelay({ ended: 'closed', backoffMs: 999999 }), 60000, 'backoff capped');
eq(T.nextStreamDelay({ ended: 'auth', backoffMs: 2000 }), 60000, 'auth failure waits a minute');

// --- press-and-hold --------------------------------------------------------
let h = T.advanceHold(null, 1000);
eq(h.elapsedMs, 0, 'hold starts at zero');
h = T.advanceHold(h, 60000);
eq(h.elapsedMs, 100, 'a stalled frame adds at most 100 ms');
eq(h.done, false, 'one long frame never completes a hold');
let t = 60000;
for (let i = 0; i < 10; i++) { t += 16; h = T.advanceHold(h, t); }
eq(h.done, false, 'short hold not done');
for (let i = 0; i < 80; i++) { t += 16; h = T.advanceHold(h, t); }
eq(h.done, true, '1.2 s of frames completes the hold');
eq(h.progress, 1, 'progress capped at 1');
eq(T.advanceHold(h, t - 500).elapsedMs, h.elapsedMs, 'clock going back adds nothing');

// hold controller: cancel (release, visibilitychange, blur, pagehide) resets
const hc = T.createHold();
eq(hc.frame(0), null, 'no frame before start');
hc.start(0);
let tt = 0;
for (let i = 0; i < 40; i++) { tt += 16; hc.frame(tt); }
eq(hc.cancel(), true, 'cancel reports an active hold');
eq(hc.active(), false, 'inactive after cancel');
eq(hc.frame(tt + 16), null, 'frames after cancel are ignored');
hc.start(tt);
let r = null;
for (let i = 0; i < 40; i++) { tt += 16; r = hc.frame(tt); }
eq(r.done, false, 'restarted hold starts from zero (no carry-over)');
for (let i = 0; i < 40; i++) { tt += 16; r = hc.frame(tt) || r; }
eq(r.done, true, 'full hold completes');
eq(hc.active(), false, 'completed hold is finished');
eq(hc.frame(tt + 16), null, 'no second completion');
eq(hc.cancel(), false, 'cancel after completion is a no-op');

// --- on-screen keyboard ----------------------------------------------------
const kbuf = T.createSecretBuffer(64);
let ks = { shift: false, sym: false };
ks = T.applyKey(ks, '{shift}', kbuf); eq(ks.shift, true, 'shift on');
ks = T.applyKey(ks, 'p', kbuf); eq(ks.shift, false, 'shift is one-shot'); eq(ks.redraw, true, 'redraw after shift use');
ks = T.applyKey(ks, 'a', kbuf);
ks = T.applyKey(ks, '{sym}', kbuf); eq(ks.sym, true, 'symbols on');
ks = T.applyKey(ks, '{shift}', kbuf); eq(ks.shift, false, 'no shift on the symbol layer');
ks = T.applyKey(ks, '!', kbuf);
ks = T.applyKey(ks, '{space}', kbuf);
ks = T.applyKey(ks, 'x', kbuf);
ks = T.applyKey(ks, '{bksp}', kbuf);
eq(kbuf.reveal(), 'Pa! ', 'typed value');
ks = T.applyKey(ks, '{bogus}', kbuf);
eq(kbuf.reveal(), 'Pa! ', 'unknown key ignored');
ks = T.applyKey(ks, '{clear}', kbuf);
eq(kbuf.length(), 0, 'clear wipes');

// --- SSID display ----------------------------------------------------------
eq(T.displaySsid('caf\u202Eexe'), 'cafexe', 'bidi override removed');
eq(T.displaySsid('a\u0000b\u200Fc'), 'abc', 'control and marks removed');
eq(T.displaySsid('x'.repeat(40)).length, 32, 'display length capped');
eq(T.displaySsid(null), '', 'null -> empty');
eq(T.displaySsid('a\u00ADb\u2028c\u2029d'), 'abcd', 'soft hyphen and line/paragraph separators removed');
eq(T.displaySsid('\u202E\u0007\u200F'), '', 'control-only SSID -> empty (button disabled)');
const emoji = '\u{1F600}'.repeat(40);
const cut = T.displaySsid(emoji);
eq(Array.from(cut).length, 32, 'cut by code point');
ok(!/[\uD800-\uDBFF]$/.test(cut.slice(0, -1)), 'no lone surrogate before the ellipsis');

// --- SSE parser -------------------------------------------------------------
const evs = [];
const parser = T.createSseParser((e) => evs.push(e));
parser.feed('event: ready\ndata: {"ok": true}\n\n');
parser.feed('event: state\ndata: {"a"');
parser.feed(': 1}\n\n: comment\n\n');
parser.feed('retry: 15000\nevent: stream_error\ndata: {"ok": false, "source": "state_stream", "error": "busy"}\n\n');
eq(evs.length, 3, 'three events');
eq(evs[0].event, 'ready', 'ready');
eq(JSON.parse(evs[1].data).a, 1, 'split chunk joined');
eq(evs[2].event, 'stream_error', 'stream_error');
eq(evs[2].retry, 15000, 'retry captured');
eq(JSON.parse(evs[2].data).error, 'busy', 'stream_error carries error (app.py on main)');
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

// --- tab bar keyboard (Edge#348): inactive tabs have tabindex -1, so the
// arrow keys are the keyboard's only way to them ---------------------------
eq(T.rovingIndex('ArrowRight', 0, 5), 1, 'tabs: right -> next');
eq(T.rovingIndex('ArrowRight', 4, 5), 0, 'tabs: right wraps');
eq(T.rovingIndex('ArrowLeft', 0, 5), 4, 'tabs: left wraps');
eq(T.rovingIndex('Home', 3, 5), 0, 'tabs: home');
eq(T.rovingIndex('End', 0, 5), 4, 'tabs: end');
eq(T.rovingIndex('Enter', 0, 5), -1, 'tabs: other keys do not move');
eq(T.rovingIndex('ArrowRight', -1, 5), -1, 'tabs: focus outside the bar -> no move');
(function () {
    const fs = require('fs');
    const html = fs.readFileSync(path.join(__dirname, '..', 'azazel_edge_web', 'templates', 'touch.html'), 'utf8');
    const tabs = html.match(/<button[^>]*role="tab"[^>]*>/g) || [];
    eq(tabs.length, 5, 'touch: five tabs');
    tabs.forEach(function (t) {
        const ctl = (t.match(/aria-controls="([^"]+)"/) || [])[1];
        const id = (t.match(/id="([^"]+)"/) || [])[1];
        ok(!!ctl && new RegExp('id="' + ctl + '"[^>]*role="tabpanel"[^>]*aria-labelledby="' + id + '"').test(html), 'touch: ' + id + ' controls a tabpanel labelled by it');
    });
})();

if (failures) {
    console.error(failures + ' failure(s)');
    process.exit(1);
}
console.log('touch console logic: all passed');
