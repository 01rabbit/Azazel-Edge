#!/usr/bin/env python3
"""Read-only local dashboard for Black Hat Europe replay artifacts.

Uses only the Python standard library; binds loopback by design.
Never executes shell commands, triggers controls, or writes evidence.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azazel-Edge | Incident Console</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,sans-serif;background:#0b1018;color:#eaf2f8}
*{box-sizing:border-box}body{margin:0;min-height:100vh}
.top{padding:17px 32px;background:#101b2a;border-bottom:1px solid #29394b;display:flex;justify-content:space-between;align-items:center;gap:18px}
.brand{font-size:19px;font-weight:800;letter-spacing:.035em}.sub{font-size:11px;color:#8aa7c0;margin-top:5px;letter-spacing:.1em}
.mode{border:1px solid #94743e;background:#312919;color:#f7d993;border-radius:5px;padding:7px 11px;font-size:11px;font-weight:800;letter-spacing:.07em}
button{border:1px solid #426b81;background:#214257;color:#e8f6fb;padding:9px 14px;border-radius:6px;cursor:pointer}button:hover{background:#30576c}
main{max-width:1500px;padding:24px 32px 32px;margin:auto}
h1{margin:0 0 5px;font-size:26px;letter-spacing:-.03em}h2{font-size:16px;margin:0 0 16px}h3{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:#a5bdd0;margin:0 0 12px}
.desc{color:#9aafc3;font-size:13px;margin:0 0 23px}.grid{display:grid;gap:14px}.kpis{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:17px}
.panel,.kpi{border:1px solid #2c3b4f;background:#142031;border-radius:9px;padding:18px}
.kpi{min-height:104px}.kpi .label{font-size:11px;color:#91a9bd;text-transform:uppercase;letter-spacing:.075em}.kpi .number{font-size:25px;font-weight:800;margin-top:9px;overflow-wrap:anywhere}
.teal{color:#64d6d4}.green{color:#73d9ae}.amber{color:#e6bb72}.red{color:#f28f91}
.layout{grid-template-columns:minmax(260px,.8fr) minmax(0,2.2fr);align-items:start}
.case{border:1px solid #397d85;border-left:4px solid #5bd7d2;padding:13px;background:#1b3040;border-radius:6px;min-width:0}
.case small,.muted{color:#9eb3c5}.case strong{display:block;margin:6px 0;font-size:16px}.case code{font-size:11px;overflow-wrap:anywhere}
.case .chip{display:inline-block;background:#345f63;color:#b6f6eb;border-radius:4px;padding:3px 7px;font-size:11px}
.blank{color:#a0afbf;font-size:13px;padding:20px 4px}
.details{display:grid;grid-template-columns:1fr 1fr;gap:14px}.full{grid-column:1/-1}
.detailrow{display:flex;justify-content:space-between;gap:12px;padding:11px 0;border-top:1px solid #2c3b4f;font-size:13px}
.detailrow:first-of-type{border:0}.detailrow span:first-child{color:#95aec0}.detailrow b{overflow-wrap:anywhere;text-align:right}
.summary{padding:14px;background:#0c1825;border-radius:6px;border:1px solid #33485b;font-size:15px;line-height:1.55}
.action{font-size:28px;color:#6adbd5;font-weight:800;text-transform:uppercase;letter-spacing:.035em}
.table{width:100%;border-collapse:collapse;font-size:12px}.table th{text-align:left;color:#90afc3;font-weight:600;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #365065;padding:9px 7px}
.table td{padding:10px 7px;border-bottom:1px solid #27394d;vertical-align:top;overflow-wrap:anywhere}
.table tr:last-child td{border-bottom:0}.pill{display:inline-block;border-radius:4px;padding:4px 7px;background:#263e4f;color:#c9dfec;font-size:11px;font-weight:700}
.pill.on{background:#19483f;color:#95e5cb}
.trail{margin:0;padding-left:21px;font-size:12px;color:#cbd9e4}.trail li{padding:6px 0}.trail li::marker{color:#5dc9ca}
.foot{margin-top:16px;color:#93aabb;font-size:11px;line-height:1.6}
details{margin-top:16px;border:1px solid #2e4354;border-radius:8px;padding:13px 16px;background:#111d2b}
summary{cursor:pointer;font-weight:700;font-size:13px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto;font:11px/1.55 ui-monospace,SFMono-Regular,monospace;color:#c3d6e2}
#trace{font-size:14px}.update{font-size:11px;color:#98afc0}
@media(max-width:950px){.layout{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}main{padding:18px}.top{padding:14px 18px}.details{grid-template-columns:1fr}}
@media(max-width:540px){.kpis{grid-template-columns:1fr}.mode{font-size:9px}.brand{font-size:14px}}
</style></head>
<body><header class="top"><div><div class="brand">AZAZEL-EDGE <span style="color:#71cbcf">/ INCIDENT CONSOLE</span></div>
<div class="sub">BLACK HAT EUROPE 2026 · OFFLINE REPLAY</div></div><div style="display:flex;align-items:center;gap:12px"><span class="mode">SYNTHETIC REPLAY · NO ENFORCEMENT</span><button id="refresh" type="button">Refresh</button></div></header>
<main><h1>Security Operations Overview</h1><p class="desc">Read-only evidence review. Decisions are deterministic; AI does not select actions. This is not live telemetry.</p>
<div class="grid kpis">
<div class="kpi"><div class="label">Evidence gate</div><div class="number" id="gate">NOT RUN</div></div>
<div class="kpi"><div class="label">Selected response</div><div class="number teal" id="action">—</div></div>
<div class="kpi"><div class="label">Retained audit chain</div><div class="number" id="chain">NOT VERIFIED</div></div>
<div class="kpi"><div class="label">Decision trace</div><div class="number" id="trace">—</div></div>
</div>
<div class="grid layout">
<div class="panel"><h2>Incident Queue</h2><h3>Local replay decision</h3><div id="case" class="blank">No replay artifacts loaded</div><p class="foot">Only the latest replay explanation is shown. This is not a live multi-incident queue or a SIEM event count.</p></div>
<div class="grid details">
<div class="panel full"><h2>Incident Investigation</h2><div class="summary" id="explain">Run a replay to review its actual decision evidence.</div>
<div class="detailrow"><span>Chosen response</span><b class="action" id="chosen">—</b></div>
<div class="detailrow"><span>Policy reasoning</span><b id="reason">—</b></div>
<div class="detailrow"><span>Release condition</span><b id="release">—</b></div>
<div class="detailrow"><span>Policy profile</span><b id="policy">—</b></div>
<div class="detailrow"><span>Config hash</span><b id="config">—</b></div>
</div>
<div class="panel full"><h2>Decision Alternatives</h2><table class="table"><thead><tr><th>Candidate action</th><th>Disposition</th><th>Recorded reason</th></tr></thead><tbody id="alternatives"><tr><td colspan="3" class="muted">No decision yet</td></tr></tbody></table></div>
<div class="panel"><h2>Audit Evidence</h2><div class="detailrow"><span>Chain verification</span><b id="auditstatus">—</b></div><div class="detailrow"><span>Retained entries verified</span><b id="auditentries">—</b></div><div class="detailrow"><span>Failure reason</span><b id="auditerror">—</b></div><p class="foot">Verification of retained records is not an external signature or a guarantee against whole-chain replacement.</p></div>
<div class="panel"><h2>Evidence Timeline</h2><ol class="trail" id="timeline"><li>Awaiting replay evidence</li></ol><p class="foot">Timeline contains recorded audit entry types only; no invented timestamps.</p></div>
</div></div>
<details><summary>Raw evidence (JSONL / troubleshooting)</summary><h3 style="margin-top:15px">Explanation record</h3><pre id="rawExplanation">—</pre><h3>Audit tail</h3><pre id="rawAudit">—</pre><h3>Optional resource verification</h3><pre id="resources">—</pre></details>
<p class="foot"><span id="updated" class="update">Waiting for artifacts</span> · Local replay display only · No active controls or outbound data transfer</p>
</main>
<script>
const $=id=>document.getElementById(id);
const show=(id,value)=>$(id).textContent=String(value??'—');
const pretty=value=>String(value??'—').replace(/_/g,' ');
function detailReason(e){return e.reason||e.why_chosen?.reason||'No plain-language reason recorded';}
function render(data){
 const g=data.gate||{},e=data.explanation||{},audit=Array.isArray(data.audit_tail)?data.audit_tail:[],v=g.chain_verification||{};
 const available=data.available&&Object.keys(e).length>0;
 show('gate',g.ok===true?'PASS':g.ok===false?'FAIL':'NOT RUN');
 $('gate').className='number '+(g.ok===true?'green':g.ok===false?'red':'amber');
 show('action',g.action||e.selected_action||'—');
 show('chain',v.ok===true&&v.entries>0?'VERIFIED':'NOT VERIFIED');
 $('chain').className='number '+(v.ok===true&&v.entries>0?'green':'amber');
 show('trace',g.trace_id||e.trace_id||'—');
 const q=$('case');q.replaceChildren();
 if(available){
   q.className='case';
   const cap=document.createElement('span');cap.className='chip';cap.textContent='SYNTHETIC CASE';
   const headline=document.createElement('strong');headline.textContent=pretty(e.selected_action||g.action)+' decision';
   const meta=document.createElement('small');meta.textContent='Trace: '+String(e.trace_id||g.trace_id||'—');
   q.append(cap,headline,meta);
 }else{q.className='blank';q.textContent='No replay artifacts loaded';}
 show('chosen',e.selected_action||g.action||'—');show('reason',pretty(detailReason(e)));
 show('release',pretty(e.release_condition));show('policy',e.policy_profile||'—');show('config',e.config_hash||'—');
 show('explain',available?'Local evidence evaluated. The deterministic replay chose '+String(e.selected_action||g.action||'an action')+'. Review the selected response, rejected alternatives, and release condition below.':'Run a replay to review its actual decision evidence.');
 const choices=$('alternatives');choices.replaceChildren();
 const rejected=Array.isArray(e.rejected_actions)?e.rejected_actions:[];
 const reasons=Array.isArray(e.why_not_others)?e.why_not_others:[];
 if(!available){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=3;td.textContent='No decision yet';tr.append(td);choices.append(tr);}
 else{
   const candidates=[{action:e.selected_action,selected:true},...rejected.map(x=>typeof x==='string'?{action:x}:{action:x.action||String(x)})];
   candidates.forEach(item=>{
     if(!item.action)return;
     const found=reasons.find(r=>r&&r.action===item.action);
     const tr=document.createElement('tr');
     [item.action,item.selected?'SELECTED':'REJECTED',item.selected?pretty(detailReason(e)):pretty(found?.reason||'Reason not recorded')].forEach((value,i)=>{
       const td=document.createElement('td');
       if(i===1){const span=document.createElement('span');span.className='pill'+(item.selected?' on':'');span.textContent=value;td.append(span);}else{td.textContent=value;}
       tr.append(td);
     });choices.append(tr);
   });
 }
 show('auditstatus',v.ok===true&&v.entries>0?'VERIFIED':v.ok===false?'FAILED':'NOT VERIFIED');
 show('auditentries',v.entries??'—');show('auditerror',v.error||'None reported');
 const trail=$('timeline');trail.replaceChildren();
 if(!audit.length){const li=document.createElement('li');li.textContent='No audit entries available';trail.append(li);}
 else audit.forEach((item,i)=>{const li=document.createElement('li');li.textContent=String(i+1)+'. '+pretty(item.kind||'record')+(item.trace_id?' · '+item.trace_id:'');trail.append(li);});
 show('rawExplanation',JSON.stringify(e,null,2));show('rawAudit',JSON.stringify(audit,null,2));show('resources',JSON.stringify(data.resources||{},null,2));
 show('updated',(data.updated_at||'')+' | '+(available?'Replay evidence loaded':'Awaiting valid evidence'));
}
async function refresh(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);render(await response.json());}catch(err){show('gate','UNAVAILABLE');show('updated','Unable to read local evidence: '+String(err));}}
$('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,3000);
</script></body></html>"""

def _read_json(path: Path):
    try:
        if path.stat().st_size > 8_000_000:
            raise ValueError("file too large")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None

def _tail_jsonl(path: Path, limit: int = 8):
    try:
        if path.stat().st_size > 8_000_000:
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        return [json.loads(x) for x in lines[-limit:] if x.strip()]
    except (OSError, ValueError, json.JSONDecodeError):
        return []

def status(directory: Path) -> dict:
    gate = _read_json(directory / "gate.json")
    explanations = _tail_jsonl(directory / "explanations.jsonl", 1)
    resources = _read_json(directory / "resource-status.json")
    return {"resources": resources or {}, "available": isinstance(gate, dict),
            "gate": gate or {},
            "explanation": explanations[-1] if explanations else {},
            "audit_tail": _tail_jsonl(directory / "audit.jsonl"),
            "updated_at": datetime.now(timezone.utc).isoformat()}

def handler_factory(directory: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = urlsplit(self.path).path
            if route == "/":
                body, mime, code = HTML.encode(), "text/html; charset=utf-8", 200
            elif route == "/api/status":
                body = json.dumps(status(directory)).encode()
                mime, code = "application/json; charset=utf-8", 200
            else:
                body, mime, code = b"Not found", "text/plain", 404
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)
    return Handler

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "artifacts/bheurope-2026")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    # Loopback only: the monitor contains local security evidence.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_factory(args.artifacts.resolve()))
    print(f"Read-only monitor: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
