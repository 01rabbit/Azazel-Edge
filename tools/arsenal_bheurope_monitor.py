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
HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azazel-Edge | Arsenal 2026</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090f19;color:#e4f0f7}
body{max-width:1100px;margin:auto;padding:26px}header{display:flex;justify-content:space-between;align-items:center}
h1{font-size:25px}small,.muted{color:#9db0c2}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:15px}
section{background:#142132;border:1px solid #34495b;border-radius:12px;padding:18px;margin:16px 0}
.value{font-size:22px;font-weight:700;color:#69d6df;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-height:400px;overflow:auto}
.ok{color:#7ce7b3}.fail{color:#ff9d9d}button{padding:9px 15px;border-radius:8px;background:#245a69;color:white;border:1px solid #56889a;cursor:pointer}
</style></head><body>
<header><div><small>BLACK HAT EUROPE 2026 / OFFLINE DEMO</small><h1>AZAZEL-EDGE · DECISION MONITOR</h1></div><button onclick="refresh()">Refresh</button></header>
<p class="muted">Read-only local replay evidence. No network enforcement. No AI action selection.</p>
<div class="grid">
<section><small>Replay gate</small><div class="value" id="gate">Waiting</div></section>
<section><small>Selected action</small><div class="value" id="action">—</div></section>
<section><small>Audit chain</small><div class="value" id="chain">—</div></section>
<section><small>Trace ID</small><div class="value" id="trace">—</div></section>
</div>
<section><h2>Decision explanation</h2><div id="release" class="muted"></div><pre id="explanation">No replay yet</pre></section>
<section><h2>Rejected alternatives</h2><pre id="rejected">—</pre></section>
<section><h2>Audit evidence</h2><pre id="audit">—</pre></section>
<small id="updated">Waiting for artifacts</small>
<script>
const $=id=>document.getElementById(id);
const show=(id,value)=>$(id).textContent=String(value??"—");
async function refresh(){
try{
 const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
 const d=await r.json(),g=d.gate||{},e=d.explanation||{};
 show('gate',g.ok===true?'PASS':g.ok===false?'FAIL':'NOT RUN');
 show('action',g.action||e.selected_action);show('trace',g.trace_id||e.trace_id);
 show('chain',g.chain_verification?.ok===true?'VERIFIED':'NOT VERIFIED');
 show('release','Release condition: '+(e.release_condition||'—'));
 show('explanation',JSON.stringify(e,null,2));
 show('rejected',JSON.stringify(e.rejected_actions||[],null,2));
 show('audit',JSON.stringify(d.audit_tail||[],null,2));
 show('updated',d.updated_at+' | '+(d.available?'Artifacts loaded':'Run the replay gate first'));
}catch(err){show('gate','UNAVAILABLE');show('updated',String(err));}
}
refresh();setInterval(refresh,3000);
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
    return {"available": isinstance(gate, dict),
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
