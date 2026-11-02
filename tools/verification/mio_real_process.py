#!/usr/bin/env python3
"""Opt-in synthetic ordinary-event socket smoke, never a deployment/HIL test.

Use an existing dependency-complete interpreter and a clean exact MIO source.
MIO_PROCESS_EVIDENCE must name a new private evidence directory;
MIO_EXACT_SOURCE must name the clean runtime-pin checkout. No network fetch.
"""
import json, os, socket, subprocess, sys, time, signal, tempfile, fcntl, urllib.request, http.server, threading
from pathlib import Path

def require_unprivileged():
    """Refuse root before evidence writes or service startup."""
    if os.geteuid() == 0:
        raise SystemExit('Refusing root execution; run this harness as an unprivileged user.')

require_unprivileged()

ROOT = Path(__file__).resolve().parents[2]
EV = Path(os.environ['MIO_PROCESS_EVIDENCE']).resolve()
EV.mkdir(mode=0o700)
SOURCE = Path(os.environ['MIO_EXACT_SOURCE']).resolve()
assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip() == '6cd015351979ba69e18517d71f79c0c347bb2722'
assert not subprocess.check_output(['git','-C',str(SOURCE),'status','--porcelain'],text=True).strip()
PY = sys.executable
BASE = {
    'PATH': '/usr/bin:/bin:/opt/homebrew/bin',
    'HOME': str(EV),
    'PYTHONDONTWRITEBYTECODE': '1',
    'PYTHONPATH': f'{ROOT}/py:{SOURCE}/src',
    'AZAZEL_LLM_ENABLED': '0',
    'AZAZEL_MIO_MODEL_ENABLED': '1',
    'AZAZEL_MIO_MODEL_TIMEOUT_SEC': '8',
    'AZAZEL_LLM_MODEL_DEGRADED': 'qwen3.5:0.8b',
    'AZAZEL_LLM_MODEL_PRIMARY': 'qwen3.5:0.8b',
    'AZAZEL_OLLAMA_ENDPOINT': 'http://127.0.0.1:11434',
    'AZAZEL_AI_METRICS_HEARTBEAT_SEC': '5',
    'AZAZEL_NORMALIZED_EVENT_LOG': str(EV/'empty-normalized-events.jsonl'),
}
(EV/'empty-normalized-events.jsonl').write_text('')
EVENT = {
 'pipeline':'rust_event_engine_v1','source':'suricata_eve',
 'normalized':{'event_type':'alert','sid':42,'severity':2,'attack_type':'port scan','category':'network-scan','protocol':'TCP','target_port':22,'action':'allowed','ts':'2026-11-02T00:00:00Z'},
 'defense':{'action':'observe'},
 'enforcement':{'trace_id':'synthetic-edge-process-525','mode':'dry_run','result':'no_disruptive_action','selected_action':'observe'},
 'enforcement_status':{'dry_run':True,'enforce_enabled':False,'enforce_level':'advisory','high_impact_auto':False,'allowed_actions':['observe','notify']},
}

def run(name, port, timeout=12, model_enabled='1'):
    d=EV/name; d.mkdir(mode=0o700)
    short=tempfile.TemporaryDirectory(prefix='mio-')
    sock=Path(short.name)/'ai.sock'; env=BASE.copy(); env.update({
       'AZAZEL_AI_SOCKET':str(sock),'AZAZEL_AI_QUERY_SOCKET':str(d/'query.sock'),
       'AZAZEL_AI_ADVISORY':str(d/'advisory.json'),'AZAZEL_AI_EVENT_LOG':str(d/'events.jsonl'),
       'AZAZEL_AI_DEFERRED_LOG':str(d/'deferred.jsonl'),'AZAZEL_AI_LLM_LOG':str(d/'llm.jsonl'),
       'AZAZEL_AI_METRICS':str(d/'metrics.json'),'AZAZEL_AI_POLICY':str(d/'policy.json'),
       'AZAZEL_AI_AUDIT_LOG':str(d/'audit.jsonl'),'AZAZEL_DECISION_LOG_DIR':str(d/'decisions'),
       'AZAZEL_OLLAMA_ENDPOINT':f'http://127.0.0.1:{port}',
       'AZAZEL_MIO_MODEL_ENABLED':model_enabled,
    })
    log=open(d/'process.log','wb')
    p=subprocess.Popen([PY,'-m','azazel_edge_ai.agent'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
    started=time.monotonic()
    try:
      while time.monotonic()-started<10:
        if p.poll() is not None: raise RuntimeError(f'agent exited {p.returncode}; see private process log')
        if sock.exists():
          try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
              s.settimeout(1); s.connect(str(sock))
            break
          except OSError: pass
        time.sleep(.05)
      else: raise TimeoutError('listener startup timeout')
      sent=time.monotonic()
      with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(1); s.connect(str(sock)); s.sendall((json.dumps(EVENT)+'\n').encode())
      end=time.monotonic()+timeout; last={}
      while time.monotonic()<end:
        try: last=json.loads((d/'ai_snapshot.json').read_text())
        except Exception: pass
        model=last.get('mio_auxiliary',{}).get('model_analysis',{}) if isinstance(last,dict) else {}
        if last.get('mio_auxiliary',{}).get('status') == 'complete' and model.get('status') in ('complete','partial','degraded','disabled') and model.get('reason') != 'fast_result_unavailable':
          break
        time.sleep(.05)
      else: raise TimeoutError('terminal snapshot deadline')
      fast=last['mio_auxiliary']; binding=fast['handoff_binding']
      assert fast['status']=='complete'
      assert fast['knowledge']=={'status':'not_queried','refs':[]}
      assert fast['authority']==model['authority']=='read_only_advisory'
      assert binding['valid'] and binding['status']=='matched'
      assert binding['generation']==fast['generation']
      assert binding['edge_trace_id']==EVENT['enforcement']['trace_id']
      assert (binding['edge_action'],binding['edge_mode'],binding['edge_result'])==('observe','dry_run','no_disruptive_action')
      if model_enabled=='1':
        assert model['fast_generation']==fast['generation']
        if model['status'] in ('complete','partial'):
          assert model['frame_id']==binding['frame_id'] and model['trace_id']==binding['mio_trace_id']
      advisory=json.loads((d/'advisory.json').read_text())
      events=[json.loads(line) for line in (d/'events.jsonl').read_text().splitlines()]
      assert events[0]['event']['enforcement']==EVENT['enforcement']
      result={'case':name,'listener_ready_ms':round((sent-started)*1000,1),'event_to_snapshot_result_ms':round((time.monotonic()-sent)*1000,1),
              'model_analysis':model,'advisory_risk_score':advisory.get('risk_score'),'advisory_recommendation':last.get('recommendation'),
              'event_enforcement':EVENT['enforcement'],'event_authority':last.get('mio_auxiliary',{}).get('authority'),
              'fast_status':last.get('mio_auxiliary',{}).get('status')}
      (d/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
      return result
    finally:
      if p.poll() is None: p.send_signal(signal.SIGTERM)
      try: p.wait(timeout=8)
      except subprocess.TimeoutExpired: p.kill(); p.wait()
      log.close()
      assert p.returncode == 0, f'unclean process exit: {p.returncode}'
      short.cleanup()
      result_path=d/'summary.json'
      if result_path.exists():
        result=json.loads(result_path.read_text()); result['process_exit_code']=p.returncode; result_path.write_text(json.dumps(result,indent=2)+'\n')

class Slow(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        time.sleep(2)
        self.close_connection=True
    def log_message(self,*args): pass

if __name__=='__main__':
    with open('/tmp/azazel-mio-local-model-smoke.lock','w') as lock:
      fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
      ps=subprocess.check_output(['ollama','ps'],text=True)
      (EV/'ollama-ps-before.txt').write_text(ps)
      assert len(ps.strip().splitlines())==1, 'Ollama not idle; stop'
      opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
      with opener.open('http://127.0.0.1:11434/api/tags',timeout=3) as response:
        models=json.load(response)['models']
      actual=next(item for item in models if item['name']=='qwen3.5:0.8b')
      assert actual['digest'].startswith('f3817196d142')
      baseline=run('disabled',11434,model_enabled='0')
      real=run('real',11434)
      with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
      absent=run('unavailable',port)
      server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Slow)
      threading.Thread(target=server.serve_forever,daemon=True).start()
      BASE['AZAZEL_MIO_MODEL_TIMEOUT_SEC']='0.2'
      try: timed=run('timeout',server.server_port)
      finally: server.shutdown(); server.server_close()
      results=[baseline,real,absent,timed]
      assert real['model_analysis']['status']=='complete'
      assert real['model_analysis']['metered_request_count']==real['model_analysis']['request_count']>0
      assert timed['model_analysis']['reason']=='deadline_exceeded'
      assert timed['event_to_snapshot_result_ms']<12000
      assert real['model_analysis']['prompt_tokens']>0
      assert real['model_analysis']['completion_tokens']>0
      assert real['model_analysis']['model']=='qwen3.5:0.8b'
      assert absent['model_analysis']['status']==timed['model_analysis']['status']=='degraded'
      assert all((r['advisory_risk_score'],r['advisory_recommendation'])==
        (baseline['advisory_risk_score'],baseline['advisory_recommendation']) for r in results)
      report={'actual_model_digest':actual['digest'],'results':results}
      (EV/'report.json').write_text(json.dumps(report,indent=2)+'\n')
      # Do not emit model statements or synthetic event details to stdout.
      print(json.dumps([{k:r[k] for k in ('case','event_to_snapshot_result_ms','advisory_risk_score')} |
        {'model':{k:r['model_analysis'].get(k) for k in ('status','reason','model','duration_ms',
          'prompt_tokens','completion_tokens','request_count','metered_request_count','usage_status')}} for r in results],indent=2))
