"""Actual separate-UID offline witness boundary. Run explicitly as root in CI.

Only temporary files/child UIDs and AF_UNIX are used; no device or live defense.
"""

import copy
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root needed for actual separate UIDs",
)

from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SignedCaptureWriter,
    SourceVerifier,
    _json,
)
from azazel_edge.outcome.input_witness import (
    serve,
    WitnessStore,
    send_message,
    recv_message,
)
from azazel_edge.outcome.journal import OutcomeJournalError, NAME
from auth_input_helpers import make_policy
from test_outcome_input_resume import event

ROOT = Path(__file__).resolve().parents[1]

WORKER = r"""
import sys,json,os
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SourceVerifier
from azazel_edge.outcome.input_witness import InputAuthentication
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.journal import ObservationJournal
from azazel_edge.outcome.input_resume import recover_input,observe_input
from azazel_edge.outcome.telemetry import persistence_context
from test_outcome_input_resume import collector,line_for
from test_outcome_telemetry_g3 import policy
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer');d=p.data
try:
 with BoundedInput(Path(d['source_path']),max_bytes=d['input_max_bytes'],max_records=d['input_max_records'],authentication=InputAuthentication(p)) as source:
  with ObservationJournal(Path(d['journal_directory']),scope_ref=d['scope_ref'],policy_ref=persistence_context(policy(),'br0'),boot_id='observer-boot',create=sys.argv[2]=='create',max_bytes=d['journal_max_bytes'],input_source=source) as j:
   recover_input(j,policy());c=collector(j)
   print(json.dumps({'ready':True,'status':j.status()}),flush=True)
   for raw in sys.stdin:
    cmd=json.loads(raw)
    try:
     if cmd['op']=='close':break
     if cmd['op']=='observe':observe_input(line_for(source,j),j,c,live_floor=100,now=110)
     elif cmd['op']=='begin':
      line=line_for(source,j);c.observe_event(json.loads(line.raw),observed_epoch=110)
     elif cmd['op']=='commit':c.finalize_due(epoch=114)
     elif cmd['op']=='fail_ack':
      def fail(*args):raise OSError('injected witness unavailable')
      j.authentication.advance=fail
      observe_input(line_for(source,j),j,c,live_floor=100,now=110)
     elif cmd['op']=='lost_ack':
      real=j.authentication.advance
      def lost(*args):real(*args);raise OSError('injected lost response')
      j.authentication.advance=lost
      observe_input(line_for(source,j),j,c,live_floor=100,now=110)
     elif cmd['op']=='probe':
      denied=[]
      for path in cmd['paths']:
       try:open(path,'rb').read();denied.append(False)
       except PermissionError:denied.append(True)
      print(json.dumps({'denied':denied}),flush=True);continue
     print(json.dumps({'status':j.status(),'outcomes':len(j.retained_outcomes())}),flush=True)
    except OSError as e:print(json.dumps({'refused':True,'status':j.status()}),flush=True)
except OSError as e:
 print(json.dumps({'startup_refused':True,'reason':str(e)}),flush=True)
"""


class Child:
    def __init__(self, f, create=False):
        env = dict(
            os.environ,
            PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py") + ":" + str(ROOT / "tests"),
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                WORKER,
                str(f.policy_file),
                "create" if create else "open",
            ],
            cwd=ROOT,
            env=env,
            user=f.p.data["observer_uid"],
            group=f.p.data["observer_uid"],
            extra_groups=[],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.initial = self.read()

    def read(self):
        assert select.select([self.process.stdout], [], [], 20)[
            0
        ], "bounded child response timeout"
        raw = self.process.stdout.readline()
        assert raw, self.process.stderr.read()
        return json.loads(raw)

    def command(self, op, **values):
        self.process.stdin.write(json.dumps(dict(op=op, **values)) + "\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write('{"op":"close"}\n')
            self.process.stdin.flush()
            self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self.process.stderr.close()

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


class Fixture:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="ea-", dir="/tmp"))
        self.root.chmod(0o755)
        self.p, _, _, pk, wk = make_policy(
            self.root, observer=65534, witness=0, producer=1000
        )
        Path(self.p.data["source_path"]).touch(mode=0o644)
        os.chown(self.p.data["source_path"], 1000, 1000)
        journal = Path(self.p.data["journal_directory"])
        journal.mkdir(mode=0o700)
        os.chown(journal, 65534, 65534)
        Path(self.p.data["anchor_directory"]).mkdir(mode=0o700)
        private = self.root / "private"
        private.mkdir(mode=0o700)
        self.pk = private / "producer"
        self.pk.write_bytes(pk)
        self.pk.chmod(0o600)
        producer_private = self.root / "producer-private"
        producer_private.mkdir(mode=0o700)
        os.chown(producer_private, 1000, 1000)
        self.pk.unlink()
        self.pk = producer_private / "producer"
        self.pk.write_bytes(pk)
        self.pk.chmod(0o600)
        os.chown(self.pk, 1000, 1000)
        self.wk = private / "witness"
        self.wk.write_bytes(wk)
        self.wk.chmod(0o600)
        self.policy_file = self.root / "trust.json"
        self.policy_file.write_bytes(_json(dict(self.p.data)))
        self.policy_file.chmod(0o644)
        self.errors = []
        self.thread = None

    @property
    def journal(self):
        return Path(self.p.data["journal_directory"]) / NAME

    @property
    def source(self):
        return Path(self.p.data["source_path"])

    @property
    def anchors(self):
        return Path(self.p.data["anchor_directory"]) / "anchors.journal"

    def start(self, initialize=False):
        self.stop = threading.Event()
        ready = threading.Event()

        def run():
            try:
                serve(
                    self.p, self.wk, initialize=initialize, stop=self.stop, ready=ready
                )
            except BaseException as exc:
                self.errors.append(exc)
                ready.set()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        assert ready.wait(10)
        if self.errors:
            raise self.errors[-1]

    def halt(self):
        if self.thread:
            self.stop.set()
            self.thread.join(5)
            assert not self.thread.is_alive()
            self.thread = None

    def capture(self, trace="new", epoch=110):
        script = """
import json,sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer')
with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref='producer-boot') as writer:
 print(json.dumps(writer.append(json.load(sys.stdin))))
"""
        env = dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py"))
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.policy_file), str(self.pk)],
            input=json.dumps(event(trace, epoch)),
            capture_output=True,
            text=True,
            env=env,
            user=1000,
            group=1000,
            extra_groups=[],
            timeout=20,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def clean(self):
        self.halt()
        shutil.rmtree(self.root)


@pytest.fixture
def f():
    value = Fixture()
    try:
        value.start(initialize=True)
        yield value
    finally:
        value.clean()


def test_actual_uid_signed_capture_witnessed_cursor_and_retained_result(f):
    c = Child(f, True)
    assert c.initial.get("ready"), c.initial
    f.capture()
    r = c.command("observe")
    assert r["status"]["pending"] == 1 and r["status"]["input_records"] == 1
    r = c.command("commit")
    assert r["outcomes"] == 1 and r["status"]["committed"] == 1
    denied = c.command("probe", paths=[str(f.pk), str(f.wk), str(f.anchors)])["denied"]
    assert denied == [True, True, True]
    c.close()
    c = Child(f)
    assert c.initial.get("ready"), c.initial
    assert c.initial["status"]["committed"] == 1 and c.initial["status"]["lost"] == 0
    c.close()
    f.halt()
    with WitnessStore(f.p, f.wk) as store:
        assert (
            store.state["journal_seq"]
            == json.loads(f.journal.read_bytes().splitlines()[-1])["seq"]
        )
        assert store.state["source_seq"] == 1


@pytest.mark.parametrize("phase", ["empty", "unread", "begun", "cursor", "committed"])
def test_sigkill_resumes_only_with_matching_protected_witness_and_keeps_loss(f, phase):
    c = Child(f, True)
    assert c.initial.get("ready"), c.initial
    if phase != "empty":
        f.capture("killed")
    if phase == "begun":
        assert c.command("begin")["status"]["pending"] == 1
    if phase in ("cursor", "committed"):
        assert c.command("observe")["status"]["pending"] == 1
    if phase == "committed":
        assert c.command("commit")["outcomes"] == 1
    c.kill()
    c = Child(f)
    assert c.initial.get("ready"), c.initial
    s = c.initial["status"]
    assert s["committed"] == (phase == "committed")
    assert (
        s["lost"] == (phase not in ("empty", "committed"))
        and not s["new_admission_closed"]
    )
    c.close()


@pytest.mark.parametrize(
    "rollback", ["journal", "both", "source-unconsumed", "signed-fork"]
)
def test_protected_witness_rejects_valid_old_or_equivocated_history(f, rollback):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    old_j = f.journal.read_bytes()
    old_source = f.source.read_bytes()
    c = Child(f)
    assert c.initial.get("ready")
    f.capture("first")
    c.command("begin")
    c.kill()
    witness_before = f.anchors.read_bytes()
    if rollback in ("journal", "both"):
        f.journal.write_bytes(old_j)
    if rollback in ("both", "source-unconsumed"):
        f.source.write_bytes(old_source)
    if rollback == "signed-fork":
        f.source.write_bytes(b"")
        f.capture("different-valid-signature")
    before = f.journal.read_bytes()
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == witness_before


def test_unwitnessed_journal_tail_refuses_automatic_catchup(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    f.capture()
    before = f.anchors.read_bytes()
    r = c.command("fail_ack")
    assert r["refused"] and not r["status"]["continuity_available"]
    c.close()
    after = f.journal.read_bytes()
    assert f.anchors.read_bytes() == before
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == after and f.anchors.read_bytes() == before


def test_lost_response_after_durable_witness_ack_recovers_as_loss(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    f.capture()
    r = c.command("lost_ack")
    assert r["refused"] and not r["status"]["continuity_available"]
    c.close()
    c = Child(f)
    assert c.initial.get("ready"), c.initial
    assert c.initial["status"]["lost"] == 1 and c.initial["status"]["committed"] == 0
    c.close()


def test_witness_unavailable_never_falls_back_to_v2_or_eof(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    f.halt()
    before = f.journal.read_bytes()
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == before


def test_wrong_peer_uid_rejected_without_anchor_write(f):
    before = f.anchors.read_bytes()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(f.p.data["socket_path"])
        send_message(
            conn, dict(op="read", nonce="a" * 64, counter=0, anchor_head="0" * 64)
        )
        assert recv_message(conn) == {"error": "continuity_unavailable"}
    assert f.anchors.read_bytes() == before


@pytest.mark.parametrize("fault", ["signature", "partial", "missing", "mode"])
def test_witness_state_cannot_be_repaired_or_reinitialized_silently(f, fault):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    f.halt()
    if fault == "signature":
        f.anchors.write_bytes(
            f.anchors.read_bytes().replace(b'"journal_seq":0', b'"journal_seq":1', 1)
        )
    elif fault == "partial":
        f.anchors.write_bytes(f.anchors.read_bytes()[:-3])
    elif fault == "missing":
        f.anchors.unlink()
    else:
        f.anchors.chmod(0o644)
    with pytest.raises(OSError):
        WitnessStore(f.p, f.wk)
    with pytest.raises(OSError):
        WitnessStore(f.p, f.wk, initialize=True)


def test_witness_fsync_failure_does_not_ack_and_poison_is_not_retried(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    f.halt()
    with WitnessStore(f.p, f.wk) as store:
        before = store.counter
        state = dict(store.state)
        state["journal_seq"] += 1
        with patch("os.fsync", side_effect=OSError("injected storage failure")):
            with pytest.raises(OSError):
                store._append(state)
        assert store.counter == before and store.poisoned
        with patch("os.write", side_effect=AssertionError("no retries")):
            with pytest.raises(OSError):
                store._append(state)


def test_old_valid_witness_response_is_not_fresh_authorization(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    real = WitnessStore.request
    captured = []

    def replay(store, request):
        result = real(store, request)
        if request["op"] == "read":
            if captured:
                return captured[0]
            captured.append(result)
        return result

    with patch.object(WitnessStore, "request", replay):
        c = Child(f)
        assert c.initial.get("ready")
        c.close()
        before = f.journal.read_bytes()
        anchors = f.anchors.read_bytes()
        c = Child(f)
        assert c.initial.get("startup_refused"), c.initial
        c.close()
        assert f.journal.read_bytes() == before and f.anchors.read_bytes() == anchors


def test_producer_cannot_read_witness_key_or_rewrite_anchor(f):
    script = """
import sys,json
result=[]
for name in sys.argv[1:]:
 try:open(name,'rb').read();result.append(False)
 except PermissionError:result.append(True)
print(json.dumps(result))
"""
    out = subprocess.run(
        [sys.executable, "-c", script, str(f.wk), str(f.anchors)],
        user=1000,
        group=1000,
        extra_groups=[],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(out.stdout) == [True, True]


@pytest.mark.parametrize("fault", ["payload", "unsigned", "partial"])
def test_bad_source_authentication_never_reaches_recovery_writes(f, fault):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    f.capture()
    if fault == "payload":
        f.source.write_bytes(
            f.source.read_bytes().replace(b'"sid":1001', b'"sid":1002')
        )
    elif fault == "unsigned":
        f.source.write_bytes(_json(event()) + b"\n")
    else:
        f.source.write_bytes(f.source.read_bytes()[:-3])
    before = f.journal.read_bytes()
    anchors = f.anchors.read_bytes()
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == anchors


def test_anchor_capacity_has_no_unprotected_ack_fallback():
    f = Fixture()
    try:
        f.p = TrustPolicy({**f.p.data, "anchor_max_records": 2})
        f.policy_file.write_bytes(_json(dict(f.p.data)))
        f.start(initialize=True)
        c = Child(f, True)
        assert c.initial.get("startup_refused"), c.initial
        c.close()
        f.halt()
        with WitnessStore(f.p, f.wk) as store:
            assert store.counter == 2
        before = f.journal.read_bytes()
        f.start()
        c = Child(f)
        assert c.initial.get("startup_refused"), c.initial
        c.close()
        assert f.journal.read_bytes() == before
    finally:
        f.clean()


FOREGROUND = r"""
import json,sys
from pathlib import Path
from unittest.mock import patch
from azazel_edge.outcome import input_resume as driver,telemetry
from azazel_edge.outcome.input_auth import TrustPolicy
from test_outcome_telemetry_g3 import FakeSource,policy
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer');d=p.data
clock={'wall':100.,'mono':0.};polls=[]
def sleep(_):
 polls.append(True);clock['wall']+=1;clock['mono']+=1
 print(json.dumps({'tick':len(polls)}),flush=True)
 if len(polls)==8:raise KeyboardInterrupt
 if not sys.stdin.readline():raise OSError('test controller lost')
with patch.object(driver.OutcomeTelemetryPolicy,'from_file',return_value=policy()),patch.object(driver,'LinuxProcTelemetrySource',FakeSource),patch.object(driver.time,'time',lambda:clock['wall']),patch.object(driver.time,'monotonic',lambda:clock['mono']),patch.object(driver.time,'sleep',sleep):
 try:
  telemetry.run_live(input_path=Path(d['source_path']),output_path=Path(d['journal_directory'])/'projection.jsonl',policy_path=Path('unused'),interface='br0',journal_directory=Path(d['journal_directory']),journal_scope=d['scope_ref'],journal_boot_id='observer-boot',initialize_journal=True,resume_input=True,authentication_policy=Path(sys.argv[1]))
 except KeyboardInterrupt:print(json.dumps({'done':True}),flush=True)
"""


def test_real_foreground_dispatch_uses_public_verification_and_witness_before_emission(
    f,
):
    env = dict(
        os.environ,
        PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py") + ":" + str(ROOT / "tests"),
    )
    process = subprocess.Popen(
        [sys.executable, "-c", FOREGROUND, str(f.policy_file)],
        cwd=ROOT,
        env=env,
        user=65534,
        group=65534,
        extra_groups=[],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for n in range(1, 9):
            assert select.select([process.stdout], [], [], 20)[0]
            line = process.stdout.readline()
            assert line, process.stderr.read()
            assert json.loads(line) == {"tick": n}
            if n == 4:
                f.capture("fresh", 104)
            if n < 8:
                process.stdin.write("continue\n")
                process.stdin.flush()
        assert json.loads(process.stdout.readline()) == {"done": True}
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    rows = [
        json.loads(line)
        for line in (Path(f.p.data["journal_directory"]) / "projection.jsonl")
        .read_text()
        .splitlines()
    ]
    assert len(rows) == 1 and rows[0]["outcome"]["decision_id"] == "fresh"
    assert rows[0]["outcome"]["causal_support"] == "inconclusive"
    f.halt()
    with WitnessStore(f.p, f.wk) as store:
        frame = json.loads(f.journal.read_bytes().splitlines()[-1])
        assert (
            store.state["journal_seq"] == frame["seq"]
            and store.state["journal_head"] == frame["sha256"]
        )


def test_valid_old_anchor_log_alone_still_refuses_current_journal(f):
    old = f.anchors.read_bytes()
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    f.halt()
    before = f.journal.read_bytes()
    f.anchors.write_bytes(old)
    f.start()
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == old


def test_producer_peer_cannot_use_observer_witness_protocol(f):
    script = """
import json,sys,socket
from azazel_edge.outcome.input_witness import send_message,recv_message
try:
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
  c.settimeout(2);c.connect(sys.argv[1])
  send_message(c,dict(op='read',nonce='a'*64,counter=0,anchor_head='0'*64))
  print(json.dumps(recv_message(c)))
except OSError:print(json.dumps({'error':'continuity_unavailable'}))
"""
    before = f.anchors.read_bytes()
    env = dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py"))
    result = subprocess.run(
        [sys.executable, "-c", script, f.p.data["socket_path"]],
        user=1000,
        group=1000,
        extra_groups=[],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert json.loads(result.stdout) == {"error": "continuity_unavailable"}
    assert f.anchors.read_bytes() == before


def test_fresh_unverified_scope_does_not_create_journal_when_witness_absent(f):
    f.halt()
    before = f.anchors.read_bytes()
    c = Child(f, True)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert list(Path(f.p.data["journal_directory"]).iterdir()) == []
    assert f.anchors.read_bytes() == before


def test_missing_crypto_profile_cannot_create_or_downgrade_authenticated_scope(f):
    script = """
import builtins,sys
from pathlib import Path
from azazel_edge.outcome import telemetry
real=builtins.__import__
def missing(name,*args,**kwargs):
 if name.startswith('cryptography'):raise ImportError('injected missing profile')
 return real(name,*args,**kwargs)
builtins.__import__=missing
try:
 telemetry.main(['--policy','unused','--input',sys.argv[2],'--output',sys.argv[3],
 '--journal-directory',sys.argv[4],'--journal-scope','scope-a','--journal-boot-id','observer-boot',
 '--journal-initialize','--journal-resume-input','--input-auth-policy',sys.argv[1]])
except OSError as exc:
 assert 'preprovisioned optional profile' in str(exc)
 print('refused')
"""
    # Use a real policy file for the ordinary G3 policy so refusal reaches the
    # requested cryptographic profile rather than failing at missing G3 config.
    from test_outcome_telemetry_g3 import POLICY_SCHEMA_VERSION

    normal = f.root / "normal.json"
    normal.write_text(
        json.dumps(
            dict(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_version="test-policy-v1",
                actions={},
            )
        )
    )
    normal.chmod(0o644)
    script = script.replace("'--policy','unused'", "'--policy',sys.argv[5]")
    env = dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py"))
    before = f.anchors.read_bytes()
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(f.policy_file),
            str(f.source),
            str(Path(f.p.data["journal_directory"]) / "projection"),
            f.p.data["journal_directory"],
            str(normal),
        ],
        user=65534,
        group=65534,
        extra_groups=[],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert out.stdout.strip() == "refused"
    assert list(Path(f.p.data["journal_directory"]).iterdir()) == []
    assert f.anchors.read_bytes() == before


def test_live_same_size_anchor_corruption_cannot_authorize_restart(f):
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    raw = f.anchors.read_bytes()
    changed = raw.replace(b'"journal_seq":0', b'"journal_seq":1', 1)
    assert len(changed) == len(raw) and changed != raw
    f.anchors.write_bytes(changed)
    before = f.journal.read_bytes()
    c = Child(f)
    assert c.initial.get("startup_refused"), c.initial
    c.close()
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == changed


def test_root_owned_anchor_below_observer_writable_ancestor_is_refused():
    f = Fixture()
    try:
        unsafe = f.root / "observer-owned"
        unsafe.mkdir(mode=0o755)
        os.chown(unsafe, 65534, 65534)
        protected = unsafe / "anchors"
        protected.mkdir(mode=0o700)
        f.p = TrustPolicy({**f.p.data, "anchor_directory": str(protected)})
        with pytest.raises(OSError, match="ancestor"):
            WitnessStore(f.p, f.wk, initialize=True)
        assert list(protected.iterdir()) == []
    finally:
        f.clean()


# Registered origin uses the real compiled core, not a Python look-alike. CI
# builds it explicitly; root-stage absence is a failure, never a skipped pass.
ORIGIN_WORKER = r"""
import sys,json
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter
from azazel_edge.outcome.input_origin import RegisteredOrigin
try:
 p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer')
 origin=RegisteredOrigin(p,Path(sys.argv[3]))
 with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref='origin-boot') as writer:
  origin.bind(writer)
  print('{"ready":true}',flush=True)
  for command in sys.stdin:
   if command.strip()=='close': break
   origin.poll(writer)
   print(json.dumps({'seq':writer.verifier.seq}),flush=True)
 origin.close()
except Exception as e:
 print(json.dumps({'refused':True,'error':str(e)}),flush=True)
 sys.exit(1)
"""


def register_origin(f):
    import hashlib

    core = Path(
        os.environ.get(
            "EDGE_ORIGIN_TEST_CORE",
            str(ROOT / "rust/azazel-edge-core/target/debug/azazel-edge-core"),
        )
    )
    assert core.is_file(), "real Rust origin must be built for this stage"
    f.binary = f.root / "core"
    shutil.copyfile(core, f.binary)
    f.binary.chmod(0o755)
    f.raw = f.root / "eve.json"
    f.raw.write_bytes(b'{"event_type":"stats"}\n')
    f.raw.chmod(0o644)
    info = f.raw.stat()
    r = dict(
        schema_version="outcome-origin-registration/v1",
        mode="readonly-core",
        **{
            k: f.p.data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path=str(f.binary),
        binary_sha256=hashlib.sha256(f.binary.read_bytes()).hexdigest(),
        raw_path=str(f.raw),
        raw_uid=0,
        raw_device=info.st_dev,
        raw_inode=info.st_ino
    )
    f.registration = f.root / "registration.json"
    data = _json(r)
    f.registration.write_bytes(data)
    f.registration.chmod(0o644)
    f.p = TrustPolicy(
        {
            **dict(f.p.data),
            "schema_version": "outcome-input-trust/v2",
            "origin_registration_sha256": hashlib.sha256(data).hexdigest(),
        }
    )
    f.policy_file.write_bytes(_json(dict(f.p.data)))


class OriginChild:
    def __init__(self, f):
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                ORIGIN_WORKER,
                str(f.policy_file),
                str(f.pk),
                str(f.registration),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
            user=1000,
            group=1000,
            extra_groups=[],
        )
        self.initial = self.read()

    def read(self):
        assert select.select([self.process.stdout], [], [], 15)[0], "origin timed out"
        line = self.process.stdout.readline()
        assert line, self.process.stderr.read()
        return json.loads(line)

    def poll(self):
        self.process.stdin.write("poll\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write("close\n")
                self.process.stdin.flush()
            except BrokenPipeError:
                pass
        self.process.wait(timeout=15)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


@pytest.fixture
def registered():
    f = Fixture()
    try:
        register_origin(f)
        yield f
    finally:
        f.clean()


def append_raw(f, suffix=b"\n"):
    with f.raw.open("ab") as raw:
        raw.write(
            b'{"event_type":"alert","timestamp":"2026-11-10T00:00:00Z","alert":{"severity":1,"signature_id":42}}'
            + suffix
        )
        raw.flush()
        os.fsync(raw.fileno())


def test_registered_real_core_pipe_signs_and_witness_reopens_without_backfill(
    registered,
):
    f = registered
    f.start(initialize=True)
    observer = Child(f, True)
    assert observer.initial.get("ready")
    origin = OriginChild(f)
    try:
        assert origin.initial.get("ready"), origin.initial
        assert origin.poll() == {"seq": 0}  # Pre-start stats never replayed.
        append_raw(f)
        assert origin.poll() == {"seq": 1}
        wire = json.loads(f.source.read_bytes())
        assert wire["event"]["normalized"]["sid"] == 42
        assert wire["event"]["enforcement"]["executed_count"] == 0
        assert (
            wire["event"]["capture_origin"]["raw_cursor"]["offset"]
            == f.raw.stat().st_size
        )
        assert SourceVerifier(f.p).verify(f.source.read_bytes())["seq"] == 1
    finally:
        origin.close()
        observer.close()
    # Verified raw prefix and signed sequence survive a new producer. Bytes
    # arriving while it was absent are excluded, not re-signed or reconstructed.
    append_raw(f)
    origin = OriginChild(f)
    try:
        assert origin.initial.get("ready"), origin.initial
        assert origin.poll() == {"seq": 1}
        append_raw(f)
        assert origin.poll() == {"seq": 2}
    finally:
        origin.close()
    observer = Child(f)
    try:
        assert observer.initial.get("ready"), observer.initial
    finally:
        observer.close()


@pytest.mark.parametrize(
    "fault",
    [
        "missing_registration",
        "digest",
        "binary",
        "key",
        "owner",
        "symlink",
        "raw_identity",
        "partial",
        "malformed",
        "legacy",
    ],
)
def test_origin_registration_refuses_without_signed_append(registered, fault):
    f = registered
    if fault == "missing_registration":
        f.registration.unlink()
    elif fault == "digest":
        f.registration.write_bytes(f.registration.read_bytes() + b" ")
    elif fault == "binary":
        f.binary.write_bytes(b"\x7fELFbad")
    elif fault == "key":
        f.pk.write_bytes(b"x" * 32)
    elif fault == "owner":
        os.chown(f.registration, 1000, 1000)
    elif fault == "symlink":
        target = f.root / "real-registration"
        f.registration.rename(target)
        f.registration.symlink_to(target)
    elif fault == "raw_identity":
        f.raw.rename(f.root / "old-eve")
        f.raw.write_bytes(b"{}\n")
    elif fault == "partial":
        f.raw.write_bytes(b"{")
    elif fault == "malformed":
        f.raw.write_bytes(b'{"duplicate":1,"duplicate":2}\n')
    elif fault == "legacy":
        d = dict(f.p.data)
        d.pop("origin_registration_sha256")
        d["schema_version"] = "outcome-input-trust/v1"
        f.policy_file.write_bytes(_json(d))
    origin = OriginChild(f)
    try:
        assert origin.initial.get("refused"), origin.initial
    finally:
        origin.close()
    assert f.source.read_bytes() == b""


@pytest.mark.parametrize(
    "fault",
    [
        "rewrite",
        "truncate",
        "replace",
        "malformed",
        "oversize",
        "partial",
        "binary_replaced",
        "restart_rewind",
    ],
)
def test_origin_live_failure_and_sealed_binary(registered, fault):
    f = registered
    origin = OriginChild(f)
    try:
        assert origin.initial.get("ready"), origin.initial
        append_raw(f)
        assert origin.poll() == {"seq": 1}
        before = f.source.read_bytes()
        if fault == "rewrite":
            f.raw.write_bytes(
                b'{"event_type":"other"}\n' + f.raw.read_bytes().split(b"\n", 1)[1]
            )
        elif fault == "truncate":
            f.raw.write_bytes(b"")
        elif fault == "replace":
            old = f.root / "old-eve"
            f.raw.rename(old)
            f.raw.write_bytes(old.read_bytes())
        elif fault == "malformed":
            with f.raw.open("ab") as out:
                out.write(b'{"duplicate":1,"duplicate":2}\n')
        elif fault == "oversize":
            with f.raw.open("ab") as out:
                out.write(b"x" * 65537)
        elif fault == "partial":
            append_raw(f, b"")
            assert origin.poll() == {"seq": 1}
            with f.raw.open("ab") as out:
                out.write(b"\n")
            assert origin.poll() == {"seq": 2}
            return
        elif fault == "binary_replaced":
            f.binary.write_bytes(b"\x7fELFbad")
            append_raw(f)
            assert origin.poll() == {"seq": 2}  # Already sealed enrolled image only.
            origin.close()
            origin = OriginChild(f)
            assert origin.initial.get("refused")
            return
        elif fault == "restart_rewind":
            origin.close()
            f.raw.write_bytes(b'{"event_type":"stats"}\n')
            origin = OriginChild(f)
            assert origin.initial.get("refused")
            assert f.source.read_bytes() == before
            return
        assert origin.poll().get("refused")
        assert f.source.read_bytes() == before
    finally:
        origin.close()


def test_offline_enrollment_candidate_pins_key_binary_and_raw_without_writes(
    registered,
):
    import hashlib
    from azazel_edge.outcome.input_enroll import prepare

    f = registered
    d = dict(f.p.data)
    d.pop("origin_registration_sha256")
    d["schema_version"] = "outcome-input-trust/v1"
    p = TrustPolicy(d)
    before = {
        path: path.read_bytes()
        for path in (f.source, f.policy_file, f.registration, f.pk, f.binary, f.raw)
    }
    candidate = prepare(p, f.binary, f.raw, 0)
    assert candidate["trust_policy"] == dict(f.p.data)
    assert (
        hashlib.sha256(_json(candidate["registration"])).hexdigest()
        == f.p.data["origin_registration_sha256"]
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())
    with pytest.raises(OSError):
        prepare(f.p, f.binary, f.raw, 0)
    f.source.write_bytes(b"not-empty")
    with pytest.raises(OSError):
        prepare(p, f.binary, f.raw, 0)


def test_registered_observer_cannot_downgrade_existing_journal(registered):
    f = registered
    f.start(initialize=True)
    c = Child(f, True)
    assert c.initial.get("ready")
    c.close()
    before = f.journal.read_bytes()
    anchors = f.anchors.read_bytes()
    d = dict(f.p.data)
    d.pop("origin_registration_sha256")
    d["schema_version"] = "outcome-input-trust/v1"
    f.policy_file.write_bytes(_json(d))
    c = Child(f)
    try:
        assert c.initial.get("startup_refused"), c.initial
    finally:
        c.close()
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == anchors


def test_unregistered_direct_capture_api_never_writes_source(registered):
    f = registered
    script = r"""
from pathlib import Path
import sys
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer')
with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref='boot') as writer:
 try:writer.append({'pipeline':'rust_event_engine_v1'})
 except OSError:print('refused')
 else:raise AssertionError('unsigned enrollment bypass')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(f.policy_file), str(f.pk)],
        env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
        capture_output=True,
        text=True,
        user=1000,
        group=1000,
        extra_groups=[],
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "refused"
    assert f.source.read_bytes() == b""


def test_real_origin_ignores_enforcement_environment_and_never_enters_runtime(
    registered,
):
    f = registered
    unexpected = f.root / "must-not-create"
    env = dict(
        os.environ,
        AZAZEL_DEFENSE_ENFORCE="1",
        AZAZEL_DEFENSE_DRY_RUN="0",
        AZAZEL_FORWARD_AI="1",
        AZAZEL_FORWARD_LOG="1",
        AZAZEL_EVENT_STDOUT="off",
        AZAZEL_DEFENSE_RELEASE_LEDGER=str(unexpected),
        AZAZEL_NORMALIZED_EVENT_LOG=str(unexpected),
        AZAZEL_REDIRECT_POLICY_PATH=str(unexpected),
        AZAZEL_EVE_PATH=str(unexpected),
    )
    for args in (["--capture-origin-once"], ["--capture-origin-once", "--from-start"]):
        result = subprocess.run(
            [str(f.binary), *args],
            input='{"event_type":"alert","alert":{"severity":1,"signature_id":42}}\n',
            env=env,
            capture_output=True,
            text=True,
            user=1000,
            group=1000,
            extra_groups=[],
            timeout=15,
        )
        if len(args) == 1:
            assert result.returncode == 0, result.stderr
            event = json.loads(result.stdout)
            assert event["enforcement_status"]["enforce_enabled"] is False
            assert event["enforcement"]["executed_count"] == 0
            assert event["enforcement"]["command_plan"] == []
        else:
            assert result.returncode != 0
        assert not unexpected.exists()
        assert f.source.read_bytes() == b""
