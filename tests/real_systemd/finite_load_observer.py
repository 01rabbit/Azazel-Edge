"""Explicit v4 enforcing observer entry; no legacy bootstrap or self-stat read."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import select
import sys
import threading
import time

from azazel_edge.outcome import input_auth, input_live, telemetry
from azazel_edge.outcome.confinement import enforce_capture
import native_accounting as accounting
import signed_network_phase_recording as phase
import signed_network_load_clock as clock
import signed_network_normal_stop as normal
from signed_network_recording import _clock_anchor

BASE = Path("/var/lib/edge400-systemd-lab/bundle")
POLICY = (
    Path(__file__).resolve().parents[1] / "fixtures/signed_network_observer_policy.json"
)
PROTOCOL_SHA256 = "9764ea4b3d907f63d53f3526cfeef9f91895af6d8a0de44cc10236f636f8beec"
EXTRA = ("phase", "calls", "context", "completion", "journal", "outcomes")


def need(value, message):
    if not value:
        raise ValueError(message)


def bootstrap(challenge):
    need(
        type(challenge) is str and re.fullmatch("[0-9a-f]{32}", challenge), "challenge"
    )
    enforce_capture("edge400-observer")
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    own = dict(
        pid=os.getpid(),
        ppid=int(fields["PPid"]),
        start_ticks=None,
        uid=int(fields["Uid"].split()[1]),
        gid=int(fields["Gid"].split()[1]),
        groups=[int(v) for v in fields["Groups"].split()],
        apparmor_label=Path("/proc/self/attr/apparmor/current").read_text().strip(),
        cap_eff=int(fields["CapEff"], 16),
        cap_prm=int(fields["CapPrm"], 16),
        cap_bnd=int(fields["CapBnd"], 16),
        cap_amb=int(fields["CapAmb"], 16),
        no_new_privs=fields["NoNewPrivs"].strip() == "1",
    )
    resolutions = {
        k: time.get_clock_info(k).resolution
        for k in ("monotonic", "process_time", "thread_time")
    }
    print(
        json.dumps(
            dict(
                schema_version="edge-finite-load-observer-bootstrap/v1",
                pid=os.getpid(),
                challenge=challenge,
                invocation_id=os.environ.get("INVOCATION_ID"),
                actor=own,
                native_tid=threading.get_native_id(),
                clock_resolutions=resolutions,
            )
        ),
        flush=True,
    )
    need(select.select([sys.stdin], [], [], 20)[0], "Root identity timeout")
    raw = sys.stdin.readline(16385)
    need(len(raw) <= 16384 and raw.endswith("\n"), "Root identity bound")
    go = json.loads(raw)
    need(
        set(go) == {"schema_version", "challenge", "identity"}
        and go["schema_version"] == "edge-finite-load-observer-go/v1"
        and go["challenge"] == challenge,
        "Root GO differs",
    )
    identity = go["identity"]
    need(
        identity["pid"] == os.getpid()
        and identity["native_tid"] == threading.get_native_id()
        and identity["boot_id"]
        == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and identity["clock_resolutions"] == resolutions
        and type(identity["start_ticks"]) is int
        and identity["start_ticks"] > 0,
        "Root incarnation differs",
    )
    return identity


@contextmanager
def bound_identity(identity):
    """Root provenance stays explicit in config/controller; no fabricated self-read."""
    originals = [(module, module._identity) for module in (phase, clock, normal)]

    def observed():
        need(
            identity["pid"] == os.getpid()
            and identity["native_tid"] == threading.get_native_id(),
            "identity thread changed",
        )
        return dict(identity)

    for module, _ in originals:
        module._identity = observed
    try:
        yield
    finally:
        for module, original in originals:
            module._identity = original


class LoadPhaseRecording(phase.PhaseRecording):
    """New initializer only; original phase recorder and old arm gates stay unchanged."""

    def __init__(self, path, *, metadata):
        need(
            set(metadata)
            == {
                "run_id",
                "arm",
                "role",
                "input_sha256",
                "code_sha256",
                "core_sha256",
                "interpreter_sha256",
            },
            "phase metadata",
        )
        need(
            metadata["arm"] in ("load-on", "load-faulted")
            and metadata["role"] == "observer",
            "load arm",
        )
        need(
            all(
                re.fullmatch("[0-9a-f]{64}", metadata[k])
                for k in (
                    "input_sha256",
                    "code_sha256",
                    "core_sha256",
                    "interpreter_sha256",
                )
            ),
            "phase pins",
        )
        self.fd = None
        self.count = self.size = self.span_count = self.active = 0
        self.previous = "0" * 64
        self.previous_write_cost = None
        self.incomplete = self.closed = False
        self.lock, self.local = threading.RLock(), threading.local()
        self.max_rows, self.max_bytes = phase.MAX_ROWS, phase.MAX_BYTES
        self.fd = os.open(
            path,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
        )
        self._append(
            "header",
            dict(
                metadata,
                **phase._identity(),
                limits=dict(max_rows=self.max_rows, max_bytes=self.max_bytes),
                unallocated_footer_flush_overhead=True,
            ),
        )
        need(not self.incomplete, "phase header failed")


def load_config(path, digest):
    path = Path(path)
    need(
        path.parent == Path("/opt/edge400-runtime/finite-load-configs")
        and re.fullmatch(r"load-[0-9a-f]{32}-config\.json", path.name),
        "fixed Root config path required",
    )
    raw = input_auth.read_regular(path, owner=0, mode=0o444, max_bytes=65536)[0]
    need(accounting.sha256(raw) == digest, "config pin differs")
    config = json.loads(raw)
    need(accounting.canonical(config) == raw, "canonical config required")
    need(
        path.name == "load-" + config["metadata"]["run_id"] + "-config.json",
        "config filename/run id differs",
    )
    need(
        set(config)
        == {
            "schema_version",
            "case_id",
            "protocol_sha256",
            "corpus_sha256",
            "registration_sha256",
            "trust_sha256",
            "helper_sha256",
            "paths",
            "metadata",
        },
        "config fields",
    )
    need(
        config["schema_version"] == "edge-finite-load-observer-config/v1"
        and config["case_id"] in ("load-on", "load-faulted")
        and config["protocol_sha256"] == PROTOCOL_SHA256,
        "explicit load profile required",
    )
    paths = config["paths"]
    need(set(paths) == {"registration", "trust", "policy", *EXTRA}, "config paths")
    need(
        paths["registration"] == str(BASE / "origin.json")
        and paths["trust"] == str(BASE / "trust.json")
        and paths["policy"] == str(POLICY),
        "fixed public paths",
    )
    for key in EXTRA:
        need(
            Path(paths[key]).parent == BASE / "observer",
            "existing writable directory only",
        )
    need(len(set(paths.values())) == len(paths), "aliased outputs")
    for key in ("registration", "trust"):
        original = input_auth.read_regular(Path(paths[key]), owner=0, max_bytes=65536)[
            0
        ]
        need(
            accounting.sha256(original) == config[key + "_sha256"], "public pin differs"
        )
    need(
        accounting.sha256(Path(__file__).read_bytes()) == config["helper_sha256"],
        "helper pin differs",
    )
    trust = input_auth.TrustPolicy.from_file(Path(paths["trust"]), role="observer")
    registration = input_live.registration(trust, Path(paths["registration"]))
    need(
        registration["schema_version"] == "outcome-live-origin-registration/v4"
        and registration["environment"].get("AZAZEL_LIVE_ORIGIN_LOAD_COST") == "v1",
        "registered v4 load profile required",
    )
    return config, trust


def audit(create=False):
    from azazel_edge.outcome.input_cursor import BoundedInput
    from azazel_edge.outcome.input_resume import recover_input
    from azazel_edge.outcome.input_witness import InputAuthentication
    from azazel_edge.outcome.journal import ObservationJournal

    trust = input_auth.TrustPolicy.from_file(BASE / "trust.json", role="observer")
    p = trust.data
    policy = telemetry.OutcomeTelemetryPolicy.from_file(POLICY)
    with BoundedInput(
        p["source_path"],
        max_bytes=p["input_max_bytes"],
        max_records=p["input_max_records"],
        authentication=InputAuthentication(trust),
    ) as source:
        with ObservationJournal(
            p["journal_directory"],
            scope_ref=p["scope_ref"],
            policy_ref=telemetry.persistence_context(policy, "lo", 0.05),
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            create=create,
            max_bytes=p["journal_max_bytes"],
            input_source=source,
        ) as journal:
            recover_input(journal, policy)
            return journal.status()


def run(config, trust):
    paths, p = config["paths"], trust.data
    options = {
        "--policy": paths["policy"],
        "--interface": "lo",
        "--sample-interval-seconds": "0.05",
        "--journal-boot-id": Path("/proc/sys/kernel/random/boot_id")
        .read_text()
        .strip(),
    }
    compatible = dict(
        metadata=config["metadata"],
        policy_path=paths["trust"],
        traces=dict(observer=paths["phase"]),
        clock=dict(calls_path=paths["calls"], context_path=paths["context"]),
        normal_stop=dict(profile="phase_and_clock", receipt_path=paths["completion"]),
    )
    recorder = LoadPhaseRecording(paths["phase"], metadata=config["metadata"])
    complete = False
    try:
        with normal.capture_control(compatible, options) as captured:
            with phase.record_observer(recorder):
                with clock.record_observer_clock(
                    paths["calls"],
                    paths["context"],
                    metadata=config["metadata"],
                    policy=json.loads(POLICY.read_bytes()),
                    policy_source_ref=str(POLICY),
                ):
                    telemetry.run_live(
                        input_path=Path(p["source_path"]),
                        output_path=Path(paths["outcomes"]),
                        policy_path=POLICY,
                        interface="lo",
                        poll_seconds=0.05,
                        sample_interval_seconds=0.05,
                        max_output_bytes=8 * 1024 * 1024,
                        journal_directory=Path(p["journal_directory"]),
                        journal_scope=p["scope_ref"],
                        journal_boot_id=options["--journal-boot-id"],
                        initialize_journal=False,
                        journal_max_bytes=p["journal_max_bytes"],
                        journal_max_identities=4096,
                        resume_input=True,
                        input_max_bytes=p["input_max_bytes"],
                        input_max_records=p["input_max_records"],
                        authentication_policy=Path(paths["trust"]),
                    )
                    captured.require_result()
            complete = True
        recorder.close(normal_return=True)
        normal.publish_completion(captured, phase_recorder=recorder)
    finally:
        recorder.close(normal_return=complete)


def main(challenge, config_path=None, config_sha256=None, create=False):
    identity = bootstrap(challenge)
    with bound_identity(identity):
        if config_path is None:
            print(json.dumps(dict(status=audit(create))), flush=True)
        else:
            config, trust = load_config(config_path, config_sha256)
            run(config, trust)
            print(json.dumps(dict(completed=True, anchor=_clock_anchor())), flush=True)
