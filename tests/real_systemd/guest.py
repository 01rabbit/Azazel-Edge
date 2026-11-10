"""Destructive fixed-unit lab, ONLY in a newly allocated marked disposable VM.

This is an integration driver, not an installer or production recovery tool.
No downloads, real keys, enforcement, model, provider or external TCP listener.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests")]
from auth_input_helpers import make_policy
from test_outcome_input_auth_linux import Child
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome.input_service import prepare, provision, verify
from azazel_edge.outcome.input_witness import WitnessStore
from azazel_edge.outcome.service_switch import Switch, Systemd, UNIT, digest

BASE = Path("/var/lib/edge400-systemd-lab")
BUNDLE = BASE / "bundle"
UNITS = Path("/etc/systemd/system")
WITNESS = "edge400-lab-witness.service"
PYTHON = Path(sys.executable)
CORE = Path("/usr/local/bin/azazel-edge-core")
MAGIC = "edge400 dedicated disposable VM; no production state\n"
ENV = {
    "AZAZEL_EVE_PATH": str(BASE / "eve.json"),
    "AZAZEL_NORMALIZED_EVENT_LOG": str(BASE / "native/log.jsonl"),
    "AZAZEL_DEFENSE_RELEASE_LEDGER": str(BASE / "native/ledger.json"),
    "AZAZEL_REDIRECT_POLICY_PATH": str(BASE / "native/no-redirect.yaml"),
    "AZAZEL_PROTECTED_FLOWS_PATH": str(BASE / "native/no-protected.yaml"),
    "AZAZEL_EVE_POLL_MS": "10",
    "AZAZEL_EVE_FROM_START": "0",
    "AZAZEL_FORWARD_AI": "0",
    "AZAZEL_FORWARD_LOG": "0",
    "AZAZEL_EVENT_STDOUT": "off",
    "AZAZEL_DEFENSE_ENFORCE": "0",
    "AZAZEL_DEFENSE_DRY_RUN": "1",
}


def command(*args, check=True):
    return subprocess.run(
        args, check=check, capture_output=True, text=True, timeout=100
    )


def guard():
    assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
    assert Path("/etc/edge400-disposable-vm").read_text() == MAGIC
    assert command("systemd-detect-virt", "--vm").stdout.strip()
    assert not command("ip", "-4", "route", "show", "default").stdout.strip()
    assert not command("ip", "-6", "route", "show", "default").stdout.strip()


def write(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
        f.flush()
        os.fsync(f.fileno())


def record(case, **details):
    value = dict(case=case, result="pass", boot_id=boot(), **details)
    with (BASE / "results.jsonl").open("a") as f:
        f.write(json.dumps(value, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps(value, sort_keys=True), flush=True)


def boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def fixture():
    p, _ = verify(BUNDLE)
    return SimpleNamespace(p=p, policy_file=BUNDLE / "trust.json")


def systemctl(*args, check=True):
    return command("systemctl", *args, check=check)


def wait_for(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("bounded transition deadline")


def source():
    return (BUNDLE / "input").read_bytes()


def events():
    data = source()
    SourceVerifier(fixture().p).verify(data)
    return [json.loads(line)["event"] for line in data.splitlines()]


def live():
    s = Systemd()

    def check():
        try:
            state = s.snapshot()
            cores = s.cores()
            if state["ActiveState"] != "active" or len(cores) != 1:
                return False
            s.capture_ready(BUNDLE, fixture().p, int(state["MainPID"]), 0)
            return cores[0]["pid"]
        except OSError:
            return False

    return wait_for(check)


def stop():
    systemctl("stop", UNIT)
    wait_for(lambda: not Systemd().cores())
    wait_for(lambda: SourceVerifier(fixture().p).verify(source()) and source_closed())


def source_closed():
    v = SourceVerifier(fixture().p)
    v.verify(source())
    return v.live_state.closed


def observer(create=False):
    child = Child(fixture(), create)
    try:
        assert child.initial.get("ready"), child.initial
        assert child.initial["status"]["committed"] == 0
        return child.initial["status"]
    finally:
        child.close()


def failed_start(case):
    before = source()
    anchor = (BUNDLE / "witness/anchors/anchors.journal").read_bytes()
    systemctl("reset-failed", UNIT, check=False)
    systemctl("start", UNIT, check=False)
    wait_for(
        lambda: Systemd().snapshot()["ActiveState"] == "failed"
        and not Systemd().cores()
    )
    time.sleep(0.25)
    assert source() == before
    assert (BUNDLE / "witness/anchors/anchors.journal").read_bytes() == anchor
    record(case, source_sha256=hashlib.sha256(before).hexdigest(), native_processes=0)


def order():
    def properties(unit):
        raw = systemctl(
            "show",
            unit,
            "-p",
            "ActiveEnterTimestampMonotonic",
            "-p",
            "ExecMainStartTimestampMonotonic",
        ).stdout
        return dict(line.split("=", 1) for line in raw.splitlines())

    witness = int(properties(WITNESS)["ActiveEnterTimestampMonotonic"])
    core = int(properties(UNIT)["ExecMainStartTimestampMonotonic"])
    assert 0 < witness <= core
    return dict(witness_ready_us=witness, launcher_start_us=core)


def alert(sid):
    event = dict(
        timestamp="2026-11-10T00:00:00Z",
        event_type="alert",
        src_ip="192.0.2.1",
        dest_ip="192.0.2.2",
        dest_port=22,
        proto="TCP",
        alert=dict(
            signature_id=sid, signature="synthetic lab", category="test", severity=2
        ),
    )
    with (BASE / "eve.json").open("a") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()
        os.fsync(f.fileno())


def saw(sid):
    return any(e.get("normalized", {}).get("sid") == sid for e in events())


def prepare_lab():
    assert not BASE.exists() and not (UNITS / UNIT).exists()
    assert not (UNITS / WITNESS).exists()
    assert not (UNITS / (UNIT + ".d")).exists()
    BASE.mkdir(mode=0o755)
    (BASE / "native").mkdir(mode=0o700)
    write(BASE / "eve.json", "")
    p, _, _, pk, wk = make_policy(BASE, producer=61001, observer=61002, witness=0)
    p = TrustPolicy(
        {**dict(p.data), "scope_ref": "systemd-lab-" + secrets.token_hex(8)}
    )
    # Key generation is confined to the synthetic lab fixture, never runtime.
    write(BASE / "template.json", json.dumps(dict(p.data)))
    write(BASE / "environment.json", json.dumps(ENV))
    write(BASE / "producer.raw", pk, 0o600)
    write(BASE / "witness.raw", wk, 0o600)
    candidates = prepare(
        BUNDLE, BASE / "template.json", CORE, BASE / "environment.json"
    )
    write(BASE / "trust-live.json", json.dumps(candidates["trust_policy"]))
    write(
        BASE / "origin.json",
        json.dumps(candidates["registration"], sort_keys=True, separators=(",", ":")),
    )
    provision(
        BUNDLE,
        BASE / "trust-live.json",
        BASE / "origin.json",
        BASE / "producer.raw",
        BASE / "witness.raw",
    )
    p = fixture().p
    with WitnessStore(p, BUNDLE / "witness/key.raw", initialize=True):
        pass
    write(
        UNITS / WITNESS,
        f"""[Unit]
Description=Disposable Edge400 lab witness; never a production installer
[Service]
Type=notify
NotifyAccess=main
User=root
Group=root
ExecStartPre=/bin/sleep 1
ExecStart={PYTHON} -I -m azazel_edge.outcome.input_witness --policy {BUNDLE}/trust.json --private-key {BUNDLE}/witness/key.raw --systemd-notify
Restart=no
TimeoutStartSec=10
TimeoutStopSec=5
RestrictAddressFamilies=AF_UNIX
""",
    )
    settings = "\n".join(
        "Environment=" + json.dumps(k + "=" + v) for k, v in ENV.items()
    )
    # Dependency-free ordinary test unit: no AI/Suricata/activation service.
    # Preserve native ExecStart and ordinary restart semantics, freeze all env.
    write(
        UNITS / UNIT,
        f"""[Unit]
Description=Disposable Edge400 lab normal core
Wants={WITNESS}
After={WITNESS}
[Service]
Type=simple
{settings}
ExecStart={CORE}
RestrictAddressFamilies=AF_UNIX
Restart=always
RestartPreventExitStatus=3
RestartSec=2
[Install]
WantedBy=multi-user.target
""",
    )
    systemctl("daemon-reload")
    systemctl("start", WITNESS)
    observer(True)
    record(
        "prepared-new-empty-synthetic-scope",
        virtualization=command("systemd-detect-virt", "--vm").stdout.strip(),
        systemd=command("systemctl", "--version").stdout.splitlines()[0],
        source_commit=(SRC / "SOURCE_REVISION").read_text().strip(),
    )


def exercise():
    systemctl("start", UNIT)
    wait_for(lambda: len(Systemd().cores()) == 1)
    switch = Switch(BUNDLE)
    hooks = UNITS / (UNIT + ".d")
    hooks.mkdir(mode=0o755)
    write(hooks / "10-lab-hook.conf", "[Service]\nExecStop=/bin/false\n")
    systemctl("daemon-reload")
    ordinary_pid = Systemd().cores()[0]["pid"]
    try:
        switch.plan()
    except OSError:
        pass
    else:
        raise AssertionError("configured lifecycle hook accepted")
    assert Systemd().cores()[0]["pid"] == ordinary_pid and source() == b""
    (hooks / "10-lab-hook.conf").unlink()
    systemctl("daemon-reload")
    record("real-configured-hook-refused-before-stop")
    plan = switch.plan()
    write(BASE / "reviewed-plan.json", json.dumps(plan), 0o600)
    result = switch.apply(plan, digest(plan))
    assert result["status"] == "started"
    pid = live()
    record("real-single-unit-handoff", native_processes=1, **order())
    before = source()
    duplicate = subprocess.run(
        [str(CORE)],
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **ENV},
        capture_output=True,
        timeout=5,
    )
    assert duplicate.returncode == 3 and source() == before and live() == pid
    duplicate = command(
        str(PYTHON),
        "-I",
        "-m",
        "azazel_edge.outcome.input_live",
        "--policy",
        str(BUNDLE / "trust.json"),
        "--registration",
        str(BUNDLE / "origin.json"),
        "--private-key",
        str(BUNDLE / "producer/key.raw"),
        "--boot-ref",
        boot(),
        check=False,
    )
    assert duplicate.returncode != 0 and source() == before and live() == pid
    systemctl("start", UNIT)
    assert live() == pid and source() == before
    record("ordinary-signed-and-systemctl-duplicate-exclusion", native_processes=1)
    alert(700001)
    wait_for(lambda: saw(700001))
    assert all(e.get("enforcement", {}).get("executed_count", 0) == 0 for e in events())
    stop()
    observer()
    alert(700002)  # real unread downtime input, never replayed on restart
    systemctl("start", UNIT)
    live()
    alert(700003)
    wait_for(lambda: saw(700003))
    assert not saw(700002)
    record("downtime-input-excluded-not-backfilled")
    systemctl("restart", UNIT)
    pid = live()
    record("real-systemctl-restart", **order())
    # Wants+After: witness loss must NOT propagate Stop to running defense.
    systemctl("stop", WITNESS)
    assert Systemd().cores()[0]["pid"] == pid
    old = source()
    try:
        Systemd().witness(BUNDLE, fixture().p)
    except OSError:
        pass
    else:
        raise AssertionError("missing witness admitted")
    assert source() == old
    record("witness-stop-preserves-running-defense-refuses-proof")
    stop()
    witness_path = UNITS / WITNESS
    saved = witness_path.with_suffix(".saved")
    witness_path.rename(saved)
    witness_path.symlink_to("/dev/null")
    systemctl("daemon-reload")
    failed_start("missing-witness-managed-start-refused")
    witness_path.unlink()
    saved.rename(witness_path)
    systemctl("daemon-reload")
    systemctl("start", WITNESS)
    systemctl("stop", WITNESS)
    witness_key = BUNDLE / "witness/key.raw"
    witness_key.chmod(0o644)
    failed_start("invalid-witness-no-ready-no-connected-start")
    assert systemctl("is-active", WITNESS, check=False).stdout.strip() == "failed"
    witness_key.chmod(0o600)
    systemctl("start", WITNESS)
    # Controlled fault injection on disposable synthetic fixtures only.
    origin = BUNDLE / "origin.json"
    origin.rename(BUNDLE / "origin.unregistered")
    failed_start("unregistered-managed-start-refused")
    (BUNDLE / "origin.unregistered").rename(origin)
    key = BUNDLE / "producer/key.raw"
    key.chmod(0o644)
    failed_start("unsafe-key-managed-start-refused")
    key.chmod(0o600)
    original = source()
    with (BUNDLE / "input").open("ab") as f:
        f.write(b"unsigned\n")
        f.flush()
        os.fsync(f.fileno())
    failed_start("invalid-signature-managed-start-refused")
    write(BASE / "injected-invalid-source", source(), 0o600)
    (BUNDLE / "input").write_bytes(original)  # lab fault rollback, NOT a recovery API
    systemctl("start", UNIT)
    pid = live()
    anchors = (BUNDLE / "witness/anchors/anchors.journal").read_bytes()
    systemctl("kill", "--kill-whom=main", "--signal=KILL", WITNESS)
    wait_for(
        lambda: systemctl("is-active", WITNESS, check=False).stdout.strip() == "failed"
    )
    assert Systemd().cores()[0]["pid"] == pid
    stale = Path(fixture().p.data["socket_path"])
    assert stale.exists()
    systemctl("restart", WITNESS)
    Systemd().witness(BUNDLE, fixture().p)
    assert (BUNDLE / "witness/anchors/anchors.journal").read_bytes() == anchors
    record("witness-sigkill-restart-retains-protected-history")
    stop()
    observer()
    systemctl("stop", WITNESS)
    assert not stale.exists()
    start = time.monotonic()
    systemctl("start", UNIT)
    live()
    assert time.monotonic() - start >= 1
    record("delayed-notify-ready-before-launch", **order())
    systemctl("enable", UNIT)
    write(
        BASE / "preboot.json",
        json.dumps(
            dict(
                boot=boot(),
                prefix_sha256=hashlib.sha256(source()).hexdigest(),
                prefix_size=len(source()),
            )
        ),
    )
    record("awaiting-clean-os-reboot-with-active-capture")


def boot_check():
    saved = json.loads((BASE / "preboot.json").read_text())
    assert boot() != saved["boot"]
    live()
    assert (
        hashlib.sha256(source()[: saved["prefix_size"]]).hexdigest()
        == saved["prefix_sha256"]
    )
    kinds = [e["capture_origin"]["kind"] for e in events()]
    assert kinds[-3:] == ["session_end", "session_prepare", "session_start"], kinds
    record(
        "actual-os-reboot-clean-close-and-verified-restart",
        previous_boot=saved["boot"],
        **order(),
    )
    stop()
    status = observer()
    assert status["committed"] == 0
    record(
        "postboot-observer-independent-recovery-no-fabricated-outcomes",
        excluded=status["missed_input_records"],
    )
    (BUNDLE / "origin.json").rename(BUNDLE / "origin.bad-boot")
    write(
        BASE / "badboot.json",
        json.dumps(
            dict(
                boot=boot(),
                source_sha256=hashlib.sha256(source()).hexdigest(),
                source_size=len(source()),
            )
        ),
    )
    record("awaiting-os-reboot-with-unregistered-origin")


def bad_boot_check():
    saved = json.loads((BASE / "badboot.json").read_text())
    assert boot() != saved["boot"]
    wait_for(
        lambda: Systemd().snapshot()["ActiveState"] == "failed"
        and not Systemd().cores()
    )
    assert (
        len(source()) == saved["source_size"]
        and hashlib.sha256(source()).hexdigest() == saved["source_sha256"]
    )
    record(
        "actual-os-reboot-unregistered-refuses-reconnect-no-backfill",
        previous_boot=saved["boot"],
    )
    # Leave no enabled core; retain all files and failed source for review.
    systemctl("disable", UNIT)
    systemctl("stop", UNIT, WITNESS)
    record("finished-disabled-retained-lab-evidence")


def smoke_finish():
    # CI exercises actual PID1 but does NOT reboot its hosted runner.
    stop()
    observer()
    systemctl("disable", UNIT)
    systemctl("stop", WITNESS)
    record("ci-smoke-finished-os-reboot-not-executed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=("prepare", "exercise", "boot-check", "bad-boot-check", "smoke-finish"),
    )
    parser.add_argument("--allow-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    guard()
    {
        "prepare": prepare_lab,
        "exercise": exercise,
        "boot-check": boot_check,
        "bad-boot-check": bad_boot_check,
        "smoke-finish": smoke_finish,
    }[args.phase]()


if __name__ == "__main__":
    main()
