"""Fixed disposable service-role checks. Never print key/payload bytes."""

import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests")]
from azazel_edge.outcome.confinement import enforce_capture

BASE = Path("/var/lib/edge400-systemd-lab")
BUNDLE = BASE / "bundle"


def status():
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    assert fields["NoNewPrivs"].strip() == "1"
    return dict(
        uid=os.getuid(),
        groups=os.getgroups(),
        cap_eff=int(fields["CapEff"], 16),
        cap_prm=int(fields["CapPrm"], 16),
        cap_amb=int(fields["CapAmb"], 16),
        no_new_privs=True,
        apparmor=Path("/proc/self/attr/apparmor/current").read_text().strip(),
    )


def observer(create):
    from azazel_edge.outcome.input_auth import TrustPolicy
    from azazel_edge.outcome.input_cursor import BoundedInput
    from azazel_edge.outcome.input_witness import InputAuthentication
    from azazel_edge.outcome.journal import ObservationJournal
    from azazel_edge.outcome.input_resume import recover_input
    from azazel_edge.outcome.telemetry import persistence_context
    from test_outcome_telemetry_g3 import policy

    p = TrustPolicy.from_file(BUNDLE / "trust.json", role="observer")
    d = p.data
    enforce_capture("edge400-observer")
    identity = status()
    assert (
        identity["uid"] == 61002
        and identity["cap_eff"] == identity["cap_prm"] == identity["cap_amb"] == 0
    )
    assert set(identity["groups"]) <= {61002}
    with BoundedInput(
        d["source_path"],
        max_bytes=d["input_max_bytes"],
        max_records=d["input_max_records"],
        authentication=InputAuthentication(p),
    ) as source:
        with ObservationJournal(
            d["journal_directory"],
            scope_ref=d["scope_ref"],
            policy_ref=persistence_context(policy(), "br0"),
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            create=create,
            max_bytes=d["journal_max_bytes"],
            input_source=source,
        ) as journal:
            recover_input(journal, policy())
            assert not journal.retained_outcomes()
            print(json.dumps(dict(status=journal.status(), identity=identity)))


def denials(role, pid):
    enforce_capture("edge400-" + role)
    identity = status()
    if role != "witness":
        assert identity["uid"] == {"capture": 61001, "observer": 61002}[role]
        assert identity["cap_eff"] == identity["cap_prm"] == identity["cap_amb"] == 0
    else:
        assert (
            identity["uid"] == 0
            and identity["cap_eff"] == identity["cap_prm"] == 4
            and identity["cap_amb"] == 0
        )
    denied = []

    def expect(name, operation, accepted=(errno.EACCES, errno.EPERM)):
        try:
            result = operation()
        except OSError as exc:
            assert exc.errno in accepted, (name, exc.errno)
            denied.append(name)
        else:
            if isinstance(result, int):
                os.close(result)
            raise AssertionError(name + " unexpectedly allowed")

    expect("aa-world-readable-canary", lambda: os.open(BASE / "aa-denied", os.O_RDONLY))
    for path in (
        [BUNDLE / "witness/key.raw", BUNDLE / "observer/observations.journal"]
        if role == "capture"
        else [BUNDLE / "producer/key.raw", BUNDLE / "witness/key.raw"]
        if role == "observer"
        else [BUNDLE / "producer/key.raw"]
    ):
        expect(
            "cross-role-" + str(path.relative_to(BUNDLE)),
            lambda p=path: os.open(p, os.O_RDONLY),
        )
    expect(
        "systemd-inet-family",
        lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        (errno.EAFNOSUPPORT, errno.EACCES, errno.EPERM),
    )
    expect(
        "systemd-inet6-family",
        lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM),
        (errno.EAFNOSUPPORT, errno.EACCES, errno.EPERM),
    )
    expect(
        "aa-unregistered-exec", lambda: subprocess.run(["/usr/bin/true"], check=True)
    )
    expect(
        "uid-escalation-or-switch", lambda: os.setuid(61003 if role == "witness" else 0)
    )
    expect("signal-core", lambda: os.kill(pid, 0))
    if role == "observer":
        expect(
            "aa-other-write",
            lambda: os.open(BASE / "namespace-canary", os.O_WRONLY),
            (errno.EACCES, errno.EPERM),
        )
    print(json.dumps(dict(identity=identity, denied=denied)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["observer", "denials"])
    parser.add_argument("--create", action="store_true")
    parser.add_argument("--role", choices=["capture", "observer", "witness"])
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    if args.mode == "observer":
        observer(args.create)
    else:
        denials(args.role, args.pid)


if __name__ == "__main__":
    main()
