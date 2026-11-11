"""Registered sealed legacy-TBF recovery in one fresh no-uplink VM namespace.

Only operator fixtures create qdiscs/old ledger state. Normal core performs the
recovery; no runtime fixture/reset/repair command or new apply path is added.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import armor as a

g = a.g
NS = "edge400-legacy-tc"
NET_UNIT = "edge400-lab-tc-net.service"
POLICY = Path("/etc/apparmor.d/edge400-tc-lab")
IFACES = (
    "tc-owned",
    "tc-denied",
    "tc-foreign",
    "tc-kind",
    "tc-params",
    "tc-child",
    "tc-newer",
    "tc-absent",
)
FOREIGN = ("tc-foreign", "tc-kind", "tc-params", "tc-child", "tc-newer")


def ns(*argv, check=True):
    return g.command("ip", "netns", "exec", NS, *argv, check=check)


def tbf(interface, handle, rate="256kbit"):
    ns(
        "tc",
        "qdisc",
        "add",
        "dev",
        interface,
        "root",
        "handle",
        handle,
        "tbf",
        "rate",
        rate,
        "burst",
        "32kbit",
        "latency",
        "1000ms",
    )


def namespaces():
    assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
    assert Path("/etc/edge400-disposable-vm").read_text() == g.MAGIC
    assert g.command("systemd-detect-virt", "--vm").stdout.strip()
    assert not Path("/run/netns", NS).exists()
    before = json.loads(g.command("tc", "-j", "qdisc", "show").stdout)
    g.command("ip", "netns", "add", NS)
    g.command("ip", "-n", NS, "link", "set", "lo", "up")
    for interface in IFACES:
        g.command("ip", "-n", NS, "link", "add", interface, "type", "dummy")
        g.command("ip", "-n", NS, "link", "set", interface, "up")
    assert not ns("ip", "-4", "route", "show", "default").stdout.strip()
    assert not ns("ip", "-6", "route", "show", "default").stdout.strip()
    # These deliberately foreign controls are rebuilt on OS boot, never by the
    # runtime. The released owned/denied roots are NOT recreated on boot.
    tbf("tc-foreign", "e1:")
    ns("tc", "qdisc", "add", "dev", "tc-kind", "root", "handle", "1c:", "fq_codel")
    tbf("tc-params", "1d:", "512kbit")
    tbf("tc-child", "2a:")
    ns(
        "tc",
        "qdisc",
        "add",
        "dev",
        "tc-child",
        "parent",
        "2a:1",
        "handle",
        "99:",
        "pfifo",
        "limit",
        "100",
    )
    tbf("tc-newer", "2b:")
    ns("tc", "qdisc", "add", "dev", "tc-owned", "clsact")
    ns(
        "tc",
        "filter",
        "add",
        "dev",
        "tc-owned",
        "ingress",
        "pref",
        "49152",
        "matchall",
        "action",
        "pass",
    )
    assert json.loads(g.command("tc", "-j", "qdisc", "show").stdout) == before


def configure():
    raw_write = g.write

    def write(path, data, mode=0o644):
        if path == g.UNITS / g.UNIT:
            data = data.replace(
                "[Unit]\n", f"[Unit]\nWants={NET_UNIT}\nAfter={NET_UNIT}\n"
            )
            data += f"\n[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nNetworkNamespacePath=/run/netns/{NS}\n"
        return raw_write(path, data, mode)

    g.write = write
    a.NATIVE = False
    a.configure()
    prepare = g.prepare
    g.prepare = lambda *args, **kwargs: prepare(
        *args, **kwargs, native_apparmor_profile="edge400-tc"
    )
    g.ENV.update(AZAZEL_FORWARD_LOG="1")  # enforcement stays disabled/dry-run


def qdiscs(interface):
    return json.loads(ns("tc", "-j", "qdisc", "show", "dev", interface).stdout)


def ingress():
    return json.loads(
        ns("tc", "-j", "filter", "show", "dev", "tc-owned", "ingress").stdout
    )


def foreign():
    return {name: qdiscs(name) for name in FOREIGN}


def tasks():
    return {
        task["task_id"]: task
        for task in json.loads((g.BASE / "native/ledger.json").read_text())["tasks"]
    }


def releases():
    return [event["release"] for event in g.events() if "release" in event]


def identity():
    pid = g.live()
    assert (
        Path(f"/proc/{pid}/attr/apparmor/current").read_text().strip()
        == "edge400-tc (enforce)"
    )
    assert os.stat(f"/proc/{pid}/ns/net").st_ino == os.stat("/run/netns/" + NS).st_ino
    assert os.stat(f"/proc/{pid}/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino
    with open(f"/proc/{pid}/exe", "rb") as image:
        assert fcntl.fcntl(image, fcntl.F_GET_SEALS) == 15
    status = Path(f"/proc/{pid}/status").read_text()
    assert int(status.split("CapEff:")[1].split()[0], 16) == 0x10C4
    assert status.split("NoNewPrivs:")[1].split()[0] == "1"
    g.record("tc-sealed-confined-isolated-native", seals=15, cap_eff=0x10C4)
    return pid


def seed_legacy():
    from azazel_edge.outcome.instance import CoreLease

    assert not g.Systemd().cores()
    with CoreLease(g.ENV["AZAZEL_DEFENSE_RELEASE_LEDGER"]):
        tbf("tc-owned", "1a:")
        tbf("tc-denied", "1e:")
        now = time.time()

        def task(name, interface, handle, status="active", created=None, due=None):
            created = now - 40 if created is None else created
            due = now - 1 if due is None else due
            return dict(
                task_id="release-tc-" + name,
                trace_id="trace-tc-" + name,
                action="throttle",
                resource_key="tc:root:" + interface,
                owner_token="azazel-edge:release-tc-" + name,
                iface=interface,
                tc_handle=handle,
                source_ip="198.18.0.2",
                destination_port=22,
                redirect_port=0,
                expected_rate_bps=256000,
                expected_burst_bytes=4096,
                expected_latency_us=1000000,
                created_epoch=created,
                updated_epoch=created,
                due_epoch=due,
                next_attempt_epoch=due,
                status=status,
                attempts=0,
                last_error="",
            )

        old = [
            task("owned", "tc-owned", "1a:", status="prepared", due=now + 300),
            task("denied", "tc-denied", "1e:"),
            task("foreign", "tc-foreign", "1b:"),
            task("kind", "tc-kind", "1c:"),
            task("params", "tc-params", "1d:"),
            task("child", "tc-child", "2a:"),
            task("older", "tc-newer", "2b:", created=now - 60),
            task("newer", "tc-newer", "2b:", created=now - 10, due=now + 1800),
            task("absent", "tc-absent", "2c:"),
        ]
        data = json.dumps(dict(schema_version="azazel-release-ledger/v1", tasks=old))
        g.write(g.BASE / "native/ledger.json", data, 0o600)
        g.write(g.BASE / "v1-ledger.fixture", data, 0o600)
    g.record(
        "tc-explicit-v1-ledger-and-operator-owned-fixtures",
        tasks=len(old),
        current_auto_enforcement=False,
    )


def assert_foreign(snapshot, classifier):
    assert foreign() == snapshot
    assert ingress() == classifier
    assert any(item.get("kind") == "clsact" for item in qdiscs("tc-owned"))


def exercise():
    sys.path.insert(0, str(g.SRC / "tests"))
    from test_outcome_socket_boundary_linux import (
        test_signer_filter_blocks_netlink_even_when_the_parent_allows_it,
    )

    test_signer_filter_blocks_netlink_even_when_the_parent_allows_it()
    snapshot, classifier = foreign(), ingress()
    assert classifier and any(
        item.get("handle") == "99:" for item in snapshot["tc-child"]
    )
    g.write(g.BASE / "foreign-controls.json", json.dumps(snapshot))
    g.write(g.BASE / "ingress-control.json", json.dumps(classifier))
    # Commission against an empty state, then stop and seed the explicit old
    # ledger under the same lifetime lock. No unconfined core sees these tasks.
    g.systemctl("start", g.UNIT)
    g.wait_for(lambda: len(g.Systemd().cores()) == 1)
    switch = g.Switch(g.BUNDLE)
    plan = switch.plan()
    assert switch.apply(plan, g.digest(plan))["status"] == "started"
    pid = identity()
    g.record("tc-reviewed-handoff-witness-order", **g.order())
    before = g.source()
    duplicate = subprocess.run([str(g.CORE)], env=g.ENV, capture_output=True, timeout=5)
    assert duplicate.returncode == 3 and g.source() == before and identity() == pid
    duplicate = g.command(
        str(g.PYTHON),
        "-I",
        "-m",
        "azazel_edge.outcome.input_live",
        "--policy",
        str(g.BUNDLE / "trust.json"),
        "--registration",
        str(g.BUNDLE / "origin.json"),
        "--private-key",
        str(g.BUNDLE / "producer/key.raw"),
        "--boot-ref",
        g.boot(),
        check=False,
    )
    assert duplicate.returncode != 0 and identity() == pid and g.source() == before
    g.systemctl("start", g.UNIT)
    assert identity() == pid
    g.record("tc-ordinary-signed-and-manager-duplicate-exclusion")
    probe = g.command(
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "CapabilityBoundingSet=" + a.ROLE_CAPS["capture"],
        "-p",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "-p",
        "NetworkNamespacePath=/run/netns/" + NS,
        str(g.PYTHON),
        "-I",
        str(g.SRC / "tests/real_systemd/native_probe.py"),
        "--tc",
    )
    g.record("tc-policy-role-and-extra-binary-denials", **json.loads(probe.stdout))
    g.stop()
    seed_legacy()
    owned_before = {name: qdiscs(name) for name in ("tc-owned", "tc-denied")}
    policy = POLICY.read_bytes()
    fault = g.BASE / "tc-deny.profile"
    fault.write_bytes(policy.replace(b"/usr/sbin/tc mrix,", b"/usr/sbin/tc mr,"))
    g.command("apparmor_parser", "-r", str(fault))
    g.systemctl("start", g.UNIT)
    identity()
    due = {"owned", "denied", "foreign", "kind", "params", "child", "absent"}
    g.wait_for(
        lambda: all(
            any(
                event["release_task_id"] == "release-tc-" + name
                and event["status"] == "retry_pending"
                for event in releases()
            )
            for name in due
        )
    )
    assert all(
        event["postcondition"].get("verified") is False
        for event in releases()
        if event["status"] == "retry_pending"
    )
    assert {name: qdiscs(name) for name in owned_before} == owned_before
    assert_foreign(snapshot, classifier)
    g.record("tc-denied-readback-no-delete-no-false-release")
    g.command("apparmor_parser", "-r", str(POLICY))  # exact policy restoration only
    expected = {
        "owned": "released",
        "denied": "released",
        "foreign": "released",
        "absent": "released",
        "older": "superseded",
        "newer": "active",
        "kind": "active",
        "params": "active",
        "child": "active",
    }

    def reconciled():
        current = tasks()
        return all(
            current["release-tc-" + name]["status"] == status
            for name, status in expected.items()
        ) and all(
            any(
                event["release_task_id"] == "release-tc-" + name
                and message in " ".join(event["errors"])
                for event in releases()
            )
            for name, message in [
                ("kind", "unexpected qdisc kind"),
                ("params", "unexpected TBF parameters"),
                ("child", "unowned child qdisc"),
            ]
        )

    g.wait_for(reconciled, timeout=45)
    assert (
        json.loads((g.BASE / "native/ledger.json").read_text())["schema_version"]
        == "azazel-release-ledger/v2"
    )
    assert not any(item.get("handle") == "1a:" for item in qdiscs("tc-owned"))
    assert not any(item.get("handle") == "1e:" for item in qdiscs("tc-denied"))
    for name in ["owned", "denied"]:
        event = next(
            event
            for event in releases()
            if event["release_task_id"] == "release-tc-" + name
            and event["status"] == "released"
        )
        assert (
            event["result"] == "rollback_applied_and_absence_verified"
            and event["command_count"] == 1
            and event["postcondition"]["verified"] is True
        )
    for name in ["foreign", "absent"]:
        event = next(
            event
            for event in releases()
            if event["release_task_id"] == "release-tc-" + name
            and event["status"] == "released"
        )
        assert (
            event["result"] == "owned_state_already_absent"
            and event["command_count"] == 0
        )
    assert_foreign(snapshot, classifier)
    g.record(
        "tc-owned-only-delete-and-verified-absence",
        v1_migrated=True,
        foreign_roots_and_child_preserved=True,
        ingress_filter_preserved=True,
    )
    g.record("tc-wrong-kind-parameters-child-retry-and-newer-owner-preserved")
    g.systemctl("restart", g.UNIT)
    identity()
    time.sleep(0.3)
    assert_foreign(snapshot, classifier)
    g.record("tc-service-restart-preserves-unowned-settings")
    g.stop()
    g.alert(920004)
    g.systemctl("start", g.UNIT)
    identity()
    time.sleep(0.3)
    assert not g.saw(920004)
    assert_foreign(snapshot, classifier)
    g.record("tc-downtime-not-backfilled")
    g.stop()
    registration = g.BUNDLE / "origin.json"
    original = registration.read_bytes()
    registration.write_bytes(original + b" ")
    g.failed_start("tc-registration-verification-failure-no-append")
    g.write(g.BASE / "injected-invalid-registration.json", registration.read_bytes())
    registration.write_bytes(original)
    registration.rename(g.BUNDLE / "origin.withheld")
    g.failed_start("tc-unregistered-refuses-without-append")
    (g.BUNDLE / "origin.withheld").rename(registration)
    g.command("apparmor_parser", "-R", str(POLICY))
    g.failed_start("tc-missing-profile-refuses-before-append")
    g.command("apparmor_parser", "-r", str(POLICY))
    g.systemctl("reset-failed", g.UNIT)
    g.systemctl("start", g.UNIT)
    identity()
    g.systemctl("enable", g.UNIT)
    g.write(
        g.BASE / "preboot.json",
        json.dumps(
            dict(
                boot=g.boot(),
                prefix_sha256=hashlib.sha256(g.source()).hexdigest(),
                prefix_size=len(g.source()),
            )
        ),
    )
    g.record("tc-awaiting-clean-os-reboot")


def boot_check():
    identity()
    # Pending foreign-owner refusals may produce more release records after
    # session_start; do not suppress them to assert a lifecycle-only tail.
    saved = json.loads((g.BASE / "preboot.json").read_text())
    assert g.boot() != saved["boot"]
    assert (
        hashlib.sha256(g.source()[: saved["prefix_size"]]).hexdigest()
        == saved["prefix_sha256"]
    )
    assert_foreign(
        json.loads((g.BASE / "foreign-controls.json").read_text()),
        json.loads((g.BASE / "ingress-control.json").read_text()),
    )
    g.record(
        "tc-actual-os-reboot-registered-recovery-foreign-preserved",
        previous_boot=saved["boot"],
        **g.order(),
    )
    g.stop()
    status = g.observer()
    assert status["committed"] == 0
    g.record(
        "tc-postboot-observer-recovery-no-fabricated-outcomes",
        excluded=status["missed_input_records"],
    )
    (g.BUNDLE / "origin.json").rename(g.BUNDLE / "origin.bad-boot")
    g.write(
        g.BASE / "badboot.json",
        json.dumps(
            dict(
                boot=g.boot(),
                source_sha256=hashlib.sha256(g.source()).hexdigest(),
                source_size=len(g.source()),
            )
        ),
    )
    g.record("tc-awaiting-unregistered-os-reboot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=[
            "namespace",
            "prepare",
            "exercise",
            "boot-check",
            "bad-boot-check",
            "smoke-finish",
        ],
    )
    parser.add_argument("--allow-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if args.phase == "namespace":
        namespaces()
        return
    g.guard()
    configure()
    if args.phase == "prepare":
        assert not g.BASE.exists() and not (g.UNITS / g.UNIT).exists()
        a.prepare_accounts()
        a.install_policy()
        policy = (g.SRC / "tests/real_systemd/edge400-tc.apparmor").read_bytes()
        assert not POLICY.exists()
        g.write(POLICY, policy)
        g.command("apparmor_parser", "-r", str(POLICY))
        g.write(
            g.UNITS / NET_UNIT,
            f"""[Unit]
Description=Disposable legacy-tc namespace setup; operator privileges only
[Service]
Type=oneshot
RemainAfterExit=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN
ExecStart={g.PYTHON} -I {g.SRC}/tests/real_systemd/legacy_tc.py namespace --allow-disposable-vm
""",
        )
        g.systemctl("daemon-reload")
        g.systemctl("start", NET_UNIT)
        g.prepare_lab()
        g.write(g.BASE / "aa-denied", "public tc policy canary\n")
        image, _ = a.read_regular(
            Path("/usr/sbin/tc"), owner=0, mode=0o755, max_bytes=64 * 1024 * 1024
        )
        g.record(
            "tc-policy-and-offline-binary-receipts",
            tc_sha256=hashlib.sha256(image).hexdigest(),
            policy_sha256=hashlib.sha256(policy).hexdigest(),
        )
    else:
        {
            "exercise": exercise,
            "boot-check": boot_check,
            "bad-boot-check": g.bad_boot_check,
            "smoke-finish": g.smoke_finish,
        }[args.phase]()


if __name__ == "__main__":
    main()
