"""Opt-in real providers in two isolated namespaces of a marked disposable VM.

Root namespace preparation is operator-owned, never a runtime provider grant.
No production paths, keys, routes, tables, model or external peer is used.
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
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
import armor as a

g = a.g
EDGE = "edge400-provider-edge"
CLIENT = "edge400-provider-client"
NET_UNIT = "edge400-lab-provider-net.service"
POLICY = Path("/etc/apparmor.d/edge400-provider-lab")
IP = "198.18.0.1"
SOURCE = "198.18.0.2"
OTHER = "198.18.0.3"


def ns(name, *argv, check=True):
    return g.command("ip", "netns", "exec", name, *argv, check=check)


def stable_ruleset():
    def strip(value):
        if isinstance(value, list):
            return [strip(item) for item in value]
        if isinstance(value, dict):
            return {
                key: (
                    {
                        k: strip(v)
                        for k, v in item.items()
                        if k not in ("packets", "bytes")
                    }
                    if key == "counter" and isinstance(item, dict)
                    else strip(item)
                )
                for key, item in value.items()
            }
        return value

    return strip(json.loads(g.command("nft", "-j", "list", "ruleset").stdout))


def namespaces():
    # Preparation runs in the manager's mount namespace so named handles are
    # visible to services. It does not need the manager's network, or touch its
    # routes/rules. Driver/runtime offline checks are separate mandatory gates.
    assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
    assert Path("/etc/edge400-disposable-vm").read_text() == g.MAGIC
    assert g.command("systemd-detect-virt", "--vm").stdout.strip()
    assert not any(Path("/run/netns", name).exists() for name in [EDGE, CLIENT])
    root_before = stable_ruleset()
    for name in [EDGE, CLIENT]:
        g.command("ip", "netns", "add", name)
        g.command("ip", "-n", name, "link", "set", "lo", "up")
    g.command(
        "ip",
        "link",
        "add",
        "edge0",
        "netns",
        EDGE,
        "type",
        "veth",
        "peer",
        "name",
        "client0",
        "netns",
        CLIENT,
    )
    for name, interface, addresses in [
        (EDGE, "edge0", [IP]),
        (CLIENT, "client0", [SOURCE, OTHER]),
    ]:
        for address in addresses:
            g.command(
                "ip", "-n", name, "addr", "add", address + "/24", "dev", interface
            )
        g.command("ip", "-n", name, "link", "set", interface, "up")
        assert not ns(name, "ip", "-4", "route", "show", "default").stdout.strip()
        assert not ns(name, "ip", "-6", "route", "show", "default").stdout.strip()
    script = """add table inet azazel_edge
add chain inet azazel_edge input { type filter hook input priority 0; policy accept; }
add chain inet azazel_edge throttle { type filter hook prerouting priority -150; policy accept; }
add chain inet azazel_edge prerouting { type nat hook prerouting priority -100; policy accept; }
add rule inet azazel_edge throttle ip saddr 203.0.113.250 counter comment "edge400-foreign-canary"
"""
    subprocess.run(
        ["ip", "netns", "exec", EDGE, "nft", "-f", "-"],
        input=script,
        text=True,
        check=True,
        timeout=10,
    )
    assert stable_ruleset() == root_before


def configure():
    raw_write = g.write

    def write(path, data, mode=0o644):
        if path == g.BASE / "template.json":
            raw_write(
                g.BASE / "native/protected.yaml",
                """protected_flows:
  version: 1
  entries:
    - {name: mgmt, role: management, network: 203.0.113.0/28}
    - {name: expert, role: expert_contact, network: 203.0.113.20, ports: [443]}
  roles_not_applicable:
    - {role: mission, approved_by: disposable-lab, reason: no mission link in isolated lab}
""",
                0o600,
            )
            raw_write(
                g.BASE / "native/redirect.yaml",
                """redirect_policy:
  enabled: true
  prepared_ports:
    22: 12222
  decoy_evidence_max_age_sec: 600
  decoy_separation_evidence_path: /var/lib/edge400-systemd-lab/native/separation.json
""",
                0o600,
            )
            raw_write(
                g.BASE / "native/separation.json",
                json.dumps(
                    dict(
                        schema="azazel-edge/decoy-separation/v1",
                        boot_id=g.boot(),
                        observed_epoch=time.time(),
                        separation="network_namespace",
                        decoy_ports=[12222],
                        ingress_interface="edge0",
                        ingress_path_check=dict(
                            result="reachable",
                            checked_epoch=time.time(),
                            via_interface="edge0",
                            decoy_ports=[12222],
                        ),
                    )
                ),
                0o600,
            )
        if path == g.UNITS / g.UNIT:
            data = data.replace(
                "[Unit]\n", "[Unit]\nWants=" + NET_UNIT + "\nAfter=" + NET_UNIT + "\n"
            )
            data += (
                "\n[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET\nNetworkNamespacePath=/run/netns/"
                + EDGE
                + "\n"
            )
        return raw_write(path, data, mode)

    g.write = write
    a.NATIVE = False
    a.configure()
    prepare = g.prepare
    g.prepare = lambda *args, **kwargs: prepare(
        *args, **kwargs, native_apparmor_profile="edge400-provider"
    )
    g.ENV.update(
        AZAZEL_DEFENSE_ENFORCE="1",
        AZAZEL_DEFENSE_DRY_RUN="0",
        AZAZEL_DEFENSE_ENFORCE_LEVEL="full-auto",
        AZAZEL_DEFENSE_ACTION_TTL_SEC="30",
        AZAZEL_DEFENSE_IFACE="edge0",
        AZAZEL_FORWARD_LOG="1",
        AZAZEL_REDIRECT_POLICY_PATH=str(g.BASE / "native/redirect.yaml"),
        AZAZEL_PROTECTED_FLOWS_PATH=str(g.BASE / "native/protected.yaml"),
    )


def rules(chain):
    data = json.loads(
        ns(
            EDGE, "nft", "-a", "-j", "list", "chain", "inet", "azazel_edge", chain
        ).stdout
    )
    return [entry["rule"] for entry in data["nftables"] if "rule" in entry]


def foreign():
    return [
        rule
        for rule in rules("throttle")
        if rule.get("comment") == "edge400-foreign-canary"
    ]


def connect(source, port):
    script = "import socket,sys;s=socket.socket();s.settimeout(2);s.bind((sys.argv[1],0));s.connect((sys.argv[2],int(sys.argv[3])));print(s.recv(32).decode());s.close()"
    return ns(CLIENT, str(g.PYTHON), "-c", script, source, IP, str(port)).stdout.strip()


def reachable():
    try:
        return connect(OTHER, 12222) == "DECOY"
    except subprocess.CalledProcessError:
        return False


def listeners():
    script = """import socket,selectors
sel=selectors.DefaultSelector()
for port,label in [(22,b'REAL'),(12222,b'DECOY')]:
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.18.0.1',port));s.listen();sel.register(s,selectors.EVENT_READ,label)
while True:
 for key,_ in sel.select():
  c,_=key.fileobj.accept();c.sendall(key.data);c.close()
"""
    return subprocess.Popen(
        ["ip", "netns", "exec", EDGE, str(g.PYTHON), "-u", "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def alert(sid, source, severity):
    value = dict(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="alert",
        src_ip=source,
        dest_ip=IP,
        dest_port=22,
        proto="TCP",
        alert=dict(
            signature_id=sid,
            signature="provider lab",
            category="test",
            severity=severity,
        ),
    )
    with (g.BASE / "eve.json").open("a") as stream:
        stream.write(json.dumps(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def outcome(sid):
    return next(
        (
            event["enforcement"]
            for event in g.events()
            if event.get("normalized", {}).get("sid") == sid
        ),
        None,
    )


def tasks():
    path = g.BASE / "native/ledger.json"
    return json.loads(path.read_text())["tasks"] if path.exists() else []


def identity():
    pid = g.live()
    assert (
        Path(f"/proc/{pid}/attr/apparmor/current").read_text().strip()
        == "edge400-provider (enforce)"
    )
    assert os.stat(f"/proc/{pid}/ns/net").st_ino == os.stat("/run/netns/" + EDGE).st_ino
    assert os.stat(f"/proc/{pid}/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino
    with open(f"/proc/{pid}/exe", "rb") as image:
        assert fcntl.fcntl(image, fcntl.F_GET_SEALS) == 15
    status = Path(f"/proc/{pid}/status").read_text()
    assert int(status.split("CapEff:")[1].split()[0], 16) == 0x10C4
    assert status.split("NoNewPrivs:")[1].split()[0] == "1"
    g.record("provider-native-sealed-confined-isolated", seals=15, cap_eff=0x10C4)
    return pid


def exercise():
    sys.path.insert(0, str(g.SRC / "tests"))
    from test_outcome_socket_boundary_linux import (
        test_signer_filter_blocks_netlink_even_when_the_parent_allows_it,
    )

    test_signer_filter_blocks_netlink_even_when_the_parent_allows_it()
    g.record("provider-signer-private-unix-only-filter-positive-and-negative-controls")
    canary = foreign()
    assert len(canary) == 1
    # Advisory-only calculation is explicitly separate from execution facts.
    from azazel_edge.outcome.input_live import sealed_image, native_arguments

    r = g.verify(g.BUNDLE)[1]
    image = sealed_image(r)
    try:
        result = subprocess.run(
            [f"/proc/self/fd/{image}", "--capture-origin-once", *native_arguments(r)],
            pass_fds=(image,),
            input=json.dumps(
                dict(
                    event_type="alert",
                    src_ip=SOURCE,
                    dest_ip=IP,
                    dest_port=22,
                    proto="TCP",
                    alert=dict(severity=1, signature_id=900000),
                )
            )
            + "\n",
            capture_output=True,
            text=True,
            timeout=5,
            env=r["environment"],
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["enforcement"]["executed_count"] == 0
        assert g.source() == b"" and foreign() == canary
    finally:
        os.close(image)
    g.record("readonly-plan-preflight-not-an-execution-fact")
    g.systemctl("start", g.UNIT)
    g.wait_for(lambda: len(g.Systemd().cores()) == 1)
    switch = g.Switch(g.BUNDLE)
    plan = switch.plan()
    assert switch.apply(plan, g.digest(plan))["status"] == "started"
    pid = identity()
    g.record("provider-reviewed-handoff-witness-order", **g.order())
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
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET",
        "-p",
        "NetworkNamespacePath=/run/netns/" + EDGE,
        str(g.PYTHON),
        "-I",
        str(g.SRC / "tests/real_systemd/native_probe.py"),
        "--provider",
    )
    g.record(
        "provider-same-root-policy-denials-and-needed-socket-controls",
        **json.loads(probe.stdout),
    )
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
    assert duplicate.returncode != 0 and g.source() == before and identity() == pid
    g.systemctl("start", g.UNIT)
    assert identity() == pid and g.source() == before
    g.record("provider-ordinary-signed-and-manager-duplicates-refused")
    listener = listeners()
    try:
        g.wait_for(reachable)
        assert connect(OTHER, 22) == "REAL"
        import provider_restoration
        restoration = provider_restoration.Recorder(
            g, EDGE,
            # Existing PUBLIC test key, unused schema role: no facts/signing.
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        )
        restoration.query("baseline")
        alert(900001, OTHER, 1)
        alert(900002, SOURCE, 2)
        for sid in [900001, 900002]:
            result = g.wait_for(lambda sid=sid: outcome(sid))
            assert (
                result["result"] == "applied"
                and result["executed_count"] == 1
                and result["failed_count"] == 0
            ), result
        active = tasks()
        assert len(active) == 2 and all(
            task["status"] == "active" for task in active
        ), active
        for task in active:
            chain = "throttle" if task["action"] == "throttle" else "prerouting"
            owned = [
                rule
                for rule in rules(chain)
                if rule.get("comment") == task["owner_token"]
            ]
            assert len(owned) == 1
            expr = owned[0]["expr"]
            matches = [part["match"] for part in expr if "match" in part]
            for field, value in [
                ("saddr", task["source_ip"]),
                ("daddr", IP),
                ("dport", 22),
            ]:
                assert any(
                    match.get("left", {}).get("payload", {}).get("field") == field
                    and match["right"] == value
                    for match in matches
                ), owned
            if chain == "prerouting":
                assert any(
                    part.get("redirect", {}).get("port") == 12222 for part in expr
                )
                assert any(
                    match.get("left", {}).get("meta", {}).get("key") == "iifname"
                    and match["right"] == "edge0"
                    for match in matches
                )
            else:
                limit = next(part["limit"] for part in expr if "limit" in part)
                units = {"bytes": 1, "kbytes": 1024, "mbytes": 1024 * 1024}
                assert (
                    limit["rate"] * units[limit["rate_unit"]]
                    == task["limit_rate_kbytes"] * 1024
                ), limit
                assert (
                    limit["burst"] * units[limit["burst_unit"]]
                    == task["limit_burst_kbytes"] * 1024
                ), limit
                assert limit["per"] == "second" and limit.get("inv") is True, limit
                assert any("drop" in part for part in expr), expr
        assert connect(SOURCE, 22) == "DECOY" and connect(OTHER, 22) == "REAL"
        redirect = next(task for task in active if task["action"] == "redirect")
        tracked = ns(
            EDGE,
            "conntrack",
            "-L",
            "-p",
            "tcp",
            "--orig-src",
            SOURCE,
            "--orig-dst",
            IP,
            "--dport",
            "22",
            "-o",
            "extended",
        ).stdout
        assert "mark=" + str(redirect["ct_mark"]) in tracked
        assert rules("input") == [] and foreign() == canary
        restoration.query("applied")
        g.record(
            "provider-signed-apply-independent-flow-readback-and-local-packet-control",
            actions=[task["action"] for task in active],
        )
        # Deny execution while owned state really exists. Apply must not claim
        # success, and unreadable release state must not become verified absence.
        policy = POLICY.read_bytes()
        fault = g.BASE / "provider-deny.profile"
        fault.write_bytes(
            policy.replace(
                b"/usr/sbin/{nft,conntrack} mrix,", b"/usr/sbin/conntrack mrix,"
            )
        )
        g.command("apparmor_parser", "-r", str(fault))
        alert(900003, "198.18.0.4", 1)
        failed = g.wait_for(lambda: outcome(900003))
        assert (
            failed["result"] == "failed"
            and failed["executed_count"] == 0
            and failed["failed_count"] > 0
        ), failed
        tokens = {task["owner_token"] for task in active}

        def denied_releases():
            return [
                event["release"]
                for event in g.events()
                if "release" in event
                and event["release"]["owner_token"] in tokens
                and event["release"]["status"] == "retry_pending"
            ]

        g.wait_for(
            lambda: {event["owner_token"] for event in denied_releases()} == tokens,
            timeout=55,
        )
        assert all(
            event["postcondition"].get("verified") is False
            for event in denied_releases()
        )
        assert all(
            task["status"] != "released"
            for task in tasks()
            if task["owner_token"] in tokens
        )
        assert (
            len(rules("prerouting")) == 1
            and len(rules("throttle")) == 2
            and foreign() == canary
        )
        g.record("provider-apply-and-readback-denied-no-false-success-or-release")
        g.command(
            "apparmor_parser", "-r", str(POLICY)
        )  # exact controlled policy restoration, no evidence repair
        g.wait_for(
            lambda: all(task["status"] == "released" for task in tasks()), timeout=45
        )
        assert (
            not rules("prerouting")
            and rules("throttle") == canary
            and foreign() == canary
        )
        release = [
            event["release"]
            for event in g.events()
            if "release" in event
            and event["release"]["owner_token"] in tokens
            and event["release"]["status"] == "released"
        ]
        assert len(release) == 2 and all(
            event["result"] == "rollback_applied_and_absence_verified"
            and event["postcondition"]["verified"] is True
            for event in release
        ), release
        restoration.query("released")
        assert (
            next(event for event in release if event["action"] == "redirect")[
                "postcondition"
            ]["existing_connections"]
            == "cleared"
        )
        after = ns(
            EDGE,
            "conntrack",
            "-L",
            "-p",
            "tcp",
            "--orig-src",
            SOURCE,
            "--orig-dst",
            IP,
            "--dport",
            "22",
            "-o",
            "extended",
            check=False,
        )
        assert "mark=" + str(redirect["ct_mark"]) not in after.stdout
        assert connect(SOURCE, 22) == "REAL" and foreign() == canary
        g.record("provider-release-absence-and-conntrack-readback-foreign-preserved")
        preserved = ns(
            EDGE,
            "conntrack",
            "-L",
            "-p",
            "tcp",
            "--orig-src",
            OTHER,
            "--orig-dst",
            IP,
            "--dport",
            "22",
            "-o",
            "extended",
        ).stdout
        assert "src=" + OTHER in preserved and "mark=0" in preserved
        g.record("provider-foreign-conntrack-control-preserved")
    finally:
        listener.terminate()
        listener.wait(timeout=5)
        listener.stderr.close()
    g.stop()
    restoration.finish()  # Original FIRST closed Source, before any restart.
    before = g.source()
    alert(900004, OTHER, 2)
    g.systemctl("start", g.UNIT)
    identity()
    time.sleep(0.3)
    assert outcome(900004) is None and g.source().startswith(before)
    g.record("provider-downtime-not-backfilled")
    g.stop()
    before = g.source()
    fault = g.BASE / "provider-missing.profile"
    fault.write_bytes(POLICY.read_bytes())
    g.command("apparmor_parser", "-R", str(fault))
    g.failed_start("provider-missing-profile-refuses-before-append")
    g.command("apparmor_parser", "-r", str(POLICY))
    registration = g.BUNDLE / "origin.json"
    original = registration.read_bytes()
    registration.write_bytes(original + b" ")
    g.failed_start("provider-registration-verification-failure-no-append")
    g.write(
        g.BASE / "injected-invalid-provider-registration.json",
        registration.read_bytes(),
    )
    registration.write_bytes(original)  # controlled synthetic fault restoration
    registration.rename(g.BUNDLE / "origin.withheld")
    g.failed_start("provider-unregistered-refuses-without-append")
    (g.BUNDLE / "origin.withheld").rename(registration)
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
    g.record("provider-awaiting-clean-os-reboot")


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
        policy = (g.SRC / "tests/real_systemd/edge400-provider.apparmor").read_bytes()
        assert not POLICY.exists()
        g.write(POLICY, policy)
        g.command("apparmor_parser", "-r", str(POLICY))
        g.write(
            g.UNITS / NET_UNIT,
            f"""[Unit]
Description=Disposable provider namespace preparation; no runtime capability grant
[Service]
Type=oneshot
RemainAfterExit=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN
ExecStart={g.PYTHON} -I {g.SRC}/tests/real_systemd/provider.py namespace --allow-disposable-vm
""",
        )
        g.systemctl("daemon-reload")
        g.systemctl("start", NET_UNIT)
        listener = listeners()
        try:
            g.wait_for(reachable)
            g.prepare_lab()  # separation.json records this measured local path
        finally:
            listener.terminate()
            listener.wait(timeout=5)
            listener.stderr.close()
        g.write(g.BASE / "aa-denied", "public synthetic provider canary\n")
        receipts = {}
        for binary in ["nft", "conntrack"]:
            raw, _ = a.read_regular(
                Path("/usr/sbin") / binary,
                owner=0,
                mode=0o755,
                max_bytes=64 * 1024 * 1024,
            )
            receipts[binary] = hashlib.sha256(raw).hexdigest()
        g.record("provider-offline-binary-receipts", **receipts)
        g.record(
            "provider-policy-prepared-operator-only-netns",
            policy_sha256=hashlib.sha256(policy).hexdigest(),
        )
    else:
        {
            "exercise": exercise,
            "boot-check": g.boot_check,
            "bad-boot-check": g.bad_boot_check,
            "smoke-finish": g.smoke_finish,
        }[args.phase]()


if __name__ == "__main__":
    main()
