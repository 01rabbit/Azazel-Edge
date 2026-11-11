"""Opt-in trusted-local-process/network trial; never production origin admission.

Three fresh namespaces, existing core flow-throttle commands, independent TCP
service audit. No systemd/AppArmor/provider changes, external route or model.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import select
import signal
import shutil
import subprocess
import sys
import time
import uuid

from azazel_edge.benchmark.benefit import BenefitInputError, SAFETY_FIELDS, analyze, manifest_digest, validate_manifest
from azazel_edge.benchmark.benefit_receipt import build_receipt
from azazel_edge.benchmark.measurement_capture import IndependentServiceCapture
from azazel_edge.benchmark.run_ledger import RunLedger
from test_core_scoped_actions_netns_v1 import CORE as DEFAULT_CORE, _alert
CORE = Path(os.environ.get("EDGE_NETWORK_MEASURE_CORE", str(DEFAULT_CORE))).resolve()
from network_measure_peer import ATK, LEGIT, SERVER, PORT, GOAL_BYTES, MAX_MESSAGE

PEER = Path(__file__).with_name("network_measure_peer.py")
SCOPE = "trusted_local_netns_mechanism_service_instrumentation_only"
ARMS = ("c0", "flow_throttle")
EXPERIMENT_VERSION = "network-c0-flow-throttle-v2"
TOOLS = ("ip", "nft", "tc", "conntrack")


def require(condition, message):
    if not condition:
        raise BenefitInputError(message)


def command(*argv, input=None, check=True, timeout=5):
    result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout, check=False)
    require(not check or result.returncode == 0, "bounded namespace command failed")
    return result


def plan(arm, core_sha256):
    require(arm in ARMS, "unknown measurement arm")
    return dict(arm=arm, core_sha256=core_sha256, horizon_seconds=5,
                objective_bytes=GOAL_BYTES, legitimate_requests=6,
                objective_start_seconds=.4, legitimate_start_seconds=.2,
                legitimate_interval_seconds=.6, ttl_seconds=30,
                mechanism="none" if arm == "c0" else "existing_core_prerouting_flow_throttle")


def experiment_identifier(source_commit):
    require(isinstance(source_commit, str) and re.fullmatch(r"[0-9a-f]{40}", source_commit),
            "reviewed source commit required for network experiment identity")
    return EXPERIMENT_VERSION + "-" + source_commit[:12]


def validate(manifest, safety, scope, core_sha256):
    assignments = validate_manifest(manifest)
    reviewed_source = manifest["provenance"]["repo_commits"].get("01rabbit/Azazel-Edge")
    require(manifest["experiment_id"] == experiment_identifier(reviewed_source),
            "new versioned network experiment identity required; do not resume old experiment")
    require(isinstance(core_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", core_sha256), "exact core SHA256 required")
    require(scope == SCOPE and manifest["phase"] == "pilot" and manifest["evidence_kind"] == "recorded_lab"
            and manifest["horizon_seconds"] == 5 and len(assignments) == 4,
            "exact four-run/two-pair five-second local pilot required")
    require(manifest["baseline"] == "c0" and manifest["candidate"] == "flow_throttle"
            and {arm["id"] for arm in manifest["arms"]} == set(ARMS), "fixed C0/flow-throttle arms required")
    for arm in manifest["arms"]:
        require(arm["source_commit"] == reviewed_source, "arm source differs from reviewed experiment source")
        require(arm["role"] == ("local_core_observe_only" if arm["id"] == "c0" else "existing_flow_scoped_throttle"),
                "arm role must name the actual existing mechanism")
        require(arm["config_sha256"] == manifest_digest(plan(arm["id"], core_sha256)), "frozen core/plan mismatch")
    pairs = {}
    for assignment in assignments.values():
        pairs.setdefault(assignment["pair_id"], []).append(assignment)
    require(len(pairs) == 2 and all({a["arm"] for a in group} == set(ARMS) for group in pairs.values()),
            "two complete paired assignments required")
    require(isinstance(safety, dict) and set(safety) == set(assignments)
            and all(isinstance(row, dict) and set(row) == set(SAFETY_FIELDS)
                    and all(type(v) is int and v == 0 for v in row.values()) for row in safety.values()),
            "explicit reviewed closed-scope safety required; unknown or known failure refuses launch")
    order = [a for pair in sorted(pairs) for a in sorted(pairs[pair], key=lambda a: a["order"])]
    require(order[0]["arm"] == "c0", "C0 plan-only control must precede namespace enforcement")
    return order


def write_new(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    require(len(raw) <= 8 * 1024 * 1024, "measurement artifact exceeds bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(raw)
        while remaining:
            n = os.write(fd, remaining)
            require(n > 0, "artifact write stopped")
            remaining = remaining[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def root_snapshot():
    def strip(value):
        if isinstance(value, list):
            return [strip(item) for item in value]
        if isinstance(value, dict):
            return {key: ({} if key == "counter" else strip(item)) for key, item in value.items()}
        return value
    return dict(nft=strip(json.loads(command("nft", "-j", "list", "ruleset").stdout)),
                routes4=command("ip", "-j", "-4", "route", "show", "table", "all").stdout,
                routes6=command("ip", "-j", "-6", "route", "show", "table", "all").stdout)


class Assets:
    def __init__(self, work):
        self.work = work
        tag = "nm" + uuid.uuid4().hex[:8]
        self.names = {kind: tag + "-" + kind for kind in ("edge", "client", "service")}
        self.created = {}
        self.creation_intents = {}
        self.processes = []
        self.core = None
        self.events = work / "events.jsonl"
        self.eve = work / "eve.jsonl"
        self.foreign = "foreign-" + tag

    def ns(self, kind, *argv, **kwargs):
        return command("ip", "netns", "exec", self.names[kind], *argv, **kwargs)

    def create_namespace(self, name):
        path = Path("/run/netns", name)
        require(not path.exists(), "namespace name exists; never predelete")
        intent = dict(name=name, state="creation_intent")
        self.creation_intents[name] = intent
        # Intent survives an ip-add timeout or a crash before identity capture.
        write_new(self.work / ("namespace-intent-" + str(len(self.creation_intents)) + ".json"), intent)
        handle = None
        try:
            command("ip", "netns", "add", name)
            handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            identity = os.fstat(handle)
        except BaseException:
            if handle is not None:
                os.close(handle)
            intent["state"] = "unknown_creation_outcome"
            # An existing handle is not proof this attempt created it. Never
            # delete or signal into that namespace without confirmed identity.
            raise
        self.created[name] = (handle, identity.st_dev, identity.st_ino)
        intent["state"] = "confirmed_created"
        intent["identity"] = dict(device=identity.st_dev, inode=identity.st_ino)
        write_new(self.work / ("namespace-confirmed-" + str(len(self.creation_intents)) + ".json"), intent)

    def setup(self):
        require(all(not Path("/run/netns", name).exists() for name in self.names.values()), "namespace name exists; never predelete")
        for name in self.names.values():
            self.create_namespace(name)
            command("ip", "-n", name, "link", "set", "lo", "up")
        for peer, edge_addr, address in (("client", "10.91.1.1", ATK), ("service", "10.91.3.1", SERVER)):
            command("ip", "link", "add", "e" + peer[0], "netns", self.names["edge"],
                    "type", "veth", "peer", "name", "peer0", "netns", self.names[peer])
            for ns, iface, ip in (("edge", "e" + peer[0], edge_addr), (peer, "peer0", address)):
                command("ip", "-n", self.names[ns], "addr", "add", ip + "/24", "dev", iface)
                command("ip", "-n", self.names[ns], "link", "set", iface, "up")
        command("ip", "-n", self.names["client"], "addr", "add", LEGIT + "/32", "dev", "peer0")
        for kind, network, gateway in (("client", "10.91.3.0/24", "10.91.1.1"),
                                       ("service", "10.91.1.0/24", "10.91.3.1"),
                                       ("service", LEGIT + "/32", "10.91.3.1"),
                                       ("edge", LEGIT + "/32", ATK)):
            self.ns(kind, "ip", "route", "add", network, "via", gateway)
        self.ns("edge", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        for kind in self.names:
            require(not self.ns(kind, "ip", "-4", "route", "show", "default").stdout.strip()
                    and not self.ns(kind, "ip", "-6", "route", "show", "default").stdout.strip(), "external/default route present")
        rules = ('add table inet azazel_edge\n'
                 'add chain inet azazel_edge input { type filter hook input priority 0; policy accept; }\n'
                 'add chain inet azazel_edge throttle { type filter hook prerouting priority -150; policy accept; }\n'
                 'add chain inet azazel_edge prerouting { type nat hook prerouting priority -100; policy accept; }\n'
                 f'add rule inet azazel_edge throttle ip saddr 203.0.113.250 counter comment "{self.foreign}"\n')
        self.ns("edge", "nft", "-f", "-", input=rules)

    def spawn(self, kind, argv, *, stdin=False, env=None):
        err = open(self.work / ("child-" + str(len(self.processes)) + ".log"), "wb")
        os.fchmod(err.fileno(), 0o600)
        try:
            process = subprocess.Popen(["ip", "netns", "exec", self.names[kind], *map(str, argv)],
                                       stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=err, env=env)
        finally:
            err.close()
        self.processes.append(process)
        return process

    def start_core(self, enforced):
        self.eve.write_text("")
        protected = self.work / "protected.yaml"
        protected.write_text("protected_flows:\n  version: 1\n  entries:\n"
                             "    - {name: legit, role: management, network: 10.91.2.2/32}\n"
                             "    - {name: expert, role: expert_contact, network: 203.0.113.9/32}\n"
                             "  roles_not_applicable:\n"
                             "    - {role: mission, approved_by: local-lab, reason: no mission asset in this isolated trial}\n")
        protected.chmod(0o600)
        env = dict(PATH=os.environ.get("PATH", ""), AZAZEL_EVE_PATH=str(self.eve), AZAZEL_EVE_FROM_START="true",
                   AZAZEL_EVE_POLL_MS="100", AZAZEL_FORWARD_AI="false", AZAZEL_FORWARD_LOG="true",
                   AZAZEL_NORMALIZED_EVENT_LOG=str(self.events), AZAZEL_EVENT_STDOUT="off",
                   AZAZEL_DEFENSE_RELEASE_LEDGER=str(self.work / "release.json"),
                   AZAZEL_DEFENSE_ENFORCE="true" if enforced else "false", AZAZEL_DEFENSE_DRY_RUN="false",
                   AZAZEL_DEFENSE_ENFORCE_LEVEL="full-auto", AZAZEL_DEFENSE_ACTION_TTL_SEC="30",
                   AZAZEL_DEFENSE_IFACE="es", AZAZEL_PROTECTED_FLOWS_PATH=str(protected),
                   AZAZEL_REDIRECT_POLICY_PATH=str(self.work / "absent-redirect.yaml"))
        self.core = self.spawn("edge", [CORE], env=env)
        time.sleep(.2)
        require(self.core.poll() is None, "local core exited at startup")

    def records(self):
        return [json.loads(line) for line in self.events.read_text().splitlines() if line] if self.events.exists() else []

    def rules(self):
        data = json.loads(self.ns("edge", "nft", "-a", "-j", "list", "chain", "inet", "azazel_edge", "throttle").stdout)
        return [item["rule"] for item in data["nftables"] if "rule" in item]

    def close(self):
        errors = []

        def attempt(step, operation):
            try:
                return True, operation()
            except BaseException as exc:
                errors.append(dict(step=step, exception_type=type(exc).__name__))
                return False, None

        # A failed terminate/wait/close must never skip another owned child.
        for number, process in enumerate(reversed(self.processes)):
            label = "child-" + str(number)
            ok, running = attempt(label + "-poll", lambda: process.poll() is None)
            if ok and running:
                attempt(label + "-terminate", process.terminate)
            ok, _ = attempt(label + "-wait", lambda: process.wait(timeout=2))
            if not ok:
                attempt(label + "-kill", process.kill)
                attempt(label + "-reap", lambda: process.wait(timeout=2))
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    attempt(label + "-close-stream", stream.close)

        for name, (handle, device, inode) in reversed(list(self.created.items())):
            path = Path("/run/netns", name)

            def identity_matches():
                pinned = os.fstat(handle)
                named = os.stat(path, follow_symlinks=False)
                require((pinned.st_dev, pinned.st_ino) == (device, inode)
                        and (named.st_dev, named.st_ino) == (device, inode),
                        "namespace identity changed; preserve unknown asset")

            ok, _ = attempt(name + "-identity", identity_matches)
            if not ok:
                attempt(name + "-close-handle", lambda: os.close(handle))
                continue
            ok, residents = attempt(name + "-list-pids", lambda: command("ip", "netns", "pids", name).stdout.split())
            if ok:
                for value in residents:
                    def kill_resident():
                        pid = int(value)
                        try:
                            pinned = os.pidfd_open(pid)
                        except ProcessLookupError:
                            return
                        try:
                            identity_matches()
                            require(os.stat(f"/proc/{pid}/ns/net").st_ino == inode,
                                    "refuse to signal outside the confirmed owned namespace")
                            signal.pidfd_send_signal(pinned, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        finally:
                            os.close(pinned)
                    attempt(name + "-signal-owned-resident", kill_resident)

                def verify_empty():
                    until = time.monotonic() + 2
                    while True:
                        identity_matches()
                        remaining = command("ip", "netns", "pids", name).stdout.strip()
                        if not remaining:
                            return
                        require(time.monotonic() < until, "owned namespace process remains")
                        time.sleep(.05)
                empty, _ = attempt(name + "-verify-empty", verify_empty)
                if empty:
                    # Recheck immediately before deletion. Never hide an
                    # unverifiable resident by merely removing its name.
                    same, _ = attempt(name + "-predelete-identity", identity_matches)
                    if same:
                        attempt(name + "-delete", lambda: command("ip", "netns", "del", name))
            attempt(name + "-close-handle", lambda: os.close(handle))

        # Check every intended name, including timed-out/unconfirmed adds.
        # Unknown assets are retained for review, never automatically deleted.
        for name in self.creation_intents:
            attempt(name + "-verify-absence", lambda name=name: require(
                not Path("/run/netns", name).exists(),
                "namespace remains or creation outcome is unknown; manual review required"))
        attempt("cleanup-evidence", lambda: write_new(self.work / "cleanup.json", dict(
            creation_intents=self.creation_intents, errors=list(errors), cleanup_verified=not errors)))
        require(not errors, "owned asset cleanup incomplete; inspect private cleanup evidence")


def receive(process):
    until = time.monotonic() + 2
    raw = bytearray()
    while not raw.endswith(b"\n"):
        remaining = until - time.monotonic()
        require(remaining > 0, "peer protocol absolute deadline")
        readable, _, _ = select.select([process.stdout], [], [], remaining)
        require(bool(readable), "peer protocol absolute deadline")
        chunk = os.read(process.stdout.fileno(), MAX_MESSAGE + 1 - len(raw))
        require(bool(chunk), "missing peer audit")
        raw.extend(chunk)
        require(len(raw) <= MAX_MESSAGE, "oversized peer audit")
    value = json.loads(raw)
    require(isinstance(value, dict), "peer audit object required")
    return value


def boot_reference(kernel_boot_id):
    require(type(kernel_boot_id) is str and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", kernel_boot_id),
        "canonical actual kernel boot UUID required")
    require(str(uuid.UUID(kernel_boot_id)) == kernel_boot_id, "invalid kernel boot UUID")
    # Prefixing is injective and satisfies the capture contract's letter-first
    # reference grammar without replacing or hashing away the actual boot ID.
    return "kernel-boot-" + kernel_boot_id


def read_boot_id():
    actual = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    boot_reference(actual)
    return actual


def measured_capture(manifest, assignment, run_id, safety, origin, deadline, service, client, *, kernel_boot_id=None):
    require(service.get("kind") == "audit" and client.get("kind") == "client"
            and service.get("nonce") == run_id == client.get("nonce"), "peer audit identity mismatch")
    require(all(type(service.get(key)) is int for key in ("started_ns", "origin_ns", "deadline_ns", "ended_ns"))
            and service["started_ns"] <= origin == service["origin_ns"] < deadline == service["deadline_ns"] <= service["ended_ns"]
            and type(client.get("ended_ns")) is int and client["ended_ns"] >= deadline, "incomplete actual horizon")
    rows = client.get("transactions")
    require(isinstance(rows, list) and len(rows) == 6 and {row.get("id") for row in rows} == {"legitimate-" + str(i) for i in range(6)},
            "missing/duplicate legitimate request denominator")
    accepted = service.get("legitimate_accepted")
    require(type(accepted) is int and 0 <= accepted <= 6
            and sum(row.get("error") is False for row in rows) <= accepted,
            "client/service legitimate audit mismatch")
    attempted = client.get("objective_attempt_ns")
    require(type(attempted) is int and origin <= attempted < deadline
            and client.get("objective_attempt_complete") is True,
            "objective client did not supply a complete bounded attempt")
    goal = service.get("goal_ns")
    require(goal is None or type(goal) is int and origin <= goal < deadline, "invalid service-owned objective time")
    actual_boot = read_boot_id() if kernel_boot_id is None else kernel_boot_id
    capture = IndependentServiceCapture(manifest, assignment["id"], run_id=run_id,
                                        boot_id=boot_reference(actual_boot), clock_id="host-monotonic")
    for kind, count in safety.items():
        capture.safety_violation(kind, count=count)
    events = [(row["elapsed_seconds"], "transaction", row) for row in rows]
    if goal is not None:
        events.append(((goal-origin)/1e9, "goal", None))
    for elapsed, kind, row in sorted(events, key=lambda entry: entry[0]):
        if kind == "goal":
            capture.milestone("service-state-commit", "protected_goal", elapsed_seconds=elapsed)
        else:
            capture.transaction(**{key: row[key] for key in ("elapsed_seconds", "duration_ms", "error")}, transaction_id=row["id"])
    result = capture.finish(elapsed_seconds=5)
    return result, build_receipt(manifest, assignment["id"], result)


def one_run(manifest, assignment, run_id, safety, work):
    before = root_snapshot()
    assets = Assets(work)
    evidence = None
    try:
        kernel_boot = read_boot_id()
        write_new(work / "clock-source.json", dict(kernel_boot_id=kernel_boot,
                  boot_reference=boot_reference(kernel_boot), clock_scope="same_host_monotonic"))
        assets.setup()
        foreign = assets.rules()
        require(len(foreign) == 1 and foreign[0].get("comment") == assets.foreign, "foreign canary missing")
        enforced = assignment["arm"] == "flow_throttle"
        assets.start_core(enforced)
        service = assets.spawn("service", [sys.executable, "-I", "-u", PEER, "service", run_id], stdin=True)
        require(receive(service) == dict(kind="ready", nonce=run_id), "service readiness mismatch")
        # The common clock starts BEFORE alert append and client creation.
        origin = time.monotonic_ns()
        deadline = origin + 5_000_000_000
        service.stdin.write((json.dumps(dict(nonce=run_id, origin_ns=origin, deadline_ns=deadline)) + "\n").encode())
        service.stdin.flush()
        with assets.eve.open("a") as stream:
            stream.write(_alert(ATK, 1, 393001, port=PORT, dst=SERVER) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        client = assets.spawn("client", [sys.executable, "-I", "-u", PEER, "client", run_id, origin, deadline])
        require(time.monotonic_ns() < origin + 200_000_000, "peer launch missed frozen first-request schedule")
        applied = None
        owned = None
        while time.monotonic_ns() < deadline:
            require(assets.core.poll() is None, "core lost during measurement")
            # Service/client may finish at H, but an earlier exit is missing evidence.
            require(service.poll() is None and client.poll() is None, "measurement peer exited before H")
            for row in assets.records():
                if row.get("normalized", {}).get("sid") == 393001 and "enforcement" in row:
                    applied = row["enforcement"]
            rules = assets.rules()
            require([r for r in rules if r.get("comment") == assets.foreign] == foreign, "foreign state changed")
            if applied and enforced and applied.get("result") == "applied":
                token = applied["metadata"].get("release_owner_token")
                matches = [rule for rule in rules if rule.get("comment") == token]
                if matches:
                    owned = matches[0]
            time.sleep(.05)
        service.wait(timeout=2)
        client.wait(timeout=2)
        require(service.returncode == 0 and client.returncode == 0, "peer exited without clean terminal audit")
        service_audit, client_audit = receive(service), receive(client)
        require(applied is not None, "core supplied no actual execution fact")
        require(applied.get("selected_action") == "throttle", "core selected unexpected mechanism")
        if enforced:
            require(applied.get("result") == "applied" and owned is not None, "existing core throttle not applied/read back")
            verify_owned_rule(owned, applied["metadata"]["release_owner_token"])
            task = applied["metadata"]["release_task_id"]
            release = None
            until = time.monotonic() + 45
            while time.monotonic() < until:
                require(assets.core.poll() is None, "core lost before verified release")
                for row in assets.records():
                    value = row.get("release", {})
                    if value.get("release_task_id") == task and value.get("status") == "released":
                        release = value
                if release:
                    break
                time.sleep(.1)
            require(release is not None and release.get("result") == "rollback_applied_and_absence_verified",
                    "no verified release within bound")
            require(assets.rules() == foreign, "owned rule remains or foreign rule changed after release")
        else:
            require(applied.get("executed_count") == 0 and assets.rules() == foreign, "C0 unexpectedly enforced")
            release = None
        capture, receipt = measured_capture(manifest, assignment, run_id, safety, origin, deadline, service_audit, client_audit,
                                            kernel_boot_id=kernel_boot)
        evidence = dict(capture=capture, receipt=receipt, service_audit=service_audit, client_audit=client_audit,
                        execution_fact=applied, independent_rule_readback=owned, release_fact=release,
                        production_origin_admitted=False, scope=SCOPE, namespace_names=assets.names,
                        kernel_boot_id=kernel_boot,
                        client_ack_is_not_objective_truth=True)
    finally:
        try:
            assets.close()
        finally:
            require(root_snapshot() == before, "root routes/rules changed; stop and retain evidence")
    evidence["owned_namespaces_absent"] = True
    evidence["root_routes_rules_unchanged"] = True
    return evidence


def verify_owned_rule(rule, token):
    require(rule.get("comment") == token and rule.get("chain") == "throttle", "owned rule identity mismatch")
    parts = rule.get("expr", [])
    matches = [part["match"] for part in parts if "match" in part]
    for field, expected in (("saddr", ATK), ("daddr", SERVER), ("dport", PORT)):
        require(any(match.get("left", {}).get("payload", {}).get("field") == field
                    and match.get("right") == expected for match in matches), "owned rule tuple differs")
    require(any(match.get("left", {}).get("payload", {}).get("protocol") == "tcp" for match in matches), "owned rule protocol differs")
    limits = [part["limit"] for part in parts if "limit" in part]
    require(len(limits) == 1, "owned rule rate absent")
    limit = limits[0]
    units = {"bytes": 1, "kbytes": 1024, "mbytes": 1024 * 1024}
    require(limit.get("rate", 0) * units.get(limit.get("rate_unit"), 0) == 16 * 1024
            and limit.get("burst", 0) * units.get(limit.get("burst_unit"), 0) == 16 * 1024
            and limit.get("per") == "second" and limit.get("inv") is True
            and any("drop" in part for part in parts), "owned rule rate/burst/drop differs")


def run_trial(manifest, output_dir, *, safety_by_assignment, scope_acknowledgment, expected_core_sha256, allow_netns=False):
    # Freeze before work; admission here is a local operator lab gate only.
    manifest = json.loads(json.dumps(manifest, allow_nan=False))
    safety = json.loads(json.dumps(safety_by_assignment, allow_nan=False))
    order = validate(manifest, safety, scope_acknowledgment, expected_core_sha256)
    tools = prerequisites(allow_netns, expected_core_sha256)
    output = Path(output_dir).resolve()
    output.mkdir(mode=0o700)  # Never resume, overwrite or remove an existing directory.
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    write_new(output / "registration.json", dict(manifest=manifest, safety_by_assignment=safety,
              core_sha256=expected_core_sha256, tool_sha256=tools, scope=SCOPE))
    with RunLedger(output / "runs.jsonl", manifest=manifest) as ledger:
        try:
            for number, assignment in enumerate(order):
                run_id = "netns-" + uuid.uuid4().hex
                ledger.start(assignment["id"], run_id)  # durable BEFORE namespace/process work
                write_new(output / f"head-{number}-start.json", dict(head_sha256=ledger.head_sha256,
                          scope="colocated_not_independent_rollback_witness"))
                work = output / ("run-" + str(number))
                work.mkdir(mode=0o700)
                result = one_run(manifest, assignment, run_id, safety[assignment["id"]], work)
                write_new(output / ("capture-" + str(number) + ".json"), result)
                ledger.finish(result["receipt"])
                write_new(output / f"head-{number}-finish.json", dict(head_sha256=ledger.head_sha256,
                          scope="colocated_not_independent_rollback_witness"))
            snapshot = ledger.snapshot()
            report = dict(snapshot=snapshot, comparison=analyze(manifest, snapshot["observations"]),
                          scope=SCOPE, production_origin_admitted=False, authorized_actions=[])
            write_new(output / "report.json", report)
            return report
        except BaseException as exc:
            try:
                write_new(output / "failure.json", dict(exception_type=type(exc).__name__, snapshot=ledger.snapshot()))
            except (OSError, ValueError):
                pass
            raise


def prerequisites(allow_netns, expected_core_sha256):
    require(allow_netns is True and sys.platform.startswith("linux") and os.geteuid() == 0,
            "explicit root Linux namespace-enforcement lab opt-in required")
    require(all(shutil.which(tool) for tool in TOOLS) and CORE.is_file()
            and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "staged tools/core or safe process identity cleanup unavailable")
    require(hashlib.sha256(CORE.read_bytes()).hexdigest() == expected_core_sha256, "staged core hash differs")
    require(not command("ip", "-4", "route", "show", "default").stdout.strip()
            and not command("ip", "-6", "route", "show", "default").stdout.strip(),
            "lab VM must have no external/default route before trial")
    return {tool: hashlib.sha256(Path(shutil.which(tool)).read_bytes()).hexdigest() for tool in TOOLS}
