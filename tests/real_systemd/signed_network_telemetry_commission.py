"""Manual one-fresh-scope authenticated connection commissioning, never a trial.

External Root source/profile staging is mandatory. No four-manifest, workload,
H/G5/effect calculation, profile load, retry, backfill or activation is exposed.
"""

import hashlib
import os
from pathlib import Path
import stat
import time

import signed_network_telemetry_commission_setup as setup
from signed_network_telemetry_namespaces import NamespaceSetup
import signed_network_telemetry_initialize as initializer
from signed_network_telemetry_live import live
from signed_network_telemetry_switch_witness import WitnessProof
import signed_network_read as reader
from telemetry_isolation_result import _sample
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, read_regular
from azazel_edge.outcome.input_live import registration
from azazel_edge.outcome.input_service import layout
from azazel_edge.outcome.telemetry import persistence_context

lab, g, plan, material = setup.lab, setup.g, setup.plan, setup.material


def _base_created(output):
    """Called only inside the current prepare_lab exclusive BASE.mkdir path."""
    parent, name = material.preflight.open_parent(g.BASE, trusted_owner=0)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
        lab.need(
            info.st_uid == 0
            and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino),
            "fresh BASE identity differs",
        )
        lab.save_json(
            output / "fresh-base-created.json",
            dict(
                device=info.st_dev,
                inode=info.st_ino,
                original_mode=stat.S_IMODE(info.st_mode),
                creator="current_guest_prepare_lab_exclusive_mkdir",
            ),
        )
        os.fchmod(fd, 0o755)
        os.fsync(fd)
        os.fsync(parent)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        lab.need(
            (after.st_dev, after.st_ino) == (info.st_dev, info.st_ino)
            and after.st_uid == 0
            and stat.S_IMODE(after.st_mode) == 0o755,
            "fresh BASE changed",
        )
        lab.save_json(
            output / "fresh-base-traversable.json",
            dict(device=info.st_dev, inode=info.st_ino, mode=0o755),
        )
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _configure(callback, created, namespace_identity, *, owner, output, arm="c0"):
    lab.need(
        type(arm) is str and arm in ("c0", "flow_throttle"), "fixed native arm required"
    )
    original = g.write
    held = dict(
        zip(("device", "inode"), initializer.proof.legacy._pair(namespace_identity))
    )
    lab.need(
        all(v > 0 for v in held.values()) and owner.edge()[1] == list(held.values()),
        "owned EDGE namespace required",
    )
    proof_adapter = WitnessProof(owner, output)
    namespace = proof_adapter.sample_namespace()

    def protected_write(path, data, mode=0o644):
        if path == g.BASE / "native/protected.yaml":
            data = plan.PROTECTED
        if path == g.UNITS / g.WITNESS:
            expected = (
                f"ExecStart={g.PYTHON} -I -m azazel_edge.outcome.input_witness "
                f"--policy {g.BUNDLE}/trust.json --private-key {g.BUNDLE}/witness/key.raw "
                "--systemd-notify --apparmor-profile edge400-witness\n"
            )
            lab.need(
                type(data) is str
                and [
                    line
                    for line in data.splitlines(keepends=True)
                    if line.lstrip().startswith("ExecStart=")
                ]
                == [expected],
                "exact current witness command required",
            )
            for key, old, new in (
                ("Type", "notify", "exec"),
                ("NotifyAccess", "main", "none"),
            ):
                lab.need(
                    [
                        line
                        for line in data.splitlines(keepends=True)
                        if line.lstrip().startswith(key + "=")
                    ]
                    == [key + "=" + old + "\n"],
                    "exact witness notify source required",
                )
                data = data.replace(key + "=" + old + "\n", key + "=" + new + "\n", 1)
            data = data.replace(
                expected,
                expected.replace(" -I -m ", " -I -B -m ").replace(
                    " --systemd-notify", ""
                ),
                1,
            )
            lab.need(
                "NetworkNamespacePath=" not in data,
                "witness namespace already configured",
            )
            data += (
                "\n[Service]\nNetworkNamespacePath=" + setup.role.NSFS_TARGETS[0] + "\n"
            )
        result = original(path, data, mode)
        if path in (g.UNITS / g.UNIT, g.UNITS / g.WITNESS):
            created(path, data)
        return result

    g.write = protected_write  # BEFORE provider captures its template writer.
    plan.p.configure()
    prepare = g.prepare

    def prepare_abstract(*args, **kwargs):
        lab.need(
            "witness_network_namespace" not in kwargs, "fixed owned namespace only"
        )
        return prepare(*args, **kwargs, witness_network_namespace=namespace)

    g.prepare = prepare_abstract
    witness = g.Systemd.witness

    def witness_in_edge(system, bundle, policy):
        return proof_adapter.run(witness, system, bundle, policy)

    g.Systemd.witness = witness_in_edge
    g.ENV.clear()
    g.ENV.update(plan.native_environment(arm))
    g.observer = callback
    return proof_adapter


def _prefix(trust, output):
    raw, _ = read_regular(
        Path(trust.data["source_path"]), owner=61001, max_bytes=4 * 1024 * 1024
    )
    lab.save(output / "source-prefix.raw", raw)
    verified = SourceVerifier(trust)
    verified.verify(raw)
    wires = [plan.strict(line) for line in raw.splitlines()]
    events = [wire["event"] for wire in wires]
    lab.need(
        len(events) == 2
        and [e["capture_origin"]["kind"] for e in events]
        == ["session_prepare", "session_start"]
        and not verified.live_state.closed
        and all(wire["boot_ref"] == g.boot().replace("-", "") for wire in wires),
        "unused exact signed two-frame prefix required",
    )
    return dict(offset=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _ready(session, trust, position, output):
    raw = None
    try:
        deadline = time.monotonic() + 2
        while True:
            lab.need(
                session.poll() is None and time.monotonic() < deadline,
                "actual input_ready missing/dead",
            )
            raw = read_regular(
                Path(trust.data["journal_directory"]) / "observations.journal",
                owner=61002,
                max_bytes=8 * 1024 * 1024,
            )[0]
            if raw.endswith(b"\n") and lab.ready_for(raw, position):
                return
            time.sleep(0.01)
    finally:
        if raw is not None:
            lab.save(output / "input-ready-journal.raw", raw)


def _evidence(output, trust, prefix, result):
    """Original bytes + existing public signature/lifecycle validators only."""
    facts = dict(raw_sha256={})
    snap = reader._Snapshot(facts)
    data, directory = trust.data, Path(trust.data["journal_directory"])
    lab.need(
        reader.recording.canonical(snap.json(g.BUNDLE / "trust.json", maximum=8192))
        == reader.recording.canonical(dict(trust.data)),
        "public trust changed",
    )
    snap.raw(g.BUNDLE / "origin.json", maximum=16384)
    source, source_info = snap.raw(Path(data["source_path"]), 61001, 4 * 1024 * 1024)
    journal, journal_info = snap.raw(
        directory / "observations.journal", 61002, 8 * 1024 * 1024
    )
    anchors, _ = snap.raw(
        Path(data["anchor_directory"]) / "anchors.journal", 0, 8 * 1024 * 1024
    )
    wire, _ = snap.raw(directory / "terminal.wire", 61002, 65536)
    decoded, _ = snap.raw(directory / "terminal.decoded", 61002, 65536)
    for name, raw in (
        ("source-final.raw", source),
        ("journal-final.raw", journal),
        ("witness-anchors.raw", anchors),
        ("terminal.wire", wire),
        ("terminal.decoded", decoded),
    ):
        lab.save(output / name, raw)
    calls_raw, _ = snap.raw(
        directory / "actual-collector-calls.jsonl", 61002, reader.recording.MAX_BYTES
    )
    lab.save(output / "actual-collector-calls.jsonl", calls_raw)
    calls = reader.recording.decode_calls(calls_raw)
    start_context = snap.json(directory / "observer-start-context.json", 61002)
    terminal = snap.json(directory / "observer-terminal-result.json", 61002)
    lab.need(
        reader.recording.canonical(start_context)
        == reader.recording.canonical(terminal["context"]),
        "original start context differs",
    )
    lab.need(
        reader.recording.canonical(terminal)
        == reader.recording.canonical(result["terminal"]),
        "original worker terminal differs",
    )
    frames, verifier, state = reader.witnessed_prefixes(
        trust, source, journal, anchors, journal_info
    )
    events = reader.terminal_chain(
        trust, source, frames, verifier, terminal, wire, decoded
    )
    lab.need(
        len(events) == 3
        and not any(f["kind"] in ("begin", "commit", "lost") for f in frames)
        and state == terminal["witness_state"]
        and terminal["context"]["source_start_position"] == prefix,
        "exact no-workload authenticated session/acknowledgement required",
    )
    payload, policy, policy_file_sha = initializer.observer.policy_material()
    reader._require_ordered_callbacks(calls, events)
    samples = [row["data"] for row in calls["calls"] if row["kind"] == "sample"]
    lab.need(bool(samples), "closed sidecar lacks an actual telemetry sample")
    for sample in samples:
        _sample(sample["sample"])
        lab.need(
            reader.recording.canonical(sample["sample"]["epoch"])
            == reader.recording.canonical(sample["epoch"]),
            "actual sample epoch differs from recorded call",
        )
    lab.need(
        reader.recording.canonical(calls["context"])
        == reader.recording.canonical(
            dict(
                policy_sha256=plan.manifest_digest(payload),
                policy_source_ref=str(plan.POLICY_PATH),
                policy_ref=policy.policy_ref,
            )
        )
        and terminal["context"]["policy_file_sha256"] == policy_file_sha
        and all(
            row["data"]["outcomes"] == []
            for row in calls["calls"]
            if row["kind"] == "finalize"
        ),
        "closed sidecar policy/no-workload context differs",
    )
    lab.need(
        reader.recording.canonical(frames[0]["data"])
        == reader.recording.canonical(
            dict(
                schema_version="outcome-observation-journal/v3",
                scope_ref=data["scope_ref"],
                policy_sha256=reader.sha(
                    persistence_context(policy, "es", plan.INTERVAL).encode()
                ),
                max_identities=4096,
                max_bytes=data["journal_max_bytes"],
                input_config=dict(
                    path_sha256=reader.sha(data["source_path"].encode()),
                    device=source_info.st_dev,
                    inode=source_info.st_ino,
                    uid=61001,
                    max_bytes=data["input_max_bytes"],
                    max_records=data["input_max_records"],
                    authentication=trust.binding(),
                ),
            )
        ),
        "original journal header policy/source binding differs",
    )
    snap.unchanged()
    return dict(
        **facts,
        session_ref=verifier.live_state.session,
        scope_ref=data["scope_ref"],
        registration_sha256=data["origin_registration_sha256"],
        collector_recording=calls,
        collector_recording_provenance="observer_owned_closed_sidecar_not_signed_journal",
        terminal=terminal,
        scope="authenticated_source_journal_signed_witness_terminal_only",
    )


def commission_telemetry(
    output,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """One explicit fresh manual Root case. No manifest or operation defaults."""
    baseline = setup.preflight(
        output,
        source_commit=source_commit,
        archive_sha256=archive_sha256,
        core_sha256=core_sha256,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
    )
    output = Path(output)
    namespaces = NamespaceSetup(output, baseline)  # Kept before any prepare mutation.
    owned, tracked, initialized, failure, evidence = set(), {}, None, None, None
    original = (
        g.write,
        g.prepare,
        g.observer,
        dict(g.ENV),
        plan.p.a.NATIVE,
        g.Systemd.witness,
    )
    try:
        namespaces.prepare()
        fd, pair = namespaces.edge()
        sources = baseline["material"]["source_sha256"]
        observer_sha = sources[str(Path(setup.role.SOURCE).relative_to(material.SRC))]
        args = dict(
            abi_sha256=abi_sha256,
            interpreter_sha256=interpreter_sha256,
            source_sha256=observer_sha,
            expected_sources=sources,
            namespace_fd=fd,
            namespace_identity=pair,
        )
        for name in ("initialize", "live"):
            material.preflight.old.private_output(output / name)

        def initialize(create=False):
            nonlocal initialized
            lab.need(
                create is True and initialized is None,
                "only current genuine fresh init",
            )
            _base_created(output)
            initialized = initializer.initialize(output / "initialize", **args)
            owned.add(setup.role.INITIALIZER_UNIT)
            tracked[setup.role.INITIALIZER_UNIT] = [
                initialized["proof"]["actor"]["evidence"]["before"]
            ]
            return initialized

        def created(path, data):
            info = os.stat(path, follow_symlinks=False)
            lab.need(
                info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "current exclusive unit creation ownership required",
            )
            owned.add(path.name)
            lab.save_json(
                output / ("created-" + path.name + ".json"),
                dict(
                    device=info.st_dev,
                    inode=info.st_ino,
                    sha256=hashlib.sha256(
                        data if type(data) is bytes else data.encode()
                    ).hexdigest(),
                ),
            )

        args["transport_context"] = _configure(
            initialize, created, pair, owner=namespaces, output=output
        )
        lab.need(not os.path.lexists(g.BASE), "new scope only")
        lab.save_json(
            output / "auth-scope-create-intent.json",
            dict(
                creator="current_guest_prepare_lab",
                environment=plan.native_environment("c0"),
            ),
        )
        # Namespace ownership/freshness precedes this trusted fixture's exclusive
        # BASE/unit writes. No existing scope/unit can be repaired or reused.
        g.prepare_lab()  # Witness READY first, then the genuine init callback.
        tracked[g.WITNESS] = [lab.unit_snapshot(g.WITNESS)]
        trust = TrustPolicy(plan.strict(material._read(g.BUNDLE / "trust.json", 8192)))
        layout(g.BUNDLE, trust)
        enrolled = registration(trust, g.BUNDLE / "origin.json")
        lab.need(
            enrolled["schema_version"] == "outcome-live-origin-registration/v4"
            and enrolled["environment"] == plan.native_environment("c0")
            and enrolled["binary_sha256"] == core_sha256,
            "registered current C0 native environment differs",
        )
        namespaces.edge()
        g.systemctl("start", g.UNIT)
        g.wait_for(lambda: len(g.Systemd().cores()) == 1)
        tracked[g.UNIT] = [lab.unit_snapshot(g.UNIT)]
        switch = g.Switch(g.BUNDLE)
        switch_plan = switch.plan()
        lab.save_json(output / "switch-plan.json", switch_plan)
        lab.need(
            switch.apply(switch_plan, g.digest(switch_plan))["status"] == "started",
            "sealed native start failed",
        )
        g.live()
        tracked[g.UNIT].append(lab.unit_snapshot(g.UNIT))
        prefix = _prefix(trust, output)
        namespaces.edge()
        with live(output / "live", initialization=initialized, **args) as session:
            owned.add(setup.role.OBSERVER_UNIT)
            _ready(session, trust, prefix, output)
            namespaces.edge()
            g.stop()  # Native/capture first; observer+witness remain for terminal.
        lab.need(session.result is not None, "typed terminal/live teardown missing")
        evidence = _evidence(output, trust, prefix, session.result)
    except BaseException as exc:
        failure = exc
    finally:
        errors = []

        def attempt(name, operation):
            try:
                return operation()
            except BaseException as exc:
                errors.append((name, type(exc).__name__))

        # Helpers own init/live pipes. Outer scope still attempts every OWNED
        # fixed actor, witness last; legacy families are never signalled here.
        units = tuple(
            u
            for u in (
                setup.role.INITIALIZER_UNIT,
                setup.role.OBSERVER_UNIT,
                g.UNIT,
                g.WITNESS,
            )
            if u in owned
        )
        cleaned = attempt(
            "owned actors",
            lambda: lab.cleanup(units, {u: tracked.get(u, []) for u in units}),
        )
        attempt(
            "actor receipt",
            lambda: lab.save_json(output / "actor-cleanup.json", cleaned),
        )
        attempt(
            "actor proof",
            lambda: lab.need(
                type(cleaned) is dict and cleaned.get("errors") == [],
                "outer actor cleanup incomplete",
            ),
        )
        if errors:
            namespaces.failed = True
        attempt("namespace/marker close", namespaces.close)
        (
            g.write,
            g.prepare,
            g.observer,
            environment,
            plan.p.a.NATIVE,
            g.Systemd.witness,
        ) = original
        g.ENV.clear()
        g.ENV.update(environment)
        if errors:
            if failure is None:
                failure = RuntimeError("commission cleanup incomplete: " + str(errors))
            else:
                failure.add_note("commission cleanup: " + str(errors))
    if failure is not None:
        raise failure
    result = dict(
        status="authenticated_connection_complete",
        scope="single_authenticated_init_live_terminal_connection_only",
        evidence=evidence,
        pins=baseline["pins"],
        kernel_boot_id=baseline["kernel_boot_id"],
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
        measurement_completed=False,
    )
    lab.save_json(output / "commission-result.json", result)
    return result
