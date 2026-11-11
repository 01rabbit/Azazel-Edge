"""Closed v2 read-only evidence composition; never runtime/admission authority.

Public signatures authenticate native/source/witness bytes. Retained Root role
metadata is structural lab provenance, never cryptographic LSM attestation.
Only the unchanged actual reader results may enter the local four-run gate.
"""

from pathlib import Path
from datetime import datetime, timezone

import signed_network_read as old
import signed_network_telemetry_contract as role
import signed_network_telemetry_proof as proof
import signed_network_telemetry_live as live
import signed_network_telemetry_material as material
from signed_network_freshness import _validate_fresh_records
from signed_network_clock import _anchor
from azazel_edge.benchmark.measurement import measure_experiment
from azazel_edge.outcome.input_transport import validate_transport

need, canonical, plan, phase = (
    old.need,
    old.recording.canonical,
    old.phase.plan,
    old.phase,
)


def _same(left, right):
    need(canonical(left) == canonical(right), "original v2 metadata binding differs")


def _effective(snap, directory, mode):
    unit = role.observer_spec(mode)["unit"]
    bus = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(
        ".", "_2e"
    )
    commands = dict(
        systemctl=[
            "systemctl",
            "show",
            unit,
            "--property=" + ",".join(proof.p.EFFECTIVE),
        ],
        busctl=[
            "/usr/bin/busctl",
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            bus,
            "org.freedesktop.systemd1.Service",
            *proof.p.old.HOOKS,
        ],
    )
    raw = {}
    for backend, argv in commands.items():
        prefix = directory / (mode + "-effective-" + backend)
        _same(snap.json(str(prefix) + ".argv.json", maximum=16384), argv)
        result = snap.json(str(prefix) + ".result.json", maximum=4096)
        need(
            set(result) == {"returncode", "error"}
            and type(result["returncode"]) is int
            and result["returncode"] == 0
            and result["error"] is None
            and snap.raw(str(prefix) + ".stderr", maximum=65536)[0] == b"",
            "original effective backend failed or warned",
        )
        raw[backend] = snap.raw(str(prefix) + ".stdout", maximum=65536)[0]
    rows = raw["systemctl"].decode().splitlines()
    need(all("=" in row for row in rows), "malformed effective raw properties")
    pairs = [row.split("=", 1) for row in rows]
    extra = {key: value for key, value in pairs if key in proof.p.EXTRA}
    need(
        len(pairs) == len({key for key, _ in pairs}) and set(extra) == proof.p.EXTRA,
        "missing/duplicate original proc properties",
    )
    base = "\n".join(
        row for row in rows if row.split("=", 1)[0] not in proof.p.EXTRA
    ).encode()
    return {**proof.p.old.merged_effective(base, raw["busctl"]), **extra}


def _role_bundle(snap, mode, binding):
    directory = phase.WORK / ("initialize" if mode == "initialize" else "live")
    name = "initializer" if mode == "initialize" else "live"
    bundle = snap.json(directory / (name + "-verified-bundle.json"))
    need(
        set(bundle) == {"proof", "binding", "binding_sha256"},
        "closed Root bundle required",
    )
    _same(bundle["binding"], binding)
    need(
        bundle["binding_sha256"] == plan.manifest_digest(binding),
        "Root bundle digest differs",
    )
    data, metadata, actor = (
        bundle["proof"],
        bundle["proof"]["metadata"],
        bundle["proof"]["actor"],
    )
    need(
        set(data) == {"ready", "effective", "actor", "metadata"},
        "complete Root pre-API bundle required",
    )
    ready = proof.parse_ready(
        snap.raw(directory / (mode + "-pre-api-ready.raw"), maximum=16384)[0],
        mode,
        kernel_boot_id=binding["kernel_boot_id"],
        source_sha256=binding["observer_source_sha256"],
    )
    _same(ready, data["ready"])
    proof.legacy.validate_role_identity(actor["identity"])
    _same(actor["identity"], ready["identity"])
    effective = _effective(snap, directory, mode)
    _same(effective, data["effective"])
    proof.p._validate_effective(
        effective, role.observer_spec(mode), proof.reserved_argv(mode)
    )
    for key, expected in dict(
        mode=mode,
        kernel_boot_id=binding["kernel_boot_id"],
        observed_kernel_boot_id=binding["kernel_boot_id"],
        source_sha256=binding["observer_source_sha256"],
        observed_source_sha256=binding["observer_source_sha256"],
        reserved_argv=proof.reserved_argv(mode),
    ).items():
        _same(metadata[key], expected)
    handles = metadata["namespaces_before"]
    _same(handles, metadata["namespaces_after"])
    _same(handles[role.NSFS_TARGETS[0]], binding["namespace"])
    evidence = actor["evidence"]
    _same(evidence["namespaces"], evidence["namespace_after"])
    _same(evidence["namespaces"]["net"], binding["namespace"])
    need(
        set(evidence["fd_names"]) == {"0", "1", "2"} and len(evidence["fd_names"]) == 3,
        "exact original stdio only",
    )
    stdio = evidence["expected_stdio"]
    need(set(stdio) == {"0", "1", "2"}, "original Root stdio counterparts required")
    proof.legacy.validate_pipe_fds(
        evidence["fds"], {int(key): value for key, value in stdio.items()}
    )
    proof._proc_view(
        evidence["raw"]["mountinfo"],
        own_mount_ns=evidence["namespaces"]["mnt"],
        pid1_mount_ns=evidence["namespaces"]["pid1_mnt"],
        proc_device=evidence["proc_device"],
    )
    proof._bind_nsfs(evidence["raw"]["mountinfo"], handles)
    before, after = evidence["before"], evidence["after"]
    need(
        before["LoadState"] == "loaded"
        and before["ActiveState"] == "active"
        and before["MainPID"] == str(actor["identity"]["pid"])
        and before["ControlPID"] == "0"
        and before["ControlGroup"]
        == "/system.slice/" + role.observer_spec(mode)["unit"],
        "actual role state differs",
    )
    for key in ("LoadState", "ActiveState", "MainPID", "ControlPID", "ControlGroup"):
        _same(before[key], after[key])
    need(
        old.lab.pid_identity(before["pid_stat"])
        == old.lab.pid_identity(after["pid_stat"]),
        "actual role PID/start drift",
    )
    status_rows = [
        line.split(":", 1) for line in evidence["raw"]["status"].splitlines()
    ]
    need(
        all(len(row) == 2 for row in status_rows)
        and len(status_rows) == len({row[0] for row in status_rows}),
        "ambiguous original kernel status",
    )
    status = dict(status_rows)
    need(
        status["Uid"].split() == status["Gid"].split() == ["61002"] * 4
        and status["NoNewPrivs"].strip() == "1"
        and all(
            int(status[key], 16) == 0
            for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd")
        )
        and int(status["Pid"]) == int(status["Tgid"]) == actor["identity"]["pid"]
        and evidence["raw"]["label"].strip() == role.PROFILE + " (enforce)"
        and evidence["raw"]["cgroup"]
        == "0::/system.slice/" + role.observer_spec(mode)["unit"] + "\n",
        "original kernel role/cgroup differs",
    )
    for key in ("status", "label", "cgroup", "mountinfo"):
        _same(
            snap.raw(directory / (mode + "-" + key + ".raw"), maximum=1024 * 1024)[
                0
            ].decode(),
            evidence["raw"][key],
        )
    return bundle


def _runtime_context(snap, inputs, prepared, facts, trust, terminal):
    need(
        prepared["schema_version"] == "signed-network-telemetry-prepared/v2",
        "v2 prepared context required",
    )
    initial = snap.json(phase.WORK / "initialize/initializer-result.json")
    binding = initial["binding"]
    live._initialized(initial, binding)
    _same(initial, prepared["initialization"])
    _same(
        binding["material"]["source_sha256"],
        inputs["manifest"]["measurement_binding"]["telemetry_lab"]["source_sha256"],
    )
    _same(
        binding["material"]["source_sha256"],
        {
            str(path.relative_to(material.SRC)): old.sha(
                snap.raw(path, maximum=1024 * 1024)[0]
            )
            for path in material.source_paths()
        },
    )
    need(
        binding["kernel_boot_id"]
        == terminal["context"]["kernel_boot_id"]
        == prepared["kernel_boot_id"]
        and binding["role"] == role.ROLE,
        "current v2 role/boot differs",
    )
    _same(
        binding["roles"],
        {mode: role.observer_spec(mode) for mode in ("initialize", "live")},
    )
    public = binding["public_auth"]
    need(
        public["trust_sha256"] == trust.digest
        and public["trust_file_sha256"]
        == old.sha(snap.raw(old.g.BUNDLE / "trust.json", maximum=16384)[0])
        and public["origin_file_sha256"]
        == old.sha(snap.raw(old.g.BUNDLE / "origin.json", maximum=16384)[0]),
        "public scope bytes differ",
    )
    for key in (
        "scope_ref",
        "source_path",
        "journal_directory",
        "origin_registration_sha256",
        "producer_uid",
        "observer_uid",
        "witness_uid",
    ):
        _same(public[key], trust.data[key])
    descriptor = validate_transport(
        trust.data["scope_ref"], public["witness_transport"]
    )
    _same(descriptor, trust.data["witness_transport"])
    need(
        public["trust_schema"] == "outcome-input-trust/v4"
        and descriptor["network_namespace"]["kernel_boot_id"]
        == binding["kernel_boot_id"],
        "explicit current abstract transport required",
    )
    witness = binding["witness_actor"]
    _same(witness["witness_transport"], descriptor)
    _same(witness["namespace_observation"], descriptor["network_namespace"])
    _same(
        witness["network_namespace"],
        dict(zip(("device", "inode"), binding["namespace"])),
    )
    need(
        witness["unit"] == old.g.WITNESS
        and type(witness["pid"]) is int
        and witness["pid"] > 1
        and witness["apparmor"] == "edge400-witness (enforce)"
        and witness["listener"]["abstract_name"] == descriptor["name"],
        "fixed witness provenance differs",
    )
    for mode in ("initialize", "live"):
        _role_bundle(snap, mode, binding)
    _same(snap.json(phase.WORK / "live/live-result.json")["terminal"], terminal)
    _same(prepared["assignment_mode_sha256"], inputs["assignment_mode_sha256"])
    return binding


def _root_children():
    return sorted(phase.WORK.glob("namespace-cookie-*-receipt.json")) + sorted(
        phase.WORK.glob("switch-witness-*-receipt.json")
    )


class _TelemetryReader:
    def __init__(self, pins):
        self.pins = pins

    def validated_inputs(self, manifest_sha256, start_head):
        import signed_network_telemetry_phase as prep

        return prep.validated_telemetry_inputs(manifest_sha256, start_head, **self.pins)

    def verify_context(self, snap, inputs, prepared, facts, trust, terminal, calls):
        self.binding = _runtime_context(snap, inputs, prepared, facts, trust, terminal)
        self._queries(snap, facts["record"], terminal, calls)
        return dict(
            scope="retained_Root_lab_metadata_not_signature_or_live_kernel_attestation",
            binding_sha256=plan.manifest_digest(self.binding),
            cryptographic_observer_label_binding=False,
        )

    def _queries(self, snap, record, terminal, calls):
        self.controller_samples, self.calls = [], calls
        start, end = (
            _anchor(record["controller_start_anchor"]),
            _anchor(record["controller_end_anchor"]),
        )
        launch_receipt = snap.json(phase.WORK / "live/live-launch.json")
        reaped = snap.json(phase.WORK / "live/live-client-reap.json")
        need(
            set(launch_receipt)
            == {
                "kind",
                "client_pid",
                "client_launch_before_ns",
                "client_launch_after_ns",
                "deadline_monotonic_ns",
                "budget_seconds",
            }
            and launch_receipt["kind"] == "owned_systemd_run_client_popen/v1"
            and type(launch_receipt["client_pid"]) is int
            and launch_receipt["client_pid"] == reaped["pid"]
            and reaped["reaped"] is True
            and reaped["forced"] is False
            and reaped["errors"] == []
            and all(
                type(launch_receipt[key]) is int
                for key in (
                    "client_launch_before_ns",
                    "client_launch_after_ns",
                    "deadline_monotonic_ns",
                    "budget_seconds",
                )
            )
            and launch_receipt["budget_seconds"] == 40
            and launch_receipt["deadline_monotonic_ns"]
            == launch_receipt["client_launch_before_ns"] + 40_000_000_000
            and type(record["observer_helper_return_ns"]) is int
            and start[2]
            <= launch_receipt["client_launch_before_ns"]
            <= launch_receipt["client_launch_after_ns"]
            <= record["origin_ns"]
            <= record["deadline_ns"]
            <= end[0]
            and end[2]
            <= terminal["end_clock_anchor"]["monotonic_before_ns"]
            <= terminal["end_clock_anchor"]["monotonic_after_ns"]
            <= record["observer_helper_return_ns"]
            <= launch_receipt["deadline_monotonic_ns"],
            "original live client launch/runtime bound differs",
        )
        for label in ("baseline", "active", "absence"):
            query = snap.json(phase.WORK / (label + "-query.json"))
            launch = snap.json(phase.WORK / (label + "-query-launch.json"))
            need(
                query["kernel_boot_id"] == record["kernel_boot_id"]
                and type(launch["launch_before_ns"]) is int
                and type(launch["launch_after_ns"]) is int,
                "actual query boot/launch missing",
            )
            first, last = (
                query["query_start_clock_anchor"],
                query["query_end_clock_anchor"],
            )
            a, b = _anchor(first), _anchor(last)
            need(
                start[2]
                <= launch["launch_before_ns"]
                <= launch["launch_after_ns"]
                <= a[0]
                <= a[2]
                <= b[0]
                <= b[2]
                <= end[0]
                <= terminal["end_clock_anchor"]["monotonic_before_ns"],
                "actual Root query outside controller/observer interval",
            )
            need(
                query["query_started_at"]
                == datetime.fromtimestamp(a[1] / 1e9, timezone.utc).isoformat()
                and query["query_ended_at"]
                == datetime.fromtimestamp(b[1] / 1e9, timezone.utc).isoformat(),
                "query UTC is not original sampled anchor epoch",
            )
            need(
                (b[2] <= launch_receipt["client_launch_before_ns"])
                if label == "baseline"
                else (
                    launch_receipt["client_launch_after_ns"]
                    <= launch["launch_before_ns"]
                ),
                "query/client launch ordering differs",
            )
            self.controller_samples.extend((first, last))
        need(len(self.controller_samples) == 6, "all six actual Root anchors required")

    def _callback_order(self, snap, record, event, label, name):
        ready = snap.json(phase.WORK / name, maximum=65536)
        need(
            set(ready)
            == {
                "row",
                "recording_identity",
                "raw_sha256",
                "complete_sha256",
                "partial_tail_bytes",
                "observed_before_ns",
                "observed_after_ns",
            },
            "closed callback prefix receipt required",
        )
        directory = old.g.BUNDLE / "observer"
        closed, info = snap.raw(
            directory / "actual-collector-calls.jsonl", 61002, old.recording.MAX_BYTES
        )
        raw = snap.raw(
            phase.WORK / (label + "-callback-prefix.raw"),
            maximum=old.recording.MAX_BYTES,
        )[0]
        complete = snap.raw(
            phase.WORK / (label + "-callback-complete.raw"),
            maximum=old.recording.MAX_BYTES,
        )[0]
        need(
            raw
            and closed.startswith(raw)
            and complete == raw[: raw.rfind(b"\n") + 1]
            and old.sha(raw) == ready["raw_sha256"]
            and old.sha(complete) == ready["complete_sha256"]
            and type(ready["partial_tail_bytes"]) is int
            and ready["partial_tail_bytes"] == len(raw) - len(complete),
            "original complete/partial callback prefix differs",
        )
        _same(
            ready["recording_identity"],
            dict(device=info.st_dev, inode=info.st_ino, uid=61002),
        )
        need(info.st_uid == 61002, "callback recording owner differs")
        matches = [
            row
            for row in self.calls["calls"]
            if row["kind"] == "event"
            and canonical(row["data"]["event"]) == canonical(event)
        ]
        need(len(matches) == 1, "unique signed collector callback required")
        _same(matches[0], ready["row"])
        need(
            any(
                canonical(old.strict(line)) == canonical(ready["row"])
                for line in complete.splitlines()
            ),
            "callback absent from original observed prefix",
        )
        before, after = ready["observed_before_ns"], ready["observed_after_ns"]
        launch = snap.json(phase.WORK / (label + "-query-launch.json"))
        data = ready["row"]["data"]
        need(
            type(before) is int
            and type(after) is int
            and 0 <= before <= after < 2**63
            and data["clock_after"]["monotonic_after_ns"]
            <= after
            <= launch["launch_before_ns"],
            "query was not launched after actual recorded callback",
        )
        query = snap.json(phase.WORK / (label + "-query.json"))
        if label == "active":
            need(
                record["origin_ns"] + 1_000_000_000
                <= data["clock_before"]["monotonic_before_ns"]
                <= data["start_ns"]
                <= data["end_ns"]
                <= data["clock_after"]["monotonic_after_ns"]
                <= record["deadline_ns"] - 2_000_000_000
                and query["query_end_clock_anchor"]["monotonic_after_ns"]
                <= record["deadline_ns"],
                "actual callback pre/post window lies outside H5",
            )
        epoch = data["epoch"]
        started, ended = (
            datetime.fromisoformat(query[key]).timestamp()
            for key in ("query_started_at", "query_ended_at")
        )
        need(
            epoch <= started <= ended and (label != "active" or ended <= epoch + 2),
            "query missed actual callback/post-window cutoff",
        )

    def verify_stop(self, snap, inputs, record):
        from signed_network_telemetry_commission_setup import UNITS

        receipt = snap.json(phase.WORK / "assignment-cleanup.json")
        actors = snap.json(phase.WORK / "actor-cleanup.json")
        namespaces = snap.json(phase.WORK / "namespace-evidence/cleanup.json")
        need(
            receipt["schema_version"] == "signed-network-telemetry-cleanup/v2"
            and receipt["errors"] == []
            and receipt["cleanup_verified"] is True
            and receipt["measurement_completed"]
            is receipt["production_admission"]
            is False,
            "v2 cleanup unavailable",
        )
        _same(receipt["actor_cleanup"], actors)
        _same(receipt["namespace_cleanup"], namespaces)
        need(
            actors["errors"] == namespaces["errors"] == []
            and namespaces["cleanup_verified"] is True
            and [a["unit"] for a in namespaces["actors"]] == list(UNITS),
            "complete closed actor union required",
        )
        for actor in namespaces["actors"]:
            state = actor["state"]
            need(
                state["ActiveState"] in ("inactive", "failed")
                and state["MainPID"] == state["ControlPID"] == "0"
                and state["ControlGroup"] in ("", "/system.slice/" + actor["unit"]),
                "actor remains or unknown",
            )
        need(
            type(receipt["processes"]) is list and len(receipt["processes"]) == 5,
            "two peers/three query clients required",
        )
        need(
            len({process["pid"] for process in receipt["processes"]}) == 5,
            "owned clients reused/duplicated",
        )
        for process in receipt["processes"]:
            need(
                type(process["pid"]) is int
                and process["pid"] > 1
                and process["forced"] is False
                and type(process["returncode"]) is int
                and process["returncode"] == 0,
                "owned client was not cleanly reaped",
            )
        launches = [
            snap.json(phase.WORK / (label + "-query-launch.json"))
            for label in ("baseline", "active", "absence")
        ] + [
            snap.json(phase.WORK / (label + "-peer-launch.json"))
            for label in ("service", "client")
        ]
        expected = []
        for launch in launches:
            need(
                type(launch["pid"]) is int
                and launch["pid"] > 1
                and type(launch["actual_child_argv"]) is list
                and launch["actual_child_argv"]
                and all(type(arg) is str for arg in launch["actual_child_argv"])
                and type(launch["launch_before_ns"]) is int
                and type(launch["launch_after_ns"]) is int
                and 0
                <= launch["launch_before_ns"]
                <= launch["launch_after_ns"]
                < 2**63,
                "original owned process launch unavailable",
            )
            expected.append(dict(pid=launch["pid"], argv=launch["actual_child_argv"]))
        need(len({row["pid"] for row in expected}) == 5, "original launch PID reused")
        _same(
            sorted(
                [
                    dict(pid=row["pid"], argv=row["argv"])
                    for row in receipt["processes"]
                ],
                key=lambda row: row["pid"],
            ),
            sorted(expected, key=lambda row: row["pid"]),
        )
        children = _root_children()
        need(
            type(receipt["root_child_count"]) is int
            and 1 <= receipt["root_child_count"] == len(children) <= 32,
            "all Root child receipts required",
        )
        for path in children:
            child = snap.json(path, maximum=16384)
            need(
                child["error"] is None
                and child["errors"] == []
                and child["group_empty_before_reap"] is child["reaped"] is True
                and type(child["status"]) is int
                and child["status"] == 0
                and not child.get("forced", False),
                "Root child remains/forced/unknown",
            )

    def root_probes(self, snap, record, inputs, event, candidate):
        for index in (1, 2, 3):
            for name in ("intent", "confirmed"):
                filename = "namespace-" + name + "-" + str(index) + ".json"
                need(
                    snap.raw(phase.WORK / filename)[0]
                    == snap.raw(phase.WORK / "namespace-evidence" / filename)[0],
                    "namespace original copy differs",
                )
        expected = dict(
            source_revision=inputs["source_commit"],
            helper_sha256=old.sha(
                snap.raw(
                    material.SRC / "tests/real_systemd/signed_network_telemetry_run.py",
                    maximum=1024 * 1024,
                )[0]
            ),
            network_driver_sha256=old.sha(
                snap.raw(Path(old.n.__file__), maximum=1024 * 1024)[0]
            ),
        )
        probe = old._root_probes(
            snap, record, inputs, event, candidate, expected_source_identity=expected
        )
        self._callback_order(
            snap, record, event, "active", "active-callback-ready.json"
        )
        if candidate:
            self._callback_order(
                snap,
                record,
                record["release"],
                "absence",
                "release-callback-ready.json",
            )
        return probe


def read_telemetry_assignment(
    expected_manifest_sha256,
    expected_start_head,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Same-guest original protected layout only; no imported runtime authority."""
    pins = dict(
        source_commit=source_commit,
        archive_sha256=archive_sha256,
        core_sha256=core_sha256,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
    )
    return old._read_assignment_artifacts(
        expected_manifest_sha256, expected_start_head, contract=_TelemetryReader(pins)
    )


def validate_fresh_telemetry_records(
    manifest,
    read_results,
    *,
    core_sha256,
    source_commit,
    archive_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Local structural check on UNCHANGED actual reader returns, not JSON auth."""
    pins = manifest["measurement_binding"]["telemetry_lab"]
    for value in (core_sha256, archive_sha256, abi_sha256, interpreter_sha256):
        material.pin(value)
    need(
        manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"] == source_commit
        and pins["source_archive_sha256"] == archive_sha256
        and pins["abi_sha256"] == abi_sha256
        and pins["interpreter_sha256"] == interpreter_sha256,
        "external shared v2 source/pins differ",
    )
    return _validate_fresh_records(
        manifest, read_results, core_sha256=core_sha256, telemetry=True
    )


def read_telemetry_experiment(manifest, read_results, **pins):
    """Read-only existing calculation after exact four fresh authenticated runs."""
    records = validate_fresh_telemetry_records(manifest, read_results, **pins)
    return measure_experiment(
        manifest, dict(manifest_sha256=plan.manifest_digest(manifest), records=records)
    )
