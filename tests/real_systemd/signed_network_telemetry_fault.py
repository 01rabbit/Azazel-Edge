"""Fixed Root-owned synthetic fault only; never a negative-case runner/admission.

Only a direct current initializer return and public TrustPolicy are inputs. Root
owns the source fault; these helpers never create a key, scope, actor or endpoint.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import stat

import signed_network_telemetry_initialize as init
import signed_network_telemetry_live as live
from signed_network_telemetry_binding import public_auth_binding
from signed_network_telemetry_negative import synthetic_prepare_frame, EXPECTED_REFUSAL
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    read_regular,
    open_parent,
)
from azazel_edge.outcome.input_service import layout
from azazel_edge.outcome.journal import OutcomeJournalError

lab, g, material = init.lab, init.g, init.material


@dataclass(frozen=True)
class FaultSnapshot:
    trust: TrustPolicy = field(repr=False)
    initialization: dict = field(repr=False)
    records: dict = field(repr=False)
    wire: bytes = field(default=b"", repr=False)


def _guard(output, snapshot):
    g.guard()
    lab.need(
        os.geteuid() == 0 and os.environ.get("EDGE_SIGNED_NETWORK_TELEMETRY") == "1",
        "explicit Root fault opt-in required",
    )
    init.proof.p._output(Path(output))
    lab.need(
        type(snapshot) is FaultSnapshot and type(snapshot.trust) is TrustPolicy,
        "direct current snapshot/trust required",
    )
    layout(g.BUNDLE, snapshot.trust)
    binding = snapshot.initialization["binding"]
    live._initialized(snapshot.initialization, binding)
    public = public_auth_binding()
    current = material.verify_current(
        abi_sha256=binding["material"]["abi_sha256"],
        interpreter_sha256=binding["material"]["interpreter_sha256"],
    )
    lab.need(
        live._same(current, binding["material"])
        and live._same(public, binding["public_auth"])
        and public["trust_sha256"] == snapshot.trust.digest
        and g.boot() == binding["kernel_boot_id"],
        "current fault material/public scope/boot differs",
    )
    lab.need(not g.Systemd().cores(), "negative fault requires no native core")


def _snapshot(output, phase):
    records, errors = {}, []
    for name, path, owner, mode in (
        ("source", g.BUNDLE / "input", 61001, 0o644),
        ("journal", g.BUNDLE / "observer/observations.journal", 61002, 0o600),
        ("anchors", g.BUNDLE / "witness/anchors/anchors.journal", 0, 0o600),
    ):
        try:
            raw, info = read_regular(
                path, owner=owner, mode=mode, max_bytes=8 * 1024 * 1024
            )
            lab.save(Path(output) / (phase + "-" + name + ".raw"), raw)
            identity = dict(
                device=info.st_dev,
                inode=info.st_ino,
                uid=info.st_uid,
                mode=stat.S_IMODE(info.st_mode),
                nlink=info.st_nlink,
            )
            lab.save_json(
                Path(output) / (phase + "-" + name + ".json"),
                dict(
                    identity=identity,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    bytes=len(raw),
                ),
            )
            records[name] = dict(raw=raw, identity=identity)
        except BaseException as exc:
            errors.append((name, type(exc).__name__))
    lab.need(not errors, "fixed fault snapshot incomplete: " + str(errors))
    return records


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def capture_init(output, *, trust, initialization):
    """Capture current genuine empty init; this does not authenticate saved JSON."""
    snapshot = FaultSnapshot(trust, initialization, {})
    _guard(output, snapshot)
    records = _snapshot(output, "fault-init")
    frames = lab.journal_frames(records["journal"]["raw"])
    lab.need(
        records["source"]["raw"] == b""
        and records["anchors"]["raw"].endswith(b"\n")
        and [f["kind"] for f in frames]
        == ["header", "session_open", "input_ready", "session_close"]
        and frames[2]["data"] == dict(offset=0, sha256=hashlib.sha256(b"").hexdigest())
        and frames[-1]["data"] == dict(boot_id=init.plan.n.boot_reference(g.boot())),
        "genuine closed empty init baseline required",
    )
    _sync(output)
    return FaultSnapshot(trust, initialization, records)


def _unchanged(records, snapshot, source):
    lab.need(
        all(records[k]["identity"] == snapshot.records[k]["identity"] for k in records)
        and records["source"]["raw"] == source
        and all(
            records[k]["raw"] == snapshot.records[k]["raw"]
            for k in ("journal", "anchors")
        ),
        "source/journal/witness fault invariant changed",
    )


def inject(output, *, snapshot, session_ref):
    """One fixed append through its original FD; never retry/restore partial IO."""
    _guard(output, snapshot)
    lab.need(snapshot.wire == b"", "fault already injected; no retry")
    before = _snapshot(output, "fault-before-append")
    _unchanged(before, snapshot, b"")
    fixture = synthetic_prepare_frame(
        snapshot.trust, kernel_boot_id=g.boot(), session_ref=session_ref
    )
    try:
        SourceVerifier(snapshot.trust).verify(fixture.wire)
    except OutcomeJournalError as exc:
        lab.need(
            str(exc) == EXPECTED_REFUSAL, "fault does not reach exact signature refusal"
        )
    else:
        lab.need(False, "synthetic fault unexpectedly verified")
    lab.save(Path(output) / "fault-wire.raw", fixture.wire)
    lab.save_json(
        Path(output) / "fault-append-intent.json",
        dict(
            fixture_kind=fixture.fixture_kind,
            source=before["source"]["identity"],
            bytes=len(fixture.wire),
            sha256=hashlib.sha256(fixture.wire).hexdigest(),
        ),
    )
    _sync(output)
    parent, name = open_parent(g.BUNDLE / "input", trusted_owner=0)
    fd, error = None, None
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        info, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
        expected = before["source"]["identity"]
        lab.need(
            all(
                stat.S_ISREG(v.st_mode)
                and v.st_uid == 61001
                and v.st_nlink == 1
                and stat.S_IMODE(v.st_mode) == 0o644
                and v.st_size == 0
                and (v.st_dev, v.st_ino) == (expected["device"], expected["inode"])
                for v in (info, named)
            ),
            "owned empty single-link source FD required",
        )
        count = os.write(fd, fixture.wire)
        lab.save_json(Path(output) / "fault-write-count.json", dict(bytes=count))
        lab.need(
            count == len(fixture.wire), "short fault append; retain partial source"
        )
        os.fsync(fd)
        os.fsync(parent)
    except BaseException as exc:
        error = exc
    finally:
        for owned in (fd, parent):
            if owned is not None:
                try:
                    os.close(owned)
                except BaseException as exc:
                    if error is None:
                        error = exc
                    else:
                        error.add_note("owned FD close: " + type(exc).__name__)
        try:
            after = _snapshot(output, "fault-after-append")
        except BaseException as exc:
            if error is None:
                error = exc
            else:
                error.add_note("fault evidence: " + type(exc).__name__)
    if error is not None:
        raise error
    _unchanged(after, snapshot, fixture.wire)
    return FaultSnapshot(
        snapshot.trust, snapshot.initialization, snapshot.records, fixture.wire
    )


def classify_refusal(output, *, snapshot, live_output, failure):
    """Narrow actual live-helper refusal facts; outer Scope cleanup still pending."""
    _guard(output, snapshot)
    live_output = Path(live_output)
    init.proof.p._output(live_output)
    after = _snapshot(output, "fault-after-refusal")
    lab.need(
        snapshot.wire
        and type(failure) is AssertionError
        and str(failure) == "actual live worker failed"
        and not getattr(failure, "__notes__", []),
        "precise primary live failure without cleanup error required",
    )
    observed = {}
    for name in (
        "live-terminal.stdout",
        "live-terminal.stderr",
        "live-terminal-client.json",
        "live-cleanup.json",
        "live-client-reap.json",
        "live-verified-bundle.json",
    ):
        raw, _ = read_regular(live_output / name, owner=0, max_bytes=1024 * 1024)
        lab.save(Path(output) / ("fault-observed-" + name), raw)
        observed[name] = raw
    client, cleanup, reap, bundle = (
        init.plan.strict(observed[name])
        for name in (
            "live-terminal-client.json",
            "live-cleanup.json",
            "live-client-reap.json",
            "live-verified-bundle.json",
        )
    )
    lab.need(
        observed["live-terminal.stdout"] == b""
        and observed["live-terminal.stderr"].decode().splitlines()[-1:]
        == ["azazel_edge.outcome.journal.OutcomeJournalError: " + EXPECTED_REFUSAL]
        and set(client) == {"returncode", "error"}
        and type(client["returncode"]) is int
        and client["returncode"] != 0
        and client["error"] is None
        and cleanup.get("errors") == []
        and reap.get("errors") == []
        and reap.get("reaped") is True
        and reap.get("forced") is False
        and live._same(bundle["binding"], snapshot.initialization["binding"])
        and bundle["binding_sha256"] == init.plan.manifest_digest(bundle["binding"])
        and set(bundle["proof"]) == {"ready", "effective", "actor", "metadata"}
        and bundle["proof"]["ready"]["mode"] == "live",
        "retained exact live signature refusal/cleanup/binding required",
    )
    absent = [live_output / "live-result.json"] + [
        g.BUNDLE / "observer" / name
        for name in (
            "observer-start-context.json",
            "actual-collector-calls.jsonl",
            "outcomes.jsonl",
            "terminal.wire",
            "terminal.decoded",
            "observer-terminal-result.json",
        )
    ]
    lab.need(
        all(not os.path.lexists(path) for path in absent),
        "unexpected live success/activity artifact",
    )
    _unchanged(after, snapshot, snapshot.wire)
    result = dict(
        status="expected_signature_refusal_observed",
        scope="fixed_source_verification_refusal_only_outer_cleanup_pending",
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
        measurement_completed=False,
    )
    lab.save_json(Path(output) / "fault-refusal.json", result)
    return result
