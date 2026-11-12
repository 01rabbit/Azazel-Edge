"""Evidence-only fixed Root readbacks on the EXISTING provider lab route.

No key generation/signing, new provider, unit, namespace or runtime authority.
Original Source/no-LF policy are retained; a separately labeled LF policy is derived.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

if __name__ == "__main__":
    sys.path[:0] = [
        str(Path(__file__).resolve().parent),
        str(Path(__file__).resolve().parents[2] / "py"),
        str(Path(__file__).resolve().parents[1]),
    ]

from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy, read_regular
from azazel_edge.outcome.journal import _json, _parse
from azazel_edge.outcome import nft_flow_evidence as flow
from azazel_edge.benchmark import safety_observations as safety
from azazel_edge.benchmark.recorded_nft_restoration import (
    evaluate_recorded_nft_restoration,
)

PHASES = ("baseline", "applied", "released")


class ProviderRestorationEvidenceError(ValueError):
    """Missing or inconsistent recorded lab provenance, never restoration."""


def _need(value, message):
    if not value:
        raise ProviderRestorationEvidenceError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _wire(value):
    return _json(value) + b"\n"


def build_projection(
    original_policy_raw,
    source_prefix_raw,
    source_raw,
    receipts,
    *,
    prefix_checkpoint,
    final_checkpoint,
    enrollment,
    observer_public_key,
):
    """Pure builder over ORIGINAL signed bytes; no synthetic lifecycle/signature.

    Enrollment/checkpoints are trusted Root lab records, not sensor attestation.
    The unused existing public observer key only satisfies the evidence schema.
    """
    try:
        _need(
            type(original_policy_raw) is bytes
            and 0 < len(original_policy_raw) <= 32768,
            "original policy byte bound",
        )
        parsed = _parse(original_policy_raw)
        _need(
            _json(parsed) == original_policy_raw,
            "original policy must be canonical NO-LF",
        )
        policy = TrustPolicy(parsed)
        derived = original_policy_raw + b"\n"
        _need(
            TrustPolicy(_parse(derived)).digest == policy.digest,
            "derived policy differs",
        )
        safety._fields(
            enrollment,
            "kernel_boot_id netns_inode query_window source_identity nft_binary_sha256 receipts scope_interval",
        )
        safety._hex(observer_public_key)
        _need(
            len(
                {
                    observer_public_key,
                    policy.data["producer_public_key"],
                    policy.data["witness_public_key"],
                }
            )
            == 3,
            "unused schema public key overlaps Source roles",
        )
        _need(
            type(source_prefix_raw) is bytes
            and type(source_raw) is bytes
            and source_raw.startswith(source_prefix_raw),
            "original Source prefix differs",
        )
        prefix = SourceVerifier(policy)
        pt = prefix.verify(source_prefix_raw)
        final = SourceVerifier(policy)
        ft = final.verify(source_raw)
        _need(
            _json(pt) == _json(prefix_checkpoint)
            and _json(ft) == _json(final_checkpoint),
            "Root checkpoint differs",
        )
        session = final.live_state.session
        _need(
            prefix.live_state.sessions
            == final.live_state.sessions
            == frozenset({session})
            and not prefix.live_state.closed
            and prefix.live_state.seq == 1
            and final.live_state.closed,
            "one prepared/started then closed session required",
        )
        prefix_lines = source_prefix_raw.splitlines(keepends=True)
        _need(
            len(prefix_lines) == 2
            and [_parse(x)["event"]["capture_origin"]["kind"] for x in prefix_lines]
            == ["session_prepare", "session_start"],
            "pre-alert prefix must be original two-frame start",
        )
        selected = []
        for raw in source_raw.splitlines(keepends=True):
            row = _parse(raw)
            event = row["event"]
            _need(
                row["boot_ref"] == uuid.UUID(enrollment["kernel_boot_id"]).hex,
                "Source boot differs",
            )
            if (
                event["capture_origin"]["kind"] == "decision_execution"
                and type(event.get("normalized", {}).get("sid")) is int
                and event["normalized"]["sid"] == 900001
            ):
                selected.append((raw, row))
        _need(len(selected) == 1, "one original signed SID900001 required")
        selected_raw, selected_row = selected[0]
        context = {
            k: policy.data[k]
            for k in (
                "scope_ref",
                "producer_ref",
                "stream_ref",
                "producer_public_key",
                "witness_public_key",
                "producer_uid",
                "observer_uid",
            )
        }
        context.update(
            registration_sha256=policy.data["origin_registration_sha256"],
            session_ref=session,
            boot_ref=uuid.UUID(enrollment["kernel_boot_id"]).hex,
        )
        contract = dict(
            schema_version="edge-finite-safety-contract/v1",
            keypins=dict(
                observer_public_key=observer_public_key,
                source_producer_public_key=policy.data["producer_public_key"],
                source_witness_public_key=policy.data["witness_public_key"],
            ),
            scope=dict(
                run_id="provider-restoration-" + session,
                source_sha256=_sha(source_prefix_raw),
                policy_sha256=_sha(derived),
                scope_ref=context["scope_ref"],
                session_ref=session,
                registration_sha256=context["registration_sha256"],
                kernel_boot_id=enrollment["kernel_boot_id"],
                owner={k: context[k] for k in ("producer_uid", "observer_uid")},
                interval=enrollment["scope_interval"],
            ),
            channels={
                c: dict(
                    channel_id="unobserved-provider-" + c,
                    capture_id="unobserved-provider-capture-" + c,
                    collector_kind="independent-root-readonly/v1",
                    collector_uid=0,
                    collector_boot_id=enrollment["kernel_boot_id"],
                    source_actor_uid=context["producer_uid"],
                )
                for c in safety.CATEGORIES
            },
            opportunities={c: [] for c in safety.CATEGORIES},
        )
        contract_raw = _wire(contract)
        source_plan = _wire(
            dict(
                schema_version="edge-source-proof-plan/v1",
                contract_sha256=_sha(contract_raw),
                trust_sha256=_sha(derived),
                context=context,
                prefix_checkpoint=prefix_checkpoint,
                final_checkpoint=final_checkpoint,
            )
        )
        plan = dict(
            schema_version="edge-recorded-nft-restoration-plan/v1",
            contract_sha256=_sha(contract_raw),
            source_plan_sha256=_sha(source_plan),
            source_event_seq=selected_row["seq"],
            source_event_sha256=_sha(selected_raw),
            **{
                k: enrollment[k]
                for k in (
                    "kernel_boot_id",
                    "netns_inode",
                    "query_window",
                    "source_identity",
                    "nft_binary_sha256",
                    "receipts",
                )
            },
        )
        plan_raw = _wire(plan)
        arguments = dict(
            plan_raw=plan_raw,
            expected_plan_sha256=_sha(plan_raw),
            source_inputs=dict(
                contract_raw=contract_raw,
                source_plan_raw=source_plan,
                trust_raw=derived,
                source_raw=source_raw,
            ),
            receipts=receipts,
        )
        result = evaluate_recorded_nft_restoration(**arguments)
        provenance = dict(
            schema_version="edge-provider-restoration-provenance/v1",
            original_policy_sha256=_sha(original_policy_raw),
            derived_policy_sha256=_sha(derived),
            policy_digest=policy.digest,
            derived_policy_label="DERIVED_canonical_policy_plus_LF_not_original_capture",
            observer_public_key=observer_public_key,
            observer_key_role="unused_schema_key_no_observations",
            source_prefix_sha256=_sha(source_prefix_raw),
            source_final_sha256=_sha(source_raw),
            selected_original_source_seq=selected_row["seq"],
            selected_original_source_sha256=_sha(selected_raw),
            Root_interval_role="actual_root_monotonic_bracket_no_opportunities_or_coverage_claim",
            Source_provenance="original_registered_signed_native_Source_not_synthetic_wrapping",
            query_provenance="original_child_query_plus_parent_actual_launch_fields",
            safety_observations_generated=False,
            **safety.FLAGS,
        )
        files = {
            "original-policy.json": original_policy_raw,
            "derived-policy.json": derived,
            "source-prefix.jsonl": source_prefix_raw,
            "source-final.jsonl": source_raw,
            "prefix-checkpoint.json": _wire(prefix_checkpoint),
            "final-checkpoint.json": _wire(final_checkpoint),
            "enrollment.json": _wire(enrollment),
            "contract.json": contract_raw,
            "source-plan.json": source_plan,
            "restoration-plan.json": plan_raw,
            "provenance.json": _wire(provenance),
            "result.json": _wire(result),
        }
        for phase in PHASES:
            if type(receipts[phase]) is bytes:
                files[phase + "-receipt.json"] = receipts[phase]
        return dict(files=files, result=result, arguments=arguments)
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
    ) as exc:
        if isinstance(exc, ProviderRestorationEvidenceError):
            raise
        raise ProviderRestorationEvidenceError(
            "invalid original provider evidence: " + str(exc)
        ) from exc


def _source_identity(g):
    root = Path(__file__).resolve().parents[2]
    raw, _ = read_regular(root / "SOURCE_REVISION", owner=0, mode=0o644, max_bytes=41)
    revision = raw.decode("ascii").removesuffix("\n")
    _need(
        re.fullmatch("[0-9a-f]{40}", revision) is not None,
        "protected source revision required",
    )
    helper, _ = read_regular(Path(__file__).resolve(), owner=0, max_bytes=1024 * 1024)
    driver, _ = read_regular(
        root / "tests/real_systemd/provider.py", owner=0, max_bytes=1024 * 1024
    )
    return dict(
        source_revision=revision,
        helper_sha256=_sha(helper),
        network_driver_sha256=_sha(driver),
    )


def _save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o444)
    finally:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def query_child():
    import provider
    from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner

    g = provider.g
    _need(sys.argv[1:] == ["--root-readonly-nft"], "fixed Root NFT query child only")
    g.guard()
    binary = Path("/usr/sbin/nft")
    resolved = shutil.which(flow.QUERY[0])
    _need(
        resolved is not None and Path(resolved).resolve() == binary.resolve(),
        "fixed query executable differs from enrolled nft binary",
    )
    binary_raw, _ = read_regular(
        binary, owner=0, mode=0o755, max_bytes=64 * 1024 * 1024
    )
    start = datetime.now(timezone.utc).isoformat()
    result = SubprocessReadOnlyRunner().run(flow.QUERY, timeout_seconds=2)
    end = datetime.now(timezone.utc).isoformat()
    print(
        json.dumps(
            dict(
                argv=list(result.argv),
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                query_started_at=start,
                query_ended_at=end,
                root_pid=os.getpid(),
                root_uid=os.geteuid(),
                kernel_boot_id=g.boot(),
                source_identity=_source_identity(g),
                netns_inode=os.stat("/proc/self/ns/net").st_ino,
                nft_binary_sha256=_sha(binary_raw),
            )
        ),
        flush=True,
    )


class Recorder:
    """One existing provider session, fixed read-only queries and exclusive exports."""

    def __init__(self, g, edge, observer_public_key):
        self.g, self.edge, self.observer_public_key = g, edge, observer_public_key
        _need(
            edge == "edge400-provider-edge",
            "fixed existing provider namespace required",
        )
        g.guard()
        self.output = g.BASE / "provider-restoration"
        self.output.mkdir(mode=0o700)
        self.original, _ = read_regular(
            g.BUNDLE / "trust.json", owner=0, mode=0o644, max_bytes=32768
        )
        parsed = _parse(self.original)
        _need(
            _json(parsed) == self.original, "canonical original no-LF policy required"
        )
        self.policy = TrustPolicy(parsed)
        self.prefix = g.source()
        self.prefix_checkpoint = SourceVerifier(self.policy).verify(self.prefix)
        self.start_ns = time.monotonic_ns()
        now = datetime.now(timezone.utc)
        self.window = dict(
            start=now.isoformat(), end=(now + timedelta(seconds=120)).isoformat()
        )
        self.identity = _source_identity(g)
        self.ns = os.stat("/run/netns/" + edge)
        self.binary = _sha(
            read_regular(
                Path("/usr/sbin/nft"), owner=0, mode=0o755, max_bytes=64 * 1024 * 1024
            )[0]
        )
        self.receipts = {}
        self.bindings = {}
        for name, raw in (
            ("original-policy.json", self.original),
            ("derived-policy.json", self.original + b"\n"),
            ("source-prefix.jsonl", self.prefix),
            ("prefix-checkpoint.json", _wire(self.prefix_checkpoint)),
        ):
            _save(self.output / name, raw)

    def query(self, phase):
        _need(
            phase in PHASES and phase not in self.receipts, "one fixed query per phase"
        )
        current = os.stat("/run/netns/" + self.edge)
        _need(
            (current.st_dev, current.st_ino) == (self.ns.st_dev, self.ns.st_ino),
            "owned namespace changed",
        )
        argv = [
            "ip",
            "netns",
            "exec",
            self.edge,
            str(self.g.PYTHON),
            "-I",
            str(Path(__file__).resolve()),
            "--root-readonly-nft",
        ]
        child = None
        handles, paths = {}, {}
        stdout, stderr = bytearray(), bytearray()
        failure, cleanup_errors = None, []
        try:
            child = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            _save(
                self.output / (phase + "-launch.json"),
                _wire(
                    dict(
                        actual_child_argv=list(child.args),
                        root_pid=child.pid,
                        expected_netns_inode=self.ns.st_ino,
                    )
                ),
            )
            paths = {
                child.stdout: (stdout, self.output / (phase + "-child.raw")),
                child.stderr: (stderr, self.output / (phase + "-child-stderr.raw")),
            }
            for stream, (_, path) in paths.items():
                handles[stream] = open(path, "xb")
            until = time.monotonic() + 8
            active = set(handles)
            while active:
                remaining = until - time.monotonic()
                _need(remaining > 0, "Root query absolute deadline")
                readable, _, _ = select.select(list(active), [], [], remaining)
                _need(readable, "Root query absolute deadline")
                for stream in readable:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        active.remove(stream)
                        continue
                    data, _ = paths[stream]
                    handles[stream].write(chunk)
                    handles[stream].flush()
                    data.extend(chunk)
                    _need(
                        len(data)
                        <= (8 * 1024 * 1024 if stream is child.stdout else 65536),
                        "Root query output bound",
                    )
            child.wait(timeout=2)
            _need(child.returncode == 0 and not stderr, "Root query child refused")
        except BaseException as exc:
            failure = exc
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=2)
                except BaseException:
                    cleanup_errors.append("owned query group reap")
            for handle in handles.values():
                try:
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), 0o444)
                except BaseException:
                    cleanup_errors.append("partial raw durability/mode")
                finally:
                    try:
                        handle.close()
                    except BaseException:
                        cleanup_errors.append("partial raw close")
            if child is not None:
                for stream in (child.stdout, child.stderr):
                    try:
                        stream.close()
                    except BaseException:
                        cleanup_errors.append("query pipe close")
            directory = None
            try:
                directory = os.open(
                    self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                os.fsync(directory)
            except BaseException:
                cleanup_errors.append("raw directory durability")
            finally:
                if directory is not None:
                    try:
                        os.close(directory)
                    except BaseException:
                        cleanup_errors.append("raw directory close")
        if failure is not None or cleanup_errors:
            raise ProviderRestorationEvidenceError(
                "fixed Root query failed"
                + (": " + str(failure) if failure else "")
                + ("; " + ",".join(cleanup_errors) if cleanup_errors else "")
            ) from failure
        receipt = flow.parse_readback(bytes(stdout))
        _need(
            receipt.get("root_pid") == child.pid
            and receipt.get("netns_inode") == self.ns.st_ino
            and receipt.get("source_identity") == self.identity
            and receipt.get("kernel_boot_id") == self.g.boot(),
            "actual Root query identity differs",
        )
        current = os.stat("/run/netns/" + self.edge)
        _need(
            (current.st_dev, current.st_ino) == (self.ns.st_dev, self.ns.st_ino),
            "owned namespace changed after query",
        )
        receipt.update(
            actual_child_argv=list(child.args),
            source="live_root_query_recorded_once_for_pure_projection",
            capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
        )
        raw = _wire(receipt)
        _save(self.output / (phase + "-receipt.json"), raw)
        self.receipts[phase] = raw
        self.bindings[phase] = dict(
            sha256=_sha(raw), root_pid=child.pid, actual_child_argv=list(child.args)
        )
        return receipt

    def finish(self):
        source = self.g.source()
        tip = SourceVerifier(self.policy).verify(source)
        _save(self.output / "source-final.jsonl", source)
        _save(self.output / "final-checkpoint.json", _wire(tip))
        enrollment = dict(
            kernel_boot_id=self.g.boot(),
            netns_inode=self.ns.st_ino,
            query_window=self.window,
            source_identity=self.identity,
            nft_binary_sha256=self.binary,
            receipts=self.bindings,
            scope_interval=dict(start_ns=self.start_ns, end_ns=time.monotonic_ns()),
        )
        _save(self.output / "enrollment.json", _wire(enrollment))
        projection = build_projection(
            self.original,
            self.prefix,
            source,
            self.receipts,
            prefix_checkpoint=self.prefix_checkpoint,
            final_checkpoint=tip,
            enrollment=enrollment,
            observer_public_key=self.observer_public_key,
        )
        for name, raw in projection["files"].items():
            if name not in {
                "original-policy.json",
                "derived-policy.json",
                "source-prefix.jsonl",
                "source-final.jsonl",
                "prefix-checkpoint.json",
                "final-checkpoint.json",
                "enrollment.json",
                "baseline-receipt.json",
                "applied-receipt.json",
                "released-receipt.json",
            }:
                _save(self.output / name, raw)
        result = projection["result"]
        _need(
            result["status"] == "sampled_fixed_chain_returned_to_baseline"
            and result["source_owner_bound"] is True,
            "recorded fixed-chain comparison incomplete or changed",
        )
        self.g.record(
            "provider-recorded-fixed-chain-returned-to-baseline",
            diagnostic=result,
            scope="recorded_actual_lab_fixed_chain_only",
            execution_fact_verified=False,
            safety_observations_generated=False,
            **safety.FLAGS,
        )
        return result


if __name__ == "__main__":
    query_child()
