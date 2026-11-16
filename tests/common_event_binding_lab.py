"""Actual original-path capture adapter; PUBLIC TEST observer key, no actor code."""

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from azazel_edge.benchmark import common_event_binding as binding
from azazel_edge.benchmark import safety_observations as safety
from safety_observation_data import digest, frozen, sign, wire

CATEGORY = "forged_evidence_accepted"
WINDOW_NS = 10_000_000_000
# Public, reproducible TEST seed distinct from both original Source roles.
OBSERVER = Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32)


def save(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


class Capture:
    """Keep raw allowlisted evidence even when the delegated original test fails."""

    def __init__(self, prefix, group, negative):
        self.fixture, self.trust, self.prefix, self.anchors, self.arguments = prefix
        self.group, self.negative = group, negative
        self.directory = Path(tempfile.mkdtemp(prefix="edge-common-event-", dir="/run"))
        self.directory.chmod(0o755)
        self.raw = {
            "baseline-source.raw": self.prefix,
            "baseline-anchors.raw": self.anchors,
            "trust.json": self.trust,
            "baseline-checkpoints.json": wire(self.arguments),
        }
        self.report = dict(
            schema_version="edge-common-event-actual-capture/v1",
            capture_group_id=group,
            negative=negative,
            control_only=not negative,
            error=None,
            evidence_kind="ACTUAL_LINUX_REFUSAL_AND_SAMPLED_FILES_WITH_LAB_PAYLOADS",
            observer_key_kind="PUBLIC_TEST_KEY_NOT_INDEPENDENT_ENROLLMENT",
            qualified_safety_count=None,
        )
        self.original = None
        self.samples = {}

    def snapshot(self, delegate, *args, **kwargs):
        result = delegate(*args, **kwargs)
        # The old sealed-intake helper also snapshots its public copies. Preserve
        # those calls, but do not relabel them as original target before/after.
        if not args or set(args[0]) != {"source", "journal", "anchors"}:
            return result
        values, metadata = deepcopy(result)
        phase = "before" if not self.samples else "after"
        assert phase not in self.samples, "original recipe exceeded its two snapshots"
        self.samples[phase] = metadata
        self.raw.update(
            {phase + "-" + name + ".raw": raw for name, raw in values.items()}
        )
        self.raw["original-samples.json"] = wire(self.samples)
        return result

    def run(self, original_run, producer_script, fixture, script, **kwargs):
        result = original_run(fixture, script, **kwargs)
        stdout, stderr, process = result
        role = "producer" if script == producer_script else "worker"
        self.raw[role + ".stdout"] = stdout
        self.raw[role + ".stderr"] = stderr
        self.raw[role + "-process.json"] = wire(process)
        if role == "producer" and process["returncode"] == 0 and not stderr:
            generated = json.loads(stdout)
            self.raw["reference-frame.raw"] = generated["valid_frame"].encode()
            if self.negative:
                self.freeze()
            else:
                self.report["control_scope"] = self.arguments["expected_context"][
                    "scope_ref"
                ]
        return result

    def freeze(self):
        # This hook runs after the real producer, before original before-samples.
        source = self.fixture.source.read_bytes()
        assert len(source) <= 1024 * 1024
        self.raw["prelaunch-invalid-source.raw"] = source
        context = self.arguments["expected_context"]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        contract = frozen()[0]
        opened = time.monotonic_ns()
        end = opened + WINDOW_NS
        contract["scope"].update(
            run_id=self.group,
            scope_ref=context["scope_ref"],
            session_ref=context["session_ref"],
            registration_sha256=context["registration_sha256"],
            kernel_boot_id=boot,
            policy_sha256=digest(self.trust),
            source_sha256=self.arguments["expected_source_checkpoint"]["sha256"],
            owner={
                "producer_uid": context["producer_uid"],
                "observer_uid": context["observer_uid"],
            },
            interval={"start_ns": opened, "end_ns": end},
        )
        contract["keypins"] = dict(
            observer_public_key=OBSERVER.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex(),
            source_producer_public_key=context["producer_public_key"],
            source_witness_public_key=context["witness_public_key"],
        )
        capture = "actual-wrong_key-" + context["scope_ref"]
        for category, channel in contract["channels"].items():
            channel.update(
                channel_id="root-" + category,
                capture_id=capture + "-" + category,
                collector_boot_id=boot,
                source_actor_uid=context["producer_uid"],
            )
        contract["channels"][CATEGORY]["capture_id"] = capture
        opportunity = dict(
            id="actual-wrong-key",
            category=CATEGORY,
            start_ns=opened,
            end_ns=end,
            challenge_sha256=digest(source),
            reference_sha256=digest(self.raw["reference-frame.raw"]),
            predicate=dict(
                invalid_input_sha256=digest(source),
                expected_disposition="refused_without_commit",
            ),
        )
        contract["opportunities"] = {
            c: [opportunity] if c == CATEGORY else [] for c in safety.CATEGORIES
        }
        contract_raw = wire(contract)
        channel = contract["channels"][CATEGORY]
        enrollment = dict(
            schema_version="edge-common-event-enrollment/v1",
            capture_group_id=self.group,
            main_contract_sha256=digest(contract_raw),
            entries=[
                dict(
                    id="wrong-key",
                    kind="forged_refusal_v2",
                    category=CATEGORY,
                    channel_id=channel["channel_id"],
                    capture_id=capture,
                    opportunity_id=opportunity["id"],
                    fact_seq=3,
                    required_layers=list(binding.REQUIRED_LAYERS),
                )
            ],
        )
        self.raw.update(
            {
                "main-contract.json": contract_raw,
                "event-enrollment.json": wire(enrollment),
            }
        )
        saved = {}
        for name in ("main-contract.json", "event-enrollment.json"):
            save(self.directory / name, self.raw[name])
            info = (self.directory / name).stat()
            saved[name] = dict(
                sha256=digest(self.raw[name]),
                bytes=len(self.raw[name]),
                uid=info.st_uid,
                mode=info.st_mode & 0o777,
                device=info.st_dev,
                inode=info.st_ino,
            )
        self.raw["prelaunch-receipt.json"] = wire(
            dict(
                schema_version="edge-common-event-prelaunch-receipt/v1",
                capture_group_id=self.group,
                opened_monotonic_ns=opened,
                saved_monotonic_ns=time.monotonic_ns(),
                files=saved,
            )
        )
        save(
            self.directory / "prelaunch-receipt.json",
            self.raw["prelaunch-receipt.json"],
        )
        self.contract, self.opened, self.end = contract, opened, end
        self.begin = time.monotonic_ns()

    def sealed(self, delegate, *args):
        # Capture immutable ORIGINAL arguments and still exercise its real intake.
        _, _, plan, trust, before, after, stdout, stderr, reference, result = deepcopy(
            args
        )
        self.raw.update(
            {
                "original-plan.json": plan,
                "trust.json": trust,
                "original-evaluation.json": wire(result),
                "worker.stdout": stdout,
                "worker.stderr": stderr,
                "reference-frame.raw": reference,
            }
        )
        for phase, values in (("before", before), ("after", after)):
            self.raw.update(
                {phase + "-" + name + ".raw": raw for name, raw in values.items()}
            )
        self.original = (plan, trust, before, after, stdout, stderr, reference, result)
        return delegate(*args)

    def evaluate(self):
        plan, trust, before, after, stdout, stderr, reference, original = self.original
        fact_ns = time.monotonic_ns()
        self.raw["root-fact-clock.json"] = wire({"monotonic_ns": fact_ns})
        # One bounded deadline wait, then ONE genuine CLOSE clock read. Never fit it.
        remaining = self.end - time.monotonic_ns()
        if remaining > 0:
            time.sleep(remaining / 1_000_000_000)
        close_ns = time.monotonic_ns()
        self.raw["root-close-clock.json"] = wire({"monotonic_ns": close_ns})
        cursor = self.arguments["expected_source_checkpoint"]["size"]
        data = dict(
            input_sha256=digest(before["source"]),
            disposition="refused",
            cursor_before=cursor,
            cursor_after=cursor,
            journal_before_sha256=digest(before["journal"]),
            journal_after_sha256=digest(after["journal"]),
            anchor_before_sha256=digest(before["anchors"]),
            anchor_after_sha256=digest(after["anchors"]),
        )
        contract_hash = digest(self.raw["main-contract.json"])
        channel = self.contract["channels"][CATEGORY]
        opportunity = self.contract["opportunities"][CATEGORY][0]
        definitions = [
            ("open", self.opened, None, {"boundary_ns": self.opened}),
            (
                "challenge_begin",
                self.begin,
                opportunity["id"],
                {"challenge_sha256": opportunity["challenge_sha256"]},
            ),
            ("verifier_disposition", fact_ns, opportunity["id"], data),
            (
                "challenge_end",
                close_ns,
                opportunity["id"],
                {"challenge_sha256": opportunity["challenge_sha256"]},
            ),
            ("close", close_ns, None, {"boundary_ns": close_ns}),
        ]
        rows = [
            dict(
                schema_version="edge-finite-safety-row/v1",
                contract_sha256=contract_hash,
                scope=deepcopy(self.contract["scope"]),
                category=CATEGORY,
                channel_id=channel["channel_id"],
                capture_id=channel["capture_id"],
                kind=kind,
                monotonic_ns=at,
                opportunity_id=oid,
                data=datum,
                raw_ref_sha256=digest(plan),
            )
            for kind, at, oid, datum in definitions
        ]
        head = sign(rows, key=OBSERVER)
        observations = dict(
            schema_version="edge-finite-safety-observations/v1",
            contract_sha256=contract_hash,
            scope=self.contract["scope"],
            channels={
                CATEGORY: dict(
                    channel_id=channel["channel_id"],
                    capture_id=channel["capture_id"],
                    rows=rows,
                )
            },
        )
        supplement = dict(
            plan=plan,
            trust=trust,
            stdout=stdout,
            stderr=stderr,
            reference_frame=reference,
            evaluation=wire(original),
        )
        for phase, values in (("before", before), ("after", after)):
            supplement.update({phase + "_" + name: raw for name, raw in values.items()})
        composition = dict(
            schema_version="edge-safety-evidence-composition-plan/v1",
            main_contract_sha256=contract_hash,
            entries=[
                dict(
                    id="wrong-key",
                    kind="forged_refusal_v2",
                    sha256={slot: digest(raw) for slot, raw in supplement.items()},
                )
            ],
        )
        pins = dict(
            expected_contract_sha256=contract_hash,
            **self.contract["keypins"],
            expected_stream_heads={
                c: head if c == CATEGORY else None for c in safety.CATEGORIES
            },
        )
        self.raw.update(
            {
                "main-observations.json": wire(observations),
                "main-pins.json": wire(pins),
                "composition-plan.json": wire(composition),
            }
        )
        result = binding.evaluate_common_event_binding(
            self.raw["main-contract.json"],
            wire(observations),
            safety_pins=pins,
            composition_plan_raw=wire(composition),
            expected_composition_plan_sha256=digest(wire(composition)),
            supplements={"wrong-key": supplement},
            event_enrollment_raw=self.raw["event-enrollment.json"],
            expected_event_enrollment_sha256=digest(self.raw["event-enrollment.json"]),
        )
        self.raw["binding-evaluation.json"] = wire(result)
        self.report.update(
            binding_status=result["bindings"][0]["status"],
            scope_ref=self.contract["scope"]["scope_ref"],
            actual_close_ns=close_ns,
            frozen_end_ns=self.end,
            exact_close_boundary_matched=close_ns == self.end,
        )
        return result

    def export(self, error):
        self.report["error"] = type(error).__name__ if error is not None else None
        self.raw["capture-report.json"] = wire(self.report)
        # Closed artifact-name allowlist: no fixture directory traversal/key reads.
        allowed = {
            "baseline-source.raw",
            "baseline-anchors.raw",
            "trust.json",
            "baseline-checkpoints.json",
            "producer.stdout",
            "producer.stderr",
            "producer-process.json",
            "worker.stdout",
            "worker.stderr",
            "worker-process.json",
            "reference-frame.raw",
            "prelaunch-invalid-source.raw",
            "main-contract.json",
            "event-enrollment.json",
            "prelaunch-receipt.json",
            "original-plan.json",
            "original-evaluation.json",
            "root-fact-clock.json",
            "root-close-clock.json",
            "main-observations.json",
            "main-pins.json",
            "composition-plan.json",
            "binding-evaluation.json",
            "capture-report.json",
            "original-samples.json",
        }
        allowed.update(
            phase + "-" + name + ".raw"
            for phase in ("before", "after")
            for name in ("source", "journal", "anchors")
        )
        assert set(self.raw) <= allowed
        index = {}
        for name, raw in self.raw.items():
            assert len(raw) <= 4 * 1024 * 1024
            path = self.directory / name
            if path.exists():
                assert path.read_bytes() == raw
            else:
                save(path, raw)
            index[name] = dict(sha256=digest(raw), bytes=len(raw))
        save(self.directory / "index.json", wire(index))
        public = os.environ.get("EDGE_COMMON_EVENT_PUBLIC_DIR")
        if public:
            target = (
                Path(public)
                / self.group
                / ("wrong-key" if self.negative else "valid-control")
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(self.directory, target)
        # Kept even without public destination: failed original scope may be gone.
        self.report["preserved_directory"] = str(self.directory)
