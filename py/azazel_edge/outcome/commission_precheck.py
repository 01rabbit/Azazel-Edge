"""Public-artifact-only commissioning PRECHECK; never authorizes a transition."""

import argparse
import hashlib
from pathlib import Path
import stat
import sys

from .input_auth import TrustPolicy, SourceVerifier, hex_bytes, read_regular
from .input_live import registration
from .input_origin import MAX_IMAGE
from .input_service import (
    POLICY,
    REGISTRATION,
    RECEIPT,
    layout,
    public_receipt,
    require_root,
)
from .journal import OutcomeJournalError, _json, _parse


UNRESOLVED = (
    "private_role_keys_and_actual_role_access",
    "installed_runtime_dependencies_and_policy_semantics",
    "actual_enforcing_labels_sealed_native_and_service_identity",
    "singleton_witness_readiness_and_registered_history_continuity",
    "legacy_tc_provenance_and_exclusive_writer_coordination",
    "physical_target_durability_resources_and_acceptance",
)


def precheck(bundle, *, expected_trust_sha256):
    """Inspect protected public bytes against an independently reviewed trust pin.

    No secret key, manager, qdisc or mutable evidence store is opened.
    Registered executable bytes are read, never launched.
    This is a point-in-time artifact inventory, never a reusable start permit.
    """
    require_root()
    hex_bytes(expected_trust_sha256, 32)
    bundle = Path(bundle)
    if not bundle.is_absolute() or ".." in bundle.parts:
        raise OutcomeJournalError("literal absolute bundle path required")
    p = TrustPolicy.from_file(bundle / POLICY, role="witness")
    if p.digest != expected_trust_sha256:
        raise OutcomeJournalError("reviewed trust digest mismatch")
    layout(bundle, p)
    r = registration(p, bundle / REGISTRATION)
    if r["schema_version"] != "outcome-live-origin-registration/v4":
        raise OutcomeJournalError("explicit v4 native confinement enrollment required")
    env = r["environment"]
    if (
        env["AZAZEL_DEFENSE_ENFORCE"].lower() not in ("0", "false", "no", "off")
        or env["AZAZEL_DEFENSE_DRY_RUN"].lower() not in ("1", "true", "yes", "on")
        or env.get("AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO", "0").lower()
        not in ("0", "false", "no", "off")
    ):
        raise OutcomeJournalError("PRECHECK requires disabled enforcement and dry-run")
    receipt, _ = read_regular(bundle / RECEIPT, owner=0, max_bytes=4096, mode=0o644)
    if _parse(receipt) != public_receipt(bundle, p, r):
        raise OutcomeJournalError("bundle completion receipt mismatch")
    image, info = read_regular(r["binary_path"], owner=0, max_bytes=MAX_IMAGE)
    if (
        not image.startswith(b"\x7fELF")
        or not info.st_mode & 0o111
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or hashlib.sha256(image).hexdigest() != r["binary_sha256"]
    ):
        raise OutcomeJournalError("unregistered live core image")
    source, _ = read_regular(
        p.data["source_path"],
        owner=p.data["producer_uid"],
        max_bytes=p.data["input_max_bytes"],
        mode=0o644,
    )
    verifier = SourceVerifier(p)
    verifier.verify(source)
    if not verifier.live_state.closed:
        raise OutcomeJournalError("unclosed signed history; PRECHECK refuses resume")
    return dict(
        schema_version="outcome-commission-precheck/v1",
        status="PRECHECK_ONLY",
        authorizes_transition=False,
        bundle=str(bundle),
        trust_sha256=p.digest,
        registration_sha256=p.data["origin_registration_sha256"],
        binary_sha256=r["binary_sha256"],
        capture_apparmor_profile=r["capture_apparmor_profile"],
        native_apparmor_profile=r["native_apparmor_profile"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_records=verifier.seq,
        unresolved=list(UNRESOLVED),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--expected-trust-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = precheck(args.bundle, expected_trust_sha256=args.expected_trust_sha256)
    except (OSError, ValueError):
        # Do not echo malformed input, file contents, environment or secret paths.
        print("commission PRECHECK refused", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_json(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
