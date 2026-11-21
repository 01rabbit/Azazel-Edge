"""Every managed start revalidates capture; no boot-time proof bypass."""

import argparse
import os
from pathlib import Path
import subprocess
import sys

from .input_service import POLICY, REGISTRATION, PRODUCER_KEY
from .service_switch import ready, Systemd, UnclosedSignedHistory
from . import native_close_receipts as close_receipts
from .input_live import launch


def run(bundle, boot_ref):
    bundle = Path(bundle)
    # This does not call a service manager, create evidence or initialize a
    # witness. Missing/invalid proof stops before launch/preparation on every
    # manual start, reboot or failed unit retry. Running defense is unaffected.
    try:
        ready(bundle, Path(sys.executable), Systemd())
    except UnclosedSignedHistory as exc:
        if os.geteuid() == 0 and close_receipts.enabled(exc.registration):
            close_receipts.emit(
                dict(
                    schema_version="outcome-managed-restart-refusal/v1",
                    stage="managed_ready_unclosed_history",
                    attempted_session_ref=None,
                    prior_session_ref=exc.prior_session_ref,
                    source_checkpoint=exc.source_checkpoint,
                    registration_sha256=exc.policy.data["origin_registration_sha256"],
                    trust_sha256=exc.policy.digest,
                    launcher_pid=os.getpid(),
                    boot_ref=boot_ref,
                    invocation_id=os.environ.get("INVOCATION_ID"),
                    core_spawn_attempted=False,
                    receiver_spawn_attempted=False,
                    root_stdout=close_receipts.stdout_object(),
                ),
                close_receipts.ROOT_LIMIT,
            )
        raise
    return launch(
        bundle / POLICY, bundle / REGISTRATION, bundle / PRODUCER_KEY, boot_ref
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verified service capture entry; no automatic recovery/fallback"
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--boot-ref", required=True)
    args = parser.parse_args(argv)
    try:
        return run(args.bundle, args.boot_ref)
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            "managed capture start refused; protected proof required; no fallback or reset",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
