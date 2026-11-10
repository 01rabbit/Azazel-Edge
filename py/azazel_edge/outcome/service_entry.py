"""Every managed start revalidates capture; no boot-time proof bypass."""

import argparse
from pathlib import Path
import subprocess
import sys

from .input_service import POLICY, REGISTRATION, PRODUCER_KEY
from .service_switch import ready, Systemd
from .input_live import launch


def run(bundle, boot_ref):
    bundle = Path(bundle)
    # This does not call a service manager, create evidence or initialize a
    # witness. Missing/invalid proof stops before launch/preparation on every
    # manual start, reboot or failed unit retry. Running defense is unaffected.
    ready(bundle, Path(sys.executable), Systemd())
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
