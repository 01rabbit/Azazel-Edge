"""Explicit capture-only AppArmor gate. Never enables policy or falls back."""

import hashlib
from pathlib import Path
import re
from .input_auth import read_regular
from .journal import OutcomeJournalError


def profile_name(value):
    if (
        type(value) is not str
        or value == "unconfined"
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", value)
    ):
        raise OutcomeJournalError("literal named capture AppArmor profile required")
    return value


def capture_image(python, expected):
    """Same installed interpreter/venv, at a fixed policy-attachment alias.

    Return no arbitrary executable: alias bytes must equal the protected
    launcher's interpreter. The child verifies its kernel label before key use.
    """
    profile_name(expected)
    if Path("/sys/module/apparmor/parameters/enabled").read_text().strip() != "Y":
        raise OutcomeJournalError("capture AppArmor unavailable")
    # Do not add MAC_ADMIN merely to enumerate policy. The actual separate-UID
    # probe and receiver must verify their own enforcing kernel label instead.
    python = Path(python).absolute()
    alias = python.with_name("edge-capture")
    original, _ = read_regular(
        python.resolve(strict=True), owner=0, max_bytes=64 * 1024 * 1024
    )
    image, _ = read_regular(alias, owner=0, mode=0o755, max_bytes=64 * 1024 * 1024)
    if image != original:
        raise OutcomeJournalError(
            "capture alias must be the same installed interpreter"
        )
    return alias, dict(
        profile=expected, python=str(alias), sha256=hashlib.sha256(image).hexdigest()
    )


def enforce_capture(expected):
    profile_name(expected)
    if (
        Path("/proc/self/attr/apparmor/current").read_text().strip()
        != expected + " (enforce)"
    ):
        raise OutcomeJournalError("capture AppArmor kernel label not enforced")
