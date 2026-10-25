from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PY_ROOT = ROOT / "py"

if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))


import os
import shutil
import subprocess

import pytest

CORE_MANIFEST = ROOT / "rust" / "azazel-edge-core" / "Cargo.toml"
CORE_RELEASE_BIN = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"


@pytest.fixture(scope="session")
def rust_core_bin() -> Path:
    """The release azazel-edge-core binary the service objectives run.

    Built (or brought up to date) once per session when cargo is on PATH, as
    the CI service-objectives job builds it; a test that needs it is skipped
    only where neither cargo nor a built binary exists.
    """

    cargo = shutil.which("cargo")
    if cargo:
        subprocess.run(
            [cargo, "build", "--release", "--quiet", "--manifest-path", str(CORE_MANIFEST)],
            check=True,
            timeout=1800,
        )
    if CORE_RELEASE_BIN.is_file() and os.access(CORE_RELEASE_BIN, os.X_OK):
        return CORE_RELEASE_BIN
    pytest.skip("the release azazel-edge-core binary is not built and cargo is not available")
