from __future__ import annotations

import os
import subprocess
import sys


def test_product_agent_import_does_not_load_legacy_mio_package():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(["py", ".", env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import azazel_edge_ai.agent; print('azazel_edge.mio' in sys.modules)"],
        check=True, capture_output=True, text=True, env=env, timeout=10,
    )
    assert result.stdout.strip().endswith("False")
