"""Real ELF, separate UID signer and real procfs observer, no live enforcement."""

import os
import sys
import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root and built Linux core required",
)


def test_real_observer_off_on_faulted_keeps_exact_decisions_and_honest_costs():
    from run_observer_cost import run

    result = run()
    assert result["decision_parity"] == "exact_for_fixed_disabled_input"
    off, on, faulted = result["arms"]
    for arm in (off, on, faulted):
        assert (
            arm["expected_decisions"]
            == arm["native_decisions"]
            == arm["signed_decisions"]
            == 3
        )
        assert arm["ticks_per_second"] > 0
        assert set(arm["processes"]) >= {"native", "signer"}
        assert arm["store_growth_bytes"] is None or arm["store_growth_bytes"] >= 0
    assert off["observer_input_records"] is None
    assert (
        on["observer_input_records"] == 5 and on["observer_unprocessed_decisions"] == 0
    )
    assert (
        faulted["observer_input_records"] == 3
        and faulted["observer_unprocessed_decisions"] == 2
    )
    assert faulted["observer_exit"] == -9
    observer = faulted["processes"]["observer"]
    assert observer["coverage"] == "incomplete"
    assert observer["cpu_seconds"] is None
    assert observer["final"]["available"] is False
    assert observer["final"]["rss_kib"] is None
