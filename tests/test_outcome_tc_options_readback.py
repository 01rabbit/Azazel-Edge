"""TBF readback from real ``tc -j qdisc show`` JSON (iproute2 nests it under ``options``).

The fixtures are captured verbatim from iproute2 in a NET_ADMIN container after
``tc qdisc replace dev d0 root handle 1a: tbf rate 256kbit burst 32kbit latency 1000ms``.
iproute2 5.5, 6.1 and 6.15 all emit the same shape. Ambiguous or incomplete readback
must never be promoted to ``observed``.
"""

from __future__ import annotations

import json
import unittest

from azazel_edge.outcome import MechanismStatus, ReadOnlyCommandResult, from_rust_event, verify_mechanism_postcondition
from tests.test_outcome_release_g1b import FakeRunner, owned_event

ARGV = ("tc", "-j", "qdisc", "show", "dev", "br0")
TC_JSON_IPROUTE2_6_15 = '[{"kind":"tbf","handle":"1a:","root":true,"refcnt":2,"options":{"rate":32000,"burst":4096,"lat":999999}}]'
TC_JSON_IPROUTE2_6_1 = '[{"kind":"tbf","handle":"1a:","root":true,"refcnt":2,"options":{"rate":32000,"burst":4096,"lat":999999}}]'


def _verify(stdout: str):
    bundle = from_rust_event(owned_event("throttle"))
    runner = FakeRunner({ARGV: ReadOnlyCommandResult(argv=ARGV, returncode=0, stdout=stdout, stderr="")})
    return verify_mechanism_postcondition(execution=bundle.execution, mechanism=bundle.mechanism, runner=runner)


def _item(**extra: object) -> str:
    return json.dumps([{"kind": "tbf", "handle": "1a:", "root": True, "refcnt": 2, **extra}])


class TcOptionsReadbackTests(unittest.TestCase):
    def test_captured_iproute2_options_shape_is_observed(self) -> None:
        for capture in (TC_JSON_IPROUTE2_6_15, TC_JSON_IPROUTE2_6_1):
            verified = _verify(capture)
            self.assertEqual(verified.status, MechanismStatus.OBSERVED)
            probe = verified.observed_parameters["postcondition_probe"]
            self.assertEqual(probe["basis"], "tc_root_tbf_parameter_readback_match")
            self.assertEqual(probe["observed"], {"rate_bps": 256000, "burst_bytes": 4096, "latency_us": 999999})

    def test_flat_top_level_shape_and_equal_duplicates_are_observed(self) -> None:
        self.assertEqual(_verify(_item(rate=32000, burst=4096, lat=999999)).status, MechanismStatus.OBSERVED)
        both = _item(rate=32000, burst=4096, lat=999999, options={"rate": 32000, "burst": 4096, "lat": 999999})
        self.assertEqual(_verify(both).status, MechanismStatus.OBSERVED)

    def test_different_options_values_are_not_observed(self) -> None:
        verified = _verify(_item(options={"rate": 64000, "burst": 4096, "lat": 999999}))
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)

    def test_ambiguous_missing_or_mistyped_readback_stays_unverified(self) -> None:
        full = {"rate": 32000, "burst": 4096, "lat": 999999}
        cases = [
            _item(rate=64000, options=full),
            _item(lat="1s", options=full),
            _item(rate=32000.0, options=full),
            _item(options={"rate": 32000, "burst": 4096}),
            _item(lat=999999, options={"rate": 32000, "burst": 4096}),
            _item(options={}),
            _item(options=None, **full),
            _item(options="rate 256Kbit", **full),
            _item(options=[full]),
            _item(options={**full, "rate": True}),
            _item(options={**full, "burst": None}),
            _item(options={**full, "rate": {"value": 32000}}),
            # value types the Rust release readback rejects are unverifiable here too
            _item(options={**full, "rate": 32000.0}),
            _item(rate=32000.0, burst=4096, lat=999999),
            _item(options={**full, "lat": -1}),
        ]
        for stdout in cases:
            with self.subTest(stdout=stdout):
                verified = _verify(stdout)
                self.assertEqual(verified.status, MechanismStatus.UNVERIFIED)
                self.assertEqual(
                    verified.observed_parameters["postcondition_probe"]["basis"],
                    "tc_root_tbf_present_but_parameters_unverifiable",
                )

    def test_non_tbf_kind_with_tbf_like_options_is_not_observed(self) -> None:
        verified = _verify(TC_JSON_IPROUTE2_6_15.replace('"kind":"tbf"', '"kind":"netem"'))
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)

    def test_options_path_keeps_the_existing_tolerance_boundaries(self) -> None:
        # rate 1% of 256000 bit/s = 320 B/s; latency max(1000, 2%) = 20000 us.
        # burst: 2% of 4096 truncates to 81 here (Rust rounds to 82); 4177 and 4179
        # are on the same side for both, the pre-existing 1-byte gap is not pinned.
        def status(rate: int, burst: int, lat: int) -> MechanismStatus:
            return _verify(_item(options={"rate": rate, "burst": burst, "lat": lat})).status

        observed, not_observed = MechanismStatus.OBSERVED, MechanismStatus.NOT_OBSERVED
        self.assertEqual(status(32320, 4096, 1_000_000), observed)
        self.assertEqual(status(31680, 4096, 1_000_000), observed)
        self.assertEqual(status(32321, 4096, 1_000_000), not_observed)
        self.assertEqual(status(31679, 4096, 1_000_000), not_observed)
        self.assertEqual(status(32000, 4177, 1_000_000), observed)
        self.assertEqual(status(32000, 4179, 1_000_000), not_observed)
        self.assertEqual(status(32000, 4096, 1_020_000), observed)
        self.assertEqual(status(32000, 4096, 980_000), observed)
        self.assertEqual(status(32000, 4096, 1_020_001), not_observed)
        self.assertEqual(status(32000, 4096, 979_999), not_observed)


if __name__ == "__main__":
    unittest.main()
