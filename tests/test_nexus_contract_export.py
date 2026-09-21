"""The contract Azazel-Nexus pins, and the guard against it drifting (Nexus#44).

Nexus verifies this package without importing the packager: the two
repositories build and test separately, and a consumer that needed the
producer's source in its own CI would be sharing an implementation rather than
verifying a contract.

So three documents are committed here and copied into Nexus verbatim. These
tests hold the Edge half of the tie:

* the committed files are what a regeneration produces, so a field added to
  the manifest cannot reach a package without also reaching the contract;
* the contract carries no digest and no timestamp, so it stays byte-identical
  across rebuilds and a diff of it always means something changed;
* the unhealthy branch is observed, not asserted.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging" / "nexus-core"))

import nexus_core_package as packager  # noqa: E402

BINARY = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
_BUILT = BINARY.is_file()
_REASON = (
    "the release binary is not built; run "
    "cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml"
)

COMMITTED = ROOT / "packaging" / "nexus-core" / "contract"
NAMES = ("health-schema.json", "manifest-schema.json", "pin.json")


class KeyPathTests(unittest.TestCase):
    """`key_paths` is what both schemas are derived from, so it is tested alone."""

    def test_nested_objects_become_dotted_paths(self) -> None:
        self.assertEqual(
            packager.key_paths({"a": {"b": 1, "c": {"d": 2}}}),
            ["a.b", "a.c.d"],
        )

    def test_a_list_of_objects_contributes_one_entry_per_field(self) -> None:
        """Not one per element: how many a build produced is not the shape."""

        paths = packager.key_paths({"components": [{"path": "x"}, {"path": "y"}]})
        self.assertEqual(paths, ["components[].path"])

    def test_fields_present_on_only_some_elements_are_still_reported(self) -> None:
        paths = packager.key_paths({"c": [{"a": 1}, {"b": 2}]})
        self.assertEqual(paths, ["c[].a", "c[].b"])

    def test_a_list_of_scalars_is_a_leaf(self) -> None:
        self.assertEqual(packager.key_paths({"notes": ["one", "two"]}), ["notes"])

    def test_the_result_is_sorted_and_deduplicated(self) -> None:
        paths = packager.key_paths({"b": 1, "a": {"z": 1, "y": 1}})
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), len(set(paths)))


class ManifestSchemaTests(unittest.TestCase):
    def test_the_schema_is_derived_from_the_manifest_builder(self) -> None:
        """Not restated. A field added to `manifest_document` appears here."""

        document = packager.manifest_document(
            version="9.9.9",
            artifact="a.tar.gz",
            digest="sha256:" + "0" * 64,
            components=[{"path": "p", "digest": "d", "size": 1}],
        )
        self.assertEqual(packager.manifest_schema()["keys"], packager.key_paths(document))

    def test_a_new_manifest_field_changes_the_schema(self) -> None:
        """The tie is only worth having if it can fail."""

        real = packager.manifest_document
        with mock.patch.object(
            packager,
            "manifest_document",
            lambda **kw: {**real(**kw), "surprise": 1},
        ):
            self.assertIn("surprise", packager.manifest_schema()["keys"])
        self.assertNotIn("surprise", packager.manifest_schema()["keys"])

    def test_the_schema_carries_no_digest_and_no_version(self) -> None:
        """Both change on every rebuild, and a contract that did would be noise."""

        text = json.dumps(packager.manifest_schema())
        self.assertNotIn("sha256:", text)
        self.assertNotIn(packager._version(ROOT), text)


@unittest.skipUnless(_BUILT, _REASON)
class HealthSchemaTests(unittest.TestCase):
    def test_the_schema_names_every_posture_check_the_binary_runs(self) -> None:
        schema = packager.health_schema(BINARY)
        observed = subprocess.run(
            [str(BINARY), "--health"], capture_output=True, text=True, timeout=30, cwd=str(ROOT)
        )
        report = json.loads(observed.stdout)
        self.assertEqual(schema["checks"], sorted(c["name"] for c in report["checks"]))
        self.assertTrue(schema["checks"])

    def test_healthy_and_unhealthy_are_different_words(self) -> None:
        schema = packager.health_schema(BINARY)
        self.assertNotEqual(schema["healthy_status"], schema["unhealthy_status"])

    def test_all_four_conditions_are_named(self) -> None:
        conditions = packager.health_schema(BINARY)["healthy_when"]
        self.assertEqual(len(conditions), 4)

    def test_the_schema_says_health_does_not_establish_running(self) -> None:
        schema = packager.health_schema(BINARY)
        self.assertIn("that the payload is running", schema["does_not_establish"])

    def test_a_binary_that_never_reports_unhealthy_refuses(self) -> None:
        """Otherwise the contract would document a branch nobody exercised."""

        always_healthy = {"code": 0, "report": {"contract": "c", "status": "healthy", "checks": []}}
        with mock.patch.object(packager, "_run_health", return_value=always_healthy):
            with self.assertRaises(packager.BuildRefused) as raised:
                packager.health_schema(BINARY)
        self.assertIn("unhealthy", str(raised.exception))

    def test_a_binary_whose_two_reports_differ_in_shape_refuses(self) -> None:
        answers = [
            {"code": 0, "report": {"contract": "c", "status": "healthy", "checks": []}},
            {"code": 1, "report": {"contract": "c", "status": "unhealthy", "extra": 1, "checks": []}},
        ]
        with mock.patch.object(packager, "_run_health", side_effect=answers):
            with self.assertRaises(packager.BuildRefused) as raised:
                packager.health_schema(BINARY)
        self.assertIn("shape", str(raised.exception))

    def test_an_unhealthy_report_that_still_exits_zero_refuses(self) -> None:
        """A consumer keying on the exit code alone must not be handed this."""

        answers = [
            {"code": 0, "report": {"contract": "c", "status": "healthy", "checks": []}},
            {"code": 0, "report": {"contract": "c", "status": "unhealthy", "checks": []}},
        ]
        with mock.patch.object(packager, "_run_health", side_effect=answers):
            with self.assertRaises(packager.BuildRefused):
                packager.health_schema(BINARY)


class PinTests(unittest.TestCase):
    def test_the_pinned_version_is_the_crate_version(self) -> None:
        self.assertEqual(packager.pin_document(packager._version(ROOT))["version"], packager._version(ROOT))

    def test_the_pin_states_that_nothing_is_signed(self) -> None:
        self.assertIs(packager.pin_document("0.1.0")["signed"], False)

    def test_the_pin_requires_six_findings_to_stay_separate(self) -> None:
        must = " ".join(packager.pin_document("0.1.0")["consumer_must"])
        for finding in ("absence", "corrupt", "version mismatch", "digest mismatch", "unhealthy", "not-running"):
            self.assertIn(finding, must)

    def test_the_pin_forbids_claiming_baseline_ready_from_the_package(self) -> None:
        must = " ".join(packager.pin_document("0.1.0")["consumer_must"])
        self.assertIn("not claim edge-baseline-ready", must)


@unittest.skipUnless(_BUILT, _REASON)
class CommittedContractTests(unittest.TestCase):
    """The committed files are the ones a regeneration produces."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.fresh = Path(cls._tmp.name) / "contract"
        packager.write_contract(ROOT, cls.fresh)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_every_expected_document_is_committed(self) -> None:
        self.assertEqual(sorted(p.name for p in COMMITTED.glob("*.json")), list(NAMES))

    def test_the_committed_documents_are_byte_identical_to_a_regeneration(self) -> None:
        for name in NAMES:
            with self.subTest(document=name):
                self.assertEqual(
                    (COMMITTED / name).read_bytes(),
                    (self.fresh / name).read_bytes(),
                    f"{name} is stale; run "
                    "python3 packaging/nexus-core/nexus_core_package.py --emit-contract",
                )

    def test_two_regenerations_are_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            second = Path(tmp) / "contract"
            packager.write_contract(ROOT, second)
            for name in NAMES:
                with self.subTest(document=name):
                    self.assertEqual(
                        (self.fresh / name).read_bytes(), (second / name).read_bytes()
                    )

    def test_no_document_carries_a_digest_or_an_absolute_path(self) -> None:
        for name in NAMES:
            text = (COMMITTED / name).read_text(encoding="utf-8")
            with self.subTest(document=name):
                self.assertNotIn("sha256:", text)
                self.assertNotIn(str(ROOT), text)

    def test_every_document_names_the_contract_it_describes(self) -> None:
        for name in NAMES:
            document = json.loads((COMMITTED / name).read_text(encoding="utf-8"))
            with self.subTest(document=name):
                self.assertTrue(document["contract"].startswith("azazel-edge-core/"))

    def test_the_committed_manifest_schema_matches_a_real_package(self) -> None:
        """The schema's whole job is to describe the manifest a build writes."""

        with tempfile.TemporaryDirectory() as tmp:
            _, manifest_path = packager.build(ROOT, Path(tmp))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        committed = json.loads((COMMITTED / "manifest-schema.json").read_text(encoding="utf-8"))
        self.assertEqual(committed["keys"], packager.key_paths(manifest))

    def test_the_committed_pin_matches_the_crate(self) -> None:
        committed = json.loads((COMMITTED / "pin.json").read_text(encoding="utf-8"))
        self.assertEqual(committed["version"], packager._version(ROOT))

    def test_emitting_the_contract_builds_no_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "contract"
            code = packager.main(["--emit-contract", "--contract-dir", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in out.iterdir()), list(NAMES))

    def test_a_binary_from_another_build_refuses_to_produce_a_contract(self) -> None:
        """Survived a mutation that dropped this check, so it is tested directly.

        Without it the pin would carry the tree's version while the health
        schema was derived by running a different binary -- a contract
        describing two builds at once, and internally consistent enough that
        nothing downstream could notice.
        """

        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "tree"
            crate = fake / "rust" / "azazel-edge-core"
            crate.mkdir(parents=True)
            (crate / "Cargo.toml").write_text('version = "9.9.9"\n', encoding="utf-8")
            target = crate / "target" / "release"
            target.mkdir(parents=True)
            payload = target / "azazel-edge-core"
            payload.write_bytes(BINARY.read_bytes())
            payload.chmod(0o755)
            with self.assertRaises(packager.BuildRefused) as raised:
                packager.contract_documents(fake)
        message = str(raised.exception)
        self.assertIn("9.9.9", message)
        self.assertIn("different builds", message)

    def test_a_tree_with_no_built_binary_refuses_rather_than_writing_from_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "tree"
            (fake / "rust" / "azazel-edge-core").mkdir(parents=True)
            (fake / "rust" / "azazel-edge-core" / "Cargo.toml").write_text(
                'version = "0.1.0"\n', encoding="utf-8"
            )
            with self.assertRaises(packager.BuildRefused) as raised:
                packager.contract_documents(fake)
        self.assertIn("is not built", str(raised.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
