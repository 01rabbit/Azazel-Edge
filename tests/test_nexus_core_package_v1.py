"""The x86_64 Edge Core package Azazel-Nexus verifies (Edge#424).

Nexus looks at five things and nothing else: the package is present, the
version matches, the digest matches, the health contract answers, and the
payload is running. **Accepting the package establishes the first four at
most, never the fifth, and never `edge-baseline-ready` on its own.** These
tests hold the Edge side of that.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging" / "nexus-core"))

# Named `nexus_core_package`, not `build`. A module called `build` on
# `sys.path` shadows the PyPI package of that name, and
# `test_runtime_dependency_contract.py` -- which scans every import in the
# repository against the declared requirements -- read it as an undeclared
# runtime dependency. It caught this on the first full run.
import nexus_core_package as packager  # noqa: E402

BINARY = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
_BUILT = BINARY.is_file()
_REASON = (
    "the release binary is not built; run "
    "cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml"
)


@unittest.skipUnless(_BUILT, _REASON)
class NexusCorePackageV1Tests(unittest.TestCase):
    """Built once for the class: the builder is deterministic, so one is enough."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name) / "first"
        cls.archive, cls.manifest_path = packager.build(ROOT, out)
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    # -- deterministic, because Nexus compares a digest --------------------

    def test_two_builds_of_one_tree_are_byte_identical(self) -> None:
        second, _ = packager.build(ROOT, Path(self._tmp.name) / "second")
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())

    def test_the_gzip_header_carries_no_timestamp(self) -> None:
        """Read out of the header rather than inferred from two builds agreeing.

        Two builds a second apart would agree on a wall-clock mtime, so the
        test above passes whether or not the timestamp is suppressed. Bytes
        4..8 of a gzip member are the MTIME field; zero means "no timestamp".
        """

        header = self.archive.read_bytes()[:8]
        self.assertEqual(header[:2], b"\x1f\x8b")
        self.assertEqual(header[4:8], b"\x00\x00\x00\x00")

    def test_the_manifest_digest_is_the_digest_of_the_archive(self) -> None:
        self.assertEqual(
            self.manifest["digest"], packager._digest(self.archive.read_bytes())
        )

    def test_no_archive_entry_carries_a_timestamp_or_an_owner(self) -> None:
        """Each is a place a build host would otherwise leak into the digest."""

        with tarfile.open(self.archive, "r:gz") as tar:
            members = tar.getmembers()
        self.assertTrue(members)
        for member in members:
            self.assertEqual(member.mtime, 0, member.name)
            self.assertEqual(member.uid, 0, member.name)
            self.assertEqual(member.gid, 0, member.name)
            self.assertEqual(member.uname, "", member.name)
            self.assertEqual(member.gname, "", member.name)

    def test_archive_order_does_not_follow_the_declared_payload_order(self) -> None:
        """`PAYLOAD` happens to be declared sorted, so sorting is a no-op on it.

        Reversed, it is not: without the sort the archive order would follow
        the declaration and the digest would depend on how somebody happened
        to type the list.
        """

        original = packager.PAYLOAD
        try:
            packager.PAYLOAD = tuple(reversed(original))
            reversed_archive, _ = packager.build(
                ROOT, Path(self._tmp.name) / "reversed"
            )
        finally:
            packager.PAYLOAD = original
        self.assertEqual(self.archive.read_bytes(), reversed_archive.read_bytes())

    def test_no_archive_entry_escapes_the_package(self) -> None:
        with tarfile.open(self.archive, "r:gz") as tar:
            names = tar.getnames()
        for name in names:
            self.assertFalse(name.startswith("/"), name)
            self.assertNotIn("..", Path(name).parts, name)

    # -- what the manifest has to say --------------------------------------

    def test_the_manifest_names_the_five_things_nexus_verifies(self) -> None:
        for field in ("package", "version", "architecture", "digest", "health"):
            self.assertIn(field, self.manifest)
        self.assertEqual(self.manifest["architecture"], "x86_64")
        self.assertEqual(self.manifest["contract"], packager.MANIFEST_CONTRACT)

    def test_the_manifest_states_that_the_digest_is_not_signed(self) -> None:
        """Edge#424 asks for this explicitly, and the answer is no.

        Nexus distinguishes "the tag is signed" from "the digest is signed".
        Neither is true here, and a consumer must degrade rather than read an
        unsigned digest as authenticity.
        """

        self.assertIs(self.manifest["signed"], False)
        self.assertIn("accidental change", self.manifest["signed_reason"])
        self.assertIn("adversary", self.manifest["signed_reason"])

    def test_the_sbom_lists_every_payload_file_with_its_own_digest(self) -> None:
        listed = {component["path"] for component in self.manifest["components"]}
        self.assertEqual(listed, {archive for archive, _ in packager.PAYLOAD})
        for component in self.manifest["components"]:
            self.assertTrue(component["digest"].startswith("sha256:"))
            self.assertGreater(component["size"], 0)

    def test_each_component_digest_matches_the_file_in_the_archive(self) -> None:
        with tarfile.open(self.archive, "r:gz") as tar:
            for component in self.manifest["components"]:
                handle = tar.extractfile(component["path"])
                self.assertIsNotNone(handle, component["path"])
                data = handle.read()
                self.assertEqual(packager._digest(data), component["digest"])
                self.assertEqual(len(data), component["size"])

    def test_the_manifest_says_what_accepting_the_package_does_not_establish(self) -> None:
        """The sentence that keeps a package from becoming a readiness claim."""

        items = self.manifest["not_established_by_accepting_this_package"]
        # Per item, not over the join: the readiness entry also contains the
        # word "running", so a joined search passes even with the payload
        # entry deleted.
        self.assertTrue(
            any("payload is running" in item for item in items),
            f"no item says the payload may not be running: {items}",
        )
        self.assertTrue(
            any("edge-baseline-ready" in item for item in items),
            f"no item names edge-baseline-ready: {items}",
        )

    def test_the_declared_posture_is_observe_only(self) -> None:
        posture = self.manifest["posture"]
        self.assertIs(posture["observe_only"], True)
        for forbidden in (
            "enforcement",
            "redirect",
            "external_device_change",
            "network_configuration_change",
        ):
            self.assertIs(posture[forbidden], False, forbidden)

    def test_the_startup_contract_changes_no_network_configuration(self) -> None:
        startup = self.manifest["startup"]
        self.assertEqual(startup["network_configuration"], "none")
        self.assertEqual(
            startup["observe_only_env"]["AZAZEL_DEFENSE_ENFORCE"], "false"
        )
        self.assertEqual(startup["observe_only_env"]["AZAZEL_DEFENSE_DRY_RUN"], "true")
        self.assertIn("starts nothing", startup["note"])

    # -- the health contract, run rather than described --------------------

    def _health(self, env_overrides: dict | None = None) -> tuple[int, dict]:
        env = dict(os.environ)
        env.update(env_overrides or {})
        completed = subprocess.run(
            [str(BINARY), "--health"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=str(ROOT),
        )
        return completed.returncode, json.loads(completed.stdout)

    def test_the_default_posture_is_healthy_and_exits_zero(self) -> None:
        code, report = self._health()
        self.assertEqual(code, 0)
        self.assertEqual(report["contract"], packager.HEALTH_CONTRACT)
        self.assertEqual(report["status"], "healthy")
        self.assertIs(report["observe_only"], True)

    def test_enforcement_enabled_is_unhealthy_and_exits_non_zero(self) -> None:
        """The condition Edge#424 calls out: unhealthy must not read as healthy."""

        code, report = self._health({"AZAZEL_DEFENSE_ENFORCE": "true"})
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "unhealthy")
        self.assertIs(report["observe_only"], False)

    def test_each_posture_check_can_fail_on_its_own(self) -> None:
        """One check per way the posture can be wrong, and each is reachable.

        A check nothing can make fail is a check that is always green, which
        is indistinguishable from a check that is not there.
        """

        cases = {
            "enforcement_disabled": {"AZAZEL_DEFENSE_ENFORCE": "true"},
            "dry_run": {"AZAZEL_DEFENSE_DRY_RUN": "false"},
            "advisory_level": {"AZAZEL_DEFENSE_ENFORCE_LEVEL": "block"},
            "high_impact_auto_disabled": {
                "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO": "true"
            },
        }
        for name, overrides in cases.items():
            with self.subTest(check=name):
                code, report = self._health(overrides)
                self.assertNotEqual(code, 0)
                failed = {c["name"] for c in report["checks"] if not c["ok"]}
                self.assertIn(name, failed)

    def test_every_check_reports_the_value_it_judged(self) -> None:
        _, report = self._health()
        for check in report["checks"]:
            self.assertTrue(check["detail"].strip(), check["name"])

    def test_health_is_one_shot_and_does_not_start_the_loop(self) -> None:
        """It returns. A health check that never returned would be unusable."""

        completed = subprocess.run(
            [str(BINARY), "--health"], capture_output=True, timeout=30, cwd=str(ROOT)
        )
        self.assertEqual(completed.returncode, 0)

    def test_the_manifest_requires_all_four_conditions_for_healthy(self) -> None:
        """Exit code alone, or status alone, must not be enough."""

        healthy_when = self.manifest["health"]["healthy_when"]
        for condition in ("exits 0", "JSON", "contract", "'healthy'"):
            self.assertIn(condition, healthy_when)

    def test_the_manifest_says_health_does_not_establish_running(self) -> None:
        """Written plainly after a first attempt that asserted almost nothing.

        The first version called `.replace()` on the manifest text to turn it
        into the phrase it then asserted was present -- which would have
        passed whatever the manifest said.
        """

        does_not = self.manifest["health"]["does_not_establish"]
        self.assertIn("running", does_not)
        self.assertIn("separately", does_not)
        self.assertNotIn("establishes that anything is running", does_not)

    # -- the version the package claims ------------------------------------

    def test_the_binary_agrees_with_the_version_being_packaged(self) -> None:
        reported = subprocess.run(
            [str(BINARY), "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
        self.assertEqual(reported, self.manifest["version"])

    def test_the_artifact_is_named_for_its_version_and_architecture(self) -> None:
        self.assertEqual(
            self.archive.name,
            f"azazel-edge-core-{self.manifest['version']}-x86_64.tar.gz",
        )
        self.assertEqual(self.manifest["artifact"], self.archive.name)


class NexusCorePackageRefusalTests(unittest.TestCase):
    """What the builder refuses rather than guesses."""

    def test_a_missing_payload_refuses_instead_of_building_a_stand_in(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            root = Path(empty)
            (root / "rust" / "azazel-edge-core").mkdir(parents=True)
            (root / "rust" / "azazel-edge-core" / "Cargo.toml").write_text(
                'version = "9.9.9"\n', encoding="utf-8"
            )
            with self.assertRaises(packager.BuildRefused) as refused:
                packager.build(root, root / "out")
            self.assertIn("never builds a stand-in", str(refused.exception))

    def test_a_binary_from_another_build_refuses(self) -> None:
        """The mistake a digest cannot catch.

        A binary built from a different checkout than the Cargo.toml being
        read produces a package that is internally consistent and wrong. The
        builder runs `--version` and compares, so it is caught here.
        """

        if not _BUILT:
            self.skipTest(_REASON)
        with tempfile.TemporaryDirectory() as fake:
            root = Path(fake)
            crate = root / "rust" / "azazel-edge-core"
            (crate / "target" / "release").mkdir(parents=True)
            (crate / "Cargo.toml").write_text('version = "9.9.9"\n', encoding="utf-8")
            target = crate / "target" / "release" / "azazel-edge-core"
            target.write_bytes(BINARY.read_bytes())
            target.chmod(0o755)
            (root / "config").mkdir()
            (root / "config" / "redirect_policy.yaml").write_text("{}\n", encoding="utf-8")

            with self.assertRaises(packager.BuildRefused) as refused:
                packager.build(root, root / "out")
            self.assertIn("different builds", str(refused.exception))

    def test_a_tree_without_a_version_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            root = Path(empty)
            (root / "rust" / "azazel-edge-core").mkdir(parents=True)
            (root / "rust" / "azazel-edge-core" / "Cargo.toml").write_text(
                "[package]\n", encoding="utf-8"
            )
            with self.assertRaises(packager.BuildRefused):
                packager.build(root, root / "out")

    def test_the_payload_is_listed_and_never_globbed(self) -> None:
        """A package whose contents depend on a working copy's state is not one."""

        source = Path(packager.__file__).read_text(encoding="utf-8")
        for globbing in ("rglob(", "glob(", "iterdir("):
            self.assertNotIn(globbing, source)

    def test_the_packager_does_not_touch_the_network_installer(self) -> None:
        """Edge#424: the existing network installer is neither used nor ported."""

        source = Path(packager.__file__).read_text(encoding="utf-8").lower()
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        for forbidden in ("subprocess.run([\"installer", "installer/internal", "nmcli", "iptables", "nft "):
            self.assertNotIn(forbidden, code, forbidden)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
