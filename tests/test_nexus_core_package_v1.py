"""The per-CPU Edge Core package Azazel-Nexus verifies (Edge#424).

Nexus looks at five things and nothing else: the package is present, the
version matches, the digest matches, the health contract answers, and the
payload is running. **Accepting the package establishes the first four at
most, never the fifth, and never `edge-baseline-ready` on its own.** These
tests hold the Edge side of that.
"""

from __future__ import annotations

import json
import os
import platform
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

#: The CPU this test runs on, by `uname -m`, read independently of the
#: packager. A release binary built here is for this CPU.
HOST = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(platform.machine(), "")
OTHER = {"x86_64": "aarch64", "aarch64": "x86_64"}.get(HOST, "")
#: `e_machine` numbers from the System V ABI, written here rather than taken
#: from the packager so the tests do not grade the packager by its own table.
EM = {"x86_64": 62, "aarch64": 183}


def elf_header(
    *, machine: int, elf_class: int = 2, data: int = 1, e_type: int = 3, version: int = 1,
    ident_version: int = 1,
) -> bytes:
    """A 64-byte ELF header with the fields the CPU check reads."""

    order = "<" if data == 1 else ">"
    ident = b"\x7fELF" + bytes([elf_class, data, ident_version, 0]) + bytes(8)
    return ident + struct.pack(order + "HHI", e_type, machine, version) + bytes(40)


def fake_tree(root: Path, binary: bytes) -> None:
    """A tree with a Cargo.toml, a policy and `binary` where the build goes."""

    crate = root / "rust" / "azazel-edge-core"
    (crate / "target" / "release").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('version = "0.1.0"\n', encoding="utf-8")
    target = crate / "target" / "release" / "azazel-edge-core"
    target.write_bytes(binary)
    target.chmod(0o755)
    (root / "config").mkdir()
    (root / "config" / "redirect_policy.yaml").write_text("{}\n", encoding="utf-8")


@unittest.skipUnless(_BUILT, _REASON)
class NexusCorePackageV1Tests(unittest.TestCase):
    """Built once for the class: the builder is deterministic, so one is enough."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name) / "first"
        cls.archive, cls.manifest_path = packager.build(ROOT, out, architecture=HOST)
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    # -- deterministic, because Nexus compares a digest --------------------

    def test_two_builds_of_one_tree_are_byte_identical(self) -> None:
        second, _ = packager.build(ROOT, Path(self._tmp.name) / "second", architecture=HOST)
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
                ROOT, Path(self._tmp.name) / "reversed", architecture=HOST
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
        self.assertEqual(self.manifest["architecture"], HOST)
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
            f"azazel-edge-core-{self.manifest['version']}-{HOST}.tar.gz",
        )
        self.assertEqual(self.manifest["artifact"], self.archive.name)
        self.assertEqual(
            self.manifest_path.name,
            f"azazel-edge-core-{self.manifest['version']}-{HOST}.manifest.json",
        )

    # -- the CPU, read from the binary rather than written down ------------

    def test_the_manifest_records_the_elf_header_of_the_packaged_binary(self) -> None:
        """Compared with the header bytes, not with the packager's table."""

        with tarfile.open(self.archive, "r:gz") as tar:
            header = tar.extractfile("bin/azazel-edge-core").read(20)
        machine = struct.unpack_from("<H", header, 18)[0]
        self.assertEqual(machine, EM[HOST])
        self.assertEqual(header[4], 2)
        self.assertEqual(header[5], 1)
        self.assertEqual(
            self.manifest["elf"],
            {"class": "ELFCLASS64", "data": "ELFDATA2LSB",
             "machine": {"x86_64": "EM_X86_64", "aarch64": "EM_AARCH64"}[HOST]},
        )

    def test_the_real_binary_is_refused_under_the_other_cpus_name(self) -> None:
        """The 2026-10-29 deviation: a binary of one CPU named for the other."""

        with self.assertRaises(packager.BuildRefused) as refused:
            packager.build(ROOT, Path(self._tmp.name) / "other", architecture=OTHER)
        self.assertIn(f"ELF header says {HOST}", str(refused.exception))
        self.assertFalse((Path(self._tmp.name) / "other").exists())

    def test_the_real_binary_with_its_machine_rewritten_is_refused(self) -> None:
        """The same build, with only `e_machine` changed to the other CPU."""

        data = bytearray(BINARY.read_bytes())
        data[18:20] = struct.pack("<H", EM[OTHER])
        with tempfile.TemporaryDirectory() as fake:
            root = Path(fake)
            fake_tree(root, bytes(data))
            with self.assertRaises(packager.BuildRefused) as refused:
                packager.build(root, root / "out", architecture=HOST)
        self.assertIn(f"ELF header says {OTHER}", str(refused.exception))


class ElfIdentityTests(unittest.TestCase):
    """The header reader, on headers written here byte by byte."""

    def test_each_reviewed_cpu_is_read_from_its_machine_number(self) -> None:
        for name, number in EM.items():
            with self.subTest(cpu=name):
                identity = packager.elf_identity(elf_header(machine=number))
                self.assertEqual(packager.architecture_of(identity), name)

    def test_an_executable_and_a_pie_are_both_executables(self) -> None:
        for e_type in (2, 3):
            with self.subTest(e_type=e_type):
                identity = packager.elf_identity(elf_header(machine=62, e_type=e_type))
                self.assertEqual(packager.architecture_of(identity), "x86_64")

    def test_headers_that_are_not_a_reviewed_cpu_are_refused(self) -> None:
        cases = {
            "32-bit": elf_header(machine=EM["x86_64"], elf_class=1),
            "big-endian aarch64": elf_header(machine=EM["aarch64"], data=2),
            "riscv64": elf_header(machine=243),
            "unlisted machine": elf_header(machine=9999),
            "relocatable object": elf_header(machine=62, e_type=1),
            "ELF version 0": elf_header(machine=62, version=0),
            "EI_VERSION 0": elf_header(machine=62, ident_version=0),
            "unknown class": elf_header(machine=62, elf_class=3),
            "not ELF": b"#!/bin/sh\n" + bytes(60),
            "truncated": elf_header(machine=62)[:19],
        }
        for name, header in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(packager.BuildRefused):
                    packager.architecture_of(packager.elf_identity(header))

    def test_the_two_cpus_have_different_identities(self) -> None:
        """Otherwise one would always be read as the other."""

        identities = list(packager.ARCHITECTURES.values())
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(sorted(packager.ARCHITECTURES), ["aarch64", "x86_64"])


class ArchitectureRefusalTests(unittest.TestCase):
    """The CPU check, on a synthetic header, without a Rust build.

    `_binary_reports` (which runs the binary) is replaced: the header is not
    executable. Where it is expected not to run at all, the test says so.
    """

    def _build(self, binary: bytes, architecture: str):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        fake_tree(root, binary)
        with mock.patch.object(packager, "_binary_reports") as ran:
            try:
                return packager.build(root, root / "out", architecture=architecture), ran, root
            except packager.BuildRefused as exc:
                return exc, ran, root

    def test_each_cpu_builds_under_its_own_name_and_records_its_header(self) -> None:
        for name, number in EM.items():
            with self.subTest(cpu=name):
                (archive, manifest_path), ran, _ = self._build(elf_header(machine=number), name)
                ran.assert_called_once()
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(manifest["architecture"], name)
                self.assertEqual(archive.name, f"azazel-edge-core-0.1.0-{name}.tar.gz")
                self.assertEqual(manifest_path.name, f"azazel-edge-core-0.1.0-{name}.manifest.json")
                self.assertEqual(manifest["artifact"], archive.name)
                self.assertEqual(manifest["elf"]["class"], "ELFCLASS64")
                self.assertEqual(manifest["elf"]["data"], "ELFDATA2LSB")
                self.assertEqual(
                    manifest["elf"]["machine"],
                    {"x86_64": "EM_X86_64", "aarch64": "EM_AARCH64"}[name],
                )

    def test_a_binary_of_one_cpu_is_refused_under_the_others_name_before_it_runs(self) -> None:
        for binary_cpu, asked in (("aarch64", "x86_64"), ("x86_64", "aarch64")):
            with self.subTest(binary=binary_cpu, asked=asked):
                refused, ran, root = self._build(elf_header(machine=EM[binary_cpu]), asked)
                self.assertIsInstance(refused, packager.BuildRefused)
                self.assertIn(f"asked to package {asked}", str(refused))
                self.assertIn(f"ELF header says {binary_cpu}", str(refused))
                ran.assert_not_called()
                self.assertFalse((root / "out").exists())

    def test_a_binary_replaced_after_the_check_is_not_what_gets_packaged(self) -> None:
        """Re522-01: the bytes checked are the bytes run, hashed and archived."""

        checked = elf_header(machine=EM["x86_64"])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        fake_tree(root, checked)
        tree_binary = root / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
        ran_on: list[tuple[Path, bytes]] = []

        def swap_after_running(path: Path, version: str) -> None:
            ran_on.append((path, path.read_bytes()))
            tree_binary.write_bytes(elf_header(machine=EM["aarch64"]))

        with mock.patch.object(packager, "_binary_reports", side_effect=swap_after_running):
            archive, manifest_path = packager.build(root, root / "out", architecture="x86_64")
        self.assertEqual(ran_on[0][1], checked)
        self.assertNotEqual(ran_on[0][0], tree_binary)
        with tarfile.open(archive, "r:gz") as tar:
            member = tar.extractfile("bin/azazel-edge-core").read()
        self.assertEqual(member, checked)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        component = {c["path"]: c for c in manifest["components"]}["bin/azazel-edge-core"]
        self.assertEqual(component["digest"], packager._digest(checked))
        self.assertEqual(component["size"], len(checked))
        self.assertEqual(manifest["architecture"], "x86_64")

    def test_a_cpu_outside_the_table_is_refused(self) -> None:
        for asked in ("arm64", "amd64", "riscv64", ""):
            with self.subTest(asked=asked):
                refused, ran, _ = self._build(elf_header(machine=EM["x86_64"]), asked)
                self.assertIsInstance(refused, packager.BuildRefused)
                ran.assert_not_called()

    def test_a_big_endian_header_is_refused_whatever_is_asked(self) -> None:
        refused, ran, _ = self._build(elf_header(machine=EM["aarch64"], data=2), "aarch64")
        self.assertIsInstance(refused, packager.BuildRefused)
        ran.assert_not_called()

    def test_building_without_an_architecture_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as fake:
            root = Path(fake)
            fake_tree(root, elf_header(machine=EM["x86_64"]))
            with mock.patch("sys.stderr"):
                code = packager.main(["--root", str(root), "--out", str(root / "out")])
            self.assertEqual(code, 2)
            self.assertFalse((root / "out").exists())


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
                packager.build(root, root / "out", architecture="x86_64")
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
                packager.build(root, root / "out", architecture=HOST)
            self.assertIn("different builds", str(refused.exception))

    def test_a_tree_without_a_version_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            root = Path(empty)
            (root / "rust" / "azazel-edge-core").mkdir(parents=True)
            (root / "rust" / "azazel-edge-core" / "Cargo.toml").write_text(
                "[package]\n", encoding="utf-8"
            )
            with self.assertRaises(packager.BuildRefused):
                packager.build(root, root / "out", architecture="x86_64")

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
