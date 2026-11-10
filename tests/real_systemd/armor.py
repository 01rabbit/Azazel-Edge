"""Named accounts and enforced role AppArmor in a fresh disposable VM only."""

import argparse
import grp
import hashlib
import json
from pathlib import Path
import pwd
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guest as g
from azazel_edge.outcome.input_auth import read_regular

ROLE_CAPS = {
    "capture": "CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID CAP_NET_ADMIN",
    "witness": "CAP_DAC_READ_SEARCH",
    "observer": "",
}
SHARED = """NoNewPrivileges=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX
"""


def execute_role(role, mode, *args):
    python = (
        g.PYTHON
        if role == "witness"
        else g.PYTHON.with_name("edge-capture" if role == "capture" else "edge-observe")
    )
    user = "root" if role == "witness" else "edge400-" + role
    return g.command(
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "-p",
        "User=" + user,
        "-p",
        "Group=" + user,
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "CapabilityBoundingSet=" + (ROLE_CAPS[role] if role == "witness" else ""),
        "-p",
        "AppArmorProfile=edge400-" + role,
        "-p",
        "RestrictAddressFamilies=AF_UNIX",
        str(python),
        "-I",
        str(g.SRC / "tests/real_systemd/role_probe.py"),
        mode,
        *args,
    )


def observer(create=False):
    result = json.loads(
        execute_role("observer", "observer", *(["--create"] if create else [])).stdout
    )
    g.record("named-confined-observer", **result["identity"])
    assert result["status"]["committed"] == 0
    return result["status"]


def prepare_accounts():
    for role, uid in [("capture", 61001), ("observer", 61002), ("ai", 61003)]:
        name = "edge400-" + role
        try:
            pwd.getpwnam(name)
        except KeyError:
            try:
                pwd.getpwuid(uid)
            except KeyError:
                pass
            else:
                raise AssertionError("existing UID refused")
            g.command("groupadd", "--gid", str(uid), name)
            g.command(
                "useradd",
                "--system",
                "--uid",
                str(uid),
                "--gid",
                name,
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                name,
            )
        account = pwd.getpwnam(name)
        locked = (
            g.command("getent", "shadow", name)
            .stdout.split(":")[1]
            .startswith(("!", "*"))
        )
        assert (
            account.pw_shell == "/usr/sbin/nologin"
            and account.pw_dir == "/nonexistent"
            and account.pw_uid == uid
            and account.pw_gid == uid
            and locked
        )
        assert not [group.gr_name for group in grp.getgrall() if name in group.gr_mem]


def install_policy():
    assert Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    for alias in ["edge-capture", "edge-observe"]:
        target = g.PYTHON.with_name(alias)
        if not target.exists():
            shutil.copyfile(g.PYTHON.resolve(), target)
            target.chmod(0o755)
        actual, _ = read_regular(
            target, owner=0, mode=0o755, max_bytes=64 * 1024 * 1024
        )
        expected, _ = read_regular(
            g.PYTHON.resolve(), owner=0, max_bytes=64 * 1024 * 1024
        )
        assert actual == expected, "existing alias differs; no replacement"
    policy, _ = read_regular(
        g.SRC / "tests/real_systemd/edge400.apparmor", owner=0, max_bytes=32768
    )
    target = Path("/etc/apparmor.d/edge400-lab")
    if target.exists():
        actual, _ = read_regular(target, owner=0, max_bytes=32768)
        assert actual == policy, "existing policy differs; no replacement"
    else:
        g.write(target, policy)
    g.command("apparmor_parser", "-r", str(target))


NATIVE = False


def configure():
    original = g.write

    def write(path, data, mode=0o644):
        if path == g.UNITS / g.UNIT:
            data = data.replace(
                "[Unit]\n", "[Unit]\nAfter=apparmor.service\nWants=apparmor.service\n"
            )
            data += (
                "\n[Service]\n"
                + SHARED
                + "PrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
                + "CapabilityBoundingSet="
                + ROLE_CAPS["capture"]
                + "\n"
            )
        elif path == g.UNITS / g.WITNESS:
            data = data.replace(
                "[Unit]\n", "[Unit]\nAfter=apparmor.service\nWants=apparmor.service\n"
            )
            data = data.replace(
                "--systemd-notify",
                "--systemd-notify --apparmor-profile edge400-witness",
            )
            data += (
                "\n[Service]\n"
                + SHARED
                + "AppArmorProfile=edge400-witness\nCapabilityBoundingSet="
                + ROLE_CAPS["witness"]
                + "\n"
            )
        return original(path, data, mode)

    g.write = write
    original_prepare = g.prepare
    g.prepare = lambda *args, **kwargs: original_prepare(
        *args,
        **kwargs,
        capture_apparmor_profile="edge400-capture",
        **({"native_apparmor_profile": "edge400-native"} if NATIVE else {}),
    )
    g.observer = observer


def identities_and_denials():
    pid = g.live()
    info = Path(f"/proc/{pid}/status").read_text()
    assert int(info.split("CapEff:")[1].split()[0], 16) == 4 + 64 + 128 + 4096
    assert info.split("NoNewPrivs:")[1].split()[0] == "1"
    # Actual running native label, distinct from the root launcher.
    assert Path(f"/proc/{pid}/attr/apparmor/current").read_text().strip() == (
        "edge400-native (enforce)" if NATIVE else "unconfined"
    )
    for role in ["capture", "observer", "witness"]:
        result = json.loads(
            execute_role(role, "denials", "--role", role, "--pid", str(pid)).stdout
        )
        g.record("enforced-role-denials-" + role, **result)
    # Default-denied world-readable canary is readable outside AA under same UID.
    for uid in [0, 61001, 61002]:
        result = __import__("subprocess").run(
            [
                str(g.PYTHON),
                "-I",
                "-c",
                "import os,sys,socket;f=os.open(sys.argv[1],os.O_RDONLY);os.close(f);s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.close()",
                str(g.BASE / "aa-denied"),
            ],
            user=uid,
            group=uid,
            extra_groups=[],
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
    g.record("unconfined-same-uid-positive-controls")
    ai = __import__("subprocess").run(
        [
            str(g.PYTHON),
            "-I",
            "-c",
            "import os,sys;\nfor path in sys.argv[1:]:\n try: fd=os.open(path,os.O_RDONLY)\n except PermissionError: pass\n else: os.close(fd);raise AssertionError('AI role accessed private state')",
            str(g.BUNDLE / "producer/key.raw"),
            str(g.BUNDLE / "witness/key.raw"),
            str(g.BUNDLE / "observer/observations.journal"),
        ],
        user=61003,
        group=61003,
        extra_groups=[],
        capture_output=True,
    )
    assert ai.returncode == 0, ai.stderr
    g.record("ai-uid-no-key-or-private-journal-access")
    # Do not attribute the family filter to AppArmor: record what this kernel
    # does with the same alias without systemd's seccomp family restriction.
    probe = __import__("subprocess").run(
        [
            str(g.PYTHON.with_name("edge-capture")),
            "-I",
            "-c",
            "import socket,errno;\ntry: s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.close();print(0)\nexcept OSError as e: assert e.errno in (errno.EACCES,errno.EPERM);print(e.errno)",
        ],
        user=61001,
        group=61001,
        extra_groups=[],
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    g.record(
        "apparmor-inet-standalone-observation",
        creation_denied=int(probe.stdout.strip()) != 0,
        required_ip_isolation="systemd-family-filter-and-offline-vm",
    )
    script = "import errno,os,sys;from pathlib import Path;assert Path('/proc/self/attr/apparmor/current').read_text().strip()=='unconfined';\ntry: os.open(sys.argv[1],os.O_WRONLY)\nexcept OSError as e: assert e.errno==errno.EROFS\nelse: raise AssertionError('not read-only')"
    g.command(
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "-p",
        "User=edge400-observer",
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "CapabilityBoundingSet=",
        "-p",
        "ProtectSystem=strict",
        "-p",
        "ReadWritePaths=" + str(g.BUNDLE / "observer"),
        str(g.PYTHON),
        "-I",
        "-c",
        script,
        str(g.BASE / "namespace-canary"),
    )
    g.record("strict-readonly-namespace-separate-control", apparmor=False)
    # Missing/complain profile and wrong attachment never become a fallback.
    g.stop()
    before = g.source()
    alias = g.PYTHON.with_name("edge-capture")
    original = alias.read_bytes()
    alias.chmod(0o777)
    g.failed_start("unsafe-alias-permissions-refuse-connected-start")
    alias.chmod(0o755)
    alias.write_bytes(b"not-the-installed-interpreter")
    g.failed_start("different-alias-image-refuses-connected-start")
    g.write(g.BASE / "injected-invalid-alias", alias.read_bytes(), 0o600)
    alias.write_bytes(original)  # controlled synthetic lab fault restoration
    # These configurations are refused, never rewritten or granted privileges.
    for setting, reason in [
        ("AppArmorProfile=edge400-witness", "confined sealed native"),
        ("User=edge400-observer\nGroup=edge400-observer", "cannot elevate"),
    ]:
        bad = g.UNITS / (g.UNIT + ".d") / "15-lab-unsupported.conf"
        g.write(bad, "[Service]\n" + setting + "\n")
        g.systemctl("daemon-reload")
        try:
            g.Switch(g.BUNDLE).plan()
        except OSError as exc:
            assert reason in str(exc), str(exc)
        else:
            raise AssertionError("unsupported unit admitted")
        if setting.startswith("User="):
            g.failed_start("nonroot-unit-not-elevated-by-managed-profile")
        bad.unlink()
        g.systemctl("daemon-reload")
    g.record("unsupported-native-aa-and-account-profiles-refused")
    policy = Path("/etc/apparmor.d/edge400-lab").read_bytes()
    temporary = g.BASE / "capture-complain.profile"
    temporary.write_bytes(
        policy.replace(
            b"profile edge400-capture /opt/edge400-runtime/bin/edge-capture {",
            b"profile edge400-capture /opt/edge400-runtime/bin/edge-capture flags=(complain) {",
        )
    )
    g.command("apparmor_parser", "-r", str(temporary))
    g.failed_start("complain-profile-refuses-connected-start")
    g.command("apparmor_parser", "-r", "/etc/apparmor.d/edge400-lab")
    temporary.write_bytes(policy.split(b"profile edge400-witness")[0])
    g.command("apparmor_parser", "-R", str(temporary))
    g.failed_start("missing-capture-profile-refuses-connected-start")
    g.command("apparmor_parser", "-r", "/etc/apparmor.d/edge400-lab")
    temporary.write_bytes(
        policy.replace(
            b"/opt/edge400-runtime/bin/edge-capture {",
            b"/opt/edge400-runtime/bin/nonexistent-capture {",
        )
    )
    g.command("apparmor_parser", "-r", str(temporary))
    g.failed_start("wrong-attachment-refuses-connected-start")
    g.command("apparmor_parser", "-r", "/etc/apparmor.d/edge400-lab")
    assert g.source() == before
    # Kernel ignores AppArmorProfile on unavailable LSM; registered gate must
    # still verify the kernel label independently (unit has no '-' prefix).
    g.systemctl("start", g.UNIT)
    g.live()
    g.record("registered-confinement-restarts-only-after-enforcement-restored")


def native_checks():
    import fcntl
    import os

    pid = g.live()
    fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
    try:
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15
        assert os.fstat(fd).st_nlink == 0
        for operation in [
            lambda: os.ftruncate(fd, 0),
            lambda: fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0),
        ]:
            try:
                operation()
            except OSError:
                pass
            else:
                raise AssertionError("running native image lost seals")
    finally:
        os.close(fd)
    assert "memfd:edge-live-origin" in os.readlink(f"/proc/{pid}/exe")
    g.record(
        "native-sealed-memfd-enforced", profile="edge400-native (enforce)", seals=15
    )
    # Same policy, same effective UID, independent operations. This probe does
    # not establish provider effects; actual Rust label/seals are checked above.
    result = g.command(
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "CapabilityBoundingSet=" + ROLE_CAPS["capture"],
        "-p",
        "RestrictAddressFamilies=AF_UNIX",
        str(g.PYTHON),
        "-I",
        str(g.SRC / "tests/real_systemd/native_probe.py"),
    )
    g.record("native-policy-independent-denials", **json.loads(result.stdout))
    g.systemctl("stop", g.UNIT)
    before = g.source()
    registered = g.verify(g.BUNDLE)[1]
    g.Systemd().native(registered)  # successful proof before the injected race
    policy = Path("/etc/apparmor.d/edge400-lab").read_bytes()
    native = (
        b"#include <tunables/global>\n"
        + policy[policy.index(b"profile edge400-native {") :]
    )
    temporary = g.BASE / "native-fault.profile"
    temporary.write_bytes(
        native.replace(
            b"profile edge400-native {", b"profile edge400-native flags=(complain) {"
        )
    )
    g.command("apparmor_parser", "-r", str(temporary))
    g.failed_start("native-complain-refuses-before-session-prepare")
    g.command("apparmor_parser", "-r", "/etc/apparmor.d/edge400-lab")
    temporary.write_bytes(native)
    g.command("apparmor_parser", "-R", str(temporary))
    g.failed_start("native-missing-refuses-before-session-prepare")
    # Race after a successful sealed preflight: repeat the actual native launch
    # with an inherited private channel. No frame/config/state/session start.
    import socket
    from azazel_edge.outcome.input_live import sealed_image, native_arguments

    image = sealed_image(registered)
    receive, send = socket.socketpair()
    try:
        result = __import__("subprocess").run(
            [
                f"/proc/self/fd/{image}",
                "--live-origin-fd",
                str(send.fileno()),
                "--live-origin-session",
                "a" * 32,
                *native_arguments(registered),
            ],
            pass_fds=(image, send.fileno()),
            capture_output=True,
            timeout=5,
            env=registered["environment"],
        )
        assert result.returncode == 3 and not result.stdout
        send.close()
        receive.settimeout(1)
        assert receive.recv(1) == b"" and g.source() == before
    finally:
        os.close(image)
        send.close()
        receive.close()
    g.record("native-profile-lost-after-preflight-no-native-start")
    g.command("apparmor_parser", "-r", "/etc/apparmor.d/edge400-lab")
    assert g.source() == before
    g.systemctl("start", g.UNIT)
    g.live()
    g.record("native-verified-enforcement-restored-no-backfill")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=["prepare", "exercise", "boot-check", "bad-boot-check", "smoke-finish"],
    )
    parser.add_argument("--allow-disposable-vm", action="store_true", required=True)
    parser.add_argument("--native-core", action="store_true")
    args = parser.parse_args()
    global NATIVE
    NATIVE = args.native_core
    g.guard()
    configure()
    if args.phase == "prepare":
        assert (
            not g.BASE.exists()
            and not (g.UNITS / g.UNIT).exists()
            and not (g.UNITS / (g.UNIT + ".d")).exists()
        )
        prepare_accounts()
        install_policy()
        g.prepare_lab()
        g.write(g.BASE / "aa-denied", "public synthetic canary\n")
        g.write(g.BASE / "namespace-canary", "read-only namespace test\n", 0o666)
        (g.BASE / "namespace-canary").chmod(0o666)
        g.record(
            "role-policy-installed",
            policy_sha256=hashlib.sha256(
                Path("/etc/apparmor.d/edge400-lab").read_bytes()
            ).hexdigest(),
            root_native_apparmor=NATIVE,
        )
    elif args.phase == "exercise":
        g.exercise()
        identities_and_denials()
        if NATIVE:
            native_checks()
    else:
        {
            "boot-check": g.boot_check,
            "bad-boot-check": g.bad_boot_check,
            "smoke-finish": g.smoke_finish,
        }[args.phase]()


if __name__ == "__main__":
    main()
