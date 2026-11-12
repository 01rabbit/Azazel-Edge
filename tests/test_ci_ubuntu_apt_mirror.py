"""Pure CI-only mirror recovery checks; never read/write the host APT files."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "ci_apt_mirror", Path(__file__).parents[1] / ".github/scripts/ubuntu_apt_mirror.py"
)
mirror = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror)
ENV = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux")
RELEASE = dict(ID="ubuntu", VERSION_ID="24.04", VERSION_CODENAME="noble")


def test_verified_runner_mirror_list_rewrites_only_known_ubuntu_uris():
    original = (
        "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
        "https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
        "https://security.ubuntu.com/ubuntu/\tpriority:3\n"
        "https://unknown.example/ubuntu/\tpriority:4\n"
    )
    expected = original.replace("http://azure.archive.ubuntu.com/ubuntu/", mirror.TARGET + "/").replace(
        "https://archive.ubuntu.com/ubuntu/", mirror.TARGET + "/"
    ).replace(
        "https://security.ubuntu.com/ubuntu/", mirror.TARGET + "/"
    )
    assert mirror.normalize(original, "apt-mirrors.txt") == expected
    assert mirror.normalize(expected, "apt-mirrors.txt") == expected


def test_deb822_preserves_suites_architectures_signedby_and_unknown_repositories():
    original = (
        "Types: deb deb-src\nURIs: http://azure.archive.ubuntu.com/ubuntu\n"
        " https://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports noble-security\n"
        "Components: main restricted universe multiverse\nArchitectures: amd64\n"
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nCheck-Valid-Until: yes\n"
        "Description: https://archive.ubuntu.com/ubuntu\n\n"
        "Types: deb\nURIs: https://packages.microsoft.com/ubuntu/24.04/prod\nSuites: noble\n"
        "Signed-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n Comment: https://archive.ubuntu.com/ubuntu\n -----END PGP PUBLIC KEY BLOCK-----\n"
    )
    expected = original.replace(
        "URIs: http://azure.archive.ubuntu.com/ubuntu", "URIs: " + mirror.TARGET
    ).replace(" https://archive.ubuntu.com/ubuntu/\nSuites:", " " + mirror.TARGET + "/\nSuites:")
    assert mirror.normalize(original, "ubuntu.sources") == expected
    assert mirror.normalize(expected, "ubuntu.sources") == expected


def test_classic_direct_azure_sources_preserve_options_and_suite_fields():
    original = (
        "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://azure.archive.ubuntu.com/ubuntu noble main restricted\n"
        "deb-src https://archive.ubuntu.com/ubuntu/ noble-updates universe\n"
        "# deb http://azure.archive.ubuntu.com/ubuntu noble main\n"
        "deb https://example.org/ubuntu noble main\n"
    )
    expected = original.replace(
        "] http://azure.archive.ubuntu.com/ubuntu ", "] " + mirror.TARGET + " "
    ).replace("deb-src https://archive.ubuntu.com/ubuntu/ ", "deb-src " + mirror.TARGET + "/ ")
    assert mirror.normalize(original, "sources.list") == expected


@pytest.mark.parametrize("filename,prefix", [("sources.list", "deb "), ("apt-mirrors.txt", "")])
def test_inline_comments_remain_byte_identical(filename, prefix):
    original = prefix + "http://azure.archive.ubuntu.com/ubuntu # https://archive.ubuntu.com/ubuntu\r\n"
    expected = prefix + mirror.TARGET + " # https://archive.ubuntu.com/ubuntu\r\n"
    assert mirror.normalize(original, filename) == expected


@pytest.mark.parametrize(
    "uri",
    [
        "https://archive.ubuntu.com.attacker/ubuntu",
        "https://attacker@archive.ubuntu.com/ubuntu",
        "https://archive.ubuntu.com:8443/ubuntu",
        "http://azure.archive.ubuntu.com/ubuntu-extra",
        "https://archive.ubuntu.com/ubuntu?extra",
        "https://archive.ubuntu.com/ubuntu#fragment",
        "https://ports.ubuntu.com/ubuntu-ports",
    ],
)
def test_wrong_hosts_or_nonexact_repository_paths_are_not_rewritten(uri):
    assert mirror.normalize(uri + "\n", "apt-mirrors.txt") == uri + "\n"


@pytest.mark.parametrize(
    "fault",
    [
        "production",
        "self-hosted",
        "not-actions",
        "runner-os",
        "darwin",
        "uid",
        "version",
        "codename",
        "distro",
    ],
)
def test_wrong_host_or_production_context_refuses(fault):
    env, release, uid, system = dict(ENV), dict(RELEASE), 0, "linux"
    if fault == "production":
        env = {}
    elif fault == "self-hosted":
        env["RUNNER_ENVIRONMENT"] = "self-hosted"
    elif fault == "not-actions":
        env["GITHUB_ACTIONS"] = "false"
    elif fault == "runner-os":
        env["RUNNER_OS"] = "macOS"
    elif fault == "darwin":
        system = "darwin"
    elif fault == "uid":
        uid = 1001
    elif fault == "version":
        release["VERSION_ID"] = "26.04"
    elif fault == "codename":
        release["VERSION_CODENAME"] = "resolute"
    else:
        release["ID"] = "debian"
    with pytest.raises(RuntimeError):
        mirror.check_context(uid, env, release, system)


def test_supported_context_and_fixed_known_files_only():
    mirror.check_context(0, ENV, RELEASE, "linux")
    assert set(mirror.FILES) == {
        "/etc/apt/apt-mirrors.txt",
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d/ubuntu.sources",
    }


def test_production_main_refuses_before_opening_any_apt_file(monkeypatch):
    monkeypatch.setattr(
        mirror.Path, "read_text", lambda self: "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"
    )
    monkeypatch.setattr(mirror.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mirror.os, "environ", {})
    monkeypatch.setattr(mirror.sys, "platform", "linux")
    monkeypatch.setattr(mirror.os, "open", lambda *a, **k: pytest.fail("APT file opened outside guarded CI"))
    with pytest.raises(RuntimeError):
        mirror.main()


def test_bootstrap_is_isolated_and_precedes_only_two_affected_jobs():
    import re

    workflow = (Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text()
    command = "sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT,RUNNER_OS /usr/bin/python3 -I .github/scripts/ubuntu_apt_mirror.py"
    assert workflow.count(command) == 2
    for job in ("outcome-systemd", "service-objectives"):
        block = re.search(r"(?ms)^  " + job + r":\n(.*?)(?=^  [\w-]+:|\Z)", workflow).group(1)
        assert block.index(command) < block.index("sudo apt-get update")

@pytest.mark.parametrize('scheme', ['http', 'https'])
@pytest.mark.parametrize('filename,prefix', [
    ('apt-mirrors.txt', ''), ('sources.list', 'deb '),
    ('ubuntu.sources', 'URIs: '),
])
def test_exact_previous_kernel_mirror_recovers_and_is_idempotent(scheme, filename, prefix):
    assert mirror.TARGET == 'https://archive.ubuntu.com/ubuntu'
    suffix = '\tpriority:1\n' if filename == 'apt-mirrors.txt' else ' noble main\n' if filename == 'sources.list' else '\n'
    old = prefix + scheme + '://mirrors.edge.kernel.org/ubuntu/' + suffix
    expected = prefix + 'https://archive.ubuntu.com/ubuntu/' + suffix
    assert mirror.normalize(old, filename) == expected
    assert mirror.normalize(expected, filename) == expected


@pytest.mark.parametrize('uri', [
    'https://mirrors.edge.kernel.org.attacker/ubuntu',
    'https://attacker@mirrors.edge.kernel.org/ubuntu',
    'https://mirrors.edge.kernel.org:443/ubuntu',
    'https://mirrors.edge.kernel.org/ubuntu-extra',
    'https://mirrors.edge.kernel.org/ubuntu?extra',
    'https://mirrors.edge.kernel.org/ubuntu#fragment',
])
def test_previous_mirror_lookalikes_are_unmodified_in_all_active_formats(uri):
    for filename, original in (
        ('apt-mirrors.txt', uri + '\n'),
        ('sources.list', 'deb ' + uri + ' noble main\n'),
        ('ubuntu.sources', 'Types: deb\nURIs: ' + uri + '\nSuites: noble\n'),
    ):
        assert mirror.normalize(original, filename) == original


def test_recovery_changes_only_active_uri_and_preserves_all_trust_configuration():
    original = (
        '# previous https://mirrors.edge.kernel.org/ubuntu\r\n'
        'Types: deb deb-src\r\nURIs: https://mirrors.edge.kernel.org/ubuntu\r\n'
        'Suites: noble noble-updates noble-backports noble-security\r\n'
        'Components: main restricted universe multiverse\r\n'
        'Architectures: amd64 arm64\r\n'
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\r\n'
        'Trusted: no\r\nAllow-Insecure: no\r\nAllow-Weak: no\r\n'
        'Allow-Downgrade-To-Insecure: no\r\nCheck-Valid-Until: yes\r\n'
        'Check-Date: yes\r\nValid-Until-Max: 604800\r\n'
        '# TLS peer/host verification remains enabled\r\n'
        'Description: https://mirrors.edge.kernel.org/ubuntu\r\n'
        '\r\nTypes: deb\r\nURIs: https://unknown.example/ubuntu\r\n'
        'Suites: noble\r\nSigned-By:\r\n -----BEGIN PGP PUBLIC KEY BLOCK-----\r\n'
        ' Comment: https://mirrors.edge.kernel.org/ubuntu\r\n'
        ' -----END PGP PUBLIC KEY BLOCK-----\r\n'
    )
    expected = original.replace(
        'URIs: https://mirrors.edge.kernel.org/ubuntu\r\n',
        'URIs: https://archive.ubuntu.com/ubuntu\r\n',
    )
    assert mirror.normalize(original, 'ubuntu.sources') == expected
    assert mirror.normalize(expected, 'ubuntu.sources') == expected
