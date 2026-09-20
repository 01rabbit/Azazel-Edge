"""A pin is a claim. What got installed is a separate fact (Azazel-Edge#423).

Written from a measurement, not a hypothesis. While preparing the move to
`v0.9.0rc4` the tag was cut at the wrong commit twice, and on the second
attempt this repository's CI installed it and reported success:

    Running command git checkout -q ca05d5ab2b8e3f7c959c3966d7c04b1d9412a327
    Created wheel for azazel-fabric: filename=azazel_fabric-0.9.0rc4.dev0-...
    Successfully installed ... azazel-fabric-0.9.0rc4.dev0 ...
    866 passed, 4 skipped

The tag pointed at the merge of the change itself rather than at the release
commit, so the *code* was right and every behavioural test passed. What was
wrong was the release: version `0.9.0rc4.dev0`, no digest manifest, no
signature. A development build was installed under a release tag and nothing
here could see it.

`requirements/fabric.txt` states the policy -- "an exact tagged release, never
a branch and never a development commit, for field deployment" -- and
`test_defensive_state_vocabulary.py` checks that the *file* says so. Neither
asks what arrived. This does.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ROOT / "requirements" / "fabric.txt"


def pinned_tag() -> str:
    """The single tag `requirements/fabric.txt` names."""

    pins = [
        line.strip()
        for line in PIN_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(pins) == 1, f"expected exactly one requirement in {PIN_FILE.name}: {pins}"
    return pins[0].rsplit("@", 1)[-1]


def installed_version() -> str:
    try:
        return version("azazel-fabric")
    except PackageNotFoundError:  # pragma: no cover - covered by the skip below
        pytest.skip("azazel-fabric is not installed; the Fabric extra is optional")


def test_the_installed_fabric_is_the_tag_this_repository_pinned():
    """The check that would have caught it, and the reason it is a comparison.

    `0.9.0rc4.dev0` starts with `0.9.0rc4`, so anything written as "does the
    installed version look like the pin" passes on exactly the build this test
    exists to refuse. It is an equality, and the `.dev0` is the difference.

    Skips when Fabric is absent, which is right for a contributor without the
    optional extra. CI installs it on every run, so the gate is where it needs
    to be.
    """

    tag = pinned_tag()
    installed = installed_version()
    expected = tag.lstrip("v")

    assert installed == expected, (
        f"requirements/fabric.txt pins {tag} but {installed!r} is installed. "
        "If these differ only by a suffix such as `.dev0`, the tag was cut "
        "from a tree whose version had not been bumped -- a development build "
        "wearing a release tag. The code may be identical and every "
        "behavioural test may pass; what is wrong is the release."
    )


def test_a_development_build_is_refused_however_close_the_version_looks():
    """The rule stated on its own, so the equality above cannot be loosened.

    A future maintainer reaching for `startswith` or a prefix match to make a
    local build pass would satisfy the test above and reintroduce exactly the
    condition it was written for. This says the thing directly: a version
    carrying a development or local suffix is not a released one.
    """

    installed = installed_version()

    assert not re.search(r"\.dev\d+|\+", installed), (
        f"the installed azazel-fabric {installed!r} is a development or local "
        "build. requirements/fabric.txt requires an exact tagged release for "
        "field deployment; a development build satisfies no release guarantee "
        "and carries no signed digest manifest"
    )


def test_the_pin_names_a_tag_rather_than_a_revision_or_branch():
    """`main` is not a pin, and neither is a commit nobody published.

    Kept here beside the two above because all three are about the same
    sentence in `requirements/fabric.txt`, and a reader who changes that
    sentence should find every check on it in one place.
    """

    tag = pinned_tag()

    assert re.fullmatch(r"v\d+\.\d+\.\d+(?:rc\d+|a\d+|b\d+)?", tag), (
        f"the Fabric pin {tag!r} is not an exact release tag. A branch moves "
        "under the pin, and a raw commit names something no release process "
        "produced -- neither can be checked against a signed manifest"
    )
