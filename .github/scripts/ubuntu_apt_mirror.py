"""Hosted Ubuntu 24.04 CI transport recovery; no APT trust setting changes."""

import os
from pathlib import Path
import re
import stat
import sys

FILES = ("/etc/apt/apt-mirrors.txt", "/etc/apt/sources.list", "/etc/apt/sources.list.d/ubuntu.sources")
TARGET = "https://security.ubuntu.com/ubuntu"
URI = re.compile(r"(?<!\S)https?://(?:azure\.archive|archive|security)\.ubuntu\.com/ubuntu(/?)(?=\s|$)")


def check_context(uid, environment, release, system):
    flags = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
    ubuntu = {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"}
    if (uid != 0 or system != "linux" or any(environment.get(k) != v for k, v in flags.items())
            or any(release.get(k) != v for k, v in ubuntu.items())):
        raise RuntimeError("mirror recovery requires root in hosted Ubuntu 24.04 CI")


def normalize(text, filename):
    result, uris = [], False
    for line in text.splitlines(keepends=True):
        if filename.endswith(".sources") and not line[:1].isspace():
            uris = line.startswith("URIs:")
        active = not line.lstrip().startswith("#") and (
            filename == "apt-mirrors.txt"
            or uris
            or filename.endswith(".list")
            and line.lstrip().startswith(("deb ", "deb\t", "deb-src ", "deb-src\t"))
        )
        comment = re.search(r"(?<!\S)#", line)
        cut = comment.start() if comment else len(line)
        prefix = URI.sub(lambda match: TARGET + match[1], line[:cut]) if active else line[:cut]
        result.append(prefix + line[cut:])
    return "".join(result)


def main():
    release = dict(
        line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line
    )
    check_context(os.geteuid(), os.environ, {k: v.strip('"') for k, v in release.items()}, sys.platform)
    changed = 0
    for name in FILES:
        try:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, "r+", encoding="utf-8", newline="") as stream:
            info = os.fstat(stream.fileno())
            unsafe = not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            if unsafe or info.st_mode & 0o022 or info.st_nlink != 1:
                raise RuntimeError("unsafe known CI APT source file")
            original = stream.read(262145)
            if len(original) > 262144:
                raise RuntimeError("oversized known CI APT source file")
            updated = normalize(original, Path(name).name)
            if updated != original:
                stream.seek(0)
                stream.write(updated)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
                changed += 1
    print(f"CI Ubuntu mirror files normalized: {changed}")


if __name__ == "__main__":
    main()
