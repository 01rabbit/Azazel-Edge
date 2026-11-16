"""Closed public evidence COPIES; never widen original fixture permissions."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat

ARMS = (
    "original_off",
    "instrumented_off",
    "original_on",
    "instrumented_on",
    "original_faulted",
    "instrumented_faulted",
)
CASES = (
    "pre_deadline_not_committed",
    "expiry_commit",
    "stop_pending_loss",
    "duplicate_does_not_reopen",
    "commit_failure_loss",
    "witness_close_failure",
    "recording_failure_prefix",
)
SYNTHETIC = dict(
    event="event.json",
    policy="policy.json",
    observations="observations.json",
    journal="journal/observations.journal",
    phase="phase.jsonl",
)
MAX_LEAF = 16 * 1024 * 1024
MAX_SYNTHETIC = 4 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inventory():
    """Fixed99 evidence leaves, independent of directory contents/descriptors."""
    result = [
        ("window-cost-completion.json", None),
        ("original-normal-clock/report.json", None),
        ("synthetic-window-cases/manifest.json", None),
    ]
    for arm in ARMS:
        slots = [
            ("raw_artifacts", name)
            for name in ("eve", "source", "audit", "audit_pre_stop", "trust")
        ]
        slots.append(("control_artifacts", "request"))
        if arm.startswith("instrumented_"):
            slots.extend(
                ("phase_artifacts", role)
                for role in ("controller", "signer", "witness")
            )
        if not arm.endswith("_off"):
            slots.extend(("control_artifacts", name) for name in ("journal", "anchors"))
            if arm.startswith("instrumented_"):
                slots.append(("phase_artifacts", "observer"))
                slots.extend(("clock_artifacts", name) for name in ("calls", "context"))
        if arm.endswith("_on"):
            slots.append(("control_artifacts", "completion"))
        result.extend(
            (
                "original-normal-clock/" + arm + "-" + group + "-" + name + ".raw",
                (arm, group, name),
            )
            for group, name in slots
        )
    result.extend(
        ("synthetic-window-cases/" + case + "/" + filename, (case, slot))
        for case in CASES
        for slot, filename in SYNTHETIC.items()
    )
    assert len(result) == 99 and len({path for path, _ in result}) == 99
    return tuple(result)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _version(info):
    return (
        _directory_identity(info),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def _parents(root, components, *, create=False):
    opened = []
    current = root
    try:
        for component in components:
            if component in ("", ".", "..") or "/" in component:
                raise ValueError("invalid path component")
            created = False
            if create:
                try:
                    os.mkdir(component, mode=0o755, dir_fd=current)
                    created = True
                except FileExistsError:
                    pass
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            child = os.open(component, DIRECTORY, dir_fd=current)
            opened.append((current, component, child))
            if created:
                os.fchmod(child, 0o755)
                before = os.stat(component, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or _directory_identity(
                before
            ) != _directory_identity(os.fstat(child)):
                raise ValueError("directory identity changed")
            current = child
        yield current
        for parent, name, child in opened:
            if _directory_identity(
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            ) != _directory_identity(os.fstat(child)):
                raise ValueError("directory identity changed")
    finally:
        for _, _, child in reversed(opened):
            os.close(child)


def _read(root, relative, maximum):
    parts = Path(relative).parts
    with _parents(root, parts[:-1]) as parent:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ValueError("not a single regular leaf")
            if _version(before) != _version(opened):
                raise ValueError("source identity changed")
            if not 0 <= opened.st_size <= maximum:
                raise ValueError("source exceeds leaf bound")
            chunks, remaining = [], maximum + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) != opened.st_size or _version(os.fstat(fd)) != _version(opened):
                raise ValueError("source changed during read")
            if _version(
                os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            ) != _version(opened):
                raise ValueError("source name changed during read")
        finally:
            os.close(fd)
    return raw


def _write(root, relative, raw):
    parts = Path(relative).parts
    with _parents(root, parts[:-1], create=True) as parent:
        fd = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o444,
            dir_fd=parent,
        )
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("publication write incomplete")
                view = view[count:]
            os.fchmod(fd, 0o444)
            os.fsync(fd)
            info = os.fstat(fd)
            if info.st_size != len(raw) or _version(
                os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            ) != _version(info):
                raise ValueError("publication leaf changed")
        finally:
            os.close(fd)


def _parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    if type(value) is not dict:
        raise ValueError("report or manifest is not an object")
    wire(value)  # Reject nonfinite numbers without rewriting the source bytes.
    return value


def _error(exc):
    return type(exc).__name__ + (":" + str(exc) if isinstance(exc, ValueError) else "")


def _copy_all(source, target):
    planned = inventory()
    cached, documents, document_errors = {}, {}, {}
    for relative, _ in planned[:3]:
        try:
            raw = _read(
                source,
                relative,
                MAX_SYNTHETIC if relative.startswith("synthetic-") else MAX_LEAF,
            )
            documents[relative] = _parse(raw)
            cached[relative] = raw
        except Exception as exc:
            document_errors[relative] = _error(exc)
    primary = documents.get("window-cost-completion.json", {})
    normal = documents.get("original-normal-clock/report.json", {})
    embedded = primary.get("original_normal_clock_evaluation")
    if (
        not primary
        or type(embedded) is not dict
        or not embedded
        or type(embedded.get("original_load_evaluation")) is not dict
        or not embedded["original_load_evaluation"]
    ):
        document_errors["window-cost-completion.json"] = (
            "ValueError:required embedded original evaluation unavailable"
        )
    if (
        not normal
        or type(normal.get("original_load_evaluation")) is not dict
        or not normal["original_load_evaluation"]
    ):
        document_errors["original-normal-clock/report.json"] = (
            "ValueError:required original report structure unavailable"
        )
    if wire(embedded) != wire(normal):
        document_errors["original-normal-clock/report.json"] = (
            "ValueError:normal report differs from original evaluation"
        )
    originals = embedded if type(embedded) is dict and embedded else normal
    try:
        arms = {
            arm["arm_id"]: arm
            for arm in originals.get("original_load_evaluation", {}).get(
                "original_arm_inputs", []
            )
        }
        controls = originals.get("control_evidence", {})
    except (AttributeError, KeyError, TypeError):
        arms, controls = {}, {}
    manifest = documents.get("synthetic-window-cases/manifest.json", {})
    try:
        cases = {case["id"]: case for case in manifest.get("cases", [])}
    except (KeyError, TypeError):
        cases = {}
    entries, errors, total = [], [], 0
    for relative, selector in planned:
        entry = dict(
            path=relative,
            expected_sha256=None,
            expected_bytes=None,
            sha256=None,
            bytes=None,
            error=None,
        )
        try:
            if relative in document_errors:
                raise ValueError(document_errors[relative])
            maximum = (
                MAX_SYNTHETIC
                if relative.startswith("synthetic-window-cases/")
                else MAX_LEAF
            )
            if selector is None:
                raw = cached[relative]
                expected = dict(sha256=sha(raw), bytes=len(raw))
            else:
                if len(selector) == 3:
                    arm_id, group, name = selector
                    arm = arms.get(arm_id, {})
                    descriptors = (
                        arm.get("normal_stop", controls.get(arm_id, {})).get(
                            "artifacts", {}
                        )
                        if group == "control_artifacts"
                        else arm.get(group, {})
                    )
                    expected = descriptors.get(name)
                else:
                    case_id, name = selector
                    expected = cases.get(case_id, {}).get("artifacts", {}).get(name)
                if (
                    type(expected) is not dict
                    or type(expected.get("bytes")) is not int
                    or type(expected.get("sha256")) is not str
                ):
                    raise ValueError("expected descriptor unavailable")
                entry.update(
                    expected_sha256=expected["sha256"], expected_bytes=expected["bytes"]
                )
                if not 0 <= expected["bytes"] <= maximum:
                    raise ValueError("expected descriptor exceeds leaf bound")
                raw = _read(source, relative, maximum)
                if len(raw) != expected["bytes"] or sha(raw) != expected["sha256"]:
                    raise ValueError("source differs from pinned descriptor")
            entry.update(
                expected_sha256=expected["sha256"], expected_bytes=expected["bytes"]
            )
            if total + len(raw) > MAX_TOTAL:
                raise ValueError("publication exceeds total bound")
            _write(target, relative, raw)
            total += len(raw)
            entry.update(sha256=sha(raw), bytes=len(raw))
        except Exception as exc:
            entry["error"] = _error(exc)
            errors.append(relative + ":" + entry["error"])
        entries.append(entry)
    result = dict(
        schema_version="edge-window-cost-publication/v1",
        status="incomplete" if errors else "complete",
        planned_files=len(planned),
        copied_files=sum(entry["error"] is None for entry in entries),
        copied_bytes=total,
        entries=entries,
        errors=errors,
    )
    _write(target, "publication-index.json", wire(result))
    return result


def publish_publication(output_dir):
    """Create a fresh99-leaf public copy and independent partial/complete index."""
    path = Path(output_dir)
    if ".." in path.parts:
        raise ValueError("parent traversal forbidden")
    absolute = Path(os.path.abspath(path))
    root = os.open("/", DIRECTORY)
    try:
        with _parents(root, absolute.parts[1:]) as source:
            # No overwrite/resume: a prior publication is an immutable separate attempt.
            os.mkdir("publication", mode=0o755, dir_fd=source)
            with _parents(source, ("publication",)) as target:
                os.fchmod(target, 0o755)
                return _copy_all(source, target)
    finally:
        os.close(root)
