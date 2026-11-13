"""Fresh SO11 post-exit snapshots; no tolerant parsing, invented rows or coverage."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

PROFILE = "so11-post-exit-ingress/v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 65536
MAX_LINE = 65536
AUDIT = "ingress-audit.jsonl"


def _int(value):
    return type(value) is int and value >= 0


def _same(actual, original):
    """Typed comparison bounded by an already parsed original, no serialization."""
    if type(actual) is not type(original):
        return False
    if type(original) is dict:
        if len(actual) != len(original):
            return False
        return all(
            key in actual and _same(actual[key], value)
            for key, value in original.items()
        )
    if type(original) is list:
        if len(actual) != len(original):
            return False
        return all(_same(actual[index], value) for index, value in enumerate(original))
    if type(original) is float:
        return (
            math.isfinite(actual)
            and math.isfinite(original)
            and actual.hex() == original.hex()
        )
    if type(original) is str:
        return len(actual) == len(original) and actual == original
    if type(original) in (int, bool, type(None)):
        return actual == original
    return False


def _hex(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _tree(value, depth=0):
    if depth > 16:
        raise ValueError("audit depth bound")
    if isinstance(value, (dict, list)):
        if len(value) > 256:
            raise ValueError("audit collection bound")
        for item in value.values() if isinstance(value, dict) else value:
            _tree(item, depth + 1)
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("nonfinite audit")


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate audit field")
        out[key] = value
    return out


def _row_kind(row):
    if type(row) is not dict:
        raise ValueError("unknown audit row")
    kinds = set(row) & {"ingress_shed", "ingress_alert_backlog"}
    if (
        len(kinds) != 1
        or set(row) != kinds | {"source", "pipeline"}
        or row["source"] != "core_ingress"
        or row["pipeline"] != "rust_ingress_v1"
    ):
        raise ValueError("unknown audit row profile")
    kind = next(iter(kinds))
    body = row[kind]
    schema = (
        "azazel-edge/ingress-shed/v1"
        if kind == "ingress_shed"
        else "azazel-edge/ingress-alert-backlog/v1"
    )
    if type(body) is not dict or body.get("schema") != schema:
        raise ValueError("unknown audit summary schema")
    common = {"schema", "emitted_epoch", "interval_end", "quota"}
    counts = (
        "polls shed_total alerts_shed admitted alerts_admitted examined max_backlog_bytes max_shed_level oversized_lines_skipped oversized_possible_alerts truncation_resets file_replacements unread_bytes_lost cumulative_shed_total cumulative_oversized_lines_skipped cumulative_resets".split()
        if kind == "ingress_shed"
        else "polls_over_bound max_backlog_bytes alert_backlog_bound_bytes alerts_admitted alerts_shed cumulative_polls_over_bound".split()
    )
    extra = (
        {"shed_by_type", "shed_by_reason", "cumulative_shed_by_type"}
        if kind == "ingress_shed"
        else {"policy"}
    )
    if set(body) != common | set(counts) | extra or body["interval_end"] not in (
        "audit_interval",
        "shutdown",
    ):
        raise ValueError("malformed audit summary fields/interval")
    for name in counts:
        if not _int(body[name]) or body[name] >= 2**64:
            raise ValueError("invalid audit summary count")
    epoch = body["emitted_epoch"]
    if type(epoch) not in (int, float) or not math.isfinite(epoch):
        raise ValueError("invalid audit emitted time")
    quota = body["quota"]
    if (
        type(quota) is not dict
        or set(quota)
        != set(
            "non_alert_per_sec non_alert_burst alerts_per_poll examine_per_poll poll_work_limit_ms max_line_bytes backlog_bound_bytes alert_backlog_bound_bytes".split()
        )
        or not all(_int(v) and 0 < v < 2**64 for v in quota.values())
    ):
        raise ValueError("malformed audit quota")
    if kind == "ingress_shed":
        for name in extra:
            keys = (
                {"non_alert_rate", "backlog"}
                if name == "shed_by_reason"
                else {"flow", "dns", "stats", "other", "unparseable"}
            )
            values = body[name]
            if (
                type(values) is not dict
                or set(values) != keys
                or not all(_int(v) and v < 2**64 for v in values.values())
            ):
                raise ValueError("malformed audit count map")
    elif (
        body["policy"]
        != "alerts are never shed or rate-limited; the backlog stays in the EVE file and is read at the Core's capacity"
    ):
        raise ValueError("unknown alert backlog policy")
    return kind


def _rows(raw, rows=None):
    if (
        len(raw) > MAX_BYTES
        or (raw and not raw.endswith(b"\n"))
        or b"\r" in raw
        or raw.count(b"\n") > MAX_ROWS
    ):
        raise ValueError("audit byte/record/framing bound")
    rows = [] if rows is None else rows
    for line in raw.split(b"\n")[:-1]:
        if not line or len(line) > MAX_LINE:
            raise ValueError("audit line bound")
        row = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("nonfinite audit")
            ),
        )
        _tree(row)
        _row_kind(row)
        rows.append(row)
    return rows


def _metadata(info):
    return tuple(
        getattr(info, k)
        for k in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


@dataclass
class Snapshot:
    metadata: dict
    raw: bytes | None


def snapshot(work, *, allow_absent=False):
    start = time.monotonic_ns()
    meta = dict(
        disposition="unavailable",
        records=None,
        records_read=None,
        raw_sha256=None,
        raw_bytes=None,
        raw_utf8=None,
        file_identity=None,
        read_started_ns=start,
        read_ended_ns=None,
        rotated=False,
        error=None,
    )
    raw = None
    fd = None
    try:
        path = Path(work) / AUDIT
        try:
            (Path(work) / (AUDIT + ".1")).lstat()
        except FileNotFoundError:
            pass
        else:
            meta["rotated"] = True
            raise ValueError("ingress audit rotated")
        try:
            before = path.lstat()
        except FileNotFoundError:
            if not allow_absent:
                raise
            meta["disposition"] = "observed_absent"
            return Snapshot(meta, None)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_mode & 0o022
            or not 0 <= opened.st_size <= MAX_BYTES
            or _metadata(before) != _metadata(opened)
        ):
            raise ValueError("unsafe or changed ingress audit")
        data = bytearray()
        while len(data) <= opened.st_size:
            chunk = os.read(fd, min(65536, opened.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        raw = bytes(data)
        if (
            len(raw) != opened.st_size
            or _metadata(opened) != _metadata(os.fstat(fd))
            or _metadata(opened) != _metadata(path.lstat())
        ):
            raise ValueError("unstable ingress audit")
        try:
            (Path(work) / (AUDIT + ".1")).lstat()
        except FileNotFoundError:
            pass
        else:
            meta["rotated"] = True
            raise ValueError("ingress audit rotated during snapshot")
        meta.update(
            records=[],
            records_read=0,
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=len(raw),
            file_identity=dict(device=opened.st_dev, inode=opened.st_ino),
        )
        meta["raw_utf8"] = raw.decode("utf-8")
        rows = _rows(raw, meta["records"])
        meta.update(
            disposition="read",
            records=rows,
            records_read=len(rows),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=len(raw),
            file_identity=dict(device=opened.st_dev, inode=opened.st_ino),
        )
    except Exception as exc:
        if isinstance(meta["records"], list):
            meta["records_read"] = len(meta["records"])
        meta["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as exc:
                meta["error"] = f"audit close: {exc}"
                meta["disposition"] = "unavailable"
        meta["read_ended_ns"] = time.monotonic_ns()
    return Snapshot(meta, raw)


def bounded_stop(proc):
    facts = dict(
        requested=False,
        forced=False,
        returncode=None,
        exit_confirmed=False,
        error=None,
        requested_ns=time.monotonic_ns(),
        exited_ns=None,
    )
    errors = []
    try:
        if proc.poll() is not None:
            raise ValueError("core exited before stop request")
        facts["requested"] = True
        proc.terminate()
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            facts["forced"] = True
            proc.kill()
            code = proc.wait(timeout=10)
        facts["returncode"] = code
        facts["exit_confirmed"] = proc.poll() == code and type(code) is int
        facts["exited_ns"] = time.monotonic_ns()
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        # Owned-process cleanup remains bounded even after a stop failure.
        try:
            if proc.poll() is None:
                facts["forced"] = True
                proc.kill()
            code = proc.wait(timeout=10)
            facts.update(
                returncode=code,
                exit_confirmed=type(code) is int and proc.poll() == code,
                exited_ns=time.monotonic_ns(),
            )
        except Exception as cleanup:
            errors.append(f"cleanup {type(cleanup).__name__}: {cleanup}")
    facts["error"] = "; ".join(errors) if errors else None
    return facts


def _stderr_diagnostic(work):
    """Private bounded owned-file diagnostic, never copied into quota_load."""
    raw = None
    diagnostic = dict(
        bytes=None,
        file_bytes=None,
        sha256=None,
        truncated=None,
        text_prefix=None,
        text_encoding="utf8_replace_diagnostic_only",
        error=None,
    )
    fd = None
    try:
        path = Path(work) / "core.stderr"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
        ):
            raise ValueError("unsafe owned Core stderr diagnostic")
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        raw = bytes(data)
        if _metadata(before) != _metadata(os.fstat(fd)) or _metadata(
            before
        ) != _metadata(path.lstat()):
            raise ValueError("unstable owned Core stderr diagnostic")
        diagnostic.update(
            bytes=len(raw),
            file_bytes=before.st_size,
            sha256=hashlib.sha256(raw).hexdigest(),
            truncated=len(raw) > 65536 or len(raw) != before.st_size,
            text_prefix=raw[:65536].decode("utf-8", errors="replace"),
        )
        if len(raw) > MAX_BYTES:
            diagnostic["error"] = "Core stderr diagnostic byte bound"
    except Exception as exc:
        diagnostic["error"] = type(exc).__name__
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                diagnostic["error"] = "Core stderr diagnostic close failed"
    return raw, diagnostic


class FinalAudit:
    """In-memory original pre-stop bytes never become a caller success flag."""

    def __init__(self, out):
        self.out = out
        self.pre = None
        self.writer_joined = False
        self.writer_joined_ns = None
        self.finished = False
        self.pre_attempted = False
        self.diagnostics = {}

    def before_stop(self, work, *, writer_joined, writer_joined_ns):
        if self.pre_attempted or self.finished:
            raise ValueError("pre-stop snapshot already attempted or finalized")
        self.pre_attempted = True
        self.writer_joined = writer_joined
        self.writer_joined_ns = writer_joined_ns
        self.pre = snapshot(work, allow_absent=True)
        self.out["ingress_audit_pre_stop"] = self.pre.metadata

    def finish(self, work, stop):
        # Retain the first successful OR failed attempt verbatim. Never repair,
        # erase known evidence, or reread on a repeated call.
        if self.finished:
            return
        self.finished = True
        stderr = None
        if stop.get("exit_confirmed") is True:
            stderr, diagnostic = _stderr_diagnostic(work)
            self.diagnostics["core_stderr"] = diagnostic
        else:
            self.diagnostics["core_stderr"] = dict(
                bytes=None,
                file_bytes=None,
                sha256=None,
                truncated=None,
                text_prefix=None,
                error="Core exit unconfirmed; diagnostic not read",
            )
        final = dict(
            profile=PROFILE,
            writer_joined=self.writer_joined,
            writer_joined_ns=self.writer_joined_ns,
            stop=dict(stop),
            read_started_ns=None,
            read_ended_ns=None,
            raw_sha256=None,
            raw_bytes=None,
            raw_utf8=None,
            file_identity=None,
            pre_stop_prefix_preserved=False,
            pre_stop_binding=None,
            error=None,
        )
        self.out["ingress_audit_finalization"] = final
        # Explicitly no pre-stop fallback in the fields consumed by SO11.
        self.out.update(
            ingress_audit=None,
            ingress_audit_records_read=None,
            ingress_audit_rotated=None,
        )
        after = None
        try:
            if (
                self.writer_joined is not True
                or self.out.get("writer_error", "missing") is not None
            ):
                raise ValueError("load writer not cleanly joined")
            if not (
                stop.get("requested") is True
                and stop.get("forced") is False
                and stop.get("exit_confirmed") is True
                and type(stop.get("returncode")) is int
                and stop["returncode"] == 0
                and stop.get("error") is None
            ):
                raise ValueError("core did not exit gracefully with status zero")
            if self.pre is None or self.pre.metadata["error"] is not None:
                raise ValueError("pre-stop snapshot unavailable")
            # The Rust writer reports append/fsync/rotation failures here even if
            # process exit itself is zero. Never replace a failed write by rows.
            if stderr is None or self.diagnostics["core_stderr"]["error"] is not None:
                raise ValueError("owned Core stderr diagnostic unavailable")
            if len(stderr) > MAX_BYTES or any(
                line.startswith(b"ingress audit write failed (")
                for line in stderr.split(b"\n")
            ):
                raise ValueError("ingress audit write failure or stderr bound")
            after = snapshot(work)
            final.update(
                {
                    k: after.metadata[k]
                    for k in (
                        "read_started_ns",
                        "read_ended_ns",
                        "raw_sha256",
                        "raw_bytes",
                        "raw_utf8",
                        "file_identity",
                        "error",
                    )
                }
            )
            self.out["ingress_audit_rotated"] = after.metadata["rotated"]
            if after.metadata["error"] is not None:
                raise ValueError("final audit read unavailable")
            if self.pre.metadata["disposition"] == "observed_absent":
                final["pre_stop_binding"] = "created_after_observed_absence"
            elif self.pre.metadata["file_identity"] == after.metadata[
                "file_identity"
            ] and after.raw.startswith(self.pre.raw):
                final["pre_stop_binding"] = "same_file_prefix"
            else:
                raise ValueError("audit replaced, shrunk or original prefix changed")
            final["pre_stop_prefix_preserved"] = True
            self.out.update(
                ingress_audit=after.metadata["records"],
                ingress_audit_records_read=after.metadata["records_read"],
            )
        except Exception as exc:
            final["error"] = f"{type(exc).__name__}: {exc}"
            if after is not None:
                self.out["ingress_audit_failed_final_snapshot"] = dict(
                    after.metadata, error=final["error"]
                )


def finalization_problems(obs):
    """Revalidate fresh metadata, row prefix and shutdown suffix without defaults."""
    problems = []
    try:
        final = obs["ingress_audit_finalization"]
        pre = obs["ingress_audit_pre_stop"]
        stop = final["stop"]
        if (
            final["profile"] != PROFILE
            or final["writer_joined"] is not True
            or final["error"] is not None
        ):
            raise ValueError("fresh audit finalization failed/missing")
        if not (
            stop["requested"] is True
            and stop["forced"] is False
            and stop["exit_confirmed"] is True
            and type(stop["returncode"]) is int
            and stop["returncode"] == 0
            and stop["error"] is None
        ):
            raise ValueError("non-graceful final audit stop")
        order = [
            obs["window_end_monotonic_ns"],
            final["writer_joined_ns"],
            pre["read_started_ns"],
            pre["read_ended_ns"],
            stop["requested_ns"],
            stop["exited_ns"],
            final["read_started_ns"],
            final["read_ended_ns"],
        ]
        if not all(_int(v) for v in order) or order != sorted(order):
            raise ValueError("final audit clock ordering/type")
        if (
            pre["error"] is not None
            or pre["rotated"] is not False
            or obs["ingress_audit_rotated"] is not False
        ):
            raise ValueError("audit error/rotation")
        rows = obs["ingress_audit"]
        if (
            type(rows) is not list
            or len(rows) > MAX_ROWS
            or type(obs["ingress_audit_records_read"]) is not int
            or len(rows) != obs["ingress_audit_records_read"]
        ):
            raise ValueError("final audit row/count mismatch")
        if (
            not _hex(final["raw_sha256"])
            or not _int(final["raw_bytes"])
            or final["raw_bytes"] > MAX_BYTES
            or final["pre_stop_prefix_preserved"] is not True
        ):
            raise ValueError("final audit raw/prefix metadata")
        final_identity = final["file_identity"]
        if (
            type(final_identity) is not dict
            or set(final_identity) != {"device", "inode"}
            or not all(_int(v) and v > 0 for v in final_identity.values())
        ):
            raise ValueError("final audit file identity unavailable")
        if type(final["raw_utf8"]) is not str or len(final["raw_utf8"]) > MAX_BYTES:
            raise ValueError("final original UTF8 bytes unavailable")
        final_raw = final["raw_utf8"].encode("utf-8")
        if len(final_raw) > MAX_BYTES:
            raise ValueError("final original UTF8 byte bound")
        parsed_rows = _rows(final_raw)
        if (
            len(final_raw) > MAX_BYTES
            or len(final_raw) != final["raw_bytes"]
            or hashlib.sha256(final_raw).hexdigest() != final["raw_sha256"]
            or not _same(rows, parsed_rows)
        ):
            raise ValueError("final original bytes/hash/typed rows differ")
        if pre["disposition"] == "observed_absent":
            if (
                any(
                    pre[k] is not None
                    for k in (
                        "records",
                        "records_read",
                        "raw_sha256",
                        "raw_bytes",
                        "file_identity",
                        "raw_utf8",
                    )
                )
                or final["pre_stop_binding"] != "created_after_observed_absence"
            ):
                raise ValueError("absence is not an empty measured snapshot")
        elif pre["disposition"] == "read":
            old = pre["records"]
            identity = pre["file_identity"]
            if (
                type(old) is not list
                or len(old) > MAX_ROWS
                or type(pre["records_read"]) is not int
                or len(old) != pre["records_read"]
                or not _hex(pre["raw_sha256"])
                or not _int(pre["raw_bytes"])
                or pre["raw_bytes"] > final["raw_bytes"]
                or final["pre_stop_binding"] != "same_file_prefix"
            ):
                raise ValueError("pre-stop metadata/prefix invalid")
            if (
                type(identity) is not dict
                or set(identity) != {"device", "inode"}
                or not all(_int(v) and v > 0 for v in identity.values())
            ):
                raise ValueError("pre-stop file identity")
            if not _same(identity, final_identity):
                raise ValueError(
                    "final file identity differs from original pre-stop file"
                )
            if type(pre["raw_utf8"]) is not str or len(pre["raw_utf8"]) > MAX_BYTES:
                raise ValueError("pre-stop original UTF8 bytes unavailable")
            pre_raw = pre["raw_utf8"].encode("utf-8")
            if (
                len(pre_raw) > MAX_BYTES
                or len(pre_raw) + len(final_raw) > 2 * MAX_BYTES
                or len(pre_raw) != pre["raw_bytes"]
                or hashlib.sha256(pre_raw).hexdigest() != pre["raw_sha256"]
                or not _same(old, _rows(pre_raw))
                or not final_raw.startswith(pre_raw)
            ):
                raise ValueError(
                    "pre-stop original bytes/hash/typed rows/prefix differ"
                )
            if len(old) > len(rows) or not _same(old, parsed_rows[: len(old)]):
                raise ValueError("pre-stop rows changed")
            if pre["raw_bytes"] == final["raw_bytes"] and (
                pre["raw_sha256"] != final["raw_sha256"] or len(old) != len(rows)
            ):
                raise ValueError("same-size raw/prefix mismatch")
        else:
            raise ValueError("pre-stop snapshot unavailable")
        if bool(rows) != (final["raw_bytes"] > 0):
            raise ValueError("empty raw/rows mismatch")
        ended = set()
        for row in rows:
            kind = _row_kind(row)
            body = row[kind]
            if type(body) is not dict or body.get("interval_end") not in (
                "audit_interval",
                "shutdown",
            ):
                raise ValueError("malformed final audit interval")
            if body["interval_end"] == "shutdown":
                if kind in ended:
                    raise ValueError("repeated shutdown kind")
                ended.add(kind)
            elif ended:
                raise ValueError("periodic row after shutdown suffix")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        problems.append(str(exc))
    return problems
