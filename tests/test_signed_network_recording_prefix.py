"""Actual original collector rows, explicitly synthetic telemetry/clock epochs."""

import json
from pathlib import Path
import sys

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError
from test_signed_network_recording import collect

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_recording as r


def recorded(tmp_path):
    path = tmp_path / "calls"
    collect(path)
    return path.read_bytes()


def test_open_complete_original_callback_matches_closed_without_synthetic_end(tmp_path):
    raw = recorded(tmp_path)
    lines = raw.splitlines(keepends=True)
    prefix = b"".join(lines[:-1])
    result = r.decode_calls_prefix(prefix)
    assert result["closed"] is False and result["partial_tail"] == b""
    assert result["complete_prefix"] == prefix
    assert result["context"] == r.decode_calls(raw)["context"]
    assert result["calls"] == r.decode_calls(raw)["calls"]
    assert any(row["kind"] == "event" for row in result["calls"])
    with pytest.raises(BenefitInputError):
        r.decode_calls(prefix)


@pytest.mark.parametrize("tail", [b"", b'{"unfinished":'])
def test_partial_edge_remains_explicit_original_wait_evidence(tmp_path, tail):
    raw = recorded(tmp_path)
    first = raw.splitlines(keepends=True)[0]
    result = r.decode_calls_prefix(first + tail)
    assert result["complete_prefix"] == first and result["partial_tail"] == tail
    assert result["calls"] == [] and result["closed"] is False
    empty = r.decode_calls_prefix(tail)
    assert (
        empty["context"] is None
        and empty["calls"] == []
        and empty["complete_prefix"] == b""
    )


def test_end_is_reported_as_closed_and_default_shape_stays_identical(tmp_path):
    raw = recorded(tmp_path)
    result = r.decode_calls_prefix(raw)
    assert result["closed"] is True
    assert r.decode_calls(raw) == {k: result[k] for k in ("context", "calls")}
    assert set(r.decode_calls(raw)) == {"context", "calls"}


@pytest.mark.parametrize(
    "fault", ["hash", "order", "unknown", "context", "clock", "complete-json"]
)
def test_bad_complete_rows_are_not_hidden_by_partial_tail(tmp_path, fault):
    lines = recorded(tmp_path).splitlines(keepends=True)
    rows = [json.loads(line) for line in lines[:-1]]
    if fault == "complete-json":
        raw = lines[0] + b'{"malformed"}\n'
    else:
        if fault == "hash":
            rows[1]["sha256"] = "0" * 64
        if fault == "order":
            rows[1]["seq"] = True
        if fault == "unknown":
            rows[1]["kind"] = "other"
        if fault == "context":
            rows[0]["data"]["extra"] = True
        if fault == "clock":
            rows[1]["data"]["clock_after"]["monotonic_after_ns"] = -1
        if fault in {"unknown", "context", "clock"}:
            previous = "0" * 64
            for row in rows:
                row["prev"] = previous
                row["sha256"] = r.manifest_digest(
                    {k: row[k] for k in ("seq", "prev", "kind", "data")}
                )
                previous = row["sha256"]
        raw = b"".join(r.canonical(row) + b"\n" for row in rows)
    with pytest.raises((BenefitInputError, ValueError)):
        r.decode_calls_prefix(raw + b'{"incomplete')
