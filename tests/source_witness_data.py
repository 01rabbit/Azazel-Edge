"""PUBLIC TEST keys, real signatures, SYNTHETIC journal assertions; no I/O."""

from copy import deepcopy
import json

from azazel_edge.outcome.input_witness import ANCHOR_DOMAIN
from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, digest, wire
from source_recovery_data import make_source_case

ZERO = "0" * 64


def anchor_checkpoint(raw):
    """Test operator retains this BEFORE negative submission mutations."""
    row = json.loads(raw.splitlines()[-1])
    return dict(
        counter=row["counter"],
        head=digest(_json(row)),
        size=len(raw),
        sha256=digest(raw),
    )


def sign_anchors(rows, *, key=KEYS[2], domain=ANCHOR_DOMAIN):
    previous = ZERO
    for row in rows:
        row.pop("signature", None)
        row["prev"] = previous
        row["signature"] = key.sign(domain + _json(row)).hex()
        previous = digest(_json(row))
    return b"".join(wire(row) for row in rows)


def make_witness_case(directory, case="valid_pinned_prefix", **context):
    source = make_source_case(directory, **context)
    tip = source["arguments"]["expected_prefix_checkpoint"]
    empty = dict(seq=0, head=ZERO, size=0, sha256=digest(b""))
    rows = []
    for counter, source_tip in enumerate((empty, tip), 1):
        state = {f"source_{name}": value for name, value in source_tip.items()}
        state.update(
            journal_seq=counter - 1,
            journal_head=ZERO if counter == 1 else "a" * 64,
            journal_size=0 if counter == 1 else 100,
            journal_sha256=digest(b"") if counter == 1 else "b" * 64,
            journal_device=0 if counter == 1 else 2,
            journal_inode=0 if counter == 1 else 3,
        )
        rows.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=counter,
                prev=ZERO,
                trust_sha256=source["trust"].digest,
                state=state,
            )
        )
    valid = sign_anchors(rows)
    args = dict(
        expected_trust_sha256=source["arguments"]["expected_trust_sha256"],
        expected_context=deepcopy(source["arguments"]["expected_context"]),
        expected_source_checkpoint=deepcopy(tip),
        expected_anchor_checkpoint=anchor_checkpoint(valid),
    )
    value = dict(
        trust_raw=source["trust_raw"],
        source_raw=source["source_raw"],
        anchors_raw=valid,
        arguments=args,
        valid_anchors=valid,
        rows=deepcopy(rows),
        source=source,
    )
    if case == "bad_source_suffix_preserves_prefix":
        value["source_raw"] += b'{"broken":'
    elif case == "bad_anchor_suffix_preserves_prefix":
        value["anchors_raw"] += b'{"broken":'
    elif case == "missing_source":
        value["source_raw"] = None
    elif case == "empty_source":
        value["source_raw"] = b""
    elif case == "missing_anchor":
        value["anchors_raw"] = None
    elif case == "missing_checkpoint":
        args["expected_anchor_checkpoint"] = None
    elif case == "old_log_vs_new_pin":
        value["anchors_raw"] = wire(rows[0])
    elif case != "valid_pinned_prefix":
        raise ValueError(case)
    return value
