"""Ephemeral synthetic trust material; never production credentials."""

import os
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy, crypto, public_hex


def make_policy(root, *, observer=None, witness=None, producer=None):
    root = Path(root).resolve()
    Private, _, serialization, _ = crypto()
    pk = Private.generate()
    wk = Private.generate()
    producer = (os.geteuid() or 1000) if producer is None else producer
    witness = (0 if os.geteuid() != 0 else 1) if witness is None else witness
    observer = (65534 if producer != 65534 else 65532) if observer is None else observer
    if producer == observer:
        producer = 65533 if witness != 65533 else 65532
    data = dict(
        schema_version="outcome-input-trust/v1",
        scope_ref="scope-a",
        producer_ref="capture-a",
        stream_ref="stream-a",
        producer_public_key=public_hex(pk),
        witness_ref="witness-a",
        witness_public_key=public_hex(wk),
        producer_uid=producer,
        witness_uid=witness,
        observer_uid=observer,
        source_path=str(root / "input"),
        journal_directory=str(root / "journal"),
        socket_path=(
            str(root / "w.sock")
            if len(str(root / "w.sock").encode()) <= 100
            else "/tmp/edge-auth-unit-unused.sock"
        ),
        anchor_directory=str(root / "anchors"),
        input_max_bytes=16 * 1024 * 1024,
        input_max_records=8192,
        journal_max_bytes=16 * 1024 * 1024,
        anchor_max_bytes=16 * 1024 * 1024,
        anchor_max_records=32768,
    )
    p = TrustPolicy(data)

    def material(key):
        return key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    return p, pk, wk, material(pk), material(wk)
