"""Emit-alongside projection of Edge audit records into Azazel-Fabric.

Phase 3 of ``docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md`` §3.3. Each record the
hash-chained ``P0AuditLogger`` writes is *additionally* projected into the
shared ``azazel_fabric.schema.AuditEvent`` envelope and appended to a
**separate, non-interleaved** file so the original chain is never perturbed and
``P0AuditLogger.verify_chain()`` keeps passing untouched.

The shared package is imported optionally: if ``azazel_fabric`` is not
installed this is a safe no-op. No function here ever raises into its caller.

**v0.4.0 update:** the projection now delegates to
``azazel_fabric.audit.project_audit_event`` (envelope construction) and
``azazel_fabric.audit.to_jsonl_line`` (serialization) instead of hand-rolling
an ``AuditEvent(...)`` call and ``model_dump_json()``. This is a pure
plumbing change: the ``event_id`` convention below (``chain_hash``, falling
back to ``trace_id:kind``) is passed explicitly to ``project_audit_event``,
so it is *not* overridden by that helper's own ``make_event_id`` default —
Edge's chain-hash-based id scheme is unchanged. The field set on the emitted
``AuditEvent`` is unchanged. The one observable difference is serialization
formatting: ``to_jsonl_line`` writes compact, key-sorted JSON
(``json.dumps(..., sort_keys=True, separators=(",", ":"))``) where the
previous code used Pydantic's default ``model_dump_json()`` (insertion-order
keys, space-padded separators). Line content is semantically identical
(same keys, same values) — no consumer parses these lines positionally or by
byte comparison, so this is treated as within "drop-in, zero behavior
change."
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:  # optional dependency — pinned in requirements/runtime.txt, absent is fine
    from azazel_fabric.schema import AuditEvent
    from azazel_fabric.audit import project_audit_event, to_jsonl_line

    HAVE_AZAZEL_FABRIC = True
except Exception:  # pragma: no cover - exercised only when the dep is absent
    HAVE_AZAZEL_FABRIC = False


def fabric_stream_path(native_path: Path) -> Path:
    """Sibling filename for the Fabric AuditEvent stream (never the chained file).

    For a chained log at ``<dir>/audit.jsonl`` the projection is written to
    ``<dir>/audit.fabric.jsonl`` — 1:1 with each chain file, never interleaved.
    """
    native_path = Path(native_path)
    return native_path.with_name(native_path.stem + ".fabric" + native_path.suffix)


def build_audit_event(record: Dict[str, Any]) -> "Optional[AuditEvent]":
    """Project one Edge audit record into a Fabric ``AuditEvent``.

    Mapping (plan §3.3): Edge has no ``event_id`` (chain position is identity),
    so it is synthesized from ``chain_hash``; ``kind``->``event_type``;
    ``source`` and ``chain_prev``/``chain_hash`` plus the free-form payload ride
    in ``AuditEvent.payload`` (Fabric does not model a hash chain);
    ``config_hash``/``hmac`` stay ``None`` (not on the base record). Returns
    ``None`` if Fabric is not installed.

    Envelope construction delegates to ``azazel_fabric.audit.project_audit_event``
    (v0.4.0). Edge's own ``event_id`` is computed here and passed through
    explicitly, so ``project_audit_event``'s ``make_event_id`` default (a
    ``product:event_type:timestamp`` convention) never applies — Edge keeps its
    chain-hash-based id scheme.
    """
    if not HAVE_AZAZEL_FABRIC:
        return None

    reserved = {"ts", "kind", "trace_id", "source", "chain_prev", "chain_hash"}
    payload: Dict[str, Any] = {k: v for k, v in record.items() if k not in reserved}
    payload["source"] = str(record.get("source") or "")
    payload["chain_prev"] = str(record.get("chain_prev") or "")
    payload["chain_hash"] = str(record.get("chain_hash") or "")

    event_id = str(record.get("chain_hash") or "")
    if not event_id:
        # Fall back to a positional identity when the chain hash is unavailable.
        event_id = f"{record.get('trace_id') or ''}:{record.get('kind') or ''}"

    return project_audit_event(
        product="edge",
        event_type=str(record.get("kind") or ""),
        timestamp=str(record.get("ts") or ""),
        trace_id=str(record.get("trace_id") or ""),
        payload=payload,
        event_id=event_id,
        config_hash=None,
        hmac=None,
    )


def project_audit_record(record: Dict[str, Any], native_path: Path) -> None:
    """Append a Fabric AuditEvent projection to the sibling stream. Best-effort.

    A no-op when Fabric is absent; never raises into the caller and never writes
    to the chained ``native_path``. Serialization delegates to
    ``azazel_fabric.audit.to_jsonl_line`` (v0.4.0) — see the module docstring
    for the (purely cosmetic) formatting difference from the prior
    ``model_dump_json()`` call.
    """
    if not HAVE_AZAZEL_FABRIC:
        return
    try:
        event = build_audit_event(record)
        if event is None:
            return
        out_path = fabric_stream_path(Path(native_path))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(to_jsonl_line(event) + "\n")
    except Exception as exc:  # pragma: no cover - defensive; must never raise
        logger.debug("fabric_audit_projection_failed: %s", exc)
