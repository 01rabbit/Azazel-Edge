"""Adapter: Edge runtime snapshot -> shared Azazel-Fabric ``StatusView``.

Owner-directed scope extension beyond ``docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md``
§3: because Edge is the series' most mature tool it must be Fabric's *top*
consumer, so it emits and reads back a shared ``StatusView`` in addition to the
§3.1/§3.2/§3.3 projections (Gadget emits StatusView only).

Edge builds the shared status view-model *next to* its existing
``ui_snapshot.json`` without changing what any renderer reads. The whole raw
snapshot is carried in ``StatusView.product_view={"edge_snapshot": snap}`` per
the peer-not-subset doctrine, so no Edge-only field is lost.

The shared package is imported optionally: if ``azazel_fabric`` is not
installed every function here becomes a safe no-op, so Edge runs identically
with or without it. No function here ever raises into its caller.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

try:  # optional dependency — pinned in requirements/runtime.txt, absent is fine
    from azazel_fabric.schema.mode import ModeState
    from azazel_fabric.view import HealthDimension, StatusView, build_status_view

    HAVE_AZAZEL_FABRIC = True
except Exception:  # pragma: no cover - exercised only when the dep is absent
    HAVE_AZAZEL_FABRIC = False

STATUS_VIEW_NAME = "ui_status_view.json"


def _evidence_ids(snap: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for item in snap.get("evidence") or []:
        if isinstance(item, dict):
            ident = item.get("id") or item.get("evidence_id")
            if ident:
                out.append(str(ident))
        elif item:
            out.append(str(item))
    return out


def _health(snap: Dict[str, Any]) -> list:
    """Map a few Edge runtime signals into render-agnostic health rows."""
    rows = []
    crit = snap.get("suricata_critical")
    warn = snap.get("suricata_warning")
    if crit is not None or warn is not None:
        rows.append(
            HealthDimension(
                key="suricata",
                label=f"crit={int(crit or 0)} warn={int(warn or 0)}",
                status="critical" if int(crit or 0) else ("warn" if int(warn or 0) else "ok"),
            )
        )
    connection = snap.get("connection") if isinstance(snap.get("connection"), dict) else {}
    wifi_state = connection.get("wifi_state")
    if wifi_state:
        rows.append(
            HealthDimension(
                key="uplink",
                label=str(wifi_state),
                status="ok" if "CONNECTED" in str(wifi_state).upper() or "N/A" in str(wifi_state).upper() else "warn",
                detail=f"uplink_if={connection.get('uplink_if', '-')} type={connection.get('uplink_type', 'unknown')}",
            )
        )
    return rows


def status_view_from_snapshot(
    snap: Dict[str, Any], mode_name: Optional[str] = None
) -> "Optional[StatusView]":
    """Build a shared ``StatusView`` from an Edge runtime snapshot dict.

    Returns ``None`` if ``azazel_fabric`` is not installed. Never raises for
    ordinary shape variation — missing keys degrade to defaults.
    """
    if not HAVE_AZAZEL_FABRIC:
        return None

    internal = snap.get("internal") if isinstance(snap.get("internal"), dict) else {}
    state_word = internal.get("state_name") or snap.get("user_state")
    resolved_mode = str(mode_name or snap.get("mode") or "shield").lower()
    since = str(snap.get("now_time") or snap.get("snapshot_epoch") or "")

    recommendation = snap.get("recommendation")

    return build_status_view(
        product="edge",
        mode=ModeState(name=resolved_mode, since=since),
        generated_at=since,
        state_word=str(state_word) if state_word else None,
        reasons=[str(r) for r in (snap.get("reasons") or [])],
        operator_wording=(str(recommendation) if recommendation else None),
        health=_health(snap),
        evidence_ids=_evidence_ids(snap),
        # Peer, not subset: carry the whole raw snapshot so no Edge-only field is lost.
        product_view={"edge_snapshot": snap},
    )


def write_status_view_alongside(
    snap: Dict[str, Any],
    snapshot_paths: Iterable[Any],
    mode_name: Optional[str] = None,
    logger: Any = None,
) -> None:
    """Write a ``StatusView`` JSON next to each snapshot path. Best-effort no-op.

    For a snapshot at ``<dir>/ui_snapshot.json`` the view is written to
    ``<dir>/ui_status_view.json``. Never raises into the caller and does nothing
    when ``azazel_fabric`` is not installed.
    """
    if not HAVE_AZAZEL_FABRIC:
        return
    try:
        view = status_view_from_snapshot(snap, mode_name=mode_name)
        if view is None:
            return
        payload = view.model_dump_json()
    except Exception as exc:  # pragma: no cover - defensive
        if logger is not None:
            logger.debug("status_view: build failed: %s", exc)
        return

    for snap_path in snapshot_paths:
        try:
            view_path = Path(snap_path).with_name(STATUS_VIEW_NAME)
            view_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = view_path.with_suffix(view_path.suffix + ".tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            os.replace(tmp_path, view_path)
        except Exception as exc:  # pragma: no cover - defensive
            if logger is not None:
                logger.debug("status_view: failed to write beside %s: %s", snap_path, exc)
