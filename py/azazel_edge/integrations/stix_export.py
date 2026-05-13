from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


STIX_SPEC_VERSION = "2.1"
STIX_BUNDLE_TYPE = "bundle"
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_id(obj_type: str, deterministic_key: str) -> str:
    uid = uuid.uuid5(STIX_NAMESPACE, f"{obj_type}:{deterministic_key}")
    return f"{obj_type}--{uid}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _to_iso(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    text = str(value or "").strip()
    if not text:
        return _iso_now()
    if text.endswith("Z"):
        return text
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except Exception:
        return _iso_now()


class STIXExporter:
    def __init__(self, identity_name: str = "Azazel-Edge", identity_id: str | None = None):
        self.identity_name = str(identity_name or "Azazel-Edge")
        self.identity_id = identity_id or _stix_id("identity", self.identity_name)

    def arbiter_to_sighting(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        action = str(decision.get("action") or "observe")
        reason = str(decision.get("reason") or "")
        evidence_ids = [str(x) for x in decision.get("evidence_ids", []) if str(x)]
        trace_id = str(decision.get("trace_id") or "unknown")
        level = str(decision.get("level") or "info")
        ts = _to_iso(decision.get("ts") or decision.get("timestamp") or decision.get("created") or _iso_now())
        indicator_ref = _stix_id("indicator", f"{reason}:{trace_id}")
        sid = _stix_id("sighting", f"{trace_id}:{action}:{','.join(sorted(evidence_ids))}")
        return {
            "type": "sighting",
            "spec_version": STIX_SPEC_VERSION,
            "id": sid,
            "created": ts,
            "modified": ts,
            "sighting_of_ref": indicator_ref,
            "count": 1,
            "where_sighted_refs": [self.identity_id],
            "description": f"action={action} level={level} reason={reason} evidence={','.join(evidence_ids)}",
            "x_azazel_trace_id": trace_id,
        }

    def suricata_alert_to_indicator(self, alert: Dict[str, Any], technique_id: str = "") -> Dict[str, Any]:
        alert_obj = alert.get("alert") if isinstance(alert.get("alert"), dict) else {}
        signature = str(alert_obj.get("signature") or alert.get("signature") or "suricata-alert")
        signature_id = str(alert_obj.get("signature_id") or alert.get("signature_id") or "0")
        src_ip = str(alert.get("src_ip") or "0.0.0.0")
        dst_ip = str(alert.get("dest_ip") or alert.get("dst_ip") or "0.0.0.0")
        created = _to_iso(alert.get("timestamp") or _iso_now())
        indicator_id = _stix_id("indicator", f"{signature_id}:{signature}:{src_ip}:{dst_ip}:{technique_id}")
        pattern = (
            f"[network-traffic:src_ref.value = '{src_ip}' AND "
            f"network-traffic:dst_ref.value = '{dst_ip}']"
        )
        name = signature if not technique_id else f"{signature} ({technique_id})"
        return {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": indicator_id,
            "created": created,
            "modified": created,
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created,
            "labels": ["suricata", "azazel-edge"],
            "x_azazel_signature_id": signature_id,
            "x_azazel_attack_technique": str(technique_id or ""),
        }

    def action_to_course_of_action(self, action: str, rationale: str = "") -> Dict[str, Any]:
        act = str(action or "observe")
        coa_id = _stix_id("course-of-action", act)
        created = _iso_now()
        return {
            "type": "course-of-action",
            "spec_version": STIX_SPEC_VERSION,
            "id": coa_id,
            "created": created,
            "modified": created,
            "name": f"azazel-edge:{act}",
            "description": str(rationale or f"Deterministic response action: {act}"),
        }

    def build_bundle(self, objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        ids = sorted(str(item.get("id") or "") for item in objects if isinstance(item, dict))
        bundle_id = _stix_id(STIX_BUNDLE_TYPE, "|".join(ids))
        return {
            "type": STIX_BUNDLE_TYPE,
            "id": bundle_id,
            "spec_version": STIX_SPEC_VERSION,
            "objects": list(objects),
        }

    def export_audit_window(
        self,
        audit_log_path: str | Path,
        max_entries: int = 100,
        since_epoch: float | None = None,
    ) -> Dict[str, Any]:
        path = Path(audit_log_path)
        if not path.exists():
            return self.build_bundle([])
        lines = path.read_text(encoding="utf-8").splitlines()
        rows = lines[-max(1, int(max_entries)) :]
        objects: List[Dict[str, Any]] = []
        for row in rows:
            row = row.strip()
            if not row:
                continue
            try:
                payload = json.loads(row)
            except Exception:
                continue
            ts_iso = _to_iso(payload.get("ts"))
            try:
                if since_epoch is not None:
                    dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                    if dt.timestamp() < float(since_epoch):
                        continue
            except Exception:
                pass
            kind = str(payload.get("kind") or "")
            if kind != "action_decision":
                continue
            decision = {
                "action": payload.get("action"),
                "reason": payload.get("reason"),
                "evidence_ids": payload.get("chosen_evidence_ids") or payload.get("evidence_ids") or [],
                "trace_id": payload.get("trace_id") or "",
                "level": payload.get("level") or "info",
                "ts": payload.get("ts") or ts_iso,
            }
            objects.append(self.arbiter_to_sighting(decision))
            objects.append(self.action_to_course_of_action(str(payload.get("action") or "observe"), str(payload.get("reason") or "")))
        return self.build_bundle(objects)


def _main() -> int:
    parser = argparse.ArgumentParser(description="Export Azazel-Edge audit decisions as STIX 2.1 Bundle JSON")
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-entries", type=int, default=100)
    args = parser.parse_args()
    exporter = STIXExporter()
    bundle = exporter.export_audit_window(args.audit_log, max_entries=args.max_entries)
    Path(args.output).write_text(json.dumps(bundle, ensure_ascii=True, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
