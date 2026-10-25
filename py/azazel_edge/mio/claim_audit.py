"""Claim-to-reference validation audit (#366 Part B / #386).

Projects M.I.O. output into explicit claims, checks that every *material*
claim cites evidence references that exist in the current SituationFrame (or
were imported this cycle through the Capability Broker, with that origin
recorded), and produces one audit record per claim:

    claim -> cited refs (with origin) -> verdict

Unsupported material claims are never silently accepted. The audit checks that
cited refs EXIST in the current context and records their ORIGIN; it does not
judge whether a ref is relevant to, or actually supports, the claim text. The
configured policy is ``reject``: the cycle ends in ``VALIDATION_REJECTED`` with the claim ids in
the error list and the full audit in the trace. No LLM is consulted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import HypothesisStatus, MioHypothesis, MioRecommendation, MioSituationFrame

CLAIM_AUDIT_SCHEMA = "mio_claim_audit/v1"
UNSUPPORTED_CLAIM_POLICY = "reject"

# Claim classes.
CLASS_INFERENCE = "inference"  # proposed/active/unresolved hypothesis: may be unreferenced
CLASS_EVIDENCE_ASSESSMENT = "evidence_assessment"  # strengthened/weakened/falsified: asserts evidence moved it
CLASS_RECOMMENDATION = "recommendation"
MATERIAL_CLASSES = frozenset({CLASS_EVIDENCE_ASSESSMENT, CLASS_RECOMMENDATION})

VERDICT_SUPPORTED = "supported"
VERDICT_INFERENCE_UNREFERENCED = "inference_unreferenced"
VERDICT_MISSING_REFS = "unsupported_missing_refs"
VERDICT_UNKNOWN_REF = "unsupported_unknown_ref"
VERDICT_UNPARSEABLE_STATUS = "unsupported_unparseable_status"
VERDICT_NAMED_GAP = "weakened_by_named_gap"  # weakened with no refuting ref but an explicit missing_evidence entry
UNSUPPORTED_VERDICTS = frozenset({VERDICT_MISSING_REFS, VERDICT_UNKNOWN_REF, VERDICT_UNPARSEABLE_STATUS})

ORIGIN_FRAME = "frame_evidence"
ORIGIN_KNOWLEDGE = "frame_knowledge"
ORIGIN_BROKER = "broker_imported"
ORIGIN_MISSING = "not_in_frame"


@dataclass(frozen=True)
class ClaimAuditRecord:
    claim_id: str
    claim_class: str
    material: bool
    refs: tuple[tuple[str, str], ...]  # (ref, origin)
    verdict: str
    reason: str = ""

    @property
    def unsupported(self) -> bool:
        return self.verdict in UNSUPPORTED_VERDICTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_class": self.claim_class,
            "material": self.material,
            "refs": [{"ref": ref, "origin": origin} for ref, origin in self.refs],
            "verdict": self.verdict,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ClaimAudit:
    records: tuple[ClaimAuditRecord, ...]

    @property
    def ok(self) -> bool:
        return not any(r.unsupported for r in self.records)

    def errors(self) -> tuple[str, ...]:
        return tuple(f"unsupported_claim:{r.claim_id}:{r.verdict}" for r in self.records if r.unsupported)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CLAIM_AUDIT_SCHEMA,
            "policy": UNSUPPORTED_CLAIM_POLICY,
            "ok": self.ok,
            "claims": [r.to_dict() for r in self.records],
        }


def _origin(ref: str, frame: MioSituationFrame, imported: set[str]) -> str:
    if ref in frame.evidence_refs:
        return ORIGIN_FRAME
    if ref in frame.knowledge_refs:
        return ORIGIN_KNOWLEDGE
    if ref in imported:
        return ORIGIN_BROKER
    return ORIGIN_MISSING


def _record(claim_id: str, claim_class: str, refs: Sequence[str], required: Sequence[str] | None, frame: MioSituationFrame, imported: set[str]) -> ClaimAuditRecord:
    material = claim_class in MATERIAL_CLASSES
    with_origin = tuple((ref, _origin(ref, frame, imported)) for ref in dict.fromkeys(refs))
    missing = [ref for ref, origin in with_origin if origin == ORIGIN_MISSING]
    if missing:
        return ClaimAuditRecord(claim_id, claim_class, material, with_origin, VERDICT_UNKNOWN_REF, "cites:" + ",".join(missing[:4])[:200])
    if material and not list(required if required is not None else refs):
        return ClaimAuditRecord(claim_id, claim_class, material, with_origin, VERDICT_MISSING_REFS, "material_claim_without_required_refs")
    if not with_origin:
        return ClaimAuditRecord(claim_id, claim_class, material, with_origin, VERDICT_INFERENCE_UNREFERENCED, "marked_inference")
    return ClaimAuditRecord(claim_id, claim_class, material, with_origin, VERDICT_SUPPORTED)


_VALID_STATUSES = frozenset(s.value for s in HypothesisStatus)


def unparseable_status_ids(items: Sequence[Any]) -> tuple[str, ...]:
    """Hypothesis ids whose raw model ``status`` is present but not a valid status.

    ``MioHypothesis.from_mapping`` silently maps such a status to ``proposed``;
    this makes that coercion visible so the audit can flag it. Ids are derived the
    same way ``from_mapping`` derives them (``hypothesis_id`` or ``h<ordinal>``).
    """
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue
        raw = item.get("status")
        if raw is None or (isinstance(raw, str) and raw in _VALID_STATUSES):
            continue
        hid = MioHypothesis.from_mapping(item, ordinal=index + 1).hypothesis_id
        out.append(hid)
    return tuple(dict.fromkeys(out))


def audit_claims(
    frame: MioSituationFrame,
    *,
    hypotheses: Sequence[MioHypothesis] = (),
    recommendation: MioRecommendation | None = None,
    imported_refs: Sequence[str] = (),
    unparseable_status: Sequence[str] = (),
) -> ClaimAudit:
    """Deterministically audit every claim in the cycle output.

    Evidence requirements match the #385 lifecycle rules
    (``lifecycle._evidence_errors``): strengthened needs a supporting ref;
    falsified needs a contradicting ref; weakened needs a contradicting ref or an
    explicit ``missing_evidence`` entry (recorded as ``weakened_by_named_gap``).
    ``imported_refs`` must contain only refs from broker results with ``ok=True``.
    """
    imported = {str(x) for x in imported_refs}
    bad_status = {str(x) for x in unparseable_status}
    records: list[ClaimAuditRecord] = []
    for h in hypotheses:
        refs = list(h.supporting_evidence_refs) + list(h.contradicting_evidence_refs)
        if h.hypothesis_id in bad_status:
            with_origin = tuple((ref, _origin(ref, frame, imported)) for ref in dict.fromkeys(refs))
            records.append(ClaimAuditRecord(f"hypothesis:{h.hypothesis_id}", CLASS_EVIDENCE_ASSESSMENT, True, with_origin, VERDICT_UNPARSEABLE_STATUS, "model_status_not_in_vocabulary_coerced_to_proposed"))
        elif h.status is HypothesisStatus.STRENGTHENED:
            records.append(_record(f"hypothesis:{h.hypothesis_id}", CLASS_EVIDENCE_ASSESSMENT, refs, h.supporting_evidence_refs, frame, imported))
        elif h.status is HypothesisStatus.FALSIFIED:
            records.append(_record(f"hypothesis:{h.hypothesis_id}", CLASS_EVIDENCE_ASSESSMENT, refs, h.contradicting_evidence_refs, frame, imported))
        elif h.status is HypothesisStatus.WEAKENED:
            record = _record(f"hypothesis:{h.hypothesis_id}", CLASS_EVIDENCE_ASSESSMENT, refs, h.contradicting_evidence_refs, frame, imported)
            if record.verdict == VERDICT_MISSING_REFS and h.missing_evidence:
                record = ClaimAuditRecord(record.claim_id, record.claim_class, True, record.refs, VERDICT_NAMED_GAP, "missing_evidence:" + "|".join(h.missing_evidence)[:160])
            records.append(record)
        else:
            records.append(_record(f"hypothesis:{h.hypothesis_id}", CLASS_INFERENCE, refs, None, frame, imported))
    if recommendation is not None:
        records.append(_record(f"recommendation:{recommendation.advisory_id}", CLASS_RECOMMENDATION, recommendation.evidence_refs, None, frame, imported))
    return ClaimAudit(tuple(records))
