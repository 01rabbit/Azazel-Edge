from __future__ import annotations

"""schema.py - Validation helper for v2 decision-explanation records.

Dependency-free (stdlib only).  Returns a list of human-readable problem
strings; an empty list means the record is valid.
"""

from typing import Any, Dict, List

# Fields that must be present and carry a specific Python type.
# Extra keys are allowed; omitted keys here are not checked.
_REQUIRED: List[tuple] = [
    ("ts", str),
    ("trace_id", str),
    ("format_version", str),
    ("selected_action", str),
    ("reason", str),
    ("rejected_actions", list),
    ("release_condition", str),
    ("policy_profile", str),
    ("config_hash", str),
    ("why_chosen", dict),
    ("why_not_others", list),
    ("evidence_ids", list),
    ("next_checks", list),
    ("operator_wording", str),
    ("machine", dict),
    ("trust_capsule", dict),
]


def validate_v2_explanation(record: Dict[str, Any]) -> List[str]:
    """Validate a v2 decision-explanation record.

    Args:
        record: The record dict to validate (typically produced by
                DecisionExplainer.explain(...)).

    Returns:
        A list of human-readable problem strings.  Empty list means valid.
    """
    problems: List[str] = []

    # format_version must be present and equal 'v2'
    if "format_version" not in record:
        problems.append("missing required field: format_version")
    elif record["format_version"] != "v2":
        problems.append(
            f"format_version must be 'v2', got {record['format_version']!r}"
        )

    # Check presence and type of every required field.
    # (format_version already handled above, but re-check type for uniformity.)
    for field_name, expected_type in _REQUIRED:
        if field_name == "format_version":
            # Already checked above; only re-check type if present.
            if field_name in record and not isinstance(record[field_name], expected_type):
                problems.append(
                    f"field '{field_name}' must be {expected_type.__name__},"
                    f" got {type(record[field_name]).__name__}"
                )
            continue

        if field_name not in record:
            problems.append(f"missing required field: {field_name}")
        elif not isinstance(record[field_name], expected_type):
            problems.append(
                f"field '{field_name}' must be {expected_type.__name__},"
                f" got {type(record[field_name]).__name__}"
            )

    # trust_capsule must carry hmac_sig (structural spot-check)
    if "trust_capsule" in record and isinstance(record["trust_capsule"], dict):
        if "hmac_sig" not in record["trust_capsule"]:
            problems.append("trust_capsule is missing required key: hmac_sig")

    return problems
