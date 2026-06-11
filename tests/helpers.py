from __future__ import annotations


def dim(score: int, label: str, evidence_ids: list[str] | None = None) -> dict:
    return {
        "score": score,
        "label": label,
        "reasons": [],
        "evidence_ids": list(evidence_ids or []),
    }


def noc(
    availability: str = "good",
    path: str = "good",
    device: str = "good",
    client: str = "good",
) -> dict:
    return {
        "availability": dim(95, availability, ["noc-a"]),
        "path_health": dim(95, path, ["noc-p"]),
        "device_health": dim(95, device, ["noc-d"]),
        "client_health": dim(95, client, ["noc-c"]),
        "summary": {"status": "good", "reasons": []},
        "evidence_ids": ["noc-a", "noc-p", "noc-d", "noc-c"],
    }


def soc(
    suspicion: int = 20,
    suspicion_label: str = "low",
    confidence: int = 30,
    confidence_label: str = "low",
    blast: int = 20,
    blast_label: str = "low",
    technique: int = 40,
    technique_label: str = "medium",
) -> dict:
    return {
        "suspicion": dim(suspicion, suspicion_label, ["soc-s"]),
        "confidence": dim(confidence, confidence_label, ["soc-c"]),
        "technique_likelihood": dim(technique, technique_label, ["soc-t"]),
        "blast_radius": dim(blast, blast_label, ["soc-b"]),
        "summary": {"status": suspicion_label, "reasons": []},
        "evidence_ids": ["soc-s", "soc-c", "soc-t", "soc-b"],
    }
