"""Verify-before-claim gate for finding bulletins.

``report`` is the check a CLI, Slack or other bulletin must pass before it
uses the words of a confirmed finding. A missing record is rejected. A
``claimed`` record, or a ``verified`` flag whose saved bytes no longer match,
is downgraded to an unverified lead. Only a ``verified`` record with an
intact reproduction bundle is accepted.

The bulletin text cites the evidence id and artifact refs. It does not copy
the saved output.
"""
from __future__ import annotations

from .store import ID_RE, EvidenceError, EvidenceStore

LABELS = {
    "accepted": "confirmed_finding",
    "downgraded": "unverified_lead",
    "rejected": "rejected",
}
HEADINGS = {
    "confirmed_finding": "FINDING CONFIRMED",
    "unverified_lead": "UNVERIFIED LEAD",
    "rejected": "REJECTED",
}


def _line(value: str) -> str:
    return " ".join(str(value).split()) or "-"


def _decision(evidence_id, record, disposition: str, reason: str | None) -> dict:
    confirmed = disposition == "accepted"
    body = {
        "evidence_id": evidence_id,
        "confirmed": confirmed,
        "disposition": disposition,
        "label": LABELS[disposition],
        "status": None if record is None else record.status,
        "category": "" if record is None else record.category,
        "target": "" if record is None else record.target,
        "summary": "" if record is None else record.summary,
        "reason": reason,
        "artifact_refs": [] if record is None else list(record.refs()),
    }
    return body


def report(store: EvidenceStore, evidence_id: str) -> dict:
    """Decide whether ``evidence_id`` may be published as a confirmed finding."""
    if not isinstance(evidence_id, str) or ID_RE.fullmatch(evidence_id) is None:
        return _decision(None, None, "rejected", "no_evidence_record")
    try:
        record = store.get(evidence_id)
    except EvidenceError as exc:
        return _decision(evidence_id, None, "rejected", str(exc))
    if record is None:
        return _decision(evidence_id, None, "rejected", "no_evidence_record")
    if record.status == "rejected":
        return _decision(evidence_id, record, "rejected", record.rejected_reason or "rejected")
    if record.status != "verified" or not store.reproduction_intact(record):
        return _decision(evidence_id, record, "downgraded", "not_verified")
    return _decision(evidence_id, record, "accepted", None)


def render_bulletin(adjudication: dict) -> str:
    """Text a reporting channel may send. The heading comes only from the gate label."""
    if not isinstance(adjudication, dict):
        raise EvidenceError("inconsistent_gate")
    label = adjudication.get("label")
    confirmed = adjudication.get("confirmed")
    if label not in HEADINGS or type(confirmed) is not bool:
        raise EvidenceError("inconsistent_gate")
    if confirmed != (label == "confirmed_finding"):
        raise EvidenceError("inconsistent_gate")
    evidence_id = adjudication.get("evidence_id") or "-"
    lines = [
        f"{HEADINGS[label]} {evidence_id}",
        f"confirmed: {str(confirmed).lower()}",
        f"disposition: {adjudication.get('disposition')}",
        f"category: {_line(adjudication.get('category') or '-')}",
        f"target: {_line(adjudication.get('target') or '-')}",
        f"summary: {_line(adjudication.get('summary') or '-')}",
    ]
    reason = adjudication.get("reason")
    if reason:
        lines.append(f"reason: {_line(reason)}")
    refs = adjudication.get("artifact_refs") or []
    if refs:
        lines.append("artifacts: " + ", ".join(_line(item) for item in refs))
    return "\n".join(lines) + "\n"
