"""Business logic for the compensating-controls tab – DB project."""
from __future__ import annotations

from typing import Any, Callable

# In the DB project, "Compliant" is the only passing status.
_PASSING_STATUSES = {"Compliant"}

_DEFAULT_COLUMN_WIDTHS = {
    "0": 190,
    "1": 150,
    "2": 170,
    "3": 220,
    "4": 170,
}
_DEFAULT_ROW_HEIGHT = 56


def control_has_findings(findings: list[Any]) -> bool:
    """Return True when at least one Finding has a non-Compliant status."""
    return any(
        str(getattr(f, "status", "")).strip() not in _PASSING_STATUSES
        for f in findings
    )


def _non_passing_findings(findings: list[Any]) -> list[Any]:
    return [
        f for f in findings
        if str(getattr(f, "status", "")).strip() not in _PASSING_STATUSES
    ]


def build_findings_brief_summary(findings: list[Any], *, control_id: str = "") -> str:
    """Return a one-sentence Hebrew summary of non-Compliant findings."""
    rows = _non_passing_findings(findings)
    if not rows:
        return "-"
    count = len(rows)
    return f"נמצאו {count} ממצאים."


def build_findings_description(findings: list[Any], *, max_chars: int = 4000) -> str:
    """Concatenate description of non-Compliant findings (capped to *max_chars*)."""
    parts: list[str] = []
    seen: set[str] = set()
    for f in _non_passing_findings(findings):
        text = str(getattr(f, "description", "") or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        parts.append(text)
    combined = "\n".join(parts)
    if len(combined) <= max_chars:
        return combined
    return combined[: max_chars - 3].rstrip() + "..."


def build_compensating_control_rows(
    summary_records: dict[str, Any],
    details_by_control: dict[str, list[Any]],
    compensating_state: dict[str, dict[str, Any]],
    get_meta_cb: Callable[[str], dict[str, str]],
    is_in_scope_cb: Callable[[str], bool],
) -> list[dict[str, Any]]:
    """Build table rows for the compensating-controls tab.

    Only controls that are in scope AND have at least one non-Compliant Finding
    are included.
    """
    rows: list[dict[str, Any]] = []
    for control_id in sorted(summary_records.keys()):
        if not is_in_scope_cb(control_id):
            continue
        findings = details_by_control.get(control_id, [])
        if not control_has_findings(findings):
            continue
        meta = get_meta_cb(control_id)
        rows.append(
            {
                "control_id": control_id,
                "risk_description": meta.get("risk_description", "-") or "-",
                "description": meta.get("description", "-") or "-",
                "findings_brief": build_findings_brief_summary(findings, control_id=control_id),
                "findings_description": build_findings_description(findings),
                "attachment": compensating_state.get(control_id),
            }
        )
    return rows


DEFAULT_COMPENSATING_COLUMN_WIDTHS = _DEFAULT_COLUMN_WIDTHS
DEFAULT_COMPENSATING_ROW_HEIGHT = _DEFAULT_ROW_HEIGHT
