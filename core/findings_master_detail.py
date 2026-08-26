"""Aggregate audit findings into APP-style master/detail structures."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from DataClasses import Finding

SUPPLEMENTAL_CONTROL_ID = "DB-SUPPLEMENTAL"
USER_REVIEW_CONTROL_ID = "DB-AM-01_PLACEHOLDER"
# Backward-compatible alias (was wrongly DB-UAR-02 / privilege review).
UAR_CONTROL_ID = USER_REVIEW_CONTROL_ID
USER_REVIEW_CATEGORY = "User Review"
REVIEW_COMPLETION_COMPARISON_RULE = "השלמת סקירת משתמשים"
UNREVIEWED_USER_COMPARISON_RULE = "משתמש שטרם נסקר"

_RISK_RANK = {"High": 0, "Medium": 1, "Low": 2}


def worst_risk(levels: Iterable[str]) -> str:
    best = None
    best_rank = 99
    for level in levels:
        text = str(level or "").strip() or "Low"
        rank = _RISK_RANK.get(text, 98)
        if rank < best_rank:
            best_rank = rank
            best = text
    return best or "Low"


def ensure_finding_control_id(finding: Finding) -> str:
    """Assign a stable control_id on the finding when missing; return the id."""
    existing = str(getattr(finding, "control_id", None) or "").strip()
    category = str(getattr(finding, "category", "") or "")
    comparison_rule = str(getattr(finding, "comparison_rule", "") or "")
    is_user_review = (
        category == USER_REVIEW_CATEGORY
        or comparison_rule == REVIEW_COMPLETION_COMPARISON_RULE
    )

    # Remap legacy privilege-review id wrongly used for user-review findings.
    if existing == "DB-UAR-02_PLACEHOLDER" and is_user_review:
        finding.control_id = USER_REVIEW_CONTROL_ID
        if not getattr(finding, "analysis_type", None) or finding.analysis_type == "PERIODIC_UAR":
            finding.analysis_type = "USER_POPULATION_REVIEW"
        return USER_REVIEW_CONTROL_ID

    if existing:
        return existing

    if is_user_review:
        finding.control_id = USER_REVIEW_CONTROL_ID
        if not getattr(finding, "analysis_type", None):
            finding.analysis_type = "USER_POPULATION_REVIEW"
        return USER_REVIEW_CONTROL_ID

    finding.control_id = SUPPLEMENTAL_CONTROL_ID
    return SUPPLEMENTAL_CONTROL_ID


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"", "none"}:
        return default
    return text not in {"false", "0", "no", "off"}


def display_control_id(control_id: str, catalog_entry: Optional[Dict[str, Any]] = None) -> str:
    """Prefer control_id_ayalon for UI; fall back to internal control_id."""
    entry = catalog_entry or {}
    ayalon = str(entry.get("control_id_ayalon", "") or "").strip()
    return ayalon or str(control_id or "").strip() or "-"


def _catalog_allows_control(control_id: str, catalog_by_id: Dict[str, Dict[str, Any]]) -> bool:
    if control_id == SUPPLEMENTAL_CONTROL_ID:
        return True
    entry = catalog_by_id.get(control_id)
    if not entry:
        return True
    return _as_bool(entry.get("in_scope", True), default=True)


def _short_description(text: str, max_len: int = 160) -> str:
    normalized = " ".join(str(text or "").split())
    if len(normalized) <= max_len:
        return normalized or "-"
    return normalized[: max_len - 1] + "…"


def details_by_control(findings: Sequence[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        control_id = ensure_finding_control_id(finding)
        grouped.setdefault(control_id, []).append(finding)
    return grouped


def is_unreviewed_user_finding(finding: Finding) -> bool:
    return str(getattr(finding, "comparison_rule", "") or "") == UNREVIEWED_USER_COMPARISON_RULE


def detail_findings_for_control(control_id: str, findings: Sequence[Finding]) -> List[Finding]:
    """Findings shown in the detail table / working-paper findings sheet.

    For the user-review control, only per-user 'טרם נסקר' rows are shown.
    """
    items = list(findings or [])
    if str(control_id or "").strip() != USER_REVIEW_CONTROL_ID:
        return [
            finding
            for finding in items
            if str(getattr(finding, "comparison_rule", "") or "") != REVIEW_COMPLETION_COMPARISON_RULE
        ]
    return [finding for finding in items if is_unreviewed_user_finding(finding)]


def aggregate_findings_by_control(
    findings: Sequence[Finding],
    catalog_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    source_file_getter=None,
) -> Dict[str, Dict[str, Any]]:
    """Build summary records keyed by control_id (in-scope catalog controls only)."""
    catalog_by_id = catalog_by_id or {}
    grouped = details_by_control(findings)
    summaries: Dict[str, Dict[str, Any]] = {}

    for control_id, group in grouped.items():
        if not _catalog_allows_control(control_id, catalog_by_id):
            continue

        entry = catalog_by_id.get(control_id, {})
        if control_id == SUPPLEMENTAL_CONTROL_ID:
            title_he = "ממצאים משלימים"
            description = "ממצאים ממנוע משלים ללא מזהה בקרה בקטלוג"
            check_type = "SUPPLEMENTAL"
        else:
            title_he = str(entry.get("title_he") or control_id)
            description = _short_description(entry.get("description") or entry.get("process") or "")
            check_type = str(
                entry.get("analysis_type")
                or getattr(group[0], "analysis_type", None)
                or getattr(group[0], "comparison_rule", None)
                or "-"
            )

        valid_records = sum(1 for item in group if str(getattr(item, "status", "")) == "Compliant")
        finding_records = len(group) - valid_records
        total_records = len(group)

        # User-review completion: counts come from report progress, not finding rows.
        if control_id == USER_REVIEW_CONTROL_ID:
            progress = _review_progress_from_findings(group)
            if progress is not None:
                valid_records = int(progress.get("reviewed", 0) or 0)
                finding_records = int(progress.get("unreviewed", 0) or 0)
                total_records = int(progress.get("total", 0) or 0)

        source_file = "-"
        extract_date = "-"
        if group:
            first = group[0]
            if source_file_getter is not None:
                source_file = str(source_file_getter(first) or "-")
            else:
                source_file = str(getattr(first, "source_file", None) or getattr(first, "source_slot", None) or "-")
            extract_date = str(getattr(first, "extract_date", None) or "-")

        summaries[control_id] = {
            "control_id": control_id,
            "control_id_ayalon": str(entry.get("control_id_ayalon", "") or "").strip(),
            "control_id_display": display_control_id(control_id, entry),
            "title_he": title_he,
            "check_type": check_type,
            "risk_level": worst_risk(getattr(item, "risk_level", "Low") for item in group),
            "valid_records": valid_records,
            "finding_records": finding_records,
            "total_records": total_records,
            "source_file": source_file,
            "extraction_date": extract_date,
            "risk_description": _short_description(entry.get("risk_description") or "", max_len=220),
            "description": description,
        }
    return summaries


def _review_progress_from_findings(group: Sequence[Finding]) -> Optional[Dict[str, int]]:
    """Extract review progress embedded on the completion finding (evidence_ref)."""
    for item in group:
        if str(getattr(item, "comparison_rule", "") or "") != REVIEW_COMPLETION_COMPARISON_RULE:
            continue
        raw = str(getattr(item, "evidence_ref", "") or "").strip()
        if not raw.startswith("review_progress|"):
            continue
        parsed: Dict[str, int] = {}
        for part in raw.split("|")[1:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            try:
                parsed[key.strip()] = int(value.strip())
            except ValueError:
                continue
        if {"reviewed", "unreviewed", "total"} <= set(parsed):
            return parsed
    return None


def sorted_summary_rows(summary_records: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort by finding_records (high→low), then risk (High→Low), then control_id."""
    return sorted(
        summary_records.values(),
        key=lambda item: (
            -int(item.get("finding_records", 0) or 0),
            _RISK_RANK.get(str(item.get("risk_level", "") or "").strip(), 98),
            str(item.get("control_id", "")),
        ),
    )


def build_summary_row_values(row_data: Dict[str, Any]) -> List[str]:
    return [
        str(row_data.get("control_id_display") or row_data.get("control_id_ayalon") or row_data.get("control_id", "-")),
        str(row_data.get("title_he", "-")),
        str(row_data.get("check_type", "-")),
        str(row_data.get("risk_level", "-")),
        str(row_data.get("valid_records", 0)),
        str(row_data.get("finding_records", 0)),
        str(row_data.get("total_records", 0)),
        str(row_data.get("source_file", "-")),
        str(row_data.get("extraction_date", "-")),
        str(row_data.get("risk_description", "-")),
        str(row_data.get("description", "-")),
    ]
