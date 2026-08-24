"""Tests for findings master/detail aggregation."""
from __future__ import annotations

from DataClasses import Finding
from core.findings_master_detail import (
    SUPPLEMENTAL_CONTROL_ID,
    UAR_CONTROL_ID,
    aggregate_findings_by_control,
    details_by_control,
    ensure_finding_control_id,
    sorted_summary_rows,
    worst_risk,
)
from core.user_review import build_review_completion_finding
import pandas as pd


def _finding(**kwargs) -> Finding:
    defaults = {
        "period_id": "2025-Q3",
        "category": "Access",
        "title": "test",
        "description": "desc",
        "risk_level": "Medium",
        "status": "Non-Compliant",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_worst_risk_picks_highest():
    assert worst_risk(["Low", "High", "Medium"]) == "High"
    assert worst_risk(["Low", "Medium"]) == "Medium"
    assert worst_risk([]) == "Low"


def test_ensure_assigns_uar_for_user_review():
    finding = _finding(category="User Review")
    assert ensure_finding_control_id(finding) == UAR_CONTROL_ID
    assert finding.control_id == UAR_CONTROL_ID


def test_ensure_assigns_supplemental_when_missing():
    finding = _finding(category="Other")
    assert ensure_finding_control_id(finding) == SUPPLEMENTAL_CONTROL_ID


def test_aggregate_groups_by_control_and_counts():
    findings = [
        _finding(control_id="DB-AM-04_PLACEHOLDER", status="Compliant", risk_level="Low", title="ok"),
        _finding(control_id="DB-AM-04_PLACEHOLDER", status="Non-Compliant", risk_level="High", title="bad"),
        _finding(control_id="DB-PP-01_PLACEHOLDER", status="Non-Compliant", risk_level="Medium", title="pwd"),
    ]
    catalog = {
        "DB-AM-04_PLACEHOLDER": {
            "title_he": "הרשאות קריטיות",
            "analysis_type": "CRITICAL_PRIVILEGES",
            "in_scope": True,
            "description": "desc am04",
            "control_id_ayalon": "DB-AM-01_04_79",
        },
        "DB-PP-01_PLACEHOLDER": {
            "title_he": "מדיניות סיסמה",
            "analysis_type": "PASSWORD_POLICY_BASELINE",
            "in_scope": True,
            "description": "desc pp01",
            "control_id_ayalon": "DB-PP-01_02_76",
        },
    }
    summary = aggregate_findings_by_control(findings, catalog)
    assert set(summary) == {"DB-AM-04_PLACEHOLDER", "DB-PP-01_PLACEHOLDER"}
    assert summary["DB-AM-04_PLACEHOLDER"]["total_records"] == 2
    assert summary["DB-AM-04_PLACEHOLDER"]["valid_records"] == 1
    assert summary["DB-AM-04_PLACEHOLDER"]["finding_records"] == 1
    assert summary["DB-AM-04_PLACEHOLDER"]["risk_level"] == "High"
    assert summary["DB-AM-04_PLACEHOLDER"]["control_id_display"] == "DB-AM-01_04_79"
    from core.findings_master_detail import build_summary_row_values

    values = build_summary_row_values(summary["DB-AM-04_PLACEHOLDER"])
    assert values[0] == "DB-AM-01_04_79"
    details = details_by_control(findings)
    assert len(details["DB-AM-04_PLACEHOLDER"]) == 2


def test_display_control_id_prefers_ayalon():
    from core.findings_master_detail import display_control_id

    assert display_control_id("DB-X_PLACEHOLDER", {"control_id_ayalon": "DB-X_1"}) == "DB-X_1"
    assert display_control_id("DB-X_PLACEHOLDER", {}) == "DB-X_PLACEHOLDER"
    assert display_control_id("DB-X_PLACEHOLDER", {"control_id_ayalon": "  "}) == "DB-X_PLACEHOLDER"


def test_out_of_scope_control_hidden():
    findings = [_finding(control_id="DB-HIDDEN", risk_level="High")]
    catalog = {"DB-HIDDEN": {"title_he": "מוסתר", "in_scope": False}}
    summary = aggregate_findings_by_control(findings, catalog)
    assert "DB-HIDDEN" not in summary


def test_sorted_summary_rows_by_finding_count_then_risk():
    summary = {
        "A": {"control_id": "A", "risk_level": "Low", "finding_records": 10},
        "B": {"control_id": "B", "risk_level": "High", "finding_records": 2},
        "C": {"control_id": "C", "risk_level": "High", "finding_records": 5},
        "D": {"control_id": "D", "risk_level": "Medium", "finding_records": 8},
    }
    rows = sorted_summary_rows(summary)
    assert [row["control_id"] for row in rows] == ["A", "D", "C", "B"]


def test_completion_finding_has_uar_control_id():
    df = pd.DataFrame({"review_status": ["נסקר", "טרם נסקר"]})
    finding = build_review_completion_finding("2025-Q3", df)
    assert finding is not None
    assert finding.control_id == UAR_CONTROL_ID
