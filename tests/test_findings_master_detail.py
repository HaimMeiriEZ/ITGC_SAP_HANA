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
        },
        "DB-PP-01_PLACEHOLDER": {
            "title_he": "מדיניות סיסמה",
            "analysis_type": "PASSWORD_POLICY_BASELINE",
            "in_scope": True,
            "description": "desc pp01",
        },
    }
    summary = aggregate_findings_by_control(findings, catalog)
    assert set(summary) == {"DB-AM-04_PLACEHOLDER", "DB-PP-01_PLACEHOLDER"}
    assert summary["DB-AM-04_PLACEHOLDER"]["total_records"] == 2
    assert summary["DB-AM-04_PLACEHOLDER"]["valid_records"] == 1
    assert summary["DB-AM-04_PLACEHOLDER"]["finding_records"] == 1
    assert summary["DB-AM-04_PLACEHOLDER"]["risk_level"] == "High"
    details = details_by_control(findings)
    assert len(details["DB-AM-04_PLACEHOLDER"]) == 2


def test_out_of_scope_control_hidden():
    findings = [_finding(control_id="DB-HIDDEN", risk_level="High")]
    catalog = {"DB-HIDDEN": {"title_he": "מוסתר", "in_scope": False}}
    summary = aggregate_findings_by_control(findings, catalog)
    assert "DB-HIDDEN" not in summary


def test_sorted_summary_rows_by_finding_count():
    summary = {
        "A": {"control_id": "A", "finding_records": 1},
        "B": {"control_id": "B", "finding_records": 5},
    }
    rows = sorted_summary_rows(summary)
    assert rows[0]["control_id"] == "B"


def test_completion_finding_has_uar_control_id():
    df = pd.DataFrame({"review_status": ["נסקר", "טרם נסקר"]})
    finding = build_review_completion_finding("2025-Q3", df)
    assert finding is not None
    assert finding.control_id == UAR_CONTROL_ID
