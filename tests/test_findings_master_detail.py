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
    assert finding.control_id == "DB-AM-01_PLACEHOLDER"


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
            "risk_description": "risk am04",
            "control_id_ayalon": "DB-AM-01_04_79",
        },
        "DB-PP-01_PLACEHOLDER": {
            "title_he": "מדיניות סיסמה",
            "analysis_type": "PASSWORD_POLICY_BASELINE",
            "in_scope": True,
            "description": "desc pp01",
            "risk_description": "risk pp01",
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
    assert summary["DB-AM-04_PLACEHOLDER"]["risk_description"] == "risk am04"
    from core.findings_master_detail import build_summary_row_values

    values = build_summary_row_values(summary["DB-AM-04_PLACEHOLDER"])
    assert values[0] == "DB-AM-01_04_79"
    assert values[-2] == "risk am04"
    assert values[-1] == "desc am04"
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
    assert finding.control_id == "DB-AM-01_PLACEHOLDER"
    assert "reviewed=1" in str(finding.evidence_ref)
    assert "unreviewed=1" in str(finding.evidence_ref)
    assert "total=2" in str(finding.evidence_ref)


def test_aggregate_user_review_uses_progress_counts():
    df = pd.DataFrame({"review_status": ["נסקר"] * 38 + ["טרם נסקר"] * 30})
    finding = build_review_completion_finding("2026-Q3", df)
    assert finding is not None
    catalog = {
        "DB-AM-01_PLACEHOLDER": {
            "title_he": "סקירת המשתמשים",
            "control_id_ayalon": "DB-AM-01_01_01_05_72",
            "in_scope": True,
            "analysis_type": "USER_POPULATION_REVIEW",
            "description": "desc",
            "risk_description": "risk",
        }
    }
    summary = aggregate_findings_by_control([finding], catalog)
    row = summary["DB-AM-01_PLACEHOLDER"]
    assert row["control_id_display"] == "DB-AM-01_01_01_05_72"
    assert row["valid_records"] == 38
    assert row["finding_records"] == 30
    assert row["total_records"] == 68


def test_build_unreviewed_user_findings_lists_each_user():
    from core.user_review import build_unreviewed_user_findings

    df = pd.DataFrame(
        {
            "user_name": ["A", "B", "C"],
            "user_type": ["Dialog", "Technical", "Generic"],
            "review_status": ["נסקר", "טרם נסקר", "טרם נסקר"],
        }
    )
    findings = build_unreviewed_user_findings("2026-Q3", df)
    assert len(findings) == 2
    assert {f.actual_value for f in findings} == {"B", "C"}
    assert all(f.control_id == "DB-AM-01_PLACEHOLDER" for f in findings)
    assert all(f.comparison_rule == "משתמש שטרם נסקר" for f in findings)


def test_detail_findings_for_user_review_control_only_unreviewed():
    from core.findings_master_detail import detail_findings_for_control
    from core.user_review import (
        REVIEW_COMPLETION_COMPARISON_RULE,
        UNREVIEWED_USER_COMPARISON_RULE,
        build_review_completion_finding,
        build_unreviewed_user_findings,
    )

    df = pd.DataFrame(
        {
            "user_name": ["A", "B"],
            "user_type": ["Dialog", "Technical"],
            "review_status": ["נסקר", "טרם נסקר"],
        }
    )
    mixed = [
        build_review_completion_finding("2026-Q3", df),
        *build_unreviewed_user_findings("2026-Q3", df),
        _finding(
            category="UAR",
            control_id="DB-AM-01_PLACEHOLDER",
            title="משתמשים לא פעילים מזמן: 9",
            risk_level="Low",
        ),
        _finding(
            category="User Review",
            control_id="DB-AM-01_PLACEHOLDER",
            title="חריג בסקירת משתמשים: X",
            comparison_rule="סקירת משתמשים",
            risk_level="High",
        ),
    ]
    mixed = [item for item in mixed if item is not None]
    detail = detail_findings_for_control("DB-AM-01_PLACEHOLDER", mixed)
    assert len(detail) == 1
    assert detail[0].comparison_rule == UNREVIEWED_USER_COMPARISON_RULE
    assert detail[0].actual_value == "B"
    assert all(item.comparison_rule != REVIEW_COMPLETION_COMPARISON_RULE for item in detail)
