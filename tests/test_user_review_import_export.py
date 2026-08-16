"""Round-trip tests for user review Excel export/import."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pandas as pd

from core.user_review import (
    USER_REVIEW_SHEET_NAME,
    export_user_review_to_excel,
    import_user_review_from_excel,
)


def _sample_report() -> dict:
    df = pd.DataFrame(
        [
            {
                "user_name": "ALICE",
                "in_scope": "כן",
                "active_status": "פעיל",
                "active_in_period": "כן",
                "period_activity_reason": "-",
                "last_login": "2025-06-01",
                "days_since_login": 30,
                "user_type": "Dialog",
                "has_privileges": "כן",
                "critical_privileges": "USER ADMIN",
                "all_privileges": "USER ADMIN",
                "password_policy_exempt_status": "לא",
                "password_policy_exempt_reason": "-",
                "password_policy_exempt_source": "-",
                "system_table_access_status": "אין גישה",
                "system_table_access_details": "-",
                "has_exception": "כן",
                "exception_reason": "הרשאה קריטית",
                "review_status": "טרם נסקר",
                "manager_decision": "",
                "manager_comments": "הערה קיימת",
                "action_required": "",
                "extract_date": "2025-01-01",
                "review_date": "2025-08-01",
                "status_sort": 0,
            },
            {
                "user_name": "BOB",
                "in_scope": "כן",
                "active_status": "פעיל",
                "active_in_period": "כן",
                "period_activity_reason": "-",
                "last_login": "2025-07-01",
                "days_since_login": 10,
                "user_type": "Technical",
                "has_privileges": "כן",
                "critical_privileges": "-",
                "all_privileges": "SELECT",
                "password_policy_exempt_status": "לא",
                "password_policy_exempt_reason": "-",
                "password_policy_exempt_source": "-",
                "system_table_access_status": "אין גישה",
                "system_table_access_details": "-",
                "has_exception": "לא",
                "exception_reason": "-",
                "review_status": "טרם נסקר",
                "manager_decision": "",
                "manager_comments": "",
                "action_required": "",
                "extract_date": "2025-01-01",
                "review_date": "2025-08-01",
                "status_sort": 1,
            },
        ]
    )
    return {
        "dataframe": df,
        "summary": {
            "total_users": 2,
            "in_scope_users": 2,
            "exception_users": 1,
            "privileged_users": 1,
            "type_distribution": {"Dialog": 1, "Technical": 1},
        },
        "metadata": {
            "period_id": "2025",
            "review_date": "2025-08-01",
            "review_period_start": "2025-01-01",
            "review_period_end": "2025-12-31",
            "users_extract_date": "-",
            "privileges_extract_date": "-",
            "inactive_days_threshold": 120,
            "generated_at": "2025-08-01 10:00:00",
        },
    }


def test_export_import_roundtrip_updates_manager_fields(tmp_path: Path):
    report = _sample_report()
    export_path = tmp_path / "review.xlsx"
    export_user_review_to_excel(report, str(export_path))

    exported = pd.read_excel(export_path, sheet_name=USER_REVIEW_SHEET_NAME).fillna("")
    assert "החלטת מנהל" in exported.columns
    assert "סטטוס סקירה" in exported.columns

    exported.loc[exported["שם משתמש"] == "ALICE", "סטטוס סקירה"] = "נסקר"
    exported.loc[exported["שם משתמש"] == "ALICE", "החלטת מנהל"] = "מאושר"
    exported.loc[exported["שם משתמש"] == "ALICE", "נדרש להסרה / מאושר להשאיר"] = "מאושר להשאיר"
    exported.loc[exported["שם משתמש"] == "ALICE", "הערות"] = "אושר ע״י מנהל"
    edited_path = tmp_path / "review_filled.xlsx"
    exported.to_excel(edited_path, sheet_name=USER_REVIEW_SHEET_NAME, index=False)

    result = import_user_review_from_excel(edited_path, report["dataframe"].copy())
    updated = result["updated_df"]
    alice = updated[updated["user_name"] == "ALICE"].iloc[0]
    assert result["matched"] == 2
    assert alice["review_status"] == "נסקר"
    assert alice["manager_decision"] == "מאושר"
    assert alice["action_required"] == "מאושר להשאיר"
    assert alice["manager_comments"] == "אושר ע״י מנהל"


def test_preserve_empty_notes_keeps_existing_comments(tmp_path: Path):
    report = _sample_report()
    export_path = tmp_path / "review.xlsx"
    export_user_review_to_excel(report, str(export_path))

    exported = pd.read_excel(export_path, sheet_name=USER_REVIEW_SHEET_NAME).fillna("")
    exported.loc[exported["שם משתמש"] == "ALICE", "סטטוס סקירה"] = "נסקר"
    exported.loc[exported["שם משתמש"] == "ALICE", "הערות"] = ""
    edited_path = tmp_path / "review_empty_notes.xlsx"
    exported.to_excel(edited_path, sheet_name=USER_REVIEW_SHEET_NAME, index=False)

    wiped = import_user_review_from_excel(
        edited_path, report["dataframe"].copy(), preserve_empty_notes=False
    )
    assert wiped["updated_df"].loc[wiped["updated_df"]["user_name"] == "ALICE", "manager_comments"].iloc[0] == ""
    assert "ALICE" in wiped["notes_cleared"]

    preserved = import_user_review_from_excel(
        edited_path, report["dataframe"].copy(), preserve_empty_notes=True
    )
    assert (
        preserved["updated_df"].loc[preserved["updated_df"]["user_name"] == "ALICE", "manager_comments"].iloc[0]
        == "הערה קיימת"
    )
    assert "ALICE" in preserved["notes_cleared"]


def test_unmatched_users_are_reported(tmp_path: Path):
    report = _sample_report()
    export_path = tmp_path / "review.xlsx"
    export_user_review_to_excel(report, str(export_path))
    exported = pd.read_excel(export_path, sheet_name=USER_REVIEW_SHEET_NAME).fillna("")
    exported.loc[len(exported)] = {col: "" for col in exported.columns}
    exported.loc[exported.index[-1], "שם משתמש"] = "UNKNOWN_USER"
    exported.loc[exported.index[-1], "סטטוס סקירה"] = "נסקר"
    edited_path = tmp_path / "review_extra.xlsx"
    exported.to_excel(edited_path, sheet_name=USER_REVIEW_SHEET_NAME, index=False)

    result = import_user_review_from_excel(edited_path, report["dataframe"].copy())
    assert "UNKNOWN_USER" in result["unmatched"]
    assert result["matched"] == 2
