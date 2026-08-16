"""Tests for user-type override and incomplete-review findings."""
from __future__ import annotations

from datetime import date

import pandas as pd

from core.user_review import (
    REVIEW_COMPLETION_COMPARISON_RULE,
    build_review_completion_finding,
    build_user_review_report,
)


def _minimal_config() -> dict:
    return {
        "user_type_rules": {
            "Dialog": [],
            "Generic": [],
            "Technical": [],
            "Application": [],
        },
        "critical_users": [],
        "critical_privileges": [],
        "inactive_days_threshold": 120,
        "system_table_authorized_users": [],
    }


def test_build_user_review_report_prefers_saved_user_type():
    users_df = pd.DataFrame(
        [
            {
                "USER_NAME": "APP_USER_1",
                "LAST_SUCCESSFUL_CONNECT": "2026-01-15",
                "USER_DEACTIVATED": "FALSE",
            }
        ]
    )
    report = build_user_review_report(
        users_df=users_df,
        privileges_df=pd.DataFrame(columns=["GRANTEE", "PRIVILEGE"]),
        config=_minimal_config(),
        extract_dates={"USERS": "2026-01-01"},
        period_id="2026-Q1",
        review_date=date(2026, 8, 1),
        review_period_start=date(2026, 1, 1),
        review_period_end=date(2026, 3, 31),
        existing_reviews={
            "APP_USER_1": {
                "user_type": "Technical",
                "review_status": "נסקר",
                "manager_decision": "מאושר",
                "manager_comments": "",
                "action_required": "",
            }
        },
    )
    row = report["dataframe"].iloc[0]
    assert row["user_type"] == "Technical"
    assert row["review_status"] == "נסקר"
    assert report["summary"]["type_distribution"].get("Technical") == 1


def test_build_review_completion_finding_when_incomplete():
    df = pd.DataFrame(
        {
            "user_name": ["A", "B"],
            "review_status": ["נסקר", "טרם נסקר"],
        }
    )
    finding = build_review_completion_finding("2026-Q1", df)
    assert finding is not None
    assert finding.comparison_rule == REVIEW_COMPLETION_COMPARISON_RULE
    assert finding.actual_value == "50%"
    assert finding.status == "Non-Compliant"


def test_build_review_completion_finding_when_complete():
    df = pd.DataFrame({"review_status": ["נסקר", "דורש מעקב"]})
    assert build_review_completion_finding("2026-Q1", df) is None
    assert build_review_completion_finding("2026-Q1", None) is None
    assert build_review_completion_finding("2026-Q1", pd.DataFrame()) is None
