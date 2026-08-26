"""Tests for user-review progress computation."""
from __future__ import annotations

import pandas as pd

from core.user_review import compute_review_progress, merge_existing_review_decisions


def test_compute_review_progress_empty():
    assert compute_review_progress(None) == {"total": 0, "reviewed": 0, "unreviewed": 0, "percent": 0}
    assert compute_review_progress(pd.DataFrame()) == {"total": 0, "reviewed": 0, "unreviewed": 0, "percent": 0}


def test_compute_review_progress_counts_reviewed_statuses():
    df = pd.DataFrame(
        {
            "user_name": ["A", "B", "C", "D"],
            "review_status": ["טרם נסקר", "נסקר", "דורש מעקב", ""],
        }
    )
    result = compute_review_progress(df)
    assert result["total"] == 4
    assert result["reviewed"] == 2
    assert result["unreviewed"] == 2
    assert result["percent"] == 50


def test_compute_review_progress_all_reviewed():
    df = pd.DataFrame({"review_status": ["נסקר", "נסקר", "דורש מעקב"]})
    result = compute_review_progress(df)
    assert result == {"total": 3, "reviewed": 3, "unreviewed": 0, "percent": 100}


def test_merge_existing_review_decisions_prefers_memory():
    db_rows = {
        "USER_A": {"review_status": "טרם נסקר", "manager_decision": ""},
        "USER_B": {"review_status": "טרם נסקר", "manager_decision": ""},
    }
    memory_df = pd.DataFrame(
        {
            "period_id": ["2026-Q3", "2026-Q3"],
            "user_name": ["USER_A", "USER_B"],
            "review_status": ["נסקר", "נסקר"],
            "manager_decision": ["מאושר", "מאושר"],
        }
    )
    merged = merge_existing_review_decisions(db_rows, memory_df, "2026-Q3")
    assert merged["USER_A"]["review_status"] == "נסקר"
    assert merged["USER_B"]["manager_decision"] == "מאושר"


def test_merge_existing_review_decisions_uses_memory_when_period_label_stale():
    memory_df = pd.DataFrame(
        {
            "period_id": ["2026-Q2", "2026-Q2"],
            "user_name": ["USER_A", "USER_B"],
            "review_status": ["נסקר", "נסקר"],
        }
    )
    merged = merge_existing_review_decisions({}, memory_df, "2026-Q3")
    assert merged["USER_A"]["review_status"] == "נסקר"
    assert merged["USER_B"]["review_status"] == "נסקר"


def test_merge_existing_review_decisions_ignores_other_period_rows():
    memory_df = pd.DataFrame(
        {
            "period_id": ["2025-Q3"],
            "user_name": ["USER_A"],
            "review_status": ["טרם נסקר"],
        }
    )
    merged = merge_existing_review_decisions({}, memory_df, "2026-Q3")
    assert merged == {}
