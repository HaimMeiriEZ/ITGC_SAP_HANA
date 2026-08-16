"""Tests for user-review progress computation."""
from __future__ import annotations

import pandas as pd

from core.user_review import compute_review_progress


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
