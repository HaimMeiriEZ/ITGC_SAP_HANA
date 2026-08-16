"""Shared helpers for Stage-C validators."""
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Iterable, Optional

import pandas as pd

from core.user_review import _find_existing_column, _is_truthy, _normalize_text, _parse_date

TECHNICAL_NAME_PREFIXES = ("_SYS", "SYS_", "XSSQLCC_", "SAP", "AFL_")
TECHNICAL_EXACT = {"SYSTEM", "SYS", "DBACOCKPIT", "SAPDBCTRL", "SAPHANADB"}


def col(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    return _find_existing_column(df, candidates)


def norm(value: Any) -> str:
    return _normalize_text(value)


def parse_date(value: Any) -> Optional[datetime]:
    return _parse_date(value)


def is_true(value: Any) -> bool:
    return _is_truthy(value) is True


def is_false(value: Any) -> bool:
    return _is_truthy(value) is False


def is_deactivated(value: Any) -> bool:
    """USER_DEACTIVATED=TRUE means locked/deactivated."""
    return is_true(value)


def looks_technical(username: str) -> bool:
    name = username.strip().upper()
    if not name:
        return False
    if name in TECHNICAL_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in TECHNICAL_NAME_PREFIXES)


def period_end_from_settings(settings: dict, period_id: str = "") -> date:
    review = settings.get("user_review_period") or {}
    end_raw = review.get("end_date") or review.get("to") or review.get("end")
    parsed = parse_date(end_raw)
    if parsed is not None:
        return parsed.date()
    # Fallback: try to parse period_id like 2026-Q2
    text = str(period_id or "").strip().upper()
    if "-Q" in text:
        try:
            year_str, quarter_str = text.split("-Q", 1)
            year = int(year_str)
            quarter = int(quarter_str)
            month = quarter * 3
            # last day of quarter month
            if month == 12:
                return date(year, 12, 31)
            return date(year, month + 1, 1) - timedelta(days=1)
        except ValueError:
            pass
    return date.today()


def lookback_start(settings: dict, period_id: str = "", default_days: int = 180) -> date:
    days = int(settings.get("user_provisioning_lookback_days", default_days))
    return period_end_from_settings(settings, period_id) - timedelta(days=days)


def users_index(df: pd.DataFrame) -> dict[str, pd.Series]:
    user_col = col(df, ["USER_NAME", "USER", "NAME"])
    if user_col is None:
        return {}
    result: dict[str, pd.Series] = {}
    for _, row in df.iterrows():
        name = norm(row.get(user_col))
        if name:
            result[name.upper()] = row
    return result
