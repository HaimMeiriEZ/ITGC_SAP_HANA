"""Tests for supplemental → catalog control_id mapping."""
from __future__ import annotations

import pandas as pd

from core.analyzer import AuditAnalyzer
from core.supplemental_control_map import (
    control_meta_for_critical_user,
    control_meta_for_ini_key,
    filter_ini_defaults_for_supplemental,
    is_pp01_ini_key,
)


def test_ini_key_mapping():
    assert control_meta_for_ini_key("log_mode") == ("DB-AL-01_PLACEHOLDER", "AUDIT_POLICY_ENABLED")
    assert control_meta_for_ini_key("password_lock_for_system_user") == (
        "DB-PP-01_PLACEHOLDER",
        "PASSWORD_POLICY_BASELINE",
    )
    assert control_meta_for_ini_key("detailed_error_on_connect")[0] == "DB-PP-01_PLACEHOLDER"
    assert control_meta_for_ini_key("unknown_key") is None


def test_critical_user_mapping():
    assert control_meta_for_critical_user("SYSTEM") == (
        "DB-AM-03_PLACEHOLDER",
        "SYSTEM_USER_LOCKDOWN",
    )
    assert control_meta_for_critical_user("SYS")[0] == "DB-AM-02_PLACEHOLDER"
    assert control_meta_for_critical_user(None)[0] == "DB-AM-02_PLACEHOLDER"


def test_filter_skips_pp01_and_global_auditing():
    defaults = [
        {"key": "global_auditing_state"},
        {"key": "log_mode"},
        {"key": "minimal_password_length"},
    ]
    filtered = filter_ini_defaults_for_supplemental(defaults, skip_pp01_keys=True)
    keys = [str(item["key"]).lower() for item in filtered]
    assert keys == ["log_mode"]
    assert is_pp01_ini_key("minimal_password_length")


def test_analyze_ini_tags_control_ids():
    df = pd.DataFrame(
        [
            {
                "FILE_NAME": "global.ini",
                "SECTION": "persistence",
                "KEY": "log_mode",
                "VALUE": "normal",
            },
            {
                "FILE_NAME": "indexserver.ini",
                "SECTION": "password policy",
                "KEY": "minimal_password_length",
                "VALUE": "8",
            },
        ]
    )
    config = {
        "ini_security_defaults": [
            {
                "file_name": "global.ini",
                "section": "persistence",
                "key": "log_mode",
                "expected_value": "normal",
                "comparison_rule": "Exact",
                "risk_level": "High",
                "title": "Log mode",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "minimal_password_length",
                "expected_value": 8,
                "comparison_rule": "Minimum",
                "risk_level": "High",
                "title": "Min length",
            },
        ]
    }
    analyzer = AuditAnalyzer(config=config)
    analyzer.analyze_ini_configuration(df, "2026-Q3")
    control_ids = {f.control_id for f in analyzer.findings}
    assert "DB-AL-01_PLACEHOLDER" in control_ids
    assert "DB-PP-01_PLACEHOLDER" in control_ids
    log_finding = next(f for f in analyzer.findings if "log_mode" in (f.description or "").lower())
    pwd_finding = next(
        f for f in analyzer.findings if "minimal_password_length" in (f.description or "").lower()
    )
    assert log_finding.control_id == "DB-AL-01_PLACEHOLDER"
    assert pwd_finding.control_id == "DB-PP-01_PLACEHOLDER"


def test_analyze_critical_users_tags_am02():
    df = pd.DataFrame(
        [
            {"USER_NAME": "APPUSER", "LAST_SUCCESSFUL_CONNECT": "?"},
        ]
    )
    analyzer = AuditAnalyzer(config={"critical_users": ["SYSTEM", "SYS"]})
    analyzer.analyze_critical_users(df, "2026-Q3")
    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].control_id == "DB-AM-02_PLACEHOLDER"
    assert analyzer.findings[0].status == "Compliant"
