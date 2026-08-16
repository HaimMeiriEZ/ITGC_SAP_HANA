"""Tests for Sprint-1 catalog validators (PP-01, AL-01, AM-04)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.config import PROJECT_ROOT
from src.pipeline import load_exports, run_audit_analysis, run_catalog_validators
from src.validators.audit_policy import validate_audit_policy_enabled
from src.validators.critical_privileges import validate_critical_privileges
from src.validators.password_policy import validate_password_policy_baseline
from src.validators.registry import resolve_validator
from src.validators.spec_rules import is_control_implemented

SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.json"


@pytest.fixture(scope="module")
def settings() -> dict:
    return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def frames():
    return load_exports()


def test_sprint1_controls_are_implemented():
    assert is_control_implemented("DB-PP-01_PLACEHOLDER") is True
    assert is_control_implemented("DB-AL-01_PLACEHOLDER") is True
    assert is_control_implemented("DB-AM-04_PLACEHOLDER") is True
    assert is_control_implemented("DB-AM-03_PLACEHOLDER") is True


def test_resolve_validator_by_ref_and_analysis_type():
    assert resolve_validator({"validator_ref": "validate_password_policy_baseline"}) is validate_password_policy_baseline
    assert resolve_validator({"analysis_type": "AUDIT_POLICY_ENABLED"}) is validate_audit_policy_enabled
    assert resolve_validator({"validator_ref": "validate_critical_privileges"}) is validate_critical_privileges


def test_validate_password_policy_baseline(frames, settings):
    findings = validate_password_policy_baseline(
        frames,
        settings,
        {
            "control_id": "DB-PP-01_PLACEHOLDER",
            "analysis_type": "PASSWORD_POLICY_BASELINE",
        },
        period_id="2026-Q2",
    )
    assert findings
    assert all(f.control_id == "DB-PP-01_PLACEHOLDER" for f in findings)
    assert all(f.analysis_type == "PASSWORD_POLICY_BASELINE" for f in findings)
    assert all(f.source_slot == "M_PASSWORD_POLICY" for f in findings)


def test_validate_audit_policy_enabled(frames, settings):
    findings = validate_audit_policy_enabled(
        frames,
        settings,
        {
            "control_id": "DB-AL-01_PLACEHOLDER",
            "analysis_type": "AUDIT_POLICY_ENABLED",
        },
        period_id="2026-Q2",
    )
    assert findings
    assert all(f.control_id == "DB-AL-01_PLACEHOLDER" for f in findings)
    slots = {f.source_slot for f in findings}
    assert "M_INIFILE_CONTENTS" in slots or "AUDIT_POLICIES" in slots


def test_validate_critical_privileges(frames, settings):
    findings = validate_critical_privileges(
        frames,
        settings,
        {
            "control_id": "DB-AM-04_PLACEHOLDER",
            "analysis_type": "CRITICAL_PRIVILEGES",
        },
        period_id="2026-Q2",
    )
    assert findings
    assert all(f.control_id == "DB-AM-04_PLACEHOLDER" for f in findings)


def test_run_catalog_validators_returns_sprint1_findings(frames, settings):
    findings, warnings = run_catalog_validators(frames, settings, period_id="2026-Q2")
    control_ids = {f.control_id for f in findings}
    assert "DB-PP-01_PLACEHOLDER" in control_ids
    assert "DB-AL-01_PLACEHOLDER" in control_ids
    assert "DB-AM-04_PLACEHOLDER" in control_ids
    assert any("AUDIT_TRAIL" in warning for warning in warnings)


def test_run_audit_analysis_combines_validators_and_supplemental(frames, settings):
    findings, warnings = run_audit_analysis(frames, settings, period_id="2026-Q2")
    assert findings
    assert any(f.control_id == "DB-PP-01_PLACEHOLDER" for f in findings)
    assert isinstance(warnings, list)


def test_settings_password_lifetime_and_builtin_users(settings):
    assert settings["password_policy_defaults"]["maximum_password_lifetime"] == 90
    assert "_SYS_XB" in settings["builtin_users"]
    assert "SYSTEM" in settings["builtin_users"]
