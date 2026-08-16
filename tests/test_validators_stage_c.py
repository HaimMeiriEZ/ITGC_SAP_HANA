"""Tests for Stage-C catalog validators."""
from __future__ import annotations

import json

import pytest

from src.config import PROJECT_ROOT
from src.pipeline import get_controls_catalog_summary, load_exports, run_catalog_validators
from src.persistence.controls_catalog_loader import get_placeholder_controls, load_and_apply_catalog
from src.validators.analytic_access import validate_analytic_object_access
from src.validators.builtin_users import validate_builtin_users_lockdown
from src.validators.password_exemptions import validate_password_policy_exemptions
from src.validators.registry import VALIDATOR_REGISTRY, resolve_validator
from src.validators.spec_rules import AUDIT_CONTROL_DEFINITIONS, is_control_implemented
from src.validators.system_tables import validate_system_table_access
from src.validators.system_user import validate_system_user_lockdown
from src.validators.user_population import validate_periodic_uar, validate_user_population
from src.validators.user_provisioning import validate_user_provisioning

SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.json"

STAGE_C_CONTROLS = [
    ("DB-AM-03_PLACEHOLDER", "SYSTEM_USER_LOCKDOWN", validate_system_user_lockdown),
    ("DB-AM-06_PLACEHOLDER", "SYSTEM_TABLE_ACCESS", validate_system_table_access),
    ("DB-AM-02_PLACEHOLDER", "BUILTIN_USERS_LOCKDOWN", validate_builtin_users_lockdown),
    ("DB-PP-02_PLACEHOLDER", "PASSWORD_POLICY_EXEMPTIONS", validate_password_policy_exemptions),
    ("DB-UAR-01_PLACEHOLDER", "USER_PROVISIONING", validate_user_provisioning),
    ("DB-AM-05_PLACEHOLDER", "ANALYTIC_OBJECT_ACCESS", validate_analytic_object_access),
    ("DB-AM-01_PLACEHOLDER", "USER_POPULATION_REVIEW", validate_user_population),
    ("DB-UAR-02_PLACEHOLDER", "PERIODIC_UAR", validate_periodic_uar),
]


@pytest.fixture(scope="module")
def settings() -> dict:
    return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def frames():
    return load_exports()


def test_all_eleven_controls_implemented():
    load_and_apply_catalog()
    assert len(AUDIT_CONTROL_DEFINITIONS) == 11
    assert all(is_control_implemented(cid) for cid in AUDIT_CONTROL_DEFINITIONS)
    assert len(get_placeholder_controls()) == 0


def test_stage_c_validators_registered():
    for control_id, analysis_type, fn in STAGE_C_CONTROLS:
        assert resolve_validator({"analysis_type": analysis_type}) is fn
        assert analysis_type in VALIDATOR_REGISTRY or f"validate_{analysis_type.lower()}" in VALIDATOR_REGISTRY


@pytest.mark.parametrize("control_id,analysis_type,fn", STAGE_C_CONTROLS)
def test_stage_c_validator_runs_on_samples(control_id, analysis_type, fn, frames, settings):
    findings = fn(
        frames,
        settings,
        {"control_id": control_id, "analysis_type": analysis_type},
        period_id="2026-Q2",
    )
    assert findings
    assert all(f.control_id == control_id for f in findings)
    assert all(f.analysis_type == analysis_type for f in findings)


def test_run_catalog_validators_covers_all_controls(frames, settings):
    findings, warnings = run_catalog_validators(frames, settings, period_id="2026-Q2")
    control_ids = {f.control_id for f in findings}
    for control_id, _, _ in STAGE_C_CONTROLS:
        assert control_id in control_ids
    assert "DB-PP-01_PLACEHOLDER" in control_ids
    assert "DB-AL-01_PLACEHOLDER" in control_ids
    assert "DB-AM-04_PLACEHOLDER" in control_ids


def test_catalog_summary_all_implemented():
    summary = get_controls_catalog_summary()
    assert len(summary) == 11
    assert all(row["status"] == "Implemented" for row in summary)


def test_settings_stage_c_keys(settings):
    assert settings.get("user_provisioning_lookback_days") == 180
    assert "builtin_users" in settings
    assert "system_table_authorized_users" in settings
