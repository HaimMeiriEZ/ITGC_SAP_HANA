"""Smoke tests for HANA export reader, catalog loader, and pipeline."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.config import SAMPLES_DIR, SLOT_KEYS
from src.persistence.controls_catalog_loader import (
    get_control_in_scope,
    get_placeholder_controls,
    load_and_apply_catalog,
    load_catalog,
    load_controls_catalog,
    save_catalog,
)
from src.pipeline import (
    get_controls_catalog_summary,
    get_missing_sample_slots,
    load_exports,
    validate_required_slots_loaded,
)
from src.readers.hana_export_reader import detect_slot_from_file, read_hana_export
from src.validators.spec_rules import AUDIT_CONTROL_DEFINITIONS, is_control_implemented

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLE_EXPECTATIONS = {
    "USERS_sample.txt": {
        "slot": "USERS",
        "columns": ["USER_NAME", "LAST_SUCCESSFUL_CONNECT", "USER_DEACTIVATED"],
    },
    "GRANTED_PRIVILEGES_sample.txt": {
        "slot": "GRANTED_PRIVILEGES",
        "columns": ["GRANTEE", "PRIVILEGE", "OBJECT_TYPE", "IS_VALID"],
    },
    "EFFECTIVE_PRIVILEGE_GRANTEES_sample.txt": {
        "slot": "EFFECTIVE_PRIVILEGE_GRANTEES",
        "columns": ["GRANTEE", "PRIVILEGE", "OBJECT_TYPE", "IS_GRANTABLE"],
    },
    "CONFIGURATION_PARAMETER_PROPERTIES_sample.txt": {
        "slot": "CONFIGURATION_PARAMETER_PROPERTIES",
        "columns": ["SECTION", "KEY", "DEFAULT_VALUE", "INIFILE_NAMES"],
    },
    "GRANTED_ROLES_sample.txt": {
        "slot": "GRANTED_ROLES",
        "columns": ["GRANTEE", "ROLE_NAME", "GRANTEE_TYPE"],
    },
    "AUDIT_POLICIES_sample.txt": {
        "slot": "AUDIT_POLICIES",
        "columns": ["AUDIT_POLICY_NAME", "IS_AUDIT_POLICY_ACTIVE"],
    },
    "M_INIFILE_CONTENTS_sample.txt": {
        "slot": "M_INIFILE_CONTENTS",
        "columns": ["SECTION", "KEY", "VALUE"],
    },
    "M_PASSWORD_POLICY_sample.txt": {
        "slot": "M_PASSWORD_POLICY",
        "columns": ["PROPERTY", "VALUE"],
    },
}


@pytest.mark.parametrize("filename,expected", list(SAMPLE_EXPECTATIONS.items()))
def test_reader_loads_sample_with_expected_columns(filename, expected):
    path = SAMPLES_DIR / filename
    assert path.exists(), f"sample missing: {path}"

    result = read_hana_export(path)
    assert result.df is not None
    assert not result.df.empty
    assert result.slot_key == expected["slot"]

    first_col = str(result.df.columns[0]).strip().upper()
    assert not (first_col == "" or first_col.startswith("UNNAMED"))

    for column in expected["columns"]:
        assert column in result.df.columns


@pytest.mark.parametrize("filename,expected", list(SAMPLE_EXPECTATIONS.items()))
def test_slot_detection_from_file(filename, expected):
    path = SAMPLES_DIR / filename
    assert detect_slot_from_file(path) == expected["slot"]


def test_catalog_has_eleven_controls_all_implemented():
    controls = load_and_apply_catalog()
    assert len(controls) == 11
    placeholders = get_placeholder_controls()
    assert len(placeholders) == 0


def test_all_controls_marked_implemented():
    for control_id in AUDIT_CONTROL_DEFINITIONS:
        assert is_control_implemented(control_id) is True


def test_load_exports_from_samples_returns_eight_frames():
    frames = load_exports()
    assert len(frames) == 8
    for slot in [
        "USERS",
        "GRANTED_PRIVILEGES",
        "EFFECTIVE_PRIVILEGE_GRANTEES",
        "GRANTED_ROLES",
        "AUDIT_POLICIES",
        "M_INIFILE_CONTENTS",
        "M_PASSWORD_POLICY",
        "CONFIGURATION_PARAMETER_PROPERTIES",
    ]:
        assert slot in frames
        assert not frames[slot].empty


def test_audit_trail_missing_from_samples():
    missing = get_missing_sample_slots()
    assert "AUDIT_TRAIL" in missing


def test_validate_required_slots_for_audit_trail_control():
    frames = load_exports()
    warnings = validate_required_slots_loaded(frames, "DB-AL-01_PLACEHOLDER")
    assert any("AUDIT_TRAIL" in warning for warning in warnings)


def test_controls_catalog_summary_for_ui():
    summary = get_controls_catalog_summary()
    assert len(summary) == 11
    assert all(row["status"] == "Implemented" for row in summary)
    assert all("control_id_ayalon" in row for row in summary)
    assert all("description" in row for row in summary)
    assert all("risk_description" in row for row in summary)
    am01 = next(row for row in summary if row["control_id"] == "DB-AM-01_PLACEHOLDER")
    assert am01["control_id_ayalon"] == "DB-AM-01_01_01_05_72"
    assert am01["description"]
    assert am01["risk_description"]
    assert am01["notify_technical"] is True
    assert am01["notify_business"] is True
    pp01 = next(row for row in summary if row["control_id"] == "DB-PP-01_PLACEHOLDER")
    assert pp01["notify_technical"] is True
    assert pp01["notify_business"] is False


def test_save_catalog_roundtrip(tmp_path: Path):
    source_controls = load_catalog()
    assert source_controls
    target_dir = tmp_path / "knowledge_base"
    # Copy-like write of current catalog then mutate and reload
    save_catalog(source_controls, knowledge_base_dir=target_dir)
    loaded = load_catalog(knowledge_base_dir=target_dir)
    assert len(loaded) == len(source_controls)

    for item in loaded:
        if str(item.get("control_id")) == "DB-AM-01_PLACEHOLDER":
            item["control_id_ayalon"] = "TEST-AYALON-ID"
            item["description"] = "תיאור בדיקה"
            item["risk_description"] = "סיכון בדיקה"
            break
    save_catalog(loaded, knowledge_base_dir=target_dir)

    reloaded = load_controls_catalog(knowledge_base_dir=target_dir)
    entry = reloaded["DB-AM-01_PLACEHOLDER"]
    assert entry["control_id_ayalon"] == "TEST-AYALON-ID"
    assert entry["description"] == "תיאור בדיקה"
    assert entry["risk_description"] == "סיכון בדיקה"


def test_save_catalog_in_scope_false_roundtrip(tmp_path: Path):
    source_controls = load_catalog()
    assert source_controls
    target_dir = tmp_path / "knowledge_base"
    save_catalog(source_controls, knowledge_base_dir=target_dir)

    loaded = load_catalog(knowledge_base_dir=target_dir)
    for item in loaded:
        if str(item.get("control_id")) == "DB-AL-01_PLACEHOLDER":
            item["in_scope"] = False
            break
    save_catalog(loaded, knowledge_base_dir=target_dir)

    assert get_control_in_scope("DB-AL-01_PLACEHOLDER", knowledge_base_dir=target_dir) is False
    reloaded = load_controls_catalog(knowledge_base_dir=target_dir)
    assert reloaded["DB-AL-01_PLACEHOLDER"]["in_scope"] is False


def test_catalog_merge_json_and_spec_rules():
    catalog = load_controls_catalog()
    assert "DB-AM-01_PLACEHOLDER" in catalog
    entry = catalog["DB-AM-01_PLACEHOLDER"]
    assert entry.get("title_he") == "סקירת המשתמשים"
    assert "USERS" in (entry.get("required_slots") or entry.get("required_tables") or [])
