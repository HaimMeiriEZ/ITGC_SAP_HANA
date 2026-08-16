"""Catalog-driven validator runner and supplemental legacy checks."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import pandas as pd

from core.analyzer import AuditAnalyzer
from DataClasses import Finding

from src.persistence.controls_catalog_loader import load_controls_catalog
from src.validators.base import Frames, Settings, slot_loaded
from src.validators.registry import resolve_validator
from src.validators.spec_rules import AUDIT_CONTROL_DEFINITIONS, is_control_implemented

# Slots that are catalog-required but soft for Sprint 1 (warn, still run).
OPTIONAL_SLOTS_BY_CONTROL: dict[str, set[str]] = {
    "DB-AL-01_PLACEHOLDER": {"AUDIT_TRAIL"},
}


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"false", "0", "no", "לא"}


def _required_slots(entry: dict[str, Any], control_id: str) -> list[str]:
    definition = AUDIT_CONTROL_DEFINITIONS.get(control_id, {})
    slots = entry.get("required_slots") or definition.get("required_tables") or []
    if isinstance(slots, str):
        return [part.strip() for part in slots.replace(";", ",").split(",") if part.strip()]
    return [str(slot).strip() for slot in slots if str(slot).strip()]


def _hard_required_slots(control_id: str, slots: list[str]) -> list[str]:
    optional = OPTIONAL_SLOTS_BY_CONTROL.get(control_id, set())
    return [slot for slot in slots if slot not in optional]


def run_catalog_validators(
    frames: Frames,
    settings: Settings,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> tuple[list[Finding], list[str]]:
    """Run implemented in-scope validators. Returns (findings, warnings)."""
    catalog = load_controls_catalog()
    findings: list[Finding] = []
    warnings: list[str] = []

    for control_id, entry in sorted(catalog.items()):
        if not _as_bool(entry.get("in_scope", True)):
            continue
        if not is_control_implemented(control_id) and str(entry.get("implementation_status") or "").lower() != "implemented":
            continue

        meta = {
            "control_id": control_id,
            "control_id_ayalon": entry.get("control_id_ayalon"),
            "analysis_type": entry.get("analysis_type")
            or AUDIT_CONTROL_DEFINITIONS.get(control_id, {}).get("analysis_type"),
            "validator_ref": entry.get("validator_ref")
            or AUDIT_CONTROL_DEFINITIONS.get(control_id, {}).get("validator_ref"),
            "title_he": entry.get("title_he"),
        }
        validator = resolve_validator(meta)
        if validator is None:
            warnings.append(f"אין validator רשום עבור {control_id}")
            continue

        slots = _required_slots(entry, control_id)
        hard_slots = _hard_required_slots(control_id, slots)
        missing_hard = [slot for slot in hard_slots if not slot_loaded(frames, slot)]
        if missing_hard:
            warnings.append(
                f"דילוג על {control_id}: חסרים slots חובה ({', '.join(missing_hard)})"
            )
            continue

        for soft_slot in OPTIONAL_SLOTS_BY_CONTROL.get(control_id, set()):
            if soft_slot in slots and not slot_loaded(frames, soft_slot):
                warnings.append(f"{control_id}: slot אופציונלי חסר ({soft_slot})")

        findings.extend(
            validator(
                frames,
                settings,
                meta,
                whitelist=whitelist,
                period_id=period_id,
            )
        )

    return findings, warnings


def run_supplemental_analyzer_checks(
    frames: Frames,
    settings: Settings,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    """Legacy analyzer checks not yet covered by Sprint-1 validators."""
    config = deepcopy(settings)
    # AL-01 already covers global_auditing_state; keep other INI hardening here.
    config["ini_security_defaults"] = [
        entry
        for entry in config.get("ini_security_defaults", [])
        if str(entry.get("key", "")).strip().lower() != "global_auditing_state"
    ]

    analyzer = AuditAnalyzer(config=config, whitelist=whitelist)

    if slot_loaded(frames, "USERS"):
        analyzer.analyze_critical_users(frames["USERS"], period_id)

    # Role inheritance only if AM-04 did not already consume GRANTED_ROLES
    # (AM-04 is implemented and runs role analysis when roles are loaded).
    # Skip duplicate role findings when AM-04 is implemented.
    if not is_control_implemented("DB-AM-04_PLACEHOLDER"):
        privilege_df = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES") or frames.get("GRANTED_PRIVILEGES")
        roles_df = frames.get("GRANTED_ROLES")
        if roles_df is not None and not roles_df.empty:
            analyzer.analyze_role_assignments(roles_df, privilege_df, period_id)

    # Audit trail only when AL-01 did not already analyze it
    if not is_control_implemented("DB-AL-01_PLACEHOLDER"):
        trail = frames.get("AUDIT_TRAIL")
        if trail is not None and not trail.empty:
            analyzer.analyze_audit_trail(trail, period_id)

    if slot_loaded(frames, "M_INIFILE_CONTENTS") and config.get("ini_security_defaults"):
        analyzer.analyze_ini_configuration(frames["M_INIFILE_CONTENTS"], period_id)

    return list(analyzer.findings)


def run_audit_analysis(
    frames: dict[str, pd.DataFrame],
    settings: Settings,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> tuple[list[Finding], list[str]]:
    """Primary entry: catalog validators + supplemental legacy checks."""
    findings, warnings = run_catalog_validators(
        frames, settings, whitelist=whitelist, period_id=period_id
    )
    findings.extend(
        run_supplemental_analyzer_checks(
            frames, settings, whitelist=whitelist, period_id=period_id
        )
    )
    return findings, warnings
