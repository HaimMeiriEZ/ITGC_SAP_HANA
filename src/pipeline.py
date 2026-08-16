"""Thin orchestration layer — Phase 1 SAP HANA DB."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from src.config import SAMPLES_DIR, SLOT_KEYS
from src.persistence.controls_catalog_loader import get_placeholder_controls, load_controls_catalog
from src.readers.hana_export_reader import ReadResult, detect_slot_from_file, read_exports, read_hana_export
from src.validators.runner import run_audit_analysis, run_catalog_validators
from src.validators.spec_rules import AUDIT_CONTROL_DEFINITIONS, get_control_required_slots


def load_slot_file(path: str | Path) -> ReadResult:
    return read_hana_export(path)


def load_exports(paths: list[Path] | None = None) -> dict[str, pd.DataFrame]:
    if paths is None:
        paths = sorted(SAMPLES_DIR.glob("*_sample.txt"))
    read_results = read_exports(paths)
    return {
        slot_key: result.df
        for slot_key, result in read_results.items()
        if result.df is not None
    }


def get_controls_catalog_summary() -> list[dict[str, Any]]:
    catalog = load_controls_catalog()
    rows: list[dict[str, Any]] = []
    for control_id in sorted(catalog.keys()):
        entry = catalog[control_id]
        definition = AUDIT_CONTROL_DEFINITIONS.get(control_id, {})
        required_slots = entry.get("required_slots") or definition.get("required_tables") or []
        if isinstance(required_slots, str):
            required_slots = [required_slots]
        status = str(entry.get("implementation_status") or definition.get("implementation_status", ""))
        status_lower = status.lower()
        if status_lower == "placeholder":
            display_status = "Placeholder — טרם יושם"
        elif status_lower == "implemented":
            display_status = "Implemented"
        else:
            display_status = status
        rows.append(
            {
                "control_id": control_id,
                "title_he": entry.get("title_he") or definition.get("title_he") or definition.get("title", ""),
                "domain": entry.get("domain") or definition.get("domain", ""),
                "required_slots": ", ".join(required_slots),
                "status": display_status,
                "in_scope": entry.get("in_scope", True),
            }
        )
    return rows


def validate_required_slots_loaded(
    frames: dict[str, pd.DataFrame],
    control_id: str,
) -> list[str]:
    warnings: list[str] = []
    for slot_key in get_control_required_slots(control_id):
        if slot_key not in frames or frames[slot_key] is None or frames[slot_key].empty:
            warnings.append(f"slot חסר עבור בקרה {control_id}: {slot_key}")
    return warnings


def get_missing_sample_slots() -> list[str]:
    loaded = load_exports()
    return [slot for slot in SLOT_KEYS if slot not in loaded]


def count_placeholder_controls() -> int:
    return len(get_placeholder_controls())


__all__ = [
    "count_placeholder_controls",
    "get_controls_catalog_summary",
    "get_missing_sample_slots",
    "load_exports",
    "load_slot_file",
    "run_audit_analysis",
    "run_catalog_validators",
    "validate_required_slots_loaded",
]
