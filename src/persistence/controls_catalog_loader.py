"""Controls catalog loader for SAP HANA DB — Phase 1 placeholder support."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.config import KNOWLEDGE_BASE_DIR
from src.validators.spec_rules import AUDIT_CONTROL_DEFINITIONS

logger = logging.getLogger(__name__)

CATALOG_FILENAME = "controls_catalog.json"

_MERGEABLE_FIELDS = (
    "title_he",
    "description",
    "process",
    "risk_description",
    "test_steps_override",
    "notes",
    "domain",
    "category",
    "implementation_status",
    "validator_ref",
)

_IDENTITY_FIELDS = (
    "control_id",
    "required_slots",
    "in_scope",
    "analysis_type",
)


def _catalog_path(knowledge_base_dir: Path | None = None) -> Path:
    base = Path(knowledge_base_dir) if knowledge_base_dir else KNOWLEDGE_BASE_DIR
    return base / CATALOG_FILENAME


def load_catalog(knowledge_base_dir: Path | None = None) -> list[dict[str, Any]]:
    path = _catalog_path(knowledge_base_dir)
    if not path.exists():
        logger.debug("controls_catalog.json not found at %s", path)
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        controls = data.get("controls", [])
        logger.info("Loaded controls catalog with %d entries from %s", len(controls), path)
        return controls
    except Exception as exc:
        logger.exception("Failed to load controls catalog %s: %s", path, exc)
        return []


def apply_catalog_to_definitions(
    controls: list[dict[str, Any]],
    definitions: dict[str, dict[str, str | list[str]]],
) -> None:
    for entry in controls:
        control_id = str(entry.get("control_id", "")).strip()
        if not control_id:
            continue
        target = definitions.get(control_id)
        if target is None:
            logger.debug("Catalog references unknown control_id %s — skipping", control_id)
            continue

        for field in _MERGEABLE_FIELDS:
            value = entry.get(field)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                target[field] = text

        required_slots = entry.get("required_slots")
        if isinstance(required_slots, list) and required_slots:
            target["required_tables"] = list(required_slots)

        analysis_type = str(entry.get("analysis_type", "") or "").strip()
        if analysis_type:
            target["analysis_type"] = analysis_type

        in_scope = entry.get("in_scope")
        if in_scope is not None:
            target["in_scope"] = "true" if in_scope else "false"


def load_and_apply_catalog(
    knowledge_base_dir: Path | None = None,
    definitions: dict[str, dict[str, str | list[str]]] | None = None,
) -> list[dict[str, Any]]:
    target_defs = definitions if definitions is not None else AUDIT_CONTROL_DEFINITIONS
    controls = load_catalog(knowledge_base_dir)
    if controls:
        apply_catalog_to_definitions(controls, target_defs)
    return controls


def load_controls_catalog(knowledge_base_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return merged catalog as control_id -> entry dict."""
    raw = load_and_apply_catalog(knowledge_base_dir)
    if raw:
        return {str(item["control_id"]): item for item in raw if item.get("control_id")}

    return {
        control_id: {
            "control_id": control_id,
            **{k: v for k, v in definition.items()},
        }
        for control_id, definition in AUDIT_CONTROL_DEFINITIONS.items()
    }


def get_control(control_id: str, knowledge_base_dir: Path | None = None) -> dict[str, Any] | None:
    catalog = load_controls_catalog(knowledge_base_dir)
    return catalog.get(control_id)


def list_controls_by_domain(domain: str, knowledge_base_dir: Path | None = None) -> list[dict[str, Any]]:
    catalog = load_controls_catalog(knowledge_base_dir)
    domain_upper = domain.strip()
    return [
        entry
        for entry in catalog.values()
        if str(entry.get("domain", "")).strip().lower() == domain_upper.lower()
    ]


def get_placeholder_controls(knowledge_base_dir: Path | None = None) -> list[dict[str, Any]]:
    catalog = load_controls_catalog(knowledge_base_dir)
    return [
        entry
        for entry in catalog.values()
        if str(entry.get("implementation_status", "")).lower() == "placeholder"
    ]


def get_control_in_scope(control_id: str, knowledge_base_dir: Path | None = None) -> bool:
    entry = get_control(control_id, knowledge_base_dir) or AUDIT_CONTROL_DEFINITIONS.get(control_id, {})
    return str(entry.get("in_scope", "true")).lower() != "false"
