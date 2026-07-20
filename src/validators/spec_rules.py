"""Audit control definitions — Phase 1 placeholder metadata for SAP HANA DB."""
from __future__ import annotations

from src.config import SLOT_DEFAULT_CONTROLS

AUDIT_CONTROL_DEFINITIONS: dict[str, dict[str, str | list[str]]] = {
    "DB-AM-01_PLACEHOLDER": {
        "title": "משתמשים קריטיים (placeholder)",
        "title_he": "משתמשים קריטיים",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["USERS"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-AM-02_PLACEHOLDER": {
        "title": "הרשאות ניהול ישירות (placeholder)",
        "title_he": "הרשאות ניהול ישירות",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["GRANTED_PRIVILEGES"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-AM-03_PLACEHOLDER": {
        "title": "הרשאות דרך roles (placeholder)",
        "title_he": "הרשאות דרך roles",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["GRANTED_ROLES", "GRANTED_PRIVILEGES"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-PP-01_PLACEHOLDER": {
        "title": "מדיניות סיסמה — טבלה (placeholder)",
        "title_he": "מדיניות סיסמה (טבלה)",
        "domain": "Password",
        "category": "Password Policy",
        "required_tables": ["M_PASSWORD_POLICY"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-PP-02_PLACEHOLDER": {
        "title": "פרמטרי INI לסיסמה (placeholder)",
        "title_he": "פרמטרי INI לסיסמה",
        "domain": "Password",
        "category": "Password Policy",
        "required_tables": ["M_INIFILE_CONTENTS"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-AL-01_PLACEHOLDER": {
        "title": "מדיניות audit (placeholder)",
        "title_he": "מדיניות audit",
        "domain": "Audit",
        "category": "Audit Logging",
        "required_tables": ["AUDIT_POLICIES"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-AL-02_PLACEHOLDER": {
        "title": "audit trail (placeholder)",
        "title_he": "audit trail",
        "domain": "Audit",
        "category": "Audit Logging",
        "required_tables": ["AUDIT_TRAIL"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-CF-01_PLACEHOLDER": {
        "title": "hardening INI (placeholder)",
        "title_he": "hardening INI",
        "domain": "Config",
        "category": "Configuration Hardening",
        "required_tables": ["M_INIFILE_CONTENTS"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
    "DB-UAR-01_PLACEHOLDER": {
        "title": "סקירת גישה (placeholder)",
        "title_he": "סקירת גישה",
        "domain": "UAR",
        "category": "User Access Review",
        "required_tables": ["USERS", "GRANTED_PRIVILEGES"],
        "implementation_status": "placeholder",
        "validator_ref": "",
        "in_scope": "true",
    },
}

CONTROL_REQUIRED_TABLES: dict[str, list[str]] = {
    control_id: list(definition.get("required_tables", []))
    for control_id, definition in AUDIT_CONTROL_DEFINITIONS.items()
}


def is_control_implemented(control_id: str) -> bool:
    entry = AUDIT_CONTROL_DEFINITIONS.get(control_id, {})
    return str(entry.get("implementation_status", "")).lower() == "implemented"


def get_control_required_slots(control_id: str) -> list[str]:
    entry = AUDIT_CONTROL_DEFINITIONS.get(control_id, {})
    tables = entry.get("required_tables", [])
    return list(tables) if isinstance(tables, list) else []


__all__ = [
    "AUDIT_CONTROL_DEFINITIONS",
    "CONTROL_REQUIRED_TABLES",
    "SLOT_DEFAULT_CONTROLS",
    "get_control_required_slots",
    "is_control_implemented",
]
