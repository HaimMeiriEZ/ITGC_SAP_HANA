"""Audit control definitions — SAP HANA DB ITGC catalog (11 controls)."""
from __future__ import annotations

from src.config import SLOT_DEFAULT_CONTROLS

AUDIT_CONTROL_DEFINITIONS: dict[str, dict[str, str | list[str]]] = {
    "DB-AM-01_PLACEHOLDER": {
        "title": "סקירת המשתמשים (placeholder)",
        "title_he": "סקירת המשתמשים",
        "domain": "UAR",
        "category": "Access Management",
        "required_tables": ["USERS"],
        "analysis_type": "USER_POPULATION_REVIEW",
        "implementation_status": "implemented",
        "validator_ref": "validate_user_population",
        "in_scope": "true",
    },
    "DB-AM-02_PLACEHOLDER": {
        "title": "משתמשי BUILT IN (placeholder)",
        "title_he": "משתמשי BUILT IN שהגיעו עם המערכת",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["USERS", "EFFECTIVE_PRIVILEGE_GRANTEES"],
        "analysis_type": "BUILTIN_USERS_LOCKDOWN",
        "implementation_status": "implemented",
        "validator_ref": "validate_builtin_users_lockdown",
        "in_scope": "true",
    },
    "DB-AM-03_PLACEHOLDER": {
        "title": "משתמש SYSTEM (placeholder)",
        "title_he": "משתמש ברירת מחדל פריבילגי",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["USERS"],
        "analysis_type": "SYSTEM_USER_LOCKDOWN",
        "implementation_status": "implemented",
        "validator_ref": "validate_system_user_lockdown",
        "in_scope": "true",
    },
    "DB-AM-04_PLACEHOLDER": {
        "title": "משתמשים פריבילגיים (placeholder)",
        "title_he": "משתמשים פריבילגיים",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["USERS", "EFFECTIVE_PRIVILEGE_GRANTEES", "GRANTED_ROLES"],
        "analysis_type": "CRITICAL_PRIVILEGES",
        "implementation_status": "implemented",
        "validator_ref": "validate_critical_privileges",
        "in_scope": "true",
    },
    "DB-AM-05_PLACEHOLDER": {
        "title": "הרשאות אנליטיות (placeholder)",
        "title_he": "הרשאות אנליטיות",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["EFFECTIVE_PRIVILEGE_GRANTEES"],
        "analysis_type": "ANALYTIC_OBJECT_ACCESS",
        "implementation_status": "implemented",
        "validator_ref": "validate_analytic_object_access",
        "in_scope": "true",
    },
    "DB-AM-06_PLACEHOLDER": {
        "title": "הרשאות לטבלאות מערכת (placeholder)",
        "title_he": "הרשאות לטבלאות מערכת",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["EFFECTIVE_PRIVILEGE_GRANTEES"],
        "analysis_type": "SYSTEM_TABLE_ACCESS",
        "implementation_status": "implemented",
        "validator_ref": "validate_system_table_access",
        "in_scope": "true",
    },
    "DB-PP-01_PLACEHOLDER": {
        "title": "מדיניות סיסמה — טבלה (placeholder)",
        "title_he": "מדיניות סיסמה (טבלה)",
        "domain": "Password",
        "category": "Password Policy",
        "required_tables": ["M_PASSWORD_POLICY"],
        "analysis_type": "PASSWORD_POLICY_BASELINE",
        "implementation_status": "implemented",
        "validator_ref": "validate_password_policy_baseline",
        "in_scope": "true",
    },
    "DB-PP-02_PLACEHOLDER": {
        "title": "החרגה ממדיניות סיסמאות (placeholder)",
        "title_he": "החרגה ממדיניות סיסמאות",
        "domain": "Password",
        "category": "Password Policy",
        "required_tables": ["USERS", "EFFECTIVE_PRIVILEGE_GRANTEES"],
        "analysis_type": "PASSWORD_POLICY_EXEMPTIONS",
        "implementation_status": "implemented",
        "validator_ref": "validate_password_policy_exemptions",
        "in_scope": "true",
    },
    "DB-AL-01_PLACEHOLDER": {
        "title": "מדיניות audit (placeholder)",
        "title_he": "מדיניות audit",
        "domain": "Audit",
        "category": "Audit Logging",
        "required_tables": ["M_INIFILE_CONTENTS", "AUDIT_POLICIES", "AUDIT_TRAIL"],
        "analysis_type": "AUDIT_POLICY_ENABLED",
        "implementation_status": "implemented",
        "validator_ref": "validate_audit_policy_enabled",
        "in_scope": "true",
    },
    "DB-UAR-01_PLACEHOLDER": {
        "title": "הקמת משתמשים חדשים (placeholder)",
        "title_he": "הקמת משתמשים חדשים",
        "domain": "Access",
        "category": "Access Management",
        "required_tables": ["USERS", "GRANTED_ROLES", "EFFECTIVE_PRIVILEGE_GRANTEES"],
        "analysis_type": "USER_PROVISIONING",
        "implementation_status": "implemented",
        "validator_ref": "validate_user_provisioning",
        "in_scope": "true",
    },
    "DB-UAR-02_PLACEHOLDER": {
        "title": "סקירת הרשאות תקופתית (placeholder)",
        "title_he": "סקירת הרשאות תקופתית",
        "domain": "UAR",
        "category": "Access Management",
        "required_tables": ["USERS", "GRANTED_PRIVILEGES"],
        "analysis_type": "PERIODIC_UAR",
        "implementation_status": "implemented",
        "validator_ref": "validate_periodic_uar",
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
