"""Map legacy supplemental analyzer findings to catalog control_ids."""
from __future__ import annotations

from typing import Any

# Password-policy INI keys covered by DB-PP-01 (also listed in controls_catalog description).
PP01_INI_KEYS = frozenset(
    {
        "detailed_error_on_connect",
        "password_lock_for_system_user",
        "force_first_password_change",
        "minimal_password_length",
        "maximum_invalid_connect_attempts",
        "last_used_passwords",
        "password_expire_warning_time",
        "password_lock_time",
        "minimal_password_lifetime",
        "maximum_password_lifetime",
        "maximum_unused_initial_password_lifetime",
        "maximum_unused_productive_password_lifetime",
        "password_layout",
    }
)

AL01_INI_KEYS = frozenset(
    {
        "log_mode",
        "global_auditing_state",
    }
)

_CONTROL_META = {
    "DB-PP-01_PLACEHOLDER": "PASSWORD_POLICY_BASELINE",
    "DB-AL-01_PLACEHOLDER": "AUDIT_POLICY_ENABLED",
    "DB-AM-02_PLACEHOLDER": "BUILTIN_USERS_LOCKDOWN",
    "DB-AM-03_PLACEHOLDER": "SYSTEM_USER_LOCKDOWN",
}


def control_meta_for_ini_key(key: str) -> tuple[str, str] | None:
    """Return (control_id, analysis_type) for an INI security key, or None."""
    normalized = str(key or "").strip().lower()
    if not normalized:
        return None
    if normalized in AL01_INI_KEYS:
        control_id = "DB-AL-01_PLACEHOLDER"
    elif normalized in PP01_INI_KEYS:
        control_id = "DB-PP-01_PLACEHOLDER"
    else:
        return None
    return control_id, _CONTROL_META[control_id]


def control_meta_for_critical_user(user_name: str | None = None) -> tuple[str, str]:
    """Map critical-user login checks to AM-02 (built-in) or AM-03 (SYSTEM)."""
    normalized = str(user_name or "").strip().upper()
    if normalized == "SYSTEM":
        control_id = "DB-AM-03_PLACEHOLDER"
    else:
        control_id = "DB-AM-02_PLACEHOLDER"
    return control_id, _CONTROL_META[control_id]


def is_pp01_ini_key(key: str) -> bool:
    return str(key or "").strip().lower() in PP01_INI_KEYS


def filter_ini_defaults_for_supplemental(
    ini_defaults: list[dict[str, Any]],
    *,
    skip_pp01_keys: bool,
    skip_global_auditing_state: bool = True,
) -> list[dict[str, Any]]:
    """Filter ini_security_defaults before supplemental INI analysis."""
    filtered: list[dict[str, Any]] = []
    for entry in ini_defaults or []:
        key = str(entry.get("key", "") or "").strip().lower()
        if skip_global_auditing_state and key == "global_auditing_state":
            continue
        if skip_pp01_keys and is_pp01_ini_key(key):
            continue
        filtered.append(entry)
    return filtered
