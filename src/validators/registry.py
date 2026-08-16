"""Registry mapping validator_ref / analysis_type to callable validators."""
from __future__ import annotations

from src.validators.analytic_access import validate_analytic_object_access
from src.validators.audit_policy import validate_audit_policy_enabled
from src.validators.base import ValidatorCallable
from src.validators.builtin_users import validate_builtin_users_lockdown
from src.validators.critical_privileges import validate_critical_privileges
from src.validators.password_exemptions import validate_password_policy_exemptions
from src.validators.password_policy import validate_password_policy_baseline
from src.validators.system_tables import validate_system_table_access
from src.validators.system_user import validate_system_user_lockdown
from src.validators.user_population import validate_periodic_uar, validate_user_population
from src.validators.user_provisioning import validate_user_provisioning

VALIDATOR_REGISTRY: dict[str, ValidatorCallable] = {
    "validate_password_policy_baseline": validate_password_policy_baseline,
    "PASSWORD_POLICY_BASELINE": validate_password_policy_baseline,
    "validate_audit_policy_enabled": validate_audit_policy_enabled,
    "AUDIT_POLICY_ENABLED": validate_audit_policy_enabled,
    "validate_critical_privileges": validate_critical_privileges,
    "CRITICAL_PRIVILEGES": validate_critical_privileges,
    "validate_system_user_lockdown": validate_system_user_lockdown,
    "SYSTEM_USER_LOCKDOWN": validate_system_user_lockdown,
    "validate_system_table_access": validate_system_table_access,
    "SYSTEM_TABLE_ACCESS": validate_system_table_access,
    "validate_builtin_users_lockdown": validate_builtin_users_lockdown,
    "BUILTIN_USERS_LOCKDOWN": validate_builtin_users_lockdown,
    "validate_password_policy_exemptions": validate_password_policy_exemptions,
    "PASSWORD_POLICY_EXEMPTIONS": validate_password_policy_exemptions,
    "validate_user_provisioning": validate_user_provisioning,
    "USER_PROVISIONING": validate_user_provisioning,
    "validate_analytic_object_access": validate_analytic_object_access,
    "ANALYTIC_OBJECT_ACCESS": validate_analytic_object_access,
    "validate_user_population": validate_user_population,
    "USER_POPULATION_REVIEW": validate_user_population,
    "validate_periodic_uar": validate_periodic_uar,
    "PERIODIC_UAR": validate_periodic_uar,
}


def resolve_validator(control_meta: dict) -> ValidatorCallable | None:
    for key in (
        str(control_meta.get("validator_ref") or "").strip(),
        str(control_meta.get("analysis_type") or "").strip(),
    ):
        if key and key in VALIDATOR_REGISTRY:
            return VALIDATOR_REGISTRY[key]
    return None
