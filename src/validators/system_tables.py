"""AM-06 — system table access."""
from __future__ import annotations

from core.user_review import (
    SYSTEM_TABLE_NAMES,
    _build_system_table_access_lookup,
    _derive_system_table_access_status,
)
from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings


def validate_system_table_access(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    del whitelist
    privs = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")
    if privs is None or privs.empty:
        privs = frames.get("GRANTED_PRIVILEGES")
    if privs is None or privs.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="קלט הרשאות חסר לבקרת טבלאות מערכת",
                    description="נדרש EFFECTIVE_PRIVILEGE_GRANTEES לבדיקת גישה לטבלאות M_*.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            ],
            control_meta,
        )

    authorized = settings.get("system_table_authorized_users") or settings.get("critical_users") or []
    authorized_upper = {str(u).strip().upper() for u in authorized}
    lookup = _build_system_table_access_lookup(privs)
    findings: list[Finding] = []

    if lookup is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="מבנה הרשאות אינו תומך בבדיקת טבלאות מערכת",
                    description="חסרות עמודות GRANTEE / OBJECT_NAME בטבלת ההרשאות.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            ],
            control_meta,
        )

    if not lookup:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="לא זוהתה גישה לחמש טבלאות המערכת",
                description=(
                    "לא נמצאו הרשאות על: "
                    + ", ".join(sorted(SYSTEM_TABLE_NAMES))
                ),
                risk_level="Low",
                status="Compliant",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            )
        )
        return tag_findings(findings, control_meta)

    for grantee, _bucket in sorted(lookup.items()):
        status = _derive_system_table_access_status(grantee, lookup, authorized_upper)
        tables = ", ".join(status["tables"]) or "-"
        if status["non_readonly_privileges"]:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"הרשאת כתיבה לטבלת מערכת | {grantee}",
                    description=(
                        f"ל-{grantee} הרשאות לא-קריאה ({', '.join(status['non_readonly_privileges'])}) "
                        f"על טבלאות: {tables}."
                    ),
                    risk_level="High",
                    status="Non-Compliant",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                    actual_value=", ".join(status["non_readonly_privileges"]),
                    expected_value="SELECT בלבד",
                )
            )
        elif status["is_authorized"] is False:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"גישה לא מורשית לטבלת מערכת | {grantee}",
                    description=(
                        f"ל-{grantee} יש גישה (SELECT) לטבלאות {tables} "
                        "והוא אינו ברשימת system_table_authorized_users / critical_users."
                    ),
                    risk_level="Medium",
                    status="Non-Compliant",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                    actual_value=tables,
                    expected_value="משתמש מורשה בלבד",
                )
            )
        else:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"גישת קריאה מורשית לטבלת מערכת | {grantee}",
                    description=f"גישת SELECT ל-{tables} עבור משתמש מורשה.",
                    risk_level="Low",
                    status="Compliant",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            )

    return tag_findings(findings, control_meta)
