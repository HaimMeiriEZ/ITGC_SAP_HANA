"""AM-05 — analytic / _SYS_REPO object access."""
from __future__ import annotations

from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings
from src.validators.helpers import col, norm

READ_PRIVS = {"SELECT", "REPO.READ"}
MODIFY_PRIVS = {
    "INSERT",
    "UPDATE",
    "ALTER",
    "REPO.EDIT_NATIVE_OBJECTS",
    "REPO.ACTIVATE",
    "REPO.EDIT_IMPORTED_OBJECTS",
}
DELETE_PRIVS = {"DELETE", "DROP"}


def _is_analytic_row(schema: str, object_type: str) -> bool:
    if schema.upper() == "_SYS_REPO":
        return True
    ot = object_type.upper()
    return ot in {"REPO", "ANALYTICALPRIVILEGE", "ANALYTICAL PRIVILEGE"}


def _classify(privilege: str, object_type: str) -> str | None:
    priv = privilege.upper()
    ot = object_type.upper()
    if priv == "EXECUTE" and "ANALYTICAL" in ot:
        return "execute"
    if priv in READ_PRIVS:
        return "read"
    if priv in MODIFY_PRIVS:
        return "modify"
    if priv in DELETE_PRIVS:
        return "delete"
    if priv in {"ALL", "ALL PRIVILEGES"}:
        return "modify"
    return None


def validate_analytic_object_access(
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
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="קלט הרשאות חסר לבקרת הרשאות אנליטיות",
                    description="נדרש EFFECTIVE_PRIVILEGE_GRANTEES לבדיקת _SYS_REPO / REPO.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            ],
            control_meta,
        )

    grantee_col = col(privs, ["GRANTEE", "USER_NAME", "USER"])
    priv_col = col(privs, ["PRIVILEGE", "PRIVILEGE_TYPE", "OBJECT_PRIVILEGE"])
    schema_col = col(privs, ["SCHEMA_NAME", "SCHEMA", "OBJECT_SCHEMA"])
    type_col = col(privs, ["OBJECT_TYPE"])
    object_col = col(privs, ["OBJECT_NAME", "OBJECT", "TABLE_NAME"])
    if grantee_col is None or priv_col is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="מבנה הרשאות אינו תומך בבדיקה אנליטית",
                    description="חסרות עמודות GRANTEE / PRIVILEGE.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            ],
            control_meta,
        )

    authorized_developers = {
        str(u).strip().upper()
        for u in settings.get("analytic_authorized_developers", [])
        if str(u).strip()
    }
    critical_users = {str(u).strip().upper() for u in settings.get("critical_users", [])}

    findings: list[Finding] = []
    modify_count = 0
    read_count = 0

    for _, row in privs.iterrows():
        grantee = norm(row.get(grantee_col))
        privilege = norm(row.get(priv_col))
        schema = norm(row.get(schema_col)) if schema_col else ""
        object_type = norm(row.get(type_col)) if type_col else ""
        object_name = norm(row.get(object_col)) if object_col else ""
        if not grantee or not privilege:
            continue
        if not _is_analytic_row(schema, object_type):
            continue

        kind = _classify(privilege, object_type)
        if kind is None or kind == "execute":
            continue
        if kind == "read":
            read_count += 1
            continue

        modify_count += 1
        upper = grantee.upper()
        allowed = upper in authorized_developers or upper in critical_users
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title=f"הרשאת {kind} על אובייקט אנליטי | {grantee}",
                description=(
                    f"{grantee} מחזיק {privilege} על schema={schema or '-'} "
                    f"object_type={object_type or '-'} object={object_name or '-'}. "
                    + (
                        "ברשימת מורשים — לאימות סביבת DEV/PRD ידנית."
                        if allowed
                        else "לא ברשימת analytic_authorized_developers — ממצא מועמד."
                    )
                ),
                risk_level="Low" if allowed else "High",
                status="Compliant" if allowed else "Non-Compliant",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                actual_value=privilege,
                expected_value="קריאה לעסקי / שינוי למפתח מורשה ב-DEV",
            )
        )

    if modify_count == 0 and read_count == 0:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="לא זוהו הרשאות על _SYS_REPO / REPO / ANALYTICALPRIVILEGE",
                description="לא נמצאו שורות רלוונטיות ב-EFFECTIVE_PRIVILEGE_GRANTEES.",
                risk_level="Low",
                status="Compliant",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            )
        )
    elif modify_count == 0:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title=f"נמצאו {read_count} הרשאות קריאה אנליטיות ללא שינוי/מחיקה",
                description="לא זוהו הרשאות modify/delete על _SYS_REPO / REPO.",
                risk_level="Low",
                status="Compliant",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            )
        )

    return tag_findings(findings, control_meta)
