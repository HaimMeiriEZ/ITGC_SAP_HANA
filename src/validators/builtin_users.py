"""AM-02 — builtin users lockdown."""
from __future__ import annotations

from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings
from src.validators.helpers import col, is_deactivated, is_false, is_true, norm, users_index


def validate_builtin_users_lockdown(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    del whitelist
    df = frames.get("USERS")
    findings: list[Finding] = []
    if df is None or df.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="קלט USERS חסר לבקרת builtin",
                    description="לא ניתן לאמת משתמשי built-in ללא טבלת USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    builtin = [str(u).strip() for u in settings.get("builtin_users", []) if str(u).strip()]
    if not builtin:
        builtin = [str(u).strip() for u in settings.get("critical_users", []) if str(u).strip()]

    index = users_index(df)
    deactivated_col = col(df, ["USER_DEACTIVATED", "IS_DEACTIVATED"])
    admin_pwd_col = col(df, ["ADMIN_GIVEN_PASSWORD"])

    for name in builtin:
        row = index.get(name.upper())
        if row is None:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"משתמש builtin חסר ב-USERS: {name}",
                    description=f"המשתמש {name} מופיע ברשימת builtin_users אך לא נמצא ב-USERS.",
                    risk_level="Medium",
                    status="Non-Compliant",
                    source_slot="USERS",
                )
            )
            continue

        deactivated = is_deactivated(row.get(deactivated_col)) if deactivated_col else False
        password_changed = is_false(row.get(admin_pwd_col)) if admin_pwd_col else False
        # Compliant if deactivated OR password changed (ADMIN_GIVEN_PASSWORD=FALSE)
        if deactivated or password_changed:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"builtin תקין: {name}",
                    description=(
                        f"{name}: מושבת={deactivated}, "
                        f"ADMIN_GIVEN_PASSWORD={norm(row.get(admin_pwd_col)) if admin_pwd_col else 'N/A'}."
                    ),
                    risk_level="Low",
                    status="Compliant",
                    source_slot="USERS",
                )
            )
        else:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"builtin פעיל עם סיסמת ברירת מחדל: {name}",
                    description=(
                        f"{name} פעיל (USER_DEACTIVATED≠TRUE) ו-ADMIN_GIVEN_PASSWORD≠FALSE. "
                        "נדרשת נעילה או החלפת סיסמה."
                    ),
                    risk_level="High",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=f"deactivated={deactivated}, admin_given={norm(row.get(admin_pwd_col)) if admin_pwd_col else '?'}",
                    expected_value="מושבת או סיסמה הוחלפה",
                )
            )

    # Optional CONNECT info for active builtins
    privs = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")
    if privs is not None and not privs.empty:
        grantee_col = col(privs, ["GRANTEE", "USER_NAME", "USER"])
        priv_col = col(privs, ["PRIVILEGE", "PRIVILEGE_TYPE"])
        type_col = col(privs, ["OBJECT_TYPE"])
        if grantee_col and priv_col:
            builtin_upper = {n.upper() for n in builtin}
            seen_connect: set[str] = set()
            for _, prow in privs.iterrows():
                grantee = norm(prow.get(grantee_col)).upper()
                privilege = norm(prow.get(priv_col)).upper()
                obj_type = norm(prow.get(type_col)).upper() if type_col else ""
                if grantee in seen_connect or grantee not in builtin_upper or privilege != "CONNECT":
                    continue
                if obj_type and obj_type not in {"SYSTEMPRIVILEGE", "SYSTEM PRIVILEGE", ""}:
                    continue
                seen_connect.add(grantee)
                row = index.get(grantee)
                deactivated = is_deactivated(row.get(deactivated_col)) if row is not None and deactivated_col else False
                findings.append(
                    Finding(
                        period_id=period_id,
                        category="Access",
                        title=f"CONNECT ל-builtin: {grantee}",
                        description=(
                            f"ל-{grantee} יש CONNECT. "
                            + ("המשתמש מושבת — מידע משלים בלבד." if deactivated else "המשתמש פעיל — לבדיקת סוקר.")
                        ),
                        risk_level="Low" if deactivated else "Medium",
                        status="Compliant" if deactivated else "Non-Compliant",
                        source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                    )
                )

    if not findings:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="לא הוגדרו builtin_users",
                description="רשימת builtin_users ריקה בהגדרות.",
                risk_level="Medium",
                status="Missing Evidence",
                source_slot="USERS",
            )
        )

    return tag_findings(findings, control_meta)
