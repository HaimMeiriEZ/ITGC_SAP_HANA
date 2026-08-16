"""PP-02 — password policy exemptions."""
from __future__ import annotations

from core.user_review import _derive_password_policy_exemption
from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings
from src.validators.helpers import col, is_deactivated, looks_technical, norm


def validate_password_policy_exemptions(
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
                    category="Password Policy",
                    title="קלט USERS חסר לבקרת החרגות סיסמה",
                    description="לא ניתן לזהות מוחרגים ממדיניות סיסמאות ללא USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    user_col = col(df, ["USER_NAME", "USER", "NAME"])
    deactivated_col = col(df, ["USER_DEACTIVATED", "IS_DEACTIVATED"])
    if user_col is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Password Policy",
                    title="עמודת USER_NAME חסרה",
                    description="לא נמצאה עמודת שם משתמש ב-USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    human_exempt = 0
    technical_exempt = 0
    for _, row in df.iterrows():
        username = norm(row.get(user_col))
        if not username:
            continue
        if deactivated_col and is_deactivated(row.get(deactivated_col)):
            continue

        exempt_info = _derive_password_policy_exemption(row)
        if exempt_info.get("is_exempt") is not True:
            continue

        if looks_technical(username):
            technical_exempt += 1
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Password Policy",
                    title=f"החרגת סיסמה למשתמש טכני: {username}",
                    description=(
                        f"{username} מוחרג ממדיניות סיסמאות "
                        f"(עמודה {exempt_info.get('source_column')}). נדרש תיעוד ידני."
                    ),
                    risk_level="Low",
                    status="Compliant",
                    source_slot="USERS",
                )
            )
        else:
            human_exempt += 1
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Password Policy",
                    title=f"החרגת סיסמה למשתמש אנושי: {username}",
                    description=(
                        f"{username} מוחרג ממדיניות סיסמאות ללא סיווג טכני אוטומטי. "
                        "נדרש תיעוד מוסמך לסיבת ההחרגה."
                    ),
                    risk_level="High",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=str(exempt_info.get("source_column")),
                    expected_value="מדיניות סיסמה פעילה או תיעוד החרגה",
                )
            )

    # Who can grant password exemptions / manage users (USER ADMIN)
    privs = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")
    if privs is not None and not privs.empty:
        grantee_col = col(privs, ["GRANTEE", "USER_NAME", "USER"])
        priv_col = col(privs, ["PRIVILEGE", "PRIVILEGE_TYPE"])
        if grantee_col and priv_col:
            admins = sorted(
                {
                    norm(r.get(grantee_col))
                    for _, r in privs.iterrows()
                    if norm(r.get(priv_col)).upper() == "USER ADMIN" and norm(r.get(grantee_col))
                }
            )
            if admins:
                findings.append(
                    Finding(
                        period_id=period_id,
                        category="Password Policy",
                        title="גורמים עם USER ADMIN (יכולת לפטור/לנהל סיסמאות)",
                        description="מחזיקים ב-USER ADMIN: " + ", ".join(admins[:30]),
                        risk_level="Low",
                        status="Compliant",
                        source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                        actual_value=str(len(admins)),
                    )
                )

    if human_exempt == 0 and technical_exempt == 0:
        findings.append(
            Finding(
                period_id=period_id,
                category="Password Policy",
                title="לא זוהו משתמשים מוחרגים ממדיניות סיסמאות",
                description="לא נמצאו משתמשים פעילים עם IS_PASSWORD_LIFETIME_CHECK_ENABLED=FALSE (או דגל החרגה מקביל).",
                risk_level="Low",
                status="Compliant",
                source_slot="USERS",
            )
        )

    return tag_findings(findings, control_meta)
