"""UAR-01 — user provisioning (new users in lookback window)."""
from __future__ import annotations

from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings
from src.validators.helpers import (
    col,
    is_deactivated,
    lookback_start,
    looks_technical,
    norm,
    parse_date,
    period_end_from_settings,
)


def validate_user_provisioning(
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
                    title="קלט USERS חסר לבקרת הקמת משתמשים",
                    description="לא ניתן לאתר משתמשים חדשים ללא USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    user_col = col(df, ["USER_NAME", "USER", "NAME"])
    create_col = col(df, ["CREATE_TIME", "CREATED_AT", "CREATE_DATE"])
    deactivated_col = col(df, ["USER_DEACTIVATED", "IS_DEACTIVATED"])
    creator_col = col(df, ["CREATOR", "CREATED_BY"])
    if user_col is None or create_col is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="חסרות עמודות CREATE_TIME / USER_NAME",
                    description="נדרשות USER_NAME ו-CREATE_TIME לסינון משתמשים חדשים.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    period_end = period_end_from_settings(settings, period_id)
    period_start = lookback_start(settings, period_id, default_days=180)
    builtin = {str(u).strip().upper() for u in settings.get("builtin_users", [])}

    new_users: list[dict] = []
    for _, row in df.iterrows():
        username = norm(row.get(user_col))
        if not username:
            continue
        upper = username.upper()
        if upper in builtin or looks_technical(username):
            continue
        if deactivated_col and is_deactivated(row.get(deactivated_col)):
            continue
        created = parse_date(row.get(create_col))
        if created is None:
            continue
        if period_start <= created.date() <= period_end:
            new_users.append(
                {
                    "user": username,
                    "created": created.date().isoformat(),
                    "creator": norm(row.get(creator_col)) if creator_col else "",
                }
            )

    if not new_users:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="לא זוהו משתמשים חדשים בתקופת הביקורת",
                description=(
                    f"לא נמצאו משתמשים לא-טכניים שנוצרו בין {period_start} ל-{period_end}."
                ),
                risk_level="Low",
                status="Compliant",
                source_slot="USERS",
            )
        )
    else:
        preview = "; ".join(f"{u['user']} ({u['created']})" for u in new_users[:15])
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title=f"זוהו {len(new_users)} משתמשים חדשים לסקירת מדגם",
                description=(
                    f"משתמשים שנוצרו בטווח {period_start}–{period_end}: {preview}. "
                    "נדרש מדגם ידני לתיעוד פתיחה ואישור מנהל."
                ),
                risk_level="Medium",
                status="Non-Compliant",
                source_slot="USERS",
                actual_value=str(len(new_users)),
                expected_value="תיעוד פתיחה לכל מדגם",
            )
        )
        for item in new_users[:10]:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title=f"משתמש חדש: {item['user']}",
                    description=(
                        f"CREATE_TIME={item['created']}; CREATOR={item['creator'] or 'לא ידוע'}."
                    ),
                    risk_level="Medium",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=item["created"],
                )
            )

    # Control environment: who holds USER ADMIN / ROLE ADMIN
    privs = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")
    if privs is not None and not privs.empty:
        grantee_col = col(privs, ["GRANTEE", "USER_NAME", "USER"])
        priv_col = col(privs, ["PRIVILEGE", "PRIVILEGE_TYPE"])
        if grantee_col and priv_col:
            admins = sorted(
                {
                    f"{norm(r.get(grantee_col))} ({norm(r.get(priv_col))})"
                    for _, r in privs.iterrows()
                    if norm(r.get(priv_col)).upper() in {"USER ADMIN", "ROLE ADMIN"}
                    and norm(r.get(grantee_col))
                }
            )
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="סביבת בקרה: מחזיקי USER ADMIN / ROLE ADMIN",
                    description=("לא נמצאו" if not admins else ", ".join(admins[:40])),
                    risk_level="Low",
                    status="Compliant",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            )

    roles = frames.get("GRANTED_ROLES")
    if roles is not None and not roles.empty and new_users:
        role_user_col = col(roles, ["GRANTEE", "USER_NAME", "USER"])
        role_name_col = col(roles, ["ROLE_NAME", "ROLE", "GRANTED_ROLE"])
        if role_user_col and role_name_col:
            new_set = {u["user"].upper() for u in new_users}
            for item in new_users[:10]:
                assigned = sorted(
                    {
                        norm(r.get(role_name_col))
                        for _, r in roles.iterrows()
                        if norm(r.get(role_user_col)).upper() == item["user"].upper()
                        and norm(r.get(role_name_col))
                    }
                )
                if assigned:
                    findings.append(
                        Finding(
                            period_id=period_id,
                            category="Access",
                            title=f"תפקידים למשתמש חדש: {item['user']}",
                            description="תפקידים: " + ", ".join(assigned[:20]),
                            risk_level="Low",
                            status="Compliant",
                            source_slot="GRANTED_ROLES",
                        )
                    )
                elif item["user"].upper() in new_set:
                    findings.append(
                        Finding(
                            period_id=period_id,
                            category="Access",
                            title=f"אין תפקידים ב-GRANTED_ROLES למשתמש: {item['user']}",
                            description="לא נמצאו ROLE assignments — לבדיקת Least Privilege ידנית.",
                            risk_level="Low",
                            status="Compliant",
                            source_slot="GRANTED_ROLES",
                        )
                    )

    return tag_findings(findings, control_meta)
