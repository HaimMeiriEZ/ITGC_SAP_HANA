"""AM-03 — SYSTEM user lockdown."""
from __future__ import annotations

from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings
from src.validators.helpers import (
    col,
    is_deactivated,
    is_true,
    lookback_start,
    norm,
    parse_date,
    period_end_from_settings,
)


def validate_system_user_lockdown(
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
    user_col = col(df, ["USER_NAME", "USER", "NAME"]) if df is not None else None
    if df is None or df.empty or user_col is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="קלט USERS חסר לבקרת SYSTEM",
                    description="לא ניתן לאמת נעילת SYSTEM ללא טבלת USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    system_rows = df[df[user_col].astype(str).str.strip().str.upper() == "SYSTEM"]
    if system_rows.empty:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="רשומת SYSTEM חסרה",
                description="לא נמצא משתמש SYSTEM בטבלת USERS.",
                risk_level="High",
                status="Non-Compliant",
                source_slot="USERS",
            )
        )
        return tag_findings(findings, control_meta)

    row = system_rows.iloc[0]
    deactivated_col = col(df, ["USER_DEACTIVATED", "IS_DEACTIVATED"])
    valid_until_col = col(df, ["VALID_UNTIL", "VALID_TO"])
    admin_pwd_col = col(df, ["ADMIN_GIVEN_PASSWORD"])
    last_connect_col = col(df, ["LAST_SUCCESSFUL_CONNECT", "LAST_SUCCESSFUL_CONNECT_DATE"])

    deactivated = is_deactivated(row.get(deactivated_col)) if deactivated_col else False
    valid_until = parse_date(row.get(valid_until_col)) if valid_until_col else None
    period_end = period_end_from_settings(settings, period_id)
    period_start = lookback_start(settings, period_id, default_days=180)
    expired_before_period = valid_until is not None and valid_until.date() < period_start

    if deactivated or expired_before_period:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="SYSTEM נעול לפעילות יומיומית",
                description=(
                    f"SYSTEM מושבת (USER_DEACTIVATED={row.get(deactivated_col)}) "
                    "או שתוקף VALID_UNTIL פג לפני תקופת הביקורת."
                ),
                risk_level="Low",
                status="Compliant",
                source_slot="USERS",
                actual_value=str(row.get(deactivated_col)),
                expected_value="TRUE או VALID_UNTIL שפג",
            )
        )
    else:
        findings.append(
            Finding(
                period_id=period_id,
                category="Access",
                title="SYSTEM פעיל ללא נעילה יומיומית",
                description=(
                    "משתמש SYSTEM פעיל (USER_DEACTIVATED≠TRUE) ואין VALID_UNTIL שפג לפני תקופת הביקורת."
                ),
                risk_level="High",
                status="Non-Compliant",
                source_slot="USERS",
                actual_value=str(row.get(deactivated_col)),
                expected_value="TRUE",
            )
        )

    if admin_pwd_col is not None:
        admin_given = is_true(row.get(admin_pwd_col))
        if admin_given and not deactivated:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="SYSTEM עם סיסמת ברירת מחדל ופעיל",
                    description="ADMIN_GIVEN_PASSWORD=TRUE עבור SYSTEM פעיל — יש להחליף סיסמה או להשבית.",
                    risk_level="High",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value="TRUE",
                    expected_value="FALSE",
                )
            )
        elif admin_given and deactivated:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="SYSTEM מושבת אך ADMIN_GIVEN_PASSWORD=TRUE",
                    description="מידע משלים בלבד: הסיסמה מסומנת כברירת מחדל אך המשתמש מושבת.",
                    risk_level="Low",
                    status="Compliant",
                    source_slot="USERS",
                )
            )

    if last_connect_col is not None:
        last_connect = parse_date(row.get(last_connect_col))
        if last_connect is not None and period_start <= last_connect.date() <= period_end:
            findings.append(
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="זוהתה התחברות SYSTEM בתקופת הביקורת",
                    description=(
                        f"LAST_SUCCESSFUL_CONNECT={norm(row.get(last_connect_col))}. "
                        "נדרש תיעוד חירום ידני (סיבה, מאשר, השבתה חוזרת)."
                    ),
                    risk_level="Medium",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=norm(row.get(last_connect_col)),
                )
            )

    return tag_findings(findings, control_meta)
