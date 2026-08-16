"""AM-01 — user population review; UAR-02 — periodic UAR report exceptions."""
from __future__ import annotations

from core.user_review import build_user_review_report
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


def validate_user_population(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    del whitelist
    df = frames.get("USERS")
    if df is None or df.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="UAR",
                    title="קלט USERS חסר לסקירת אוכלוסייה",
                    description="לא ניתן לבצע סקירת משתמשים פעילים ללא USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    user_col = col(df, ["USER_NAME", "USER", "NAME"])
    deactivated_col = col(df, ["USER_DEACTIVATED", "IS_DEACTIVATED"])
    last_connect_col = col(df, ["LAST_SUCCESSFUL_CONNECT", "LAST_SUCCESSFUL_CONNECT_DATE"])
    if user_col is None:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="UAR",
                    title="עמודת USER_NAME חסרה",
                    description="לא נמצאה עמודת שם משתמש ב-USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )

    period_end = period_end_from_settings(settings, period_id)
    period_start = lookback_start(settings, period_id, default_days=180)
    inactive_days = int(settings.get("inactive_days_threshold", 120))

    active_users: list[str] = []
    active_with_login: list[str] = []
    active_no_login: list[str] = []
    stale_active: list[str] = []

    for _, row in df.iterrows():
        username = norm(row.get(user_col))
        if not username:
            continue
        deactivated = is_deactivated(row.get(deactivated_col)) if deactivated_col else False
        if deactivated:
            continue
        active_users.append(username)
        last_connect = parse_date(row.get(last_connect_col)) if last_connect_col else None
        if last_connect is None:
            active_no_login.append(username)
            continue
        active_with_login.append(username)
        age_days = (period_end - last_connect.date()).days
        if age_days > inactive_days:
            stale_active.append(username)

    findings: list[Finding] = [
        Finding(
            period_id=period_id,
            category="UAR",
            title=f"אוכלוסיית משתמשים פעילים: {len(active_users)}",
            description=(
                f"פעילים={len(active_users)}; עם התחברות={len(active_with_login)}; "
                f"ללא התחברות={len(active_no_login)}; "
                f"פעילים מעל {inactive_days} ימים ללא התחברות={len(stale_active)}. "
                f"טווח סקירה: {period_start}–{period_end}."
            ),
            risk_level="Low",
            status="Compliant",
            source_slot="USERS",
            actual_value=str(len(active_users)),
        )
    ]

    # Highlight non-technical active users without login — candidates for removal review
    candidates = [u for u in active_no_login if not looks_technical(u)][:20]
    if candidates:
        findings.append(
            Finding(
                period_id=period_id,
                category="UAR",
                title=f"משתמשים פעילים ללא LAST_SUCCESSFUL_CONNECT ({len(candidates)}+)",
                description="מועמדים לסקירה ידנית: " + ", ".join(candidates),
                risk_level="Medium",
                status="Non-Compliant",
                source_slot="USERS",
            )
        )

    if stale_active:
        preview = ", ".join(stale_active[:20])
        findings.append(
            Finding(
                period_id=period_id,
                category="UAR",
                title=f"משתמשים פעילים לא פעילים זמן רב ({len(stale_active)})",
                description=(
                    f"פעילים עם התחברות אחרונה לפני יותר מ-{inactive_days} ימים: {preview}."
                ),
                risk_level="Medium",
                status="Non-Compliant",
                source_slot="USERS",
            )
        )

    return tag_findings(findings, control_meta)


def validate_periodic_uar(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    del whitelist
    users_df = frames.get("USERS")
    privs = frames.get("GRANTED_PRIVILEGES")
    if privs is None or (hasattr(privs, "empty") and privs.empty):
        privs = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")

    if users_df is None or users_df.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="UAR",
                    title="קלט USERS חסר ל-UAR תקופתי",
                    description="build_user_review_report דורש USERS.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="USERS",
                )
            ],
            control_meta,
        )
    if privs is None or privs.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="UAR",
                    title="קלט הרשאות חסר ל-UAR תקופתי",
                    description="נדרש GRANTED_PRIVILEGES (או EFFECTIVE) להפקת דוח סקירה.",
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="GRANTED_PRIVILEGES",
                )
            ],
            control_meta,
        )

    review_period = settings.get("user_review_period") or {}
    period_end = period_end_from_settings(settings, period_id)
    period_start = lookback_start(settings, period_id, default_days=180)
    start = parse_date(review_period.get("start_date") or review_period.get("from"))
    end = parse_date(review_period.get("end_date") or review_period.get("to"))
    start_date = start.date() if start else period_start
    end_date = end.date() if end else period_end

    report = build_user_review_report(
        users_df=users_df,
        privileges_df=privs,
        config=settings,
        extract_dates={},
        period_id=period_id or "UAR",
        review_date=end_date,
        review_period_start=start_date,
        review_period_end=end_date,
        existing_reviews={},
    )
    report_df = report["dataframe"]
    summary = report["summary"]

    findings: list[Finding] = [
        Finding(
            period_id=period_id,
            category="UAR",
            title="הופק דוח סקירת משתמשים תקופתית",
            description=(
                f"סה\"כ משתמשים={summary.get('total_users', 0)}; "
                f"באוכלוסייה={summary.get('in_scope_users', 0)}; "
                f"חריגים={summary.get('exception_users', 0)}; "
                f"פריבילגיים={summary.get('privileged_users', 0)}. "
                "נדרשים אישור/חתימה ידניים מחוץ לכלי."
            ),
            risk_level="Low",
            status="Compliant",
            source_slot="USERS",
            actual_value=str(summary.get("exception_users", 0)),
        )
    ]

    if not report_df.empty and "has_exception" in report_df.columns:
        exceptions = report_df[report_df["has_exception"] == "כן"]
        for _, row in exceptions.head(50).iterrows():
            username = norm(row.get("user_name"))
            reason = norm(row.get("exception_reason")) or "-"
            findings.append(
                Finding(
                    period_id=period_id,
                    category="UAR",
                    title=f"חריג בדוח UAR: {username}",
                    description=f"סיבה: {reason}",
                    risk_level="High" if "קריטי" in reason else "Medium",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=reason,
                )
            )

    return tag_findings(findings, control_meta)
