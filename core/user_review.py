from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd


ACTIVE_STATUS_COLUMNS = [
    "USER_DEACTIVATED",
    "IS_DEACTIVATED",
    "DEACTIVATED",
    "USER_LOCKED",
    "IS_LOCKED",
    "LOCKED",
    "ACCOUNT_STATUS",
    "STATUS",
    "VALID_TO",
]

LAST_LOGIN_COLUMNS = ["LAST_SUCCESSFUL_CONNECT", "LAST_SUCCESSFUL_CONNECT_DATE"]

PERIOD_START_COLUMNS = ["VALID_FROM", "USER_VALID_FROM", "CREATED_ON", "CREATE_DATE", "VALIDITY_START"]
PERIOD_END_COLUMNS = ["VALID_TO", "USER_VALID_TO", "DEACTIVATION_DATE", "DEACTIVATED_ON", "VALIDITY_END"]

PASSWORD_EXEMPT_FLAG_COLUMNS = [
    "PASSWORD_POLICY_EXEMPT",
    "IS_PASSWORD_POLICY_EXEMPT",
    "IS_PASSWORD_POLICY_DISABLED",
    "PASSWORD_EXEMPT",
    "IS_PASSWORD_EXEMPT",
    "IS_PASSWORD_ENABLED",
    "PASSWORD_ENABLED",
    "PASSWORD_DISABLED",
    "NO_PASSWORD",
    "IS_PASSWORD_CHECK_DISABLED",
]

PASSWORD_EXEMPT_REASON_COLUMNS = [
    "PASSWORD_POLICY_EXEMPT_REASON",
    "PASSWORD_EXEMPT_REASON",
    "EXEMPTION_REASON",
    "NO_PASSWORD_REASON",
    "PASSWORD_DISABLE_REASON",
    "REASON",
]

SYSTEM_TABLE_NAMES = {
    "M_VOLUME_FILES",
    "M_SERVICES",
    "M_SERVICE_STATISTICS",
    "M_SYSTEM_OVERVIEW",
    "M_HOST_INFORMATION",
}
READ_ONLY_SYSTEM_TABLE_PRIVILEGES = {"SELECT"}


def _find_existing_column(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    for column_name in candidates:
        if column_name in df.columns:
            return column_name
    return None


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    return str(value).strip()


def _parse_date(value: Any) -> Optional[datetime]:
    text = _normalize_text(value)
    if not text or text == "?":
        return None
    parsed = pd.to_datetime(text, errors="coerce")
    if pd.isna(parsed):
        return None
    if hasattr(parsed, "to_pydatetime"):
        return parsed.to_pydatetime()
    return parsed


def _find_first_date_in_row(row: pd.Series, candidates: Iterable[str]) -> Optional[datetime]:
    for column_name in candidates:
        if column_name in row.index:
            parsed = _parse_date(row[column_name])
            if parsed is not None:
                return parsed
    return None


def _is_date_in_period(value: Optional[datetime], period_start: date, period_end: date) -> bool:
    if value is None:
        return False
    value_date = value.date()
    return period_start <= value_date <= period_end


def _was_active_in_period(
    row: pd.Series,
    is_currently_active: bool,
    period_start: date,
    period_end: date,
    last_login: Optional[datetime],
) -> Dict[str, Any]:
    reasons: List[str] = []

    if is_currently_active:
        reasons.append("משתמש פעיל בתאריך הסקירה")

    if _is_date_in_period(last_login, period_start, period_end):
        reasons.append("בוצעה התחברות בתקופת הביקורת")

    valid_from = _find_first_date_in_row(row, PERIOD_START_COLUMNS)
    valid_to = _find_first_date_in_row(row, PERIOD_END_COLUMNS)
    # Avoid false positives from open-ended/default validity values (e.g., VALID_TO=9999-12-31).
    # We only rely on validity overlap when both boundaries are present in source data.
    if valid_from is not None and valid_to is not None:
        effective_start = valid_from.date()
        effective_end = valid_to.date()
        if effective_start <= period_end and effective_end >= period_start:
            reasons.append("טווח תוקף המשתמש חופף לתקופת הביקורת")

    return {
        "is_active_in_period": bool(reasons),
        "period_reason": " | ".join(reasons) if reasons else "לא זוהתה פעילות בתקופת הביקורת",
    }


def _is_truthy(value: Any) -> Optional[bool]:
    text = _normalize_text(value).upper()
    if not text:
        return None
    if text in {"TRUE", "Y", "YES", "1", "ACTIVE", "OPEN", "UNLOCKED", "FALSE=NO"}:
        return True
    if text in {"FALSE", "N", "NO", "0", "INACTIVE", "LOCKED", "DEACTIVATED", "DISABLED", "EXPIRED"}:
        return False
    return None


def _derive_password_policy_exemption(row: pd.Series) -> Dict[str, Any]:
    for column_name in PASSWORD_EXEMPT_FLAG_COLUMNS:
        if column_name not in row.index:
            continue

        flag = _is_truthy(row[column_name])
        if flag is None:
            continue

        normalized_col = column_name.upper()
        if "ENABLED" in normalized_col:
            is_exempt = not flag
        else:
            is_exempt = flag

        return {
            "is_exempt": is_exempt,
            "source_column": column_name,
            "status_text": "כן" if is_exempt else "לא",
        }

    return {
        "is_exempt": None,
        "source_column": "-",
        "status_text": "לא זוהה",
    }


def _derive_password_exempt_reason(row: pd.Series) -> str:
    for column_name in PASSWORD_EXEMPT_REASON_COLUMNS:
        if column_name not in row.index:
            continue
        value = _normalize_text(row[column_name])
        if value and value not in {"?", "-"}:
            return value
    return ""


def _derive_active_status(row: pd.Series, review_date: date) -> Dict[str, Any]:
    for column_name in ("USER_DEACTIVATED", "IS_DEACTIVATED", "DEACTIVATED"):
        if column_name in row.index:
            flag = _is_truthy(row[column_name])
            if flag is False:
                return {"status_text": f"לא פעיל ({column_name})", "is_active": False}
            if flag is True:
                return {"status_text": f"פעיל ({column_name})", "is_active": True}

    for column_name in ("USER_LOCKED", "IS_LOCKED", "LOCKED"):
        if column_name in row.index:
            flag = _is_truthy(row[column_name])
            if flag is False:
                return {"status_text": f"פעיל ({column_name})", "is_active": True}
            if flag is True:
                return {"status_text": f"לא פעיל ({column_name})", "is_active": False}

    for column_name in ("ACCOUNT_STATUS", "STATUS"):
        if column_name in row.index:
            text = _normalize_text(row[column_name]).upper()
            if text:
                if any(token in text for token in ("LOCK", "DEACT", "DISABLE", "INACTIVE", "EXPIRE")):
                    return {"status_text": f"לא פעיל ({text})", "is_active": False}
                if any(token in text for token in ("ACTIVE", "ENABLE", "OPEN", "VALID")):
                    return {"status_text": f"פעיל ({text})", "is_active": True}

    if "VALID_TO" in row.index:
        valid_to = _parse_date(row["VALID_TO"])
        if valid_to is not None:
            is_active = valid_to.date() >= review_date
            return {
                "status_text": f"{'פעיל' if is_active else 'לא פעיל'} (VALID_TO={valid_to.date().isoformat()})",
                "is_active": is_active,
            }

    return {"status_text": "פעיל (ברירת מחדל)", "is_active": True}


def _classify_user(username: str, rules: Dict[str, List[str]], critical_users: List[str]) -> str:
    normalized_username = username.upper()

    if normalized_username in {user.upper() for user in critical_users}:
        return "Generic"

    ordered_types = ["Dialog", "Generic", "Technical", "Application"]
    for user_type in ordered_types:
        for pattern in rules.get(user_type, []):
            if pattern and pattern.upper() in normalized_username:
                return user_type

    return "Application"


def _build_privilege_lookup(df_privs: Optional[pd.DataFrame], critical_privileges: List[str]) -> Dict[str, Dict[str, List[str]]]:
    lookup: Dict[str, Dict[str, List[str]]] = {}
    if df_privs is None or df_privs.empty:
        return lookup

    critical_set = {item.upper() for item in critical_privileges}
    for _, row in df_privs.iterrows():
        grantee = _normalize_text(row.get("GRANTEE"))
        privilege = _normalize_text(row.get("PRIVILEGE"))
        if not grantee:
            continue
        bucket = lookup.setdefault(grantee, {"all": [], "critical": []})
        if privilege and privilege not in bucket["all"]:
            bucket["all"].append(privilege)
        if privilege.upper() in critical_set and privilege not in bucket["critical"]:
            bucket["critical"].append(privilege)
    return lookup


def _normalize_object_name(raw_value: Any) -> str:
    object_name = _normalize_text(raw_value).upper().replace('"', "")
    if not object_name:
        return ""
    if "." in object_name:
        object_name = object_name.split(".")[-1]
    return object_name.strip()


def _build_system_table_access_lookup(df_privs: Optional[pd.DataFrame]) -> Optional[Dict[str, Dict[str, Any]]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    if df_privs is None:
        return None
    if df_privs.empty:
        return lookup

    grantee_column = _find_existing_column(df_privs, ["GRANTEE", "USER_NAME", "USER"])
    privilege_column = _find_existing_column(df_privs, ["PRIVILEGE", "PRIVILEGE_TYPE", "OBJECT_PRIVILEGE"])
    object_column = _find_existing_column(df_privs, ["TABLE_NAME", "OBJECT_NAME", "OBJECT", "OBJECTNAME"])

    if grantee_column is None or object_column is None:
        return None

    for _, row in df_privs.iterrows():
        grantee = _normalize_text(row.get(grantee_column))
        table_name = _normalize_object_name(row.get(object_column))
        privilege_name = _normalize_text(row.get(privilege_column)).upper() if privilege_column else ""

        if not grantee or table_name not in SYSTEM_TABLE_NAMES:
            continue

        bucket = lookup.setdefault(
            grantee,
            {
                "tables": set(),
                "privileges": set(),
            },
        )
        bucket["tables"].add(table_name)
        if privilege_name:
            bucket["privileges"].add(privilege_name)

    return lookup


def _derive_system_table_access_status(
    username: str,
    access_lookup: Optional[Dict[str, Dict[str, Any]]],
    authorized_users_upper: set,
) -> Dict[str, Any]:
    if access_lookup is None:
        return {
            "status_text": "לא נבדק",
            "details_text": "לא נמצאו עמודות מתאימות בטבלת GRANTED_PRIVILEGES",
            "is_exception": False,
            "is_authorized": None,
            "non_readonly_privileges": [],
            "tables": [],
        }

    entry = access_lookup.get(username)
    if not entry:
        return {
            "status_text": "אין גישה",
            "details_text": "-",
            "is_exception": False,
            "is_authorized": True,
            "non_readonly_privileges": [],
            "tables": [],
        }

    tables = sorted(entry.get("tables", []))
    privileges = sorted(entry.get("privileges", []))
    non_readonly = [priv for priv in privileges if priv and priv not in READ_ONLY_SYSTEM_TABLE_PRIVILEGES]
    is_authorized = username.upper() in authorized_users_upper
    is_exception = (not is_authorized) or bool(non_readonly)

    status_text = "תקין" if not is_exception else "חריג"
    details_parts = [
        f"טבלאות: {', '.join(tables) if tables else '-'}",
        f"הרשאות: {', '.join(privileges) if privileges else '-'}",
    ]

    return {
        "status_text": status_text,
        "details_text": " | ".join(details_parts),
        "is_exception": is_exception,
        "is_authorized": is_authorized,
        "non_readonly_privileges": non_readonly,
        "tables": tables,
    }


def build_user_review_report(
    users_df: pd.DataFrame,
    privileges_df: Optional[pd.DataFrame],
    config: Dict[str, Any],
    extract_dates: Dict[str, str],
    period_id: str,
    review_date: date,
    review_period_start: Optional[date] = None,
    review_period_end: Optional[date] = None,
    existing_reviews: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    existing_reviews = existing_reviews or {}
    user_type_rules = config.get("user_type_rules", {})
    inactive_days_threshold = int(config.get("inactive_days_threshold", 120))
    critical_users = config.get("critical_users", [])
    critical_privileges = config.get("critical_privileges", [])
    critical_users_upper = {str(user).upper() for user in critical_users}
    authorized_system_table_users = config.get("system_table_authorized_users", critical_users)
    authorized_system_table_users_upper = {str(user).upper() for user in authorized_system_table_users}
    period_start = review_period_start or review_date
    period_end = review_period_end or review_date
    if period_end < period_start:
        raise ValueError("תאריך סוף התקופה חייב להיות גדול או שווה לתאריך ההתחלה")

    user_column = "USER_NAME" if "USER_NAME" in users_df.columns else users_df.columns[0]
    last_login_column = _find_existing_column(users_df, LAST_LOGIN_COLUMNS)
    privilege_lookup = _build_privilege_lookup(privileges_df, critical_privileges)
    system_table_access_lookup = _build_system_table_access_lookup(privileges_df)

    rows: List[Dict[str, Any]] = []
    type_distribution: Dict[str, int] = {}
    exception_count = 0
    in_scope_count = 0
    privileged_count = 0
    active_in_period_count = 0

    for _, row in users_df.iterrows():
        username = _normalize_text(row.get(user_column))
        if not username:
            continue

        saved_review = existing_reviews.get(username, {})

        active_info = _derive_active_status(row, review_date)
        last_login = _parse_date(row.get(last_login_column)) if last_login_column else None
        days_since_login = (review_date - last_login.date()).days if last_login is not None else None
        period_activity_info = _was_active_in_period(
            row=row,
            is_currently_active=bool(active_info["is_active"]),
            period_start=period_start,
            period_end=period_end,
            last_login=last_login,
        )
        privilege_info = privilege_lookup.get(username, {"all": [], "critical": []})
        user_type = _classify_user(username, user_type_rules, critical_users)
        type_distribution[user_type] = type_distribution.get(user_type, 0) + 1

        is_in_scope = bool(period_activity_info["is_active_in_period"])
        has_any_privileges = bool(privilege_info["all"])
        has_critical_privileges = bool(privilege_info["critical"])
        password_exempt_info = _derive_password_policy_exemption(row)
        source_password_exempt_reason = _derive_password_exempt_reason(row)
        manager_documented_reason = _normalize_text(saved_review.get("manager_comments", ""))
        system_table_access = _derive_system_table_access_status(
            username=username,
            access_lookup=system_table_access_lookup,
            authorized_users_upper=authorized_system_table_users_upper,
        )

        exception_reasons: List[str] = []
        if is_in_scope:
            in_scope_count += 1
            active_in_period_count += 1

        if has_any_privileges and user_type == "Dialog" and days_since_login is not None and days_since_login > inactive_days_threshold:
            exception_reasons.append(f"משתמש Dialog ללא שימוש מעל {inactive_days_threshold} ימים ועדיין עם הרשאות")

        if last_login is not None and username.upper() in critical_users_upper:
            exception_reasons.append("שימוש במשתמש קריטי (SYSTEM/Generic) זוהה בהתחברות מוצלחת")
        elif last_login is not None and user_type == "Generic":
            exception_reasons.append("שימוש במשתמש Generic זוהה בהתחברות מוצלחת")

        if has_critical_privileges and user_type in {"Dialog", "Application"}:
            exception_reasons.append("משתמש בעל הרשאות קריטיות שאינו מסווג כ-Generic/Technical")

        if user_type == "Dialog" and is_in_scope and password_exempt_info["is_exempt"] is True:
            if source_password_exempt_reason or manager_documented_reason:
                exception_reasons.append("משתמש אנושי מוחרג ממדיניות סיסמאות - קיימת סיבה מתועדת")
            else:
                exception_reasons.append("משתמש אנושי מוחרג ממדיניות סיסמאות ללא סיבה מתועדת")

        if system_table_access["is_exception"]:
            if system_table_access["is_authorized"] is False:
                tables_text = ", ".join(system_table_access["tables"]) if system_table_access["tables"] else "טבלאות מערכת"
                exception_reasons.append(f"גישה לטבלאות מערכת למשתמש לא מורשה ({tables_text})")
            if system_table_access["non_readonly_privileges"]:
                privileges_text = ", ".join(system_table_access["non_readonly_privileges"])
                exception_reasons.append(f"גישה לטבלאות מערכת שאינה קריאה בלבד ({privileges_text})")

        if has_critical_privileges:
            privileged_count += 1

        if exception_reasons:
            exception_count += 1

        reported_password_reason = source_password_exempt_reason or (manager_documented_reason if password_exempt_info["is_exempt"] is True else "")
        rows.append(
            {
                "period_id": period_id,
                "user_name": username,
                "in_scope": "כן" if is_in_scope else "לא",
                "active_status": active_info["status_text"],
                "active_in_period": "כן" if period_activity_info["is_active_in_period"] else "לא",
                "period_activity_reason": period_activity_info["period_reason"],
                "last_login": last_login.date().isoformat() if last_login is not None else "לא זוהה",
                "days_since_login": days_since_login if days_since_login is not None else "לא זוהה",
                "user_type": user_type,
                "has_privileges": "כן" if has_any_privileges else "לא",
                "critical_privileges": ", ".join(privilege_info["critical"]) if privilege_info["critical"] else "-",
                "all_privileges": ", ".join(privilege_info["all"]) if privilege_info["all"] else "-",
                "password_policy_exempt_status": password_exempt_info["status_text"],
                "password_policy_exempt_reason": reported_password_reason or "-",
                "password_policy_exempt_source": password_exempt_info["source_column"],
                "system_table_access_status": system_table_access["status_text"],
                "system_table_access_details": system_table_access["details_text"],
                "has_exception": "כן" if exception_reasons else "לא",
                "exception_reason": " | ".join(exception_reasons) if exception_reasons else "-",
                "status_sort": 0 if exception_reasons else 1,
                "review_status": saved_review.get("review_status", "טרם נסקר"),
                "manager_decision": saved_review.get("manager_decision", ""),
                "manager_comments": saved_review.get("manager_comments", ""),
                "action_required": saved_review.get("action_required", ""),
                "extract_date": extract_dates.get("USERS", "-"),
                "review_date": review_date.isoformat(),
            }
        )

    review_df = pd.DataFrame(rows)
    if not review_df.empty:
        review_df = review_df.sort_values(by=["status_sort", "user_name"], ascending=[True, True]).reset_index(drop=True)

    return {
        "metadata": {
            "period_id": period_id,
            "review_date": review_date.isoformat(),
            "review_period_start": period_start.isoformat(),
            "review_period_end": period_end.isoformat(),
            "users_extract_date": extract_dates.get("USERS", "-"),
            "privileges_extract_date": extract_dates.get("GRANTED_PRIVILEGES", extract_dates.get("EFFECTIVE_PRIVILEGE_GRANTEES", "-")),
            "inactive_days_threshold": inactive_days_threshold,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary": {
            "total_users": len(review_df.index),
            "in_scope_users": in_scope_count,
            "active_in_period_users": active_in_period_count,
            "exception_users": exception_count,
            "privileged_users": privileged_count,
            "type_distribution": type_distribution,
        },
        "dataframe": review_df,
    }


def export_user_review_to_excel(report_data: Dict[str, Any], file_path: str):
    review_df = report_data["dataframe"]
    summary = report_data["summary"]
    metadata = report_data["metadata"]

    summary_rows = [
        {"מדד": "סה\"כ משתמשים", "ערך": summary["total_users"]},
        {"מדד": "משתמשים באוכלוסיית הסקירה", "ערך": summary["in_scope_users"]},
        {"מדד": "משתמשים חריגים", "ערך": summary["exception_users"]},
        {"מדד": "משתמשים עם הרשאות קריטיות", "ערך": summary["privileged_users"]},
    ]

    type_rows = [
        {"סוג משתמש": user_type, "כמות": count}
        for user_type, count in sorted(summary["type_distribution"].items())
    ]

    metadata_rows = [
        {"שדה": "תקופה", "ערך": metadata["period_id"]},
        {"שדה": "תאריך סקירה", "ערך": metadata["review_date"]},
        {"שדה": "טווח בחינה", "ערך": f"{metadata['review_period_start']} עד {metadata['review_period_end']}"},
        {"שדה": "תאריך הפקת USERS", "ערך": metadata["users_extract_date"]},
        {"שדה": "תאריך הפקת PRIVILEGES", "ערך": metadata["privileges_extract_date"]},
        {"שדה": "סף חוסר שימוש (ימים)", "ערך": metadata["inactive_days_threshold"]},
        {"שדה": "מועד הפקה", "ערך": metadata["generated_at"]},
    ]

    export_df = review_df.rename(
        columns={
            "user_name": "שם משתמש",
            "in_scope": "באוכלוסיית הסקירה",
            "active_status": "סטטוס משתמש",
            "active_in_period": "פעיל בתקופת הביקורת",
            "period_activity_reason": "נימוק פעילות בתקופה",
            "last_login": "התחברות אחרונה",
            "days_since_login": "ימים מאז התחברות",
            "user_type": "סוג משתמש",
            "has_privileges": "יש הרשאות",
            "critical_privileges": "הרשאות קריטיות",
            "all_privileges": "כלל הרשאות",
            "password_policy_exempt_status": "מוחרג ממדיניות סיסמה",
            "password_policy_exempt_reason": "סיבת החרגה",
            "password_policy_exempt_source": "עמודת מקור להחרגה",
            "system_table_access_status": "גישה לטבלאות מערכת",
            "system_table_access_details": "פירוט גישה לטבלאות מערכת",
            "has_exception": "חריג",
            "exception_reason": "סיבת חריג",
            "review_status": "סטטוס סקירה",
            "manager_decision": "החלטת מנהל",
            "manager_comments": "הערות",
            "action_required": "נדרש להסרה / מאושר להשאיר",
            "extract_date": "תאריך הפקה",
            "review_date": "תאריך סקירה",
        }
    )

    with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
        pd.DataFrame(summary_rows).to_excel(writer, sheet_name="Executive Summary", index=False)
        pd.DataFrame(type_rows).to_excel(writer, sheet_name="User Types", index=False)
        pd.DataFrame(metadata_rows).to_excel(writer, sheet_name="Metadata", index=False)
        export_df.drop(columns=["status_sort"], errors="ignore").to_excel(writer, sheet_name="User Review", index=False)

        workbook = writer.book
        for sheet in workbook.worksheets:
            sheet.freeze_panes = "A2"
            for column_cells in sheet.columns:
                max_length = max(len(str(cell.value)) if cell.value is not None else 0 for cell in column_cells)
                sheet.column_dimensions[column_cells[0].column_letter].width = min(max(max_length + 2, 12), 40)


def export_user_review_to_pdf(report_data: Dict[str, Any], file_path: str):
    from bidi.algorithm import get_display
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    def rtl(text: Any) -> str:
        value = "" if text is None else str(text)
        return get_display(value)

    font_name = "Helvetica"
    windows_arial = Path("C:/Windows/Fonts/arial.ttf")
    if windows_arial.exists():
        font_name = "ArialUnicodeHebrew"
        if font_name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(font_name, str(windows_arial)))

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleRtl", parent=styles["Title"], fontName=font_name, fontSize=16, leading=20, alignment=2)
    normal_style = ParagraphStyle("NormalRtl", parent=styles["Normal"], fontName=font_name, fontSize=9, leading=12, alignment=2)
    small_style = ParagraphStyle("SmallRtl", parent=styles["Normal"], fontName=font_name, fontSize=8, leading=10, alignment=2)

    metadata = report_data["metadata"]
    summary = report_data["summary"]
    review_df = report_data["dataframe"].copy()

    doc = SimpleDocTemplate(file_path, pagesize=landscape(A4), rightMargin=12 * mm, leftMargin=12 * mm, topMargin=10 * mm, bottomMargin=10 * mm)
    story = []
    story.append(Paragraph(rtl("דוח סקירת משתמשים מנהלי"), title_style))
    story.append(Spacer(1, 5 * mm))

    meta_lines = [
        f"תקופה: {metadata['period_id']}",
        f"תאריך סקירה: {metadata['review_date']}",
        f"טווח בחינה: {metadata['review_period_start']} עד {metadata['review_period_end']}",
        f"תאריך הפקת USERS: {metadata['users_extract_date']}",
        f"תאריך הפקת PRIVILEGES: {metadata['privileges_extract_date']}",
        f"סף אי שימוש: {metadata['inactive_days_threshold']} ימים",
        f"מועד הפקה: {metadata['generated_at']}",
    ]
    for line in meta_lines:
        story.append(Paragraph(rtl(line), normal_style))
    story.append(Spacer(1, 4 * mm))

    summary_table = Table(
        [
            [Paragraph(rtl("מדד"), normal_style), Paragraph(rtl("ערך"), normal_style)],
            [Paragraph(rtl("סה\"כ משתמשים"), normal_style), Paragraph(str(summary["total_users"]), normal_style)],
            [Paragraph(rtl("באוכלוסיית הסקירה"), normal_style), Paragraph(str(summary["in_scope_users"]), normal_style)],
            [Paragraph(rtl("משתמשים חריגים"), normal_style), Paragraph(str(summary["exception_users"]), normal_style)],
            [Paragraph(rtl("משתמשים עם הרשאות קריטיות"), normal_style), Paragraph(str(summary["privileged_users"]), normal_style)],
        ],
        colWidths=[60 * mm, 35 * mm],
        hAlign="RIGHT",
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7f3")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 5 * mm))

    type_rows = [[Paragraph(rtl("סוג משתמש"), normal_style), Paragraph(rtl("כמות"), normal_style)]]
    for user_type, count in sorted(summary["type_distribution"].items()):
        type_rows.append([Paragraph(rtl(user_type), normal_style), Paragraph(str(count), normal_style)])
    type_table = Table(type_rows, colWidths=[60 * mm, 25 * mm], hAlign="RIGHT")
    type_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3d8")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(type_table)
    story.append(Spacer(1, 5 * mm))

    display_columns = [
        ("user_name", "שם משתמש"),
        ("user_type", "סוג משתמש"),
        ("active_status", "סטטוס"),
        ("active_in_period", "פעיל בתקופה"),
        ("last_login", "התחברות אחרונה"),
        ("password_policy_exempt_status", "החרגת סיסמה"),
        ("password_policy_exempt_reason", "סיבת החרגה"),
        ("system_table_access_status", "גישה לטבלאות מערכת"),
        ("critical_privileges", "הרשאות קריטיות"),
        ("has_exception", "חריג"),
        ("exception_reason", "סיבת חריג"),
        ("review_status", "סטטוס סקירה"),
        ("manager_decision", "החלטת מנהל"),
        ("action_required", "החלטה"),
    ]

    table_data = [[Paragraph(rtl(label), small_style) for _, label in display_columns]]
    for _, record in review_df.iterrows():
        table_data.append([Paragraph(rtl(record.get(key, "")), small_style) for key, _ in display_columns])

    detail_table = Table(table_data, repeatRows=1, hAlign="RIGHT")
    detail_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e78")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f7fbff")]),
            ]
        )
    )
    story.append(detail_table)
    doc.build(story)