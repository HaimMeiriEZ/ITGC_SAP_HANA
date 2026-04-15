import pandas as pd
from typing import List, Dict, Any, Optional
from DataClasses import Finding
from datetime import datetime


RISK_PRIORITY = {"High": 0, "Medium": 1, "Low": 2}

class AuditAnalyzer:
    """
    מנוע הניתוח המרכזי לביקורת ITGC.
    מבצע הצלבות נתונים בין טבלאות המקור של SAP HANA ומפיק ממצאים מבוססי סיכון.
    """

    def __init__(self, config: Dict[str, Any], whitelist: List[Dict] = None):
        self.config = config
        self.whitelist = whitelist or []
        self.findings: List[Finding] = []

    def _is_whitelisted(self, object_type: str, object_name: str) -> bool:
        """בדיקה האם יש החרגה מאושרת לאובייקט מסוים"""
        for rule in self.whitelist:
            if rule.get('object_type') == object_type and rule.get('object_name') == object_name:
                return True
        return False

    def _sort_findings(self):
        self.findings.sort(
            key=lambda finding: (
                RISK_PRIORITY.get(finding.risk_level, 99),
                finding.category,
                finding.title,
            )
        )

    def _normalize_password_property_key(self, property_name: str) -> str:
        property_key = property_name.lower().strip()
        # Backward compatibility for previous config key naming.
        if property_key == "maximum_password_validity":
            return "maximum_password_lifetime"
        return property_key

    def _coerce_int(self, value):
        return int(str(value).strip())

    def _is_password_policy_compliant(self, property_name: str, actual_value, expected_value) -> bool:
        property_key = self._normalize_password_property_key(property_name)

        try:
            if property_key == "minimal_password_length":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)

            if property_key == "maximum_password_lifetime":
                return self._coerce_int(actual_value) <= self._coerce_int(expected_value)

            if property_key == "maximum_invalid_connect_attempts":
                return self._coerce_int(actual_value) <= self._coerce_int(expected_value)

            if property_key == "maximum_unused_initial_password_lifetime":
                return self._coerce_int(actual_value) <= self._coerce_int(expected_value)

            if property_key == "maximum_unused_productive_password_lifetime":
                return self._coerce_int(actual_value) <= self._coerce_int(expected_value)

            if property_key == "password_lock_time":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)

            if property_key == "minimal_password_lifetime":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)

            if property_key == "last_used_passwords":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)

            if property_key == "password_expire_warning_time":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)

        except (TypeError, ValueError):
            return str(actual_value).strip().upper() == str(expected_value).strip().upper()

        return str(actual_value).strip().upper() == str(expected_value).strip().upper()

    def _build_password_policy_description(self, property_name: str, actual_value, expected_value) -> str:
        property_key = self._normalize_password_property_key(property_name)

        if property_key == "minimal_password_length":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמערכת דורשת אורך מינימלי של לפחות {expected_value} תווים"

        if property_key == "maximum_password_lifetime":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות מאפשרת מקסימום של {expected_value} ימים"

        if property_key == "maximum_invalid_connect_attempts":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות מאפשרת עד {expected_value} ניסיונות כושלים"

        if property_key == "maximum_unused_initial_password_lifetime":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות מאפשרת מקסימום של {expected_value} ימים לסיסמה ראשונית שלא נוצלה"

        if property_key == "maximum_unused_productive_password_lifetime":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות מאפשרת מקסימום של {expected_value} ימים לסיסמה בסביבה פרודוקטיבית ללא שימוש"

        if property_key == "password_lock_time":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות דורשת נעילה של לפחות {expected_value} דקות"

        if property_key == "minimal_password_lifetime":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות דורשת מינימום {expected_value} ימים לפני החלפת סיסמה נוספת"

        if property_key == "last_used_passwords":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות דורשת היסטוריית סיסמאות של לפחות {expected_value}"

        if property_key == "password_expire_warning_time":
            return f"הערך בפועל הוא {actual_value}, בעוד שהמדיניות דורשת התראה מוקדמת של לפחות {expected_value} ימים"

        return f"ערך מוגדר: {actual_value}, ערך מצופה לפי מדיניות: {expected_value}"

    def _get_password_policy_comparison_rule(self, property_name: str) -> str:
        property_key = self._normalize_password_property_key(property_name)

        if property_key == "minimal_password_length":
            return "מינימום"

        if property_key in {
            "maximum_password_lifetime",
            "maximum_invalid_connect_attempts",
            "maximum_unused_initial_password_lifetime",
            "maximum_unused_productive_password_lifetime",
        }:
            return "מקסימום"

        if property_key in {
            "password_lock_time",
            "minimal_password_lifetime",
            "last_used_passwords",
            "password_expire_warning_time",
        }:
            return "מינימום"

        return "התאמה מדויקת"

    def _get_first_existing_column(self, df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
        for column_name in candidates:
            if column_name in df.columns:
                return column_name
        return None

    def _normalize_ini_token(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and pd.isna(value):
            return ""
        return str(value).strip().strip('"').lower()

    def _normalize_access_token(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and pd.isna(value):
            return ""
        return str(value).strip().strip('"').upper()

    def _build_role_privilege_lookup(self, df_privs: Optional[pd.DataFrame]) -> Dict[str, List[str]]:
        lookup: Dict[str, List[str]] = {}
        if df_privs is None or df_privs.empty:
            return lookup

        grantee_col = self._get_first_existing_column(df_privs, ["GRANTEE", "GRANTEE_NAME", "USER_NAME", "USER"])
        privilege_col = self._get_first_existing_column(df_privs, ["PRIVILEGE", "PRIVILEGE_TYPE", "OBJECT_PRIVILEGE"])
        if grantee_col is None or privilege_col is None:
            return lookup

        critical_privileges = {self._normalize_access_token(item) for item in self.config.get("critical_privileges", [])}
        for _, row in df_privs.iterrows():
            grantee = self._normalize_access_token(row.get(grantee_col))
            privilege = self._normalize_access_token(row.get(privilege_col))
            if not grantee or privilege not in critical_privileges:
                continue
            bucket = lookup.setdefault(grantee, [])
            if privilege not in bucket:
                bucket.append(privilege)

        return lookup

    def _compare_config_value(self, actual_value, expected_value, comparison_rule: str) -> bool:
        actual_text = self._normalize_ini_token(actual_value)
        expected_text = self._normalize_ini_token(expected_value)
        normalized_rule = self._normalize_ini_token(comparison_rule)

        try:
            if normalized_rule == "minimum":
                return self._coerce_int(actual_value) >= self._coerce_int(expected_value)
            if normalized_rule == "maximum":
                return self._coerce_int(actual_value) <= self._coerce_int(expected_value)
        except (TypeError, ValueError):
            return actual_text == expected_text

        if normalized_rule == "contains":
            return expected_text in actual_text
        if normalized_rule == "not_contains":
            return expected_text not in actual_text
        return actual_text == expected_text

    def _build_ini_configuration_lookup(self, df_ini: pd.DataFrame) -> List[Dict[str, Any]]:
        file_col = self._get_first_existing_column(df_ini, ["FILE_NAME", "FILE", "FILENAME", "CONFIG_FILE_NAME"])
        section_col = self._get_first_existing_column(df_ini, ["SECTION", "SECTION_NAME"])
        key_col = self._get_first_existing_column(df_ini, ["KEY", "KEY_NAME", "PARAMETER_NAME", "PROPERTY"])
        value_col = self._get_first_existing_column(df_ini, ["VALUE", "CONFIGURED_VALUE", "CURRENT_VALUE"])

        if key_col is None or value_col is None:
            return []

        entries: List[Dict[str, Any]] = []
        for _, row in df_ini.iterrows():
            entries.append({
                "file_name": self._normalize_ini_token(row.get(file_col)) if file_col else "",
                "section": self._normalize_ini_token(row.get(section_col)) if section_col else "",
                "key": self._normalize_ini_token(row.get(key_col)),
                "value": row.get(value_col),
            })
        return entries

    def _get_first_loaded_frame(self, data_frames: Dict[str, pd.DataFrame], keys: List[str]) -> Optional[pd.DataFrame]:
        for key in keys:
            frame = data_frames.get(key)
            if frame is not None:
                return frame
        return None

    def analyze_password_policy(self, df_policy: pd.DataFrame, period_id: str):
        """ניתוח טבלת M_PASSWORD_POLICY מול ערכי הסף המוגדרים"""
        if df_policy is None or df_policy.empty:
            return

        # המרת הנתונים למילון (PROPERTY -> VALUE) לצורך השוואה מהירה
        policy_map = dict(zip(df_policy['PROPERTY'], df_policy['VALUE']))
        thresholds = self.config.get("password_policy_defaults", {})

        for property_name, expected_value in thresholds.items():
            actual_value = policy_map.get(property_name.upper())
            
            if actual_value is None:
                continue

            is_compliant = self._is_password_policy_compliant(property_name, actual_value, expected_value)
            if not is_compliant:
                self.findings.append(Finding(
                    period_id=period_id,
                    category="Password Policy",
                    title=f"חריגה במדיניות סיסמאות: {property_name}",
                    description=self._build_password_policy_description(property_name, actual_value, expected_value),
                    risk_level="Medium",
                    status="Non-Compliant",
                    source_slot="M_PASSWORD_POLICY",
                    actual_value=str(actual_value),
                    expected_value=str(expected_value),
                    comparison_rule=self._get_password_policy_comparison_rule(property_name),
                ))
            else:
                self.findings.append(Finding(
                    period_id=period_id,
                    category="Password Policy",
                    title=f"מדיניות סיסמאות תקינה: {property_name}",
                    description=self._build_password_policy_description(property_name, actual_value, expected_value),
                    risk_level="Low",
                    status="Compliant",
                    source_slot="M_PASSWORD_POLICY",
                    actual_value=str(actual_value),
                    expected_value=str(expected_value),
                    comparison_rule=self._get_password_policy_comparison_rule(property_name),
                ))

    def analyze_critical_users(self, df_users: pd.DataFrame, period_id: str):
        """ניתוח טבלת USERS לאיתור שימוש לא מורשה במשתמשי מערכת/טכניים"""
        if df_users is None or df_users.empty:
            return

        critical_users = self.config.get("critical_users", [])
        
        # זיהוי עמודות רלוונטיות (SAP HANA לעיתים משתמשת בשמות שונים מעט)
        user_col = 'USER_NAME' if 'USER_NAME' in df_users.columns else df_users.columns[0]
        date_col = 'LAST_SUCCESSFUL_CONNECT' if 'LAST_SUCCESSFUL_CONNECT' in df_users.columns else 'LAST_SUCCESSFUL_CONNECT_DATE'

        if date_col not in df_users.columns:
            return

        # סינון: משתמש קריטי שביצע התחברות מוצלחת (אינו '?')
        violations = df_users[
            (df_users[user_col].isin(critical_users)) & 
            (df_users[date_col] != '?') & 
            (df_users[date_col].notna())
        ]

        if violations.empty:
            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title="לא זוהה שימוש במשתמשים קריטיים",
                description="לא אותרו התחברויות פעילות למשתמשי מערכת או משתמשים קריטיים ברשימת הבדיקה.",
                risk_level="Low",
                status="Compliant",
                source_slot="USERS",
            ))
            return

        for _, row in violations.iterrows():
            user_name = row[user_col]
            status = "Exception Approved" if self._is_whitelisted("User", user_name) else "Non-Compliant"
            
            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title=f"שימוש במשתמש קריטי: {user_name}",
                description=f"זוהתה התחברות מוצלחת של משתמש מערכת/טכני בתאריך {row[date_col]}",
                risk_level="High",
                status=status,
                source_slot="USERS",
            ))

    def analyze_privileges(self, df_privs: pd.DataFrame, period_id: str):
        """ניתוח טבלת EFFECTIVE_PRIVILEGE_GRANTEES לאיתור הרשאות ADMIN חריגות"""
        if df_privs is None or df_privs.empty:
            return

        grantee_col = self._get_first_existing_column(df_privs, ["GRANTEE", "GRANTEE_NAME", "USER_NAME", "USER"])
        privilege_col = self._get_first_existing_column(df_privs, ["PRIVILEGE", "PRIVILEGE_TYPE", "OBJECT_PRIVILEGE"])
        if grantee_col is None or privilege_col is None:
            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title="מבנה טבלת ההרשאות אינו נתמך",
                description="לא נמצאו עמודות מתאימות כגון GRANTEE ו-PRIVILEGE בטבלת ההרשאות.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            ))
            return

        critical_privs = {self._normalize_access_token(item) for item in self.config.get("critical_privileges", [])}
        critical_users = {self._normalize_access_token(item) for item in self.config.get("critical_users", [])}

        privilege_series = df_privs[privilege_col].map(self._normalize_access_token)
        violations = df_privs[privilege_series.isin(critical_privs)]

        if violations.empty:
            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title="לא זוהו הרשאות קריטיות חריגות",
                description="לא נמצאו הרשאות רגישות שהוקצו למשתמשים שאינם מורשים לפי רשימת ההגדרות.",
                risk_level="Low",
                status="Compliant",
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            ))
            return

        for _, row in violations.iterrows():
            grantee = str(row.get(grantee_col, "")).strip()
            privilege = str(row.get(privilege_col, "")).strip()
            normalized_grantee = self._normalize_access_token(grantee)

            if normalized_grantee in critical_users:
                continue

            status = "Exception Approved" if self._is_whitelisted("Privilege", privilege) else "Non-Compliant"
            description = f"המשתמש/אובייקט {grantee} מחזיק בהרשאת ניהול רגישה ללא הרשאה מתאימה"
            if normalized_grantee == "PUBLIC":
                description = f"ההרשאה {privilege} הוקצתה ל-PUBLIC ולכן עשויה להיות זמינה לכלל המשתמשים במערכת"

            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title=f"הרשאה קריטית חריגה: {privilege} | משתמש: {grantee}",
                description=description,
                risk_level="High",
                status=status,
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
            ))

    def analyze_role_assignments(self, df_roles: pd.DataFrame, df_privs: Optional[pd.DataFrame], period_id: str):
        """ניתוח הקצאות ROLE כדי לזהות הרשאות רגישות שמגיעות בירושה דרך תפקידים"""
        if df_roles is None or df_roles.empty:
            return

        role_col = self._get_first_existing_column(df_roles, ["ROLE_NAME", "ROLE", "GRANTED_ROLE_NAME", "GRANTED_ROLE"])
        grantee_col = self._get_first_existing_column(df_roles, ["GRANTEE", "GRANTEE_NAME", "USER_NAME", "USER"])
        if role_col is None or grantee_col is None:
            self.findings.append(Finding(
                period_id=period_id,
                category="Role-Based Access",
                title="מבנה טבלת התפקידים אינו נתמך",
                description="לא נמצאו עמודות מתאימות כגון ROLE_NAME ו-GRANTEE בטבלת GRANTED_ROLES.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="GRANTED_ROLES",
            ))
            return

        critical_users = {self._normalize_access_token(item) for item in self.config.get("critical_users", [])}
        critical_roles = {self._normalize_access_token(item) for item in self.config.get("critical_roles", [])}
        role_privilege_lookup = self._build_role_privilege_lookup(df_privs)
        sensitive_found = False

        for _, row in df_roles.iterrows():
            role_name = str(row.get(role_col, "")).strip()
            grantee = str(row.get(grantee_col, "")).strip()
            normalized_role = self._normalize_access_token(role_name)
            normalized_grantee = self._normalize_access_token(grantee)

            if not normalized_role or not normalized_grantee:
                continue
            if normalized_grantee in critical_users:
                continue

            inherited_privileges = role_privilege_lookup.get(normalized_role, [])
            is_sensitive_role = normalized_role in critical_roles or bool(inherited_privileges) or normalized_grantee == "PUBLIC"
            if not is_sensitive_role:
                continue

            sensitive_found = True
            if normalized_grantee == "PUBLIC":
                title = f"תפקיד הוקצה ל-PUBLIC: {role_name}"
                description = f"התפקיד {role_name} הוקצה ל-PUBLIC ולכן החשיפה רחבה לכלל המשתמשים במערכת."
                risk_level = "High"
            else:
                privilege_text = ", ".join(inherited_privileges) if inherited_privileges else "תפקיד שהוגדר כרגיש בהגדרות"
                title = f"תפקיד רגיש הוקצה: {role_name} | משתמש: {grantee}"
                description = f"המשתמש {grantee} קיבל את התפקיד {role_name}, הכולל {privilege_text}."
                risk_level = "High" if inherited_privileges else "Medium"

            status = "Exception Approved" if self._is_whitelisted("Role", role_name) else "Non-Compliant"
            self.findings.append(Finding(
                period_id=period_id,
                category="Role-Based Access",
                title=title,
                description=description,
                risk_level=risk_level,
                status=status,
                source_slot="GRANTED_ROLES",
            ))

        if not sensitive_found:
            self.findings.append(Finding(
                period_id=period_id,
                category="Role-Based Access",
                title="לא זוהו תפקידים רגישים שהוקצו בירושה",
                description="לא אותרו Role assignments רגישים או תפקידים עם הרשאות קריטיות שהוקצו למשתמשים שאינם מורשים.",
                risk_level="Low",
                status="Compliant",
                source_slot="GRANTED_ROLES",
            ))

    def analyze_audit_trail(self, df_audit_trail: pd.DataFrame, period_id: str):
        """בדיקת ראיות Audit בפועל על בסיס תמצית יומן אירועים"""
        if df_audit_trail is None or df_audit_trail.empty:
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Evidence",
                title="קובץ Audit Trail לא נטען או ריק",
                description="לא ניתן לאמת ראיות Audit בפועל מאחר שקובץ התיעוד לא נטען או אינו כולל שורות.",
                risk_level="Medium",
                status="Missing Evidence",
                source_slot="AUDIT_TRAIL",
            ))
            return

        event_col = self._get_first_existing_column(df_audit_trail, ["ACTION", "ACTION_NAME", "EVENT_ACTION", "EVENT", "STATEMENT_STRING", "COMMAND_TEXT"])
        user_col = self._get_first_existing_column(df_audit_trail, ["USER_NAME", "USER", "DB_USER", "EXECUTING_USER"])
        status_col = self._get_first_existing_column(df_audit_trail, ["STATUS", "RESULT", "OUTCOME", "SUCCESS"])
        if event_col is None:
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Evidence",
                title="מבנה Audit Trail אינו נתמך",
                description="לא אותרה עמודת פעולה מתאימה כגון ACTION או EVENT בקובץ ה-Audit Trail.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="AUDIT_TRAIL",
            ))
            return

        keywords = [self._normalize_access_token(item) for item in self.config.get("audit_event_keywords", ["CREATE USER", "ALTER USER", "DROP USER", "GRANT ROLE", "REVOKE", "AUDIT POLICY"])]
        matched_events = []
        failed_events = []

        for _, row in df_audit_trail.iterrows():
            action_text = self._normalize_access_token(row.get(event_col))
            if not any(keyword in action_text for keyword in keywords):
                continue

            event_details = {
                "action": str(row.get(event_col, "")).strip(),
                "user": str(row.get(user_col, "לא ידוע")).strip() if user_col else "לא ידוע",
                "status": self._normalize_access_token(row.get(status_col)) if status_col else "",
            }
            matched_events.append(event_details)
            if any(token in event_details["status"] for token in ["FAIL", "ERROR", "DENIED", "UNAUTHORIZED", "REJECT"]):
                failed_events.append(event_details)

        if matched_events:
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Evidence",
                title="נמצאו אירועי Audit קריטיים ביומן",
                description=f"זוהו {len(matched_events)} אירועים מנהליים קריטיים בתמצית ה-Audit Trail.",
                risk_level="Low",
                status="Compliant",
                source_slot="AUDIT_TRAIL",
            ))

        if failed_events:
            for event in failed_events[:10]:
                self.findings.append(Finding(
                    period_id=period_id,
                    category="Audit Evidence",
                    title=f"אירוע Audit חריג: {event['action']} | משתמש: {event['user']}",
                    description=f"אירוע Audit זוהה עם סטטוס כשל או דחייה: {event['status'] or 'לא ידוע'}.",
                    risk_level="High",
                    status="Non-Compliant",
                    source_slot="AUDIT_TRAIL",
                ))
        elif not matched_events:
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Evidence",
                title="לא אותרו אירועי Audit מנהליים קריטיים",
                description="קובץ ה-Audit Trail נטען אך לא אותרו בו פעולות רגישות מתוך רשימת מילות המפתח המוגדרת.",
                risk_level="Medium",
                status="Compliant",
                source_slot="AUDIT_TRAIL",
            ))

    def analyze_audit_policies(self, df_audit: pd.DataFrame, period_id: str):
        """ניתוח טבלת AUDIT_POLICIES לוודא שאירועים קריטיים מנוטרים"""
        if df_audit is None or df_audit.empty:
            # במידה ואין פוליסי בכלל - זו חריגה חמורה
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Config",
                title="מדיניות ניטור (Audit) אינה מוגדרת",
                description="לא נמצאו הגדרות ניטור פעילות במערכת SAP HANA",
                risk_level="High",
                status="Non-Compliant",
                source_slot="AUDIT_POLICIES",
            ))
            return

        # בדיקה אם יש פוליסי בסטטוס מושבת
        disabled_policies = df_audit[df_audit['IS_AUDIT_POLICY_ACTIVE'] == 'FALSE']
        active_policies = df_audit[df_audit['IS_AUDIT_POLICY_ACTIVE'] == 'TRUE']

        for _, row in active_policies.iterrows():
            policy_name = row['AUDIT_POLICY_NAME']
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Config",
                title=f"מדיניות ניטור פעילה: {policy_name}",
                description=f"הפוליסי {policy_name} פעיל במערכת ומוגדר לניטור.",
                risk_level="Low",
                status="Compliant",
                source_slot="AUDIT_POLICIES",
                actual_value="TRUE",
                expected_value="TRUE",
                comparison_rule="התאמה מדויקת",
            ))
        
        for _, row in disabled_policies.iterrows():
            policy_name = row['AUDIT_POLICY_NAME']
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Config",
                title=f"מדיניות ניטור מושבתת: {policy_name}",
                description=f"הפוליסי {policy_name} קיים במערכת אך אינו פעיל (Disabled)",
                risk_level="Medium",
                status="Non-Compliant",
                source_slot="AUDIT_POLICIES",
                actual_value="FALSE",
                expected_value="TRUE",
                comparison_rule="התאמה מדויקת",
            ))

    def analyze_ini_configuration(self, df_ini: pd.DataFrame, period_id: str):
        """ניתוח טבלת M_INIFILE_CONTENTS לזיהוי חריגות בהגדרות קונפיגורציה קריטיות"""
        if df_ini is None or df_ini.empty:
            self.findings.append(Finding(
                period_id=period_id,
                category="Configuration Hardening",
                title="קובץ M_INIFILE_CONTENTS לא נטען או ריק",
                description="לא ניתן לאמת הגדרות קונפיגורציה קריטיות ללא תמצית M_INIFILE_CONTENTS.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="M_INIFILE_CONTENTS",
            ))
            return

        expected_controls = self.config.get("ini_security_defaults", [])
        if not expected_controls:
            return

        ini_entries = self._build_ini_configuration_lookup(df_ini)
        if not ini_entries:
            self.findings.append(Finding(
                period_id=period_id,
                category="Configuration Hardening",
                title="מבנה M_INIFILE_CONTENTS אינו נתמך",
                description="לא אותרו עמודות מפתח מתאימות כגון FILE_NAME / SECTION / KEY / VALUE.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="M_INIFILE_CONTENTS",
            ))
            return

        for control in expected_controls:
            file_name = self._normalize_ini_token(control.get("file_name", ""))
            section_name = self._normalize_ini_token(control.get("section", ""))
            key_name = self._normalize_ini_token(control.get("key", ""))
            expected_value = control.get("expected_value", "")
            comparison_rule = control.get("comparison_rule", "Exact")
            title = control.get("title") or f"בדיקת קונפיגורציה: {key_name}"
            risk_level = control.get("risk_level", "Medium")

            matched_entries = [
                entry for entry in ini_entries
                if entry.get("key") == key_name
                and (not file_name or not entry.get("file_name") or entry.get("file_name") == file_name)
                and (not section_name or entry.get("section") == section_name)
            ]

            if not matched_entries:
                self.findings.append(Finding(
                    period_id=period_id,
                    category="Configuration Hardening",
                    title=f"פרמטר קונפיגורציה חסר: {key_name}",
                    description=f"הפרמטר {key_name} לא אותר ב-M_INIFILE_CONTENTS ולכן לא ניתן לאמת את ההגדרה הנדרשת.",
                    risk_level=risk_level,
                    status="Non-Compliant",
                    source_slot="M_INIFILE_CONTENTS",
                    actual_value="Missing",
                    expected_value=str(expected_value),
                    comparison_rule=str(comparison_rule),
                ))
                continue

            actual_value = matched_entries[0].get("value")
            is_compliant = self._compare_config_value(actual_value, expected_value, comparison_rule)
            description = (
                f"בדיקת הפרמטר {key_name} מתוך {matched_entries[0].get('file_name') or '-'}"
                f" / {matched_entries[0].get('section') or '-'}: ערך בפועל {actual_value}, ערך נדרש {expected_value}."
            )

            self.findings.append(Finding(
                period_id=period_id,
                category="Configuration Hardening",
                title=title,
                description=description,
                risk_level="Low" if is_compliant else risk_level,
                status="Compliant" if is_compliant else "Non-Compliant",
                source_slot="M_INIFILE_CONTENTS",
                actual_value=str(actual_value),
                expected_value=str(expected_value),
                comparison_rule=str(comparison_rule),
            ))

    def run_all_checks(self, data_frames: Dict[str, pd.DataFrame], period_id: str) -> List[Finding]:
        """הרצת הניתוח הכולל על כל המקורות שנטענו"""
        self.findings = []
        
        # הרצת הבדיקות לפי הסלוטים שהוגדרו ב-app.py
        if 'M_PASSWORD_POLICY' in data_frames:
            self.analyze_password_policy(data_frames['M_PASSWORD_POLICY'], period_id)
            
        if 'USERS' in data_frames:
            self.analyze_critical_users(data_frames['USERS'], period_id)
            
        if 'EFFECTIVE_PRIVILEGE_GRANTEES' in data_frames:
            self.analyze_privileges(data_frames['EFFECTIVE_PRIVILEGE_GRANTEES'], period_id)
            
        if 'AUDIT_POLICIES' in data_frames:
            self.analyze_audit_policies(data_frames['AUDIT_POLICIES'], period_id)

        roles_df = self._get_first_loaded_frame(data_frames, ['GRANTED_ROLES', 'EFFECTIVE_ROLES', 'EFFECTIVE_ROLE_GRANTEES'])
        privilege_df = self._get_first_loaded_frame(data_frames, ['EFFECTIVE_PRIVILEGE_GRANTEES', 'GRANTED_PRIVILEGES'])
        if roles_df is not None:
            self.analyze_role_assignments(roles_df, privilege_df, period_id)
        else:
            self.findings.append(Finding(
                period_id=period_id,
                category="Role-Based Access",
                title="קלט GRANTED_ROLES חסר",
                description="לא הוטען מקור תפקידי Role inheritance ולכן לא בוצעה בדיקת עומק להקצאות תפקידים רגישות.",
                risk_level="Medium",
                status="Missing Evidence",
                source_slot="GRANTED_ROLES",
            ))

        audit_trail_df = self._get_first_loaded_frame(data_frames, ['AUDIT_TRAIL', 'AUDIT_LOG', 'AUDIT_LOGS'])
        if audit_trail_df is not None:
            self.analyze_audit_trail(audit_trail_df, period_id)
        else:
            self.findings.append(Finding(
                period_id=period_id,
                category="Audit Evidence",
                title="קלט AUDIT_TRAIL חסר",
                description="לא הוטען קובץ Audit Trail ולכן לא ניתן לאמת בפועל אירועים מנהליים רגישים מתקופת הביקורת.",
                risk_level="Medium",
                status="Missing Evidence",
                source_slot="AUDIT_TRAIL",
            ))

        if 'M_INIFILE_CONTENTS' in data_frames:
            self.analyze_ini_configuration(data_frames['M_INIFILE_CONTENTS'], period_id)
        else:
            self.findings.append(Finding(
                period_id=period_id,
                category="Configuration Hardening",
                title="קלט M_INIFILE_CONTENTS חסר",
                description="לא הוטען מקור הנתונים M_INIFILE_CONTENTS ולכן חלק מבדיקות הקשחת התצורה לא בוצעו.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="M_INIFILE_CONTENTS",
            ))

        self._sort_findings()
        return self.findings