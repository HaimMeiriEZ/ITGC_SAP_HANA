import pandas as pd
from typing import List, Dict, Any
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

        critical_privs = self.config.get("critical_privileges", [])
        critical_users = self.config.get("critical_users", [])

        # סינון הרשאות רגישות
        violations = df_privs[df_privs['PRIVILEGE'].isin(critical_privs)]

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
            grantee = row['GRANTEE']
            privilege = row['PRIVILEGE']
            
            # דילוג אם המשתמש מוגדר כמשתמש מערכת מורשה
            if grantee in critical_users:
                continue
                
            status = "Exception Approved" if self._is_whitelisted("Privilege", privilege) else "Non-Compliant"

            self.findings.append(Finding(
                period_id=period_id,
                category="Access",
                title=f"הרשאה קריטית חריגה: {privilege} | משתמש: {grantee}",
                description=f"המשתמש {grantee} מחזיק בהרשאת ניהול רגישה ללא הרשאה מתאימה",
                risk_level="High",
                status=status,
                source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
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

        self._sort_findings()
        return self.findings