# מדריך מילוי קטלוג בקרות — SAP HANA DB

מסמך זה מתאר כיצד להחליף את בקרות ה-placeholder במזהי Ayalon סופיים ולמלא את הקטלוג.

## מיפוי EY → Placeholder IDs

| תחום EY | בקרה (EY) | control_id (placeholder) | required_slots |
|---------|-----------|--------------------------|----------------|
| Access Management | משתמשים קריטיים | `DB-AM-01_PLACEHOLDER` | USERS |
| Access Management | הרשאות ניהול ישירות | `DB-AM-02_PLACEHOLDER` | GRANTED_PRIVILEGES |
| Access Management | הרשאות דרך roles | `DB-AM-03_PLACEHOLDER` | GRANTED_ROLES, GRANTED_PRIVILEGES |
| Password Policy | מדיניות סיסמה (טבלה) | `DB-PP-01_PLACEHOLDER` | M_PASSWORD_POLICY |
| Password Policy | פרמטרי INI | `DB-PP-02_PLACEHOLDER` | M_INIFILE_CONTENTS |
| Audit Logging | מדיניות audit | `DB-AL-01_PLACEHOLDER` | AUDIT_POLICIES |
| Audit Logging | audit trail | `DB-AL-02_PLACEHOLDER` | AUDIT_TRAIL |
| Configuration Hardening | hardening INI | `DB-CF-01_PLACEHOLDER` | M_INIFILE_CONTENTS |
| User Access Review | סקירת גישה | `DB-UAR-01_PLACEHOLDER` | USERS, GRANTED_PRIVILEGES |

## שדות חובה ב-entry

| שדה | תיאור |
|-----|--------|
| `control_id` | מזהה ייחודי (Ayalon) |
| `title_he` | כותרת בעברית |
| `domain` | Access / Password / Audit / Config / UAR |
| `required_slots` | רשימת slot keys |
| `implementation_status` | `placeholder` או `implemented` |
| `validator_ref` | `null` עד יישום validator ב-`src/validators/` |
| `in_scope` | true/false |
| `description` | תיאור הבקרה (מ-workpaper) |
| `risk_description` | תיאור הסיכון |
| `test_steps_override` | צעדי בדיקה (override) |

## דוגמת entry מלאה (commented)

```json
{
  "control_id": "DB1-1_AYALON_XX",
  "title_he": "משתמשים קריטיים",
  "domain": "Access",
  "category": "Access Management",
  "required_slots": ["USERS"],
  "implementation_status": "implemented",
  "validator_ref": "validate_critical_users",
  "in_scope": true,
  "analysis_type": "CRITICAL_USERS",
  "description": "אחת ל...",
  "process": "ניהול גישה",
  "risk_description": "...",
  "test_steps_override": "",
  "notes": ""
}
```

## סדר עבודה מומלץ

1. עדכון `data/knowledge_base/controls_catalog.json`
2. עדכון `src/validators/spec_rules.py` — `AUDIT_CONTROL_DEFINITIONS` + `SLOT_DEFAULT_CONTROLS`
3. יישום validator ב-`src/validators/` (Phase 2+)
4. עדכון `implementation_status` ל-`implemented`
5. הרצת `pytest tests/test_hana_reader_and_catalog.py`

## קבצים קשורים

- [data/knowledge_base/README.md](../data/knowledge_base/README.md)
- [docs/ey_control_mapping_report.md](ey_control_mapping_report.md)
- [data/knowledge_base/_templates/controls_catalog.template.json](../data/knowledge_base/_templates/controls_catalog.template.json)
