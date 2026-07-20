# Knowledge Base — ITGC SAP HANA DB

תיקייה זו מכילה את קטלוג הבקרות והמטא-דאטה לניתוח ITGC על יצואי SAP HANA DB.

## קבצים

| קובץ | תפקיד |
|------|--------|
| `controls_catalog.json` | קטלוג בקרות — מזהים, כותרות, דומיין, slots נדרשים, סטטוס יישום |
| `field_labels.json` | תוויות עברית לעמודות ביצואי HANA (לפי slot) |
| `slot_definitions.json` | הגדרות slot: דפוסי שם קובץ, עמודות חובה/אופציונליות |
| `_templates/` | תבניות JSON למילוי עתידי |

## מצב נוכחי (Phase 1)

כל הבקרות מסומנות `implementation_status: "placeholder"`.  
ה-validator logic עדיין ב-`core/analyzer.py`; קטלוג זה הוא תשתית ל-migration עתידי.

## קשר ל-EY mapping

ראו [docs/ey_control_mapping_report.md](../../docs/ey_control_mapping_report.md) ו-[docs/CONTROLS_CATALOG_FILL_GUIDE.md](../../docs/CONTROLS_CATALOG_FILL_GUIDE.md).

## סדר מילוי עתידי

1. החלפת `*_PLACEHOLDER` במזהי Ayalon סופיים
2. מילוי `description`, `risk_description`, `test_steps_override`
3. הגדרת `implementation_status: "implemented"` והפניית `validator_ref`
4. הרצת smoke tests ב-`tests/test_hana_reader_and_catalog.py`
