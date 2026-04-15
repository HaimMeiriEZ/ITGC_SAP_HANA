# דוח מיפוי בקרות ITGC ל-SAP HANA DB

## מטרת הדוח
דוח זה ממפה בין הבקרות שנדרשות לצורך ביקורת ITGC בסביבת SAP HANA DB, לבין מקורות הקלט הנדרשים, אופן הזיהוי במערכת, וסוגי הממצאים שהכלי מפיק בפועל.

> הערה: כאשר מקור קלט אינו זמין, הכלי מפיק ממצא מסוג Missing Evidence כדי לתעד פער ראייתי בביקורת.

## מטריצת מיפוי

| תחום בקרה | בקרה נבדקת | מקור קלט | רמת דרישה | קטגוריית ממצא | דוגמאות לממצאים שהכלי מפיק | סטטוס כיסוי |
|---|---|---|---|---|---|---|
| Access Management | שימוש במשתמשים קריטיים | USERS | חובה | Access | שימוש במשתמש קריטי; לא זוהה שימוש במשתמשים קריטיים | מיושם |
| Access Management | הרשאות ניהול ישירות למשתמשים | GRANTED_PRIVILEGES | חובה | Access | הרשאה קריטית חריגה; לא זוהו הרשאות קריטיות חריגות | מיושם |
| Access Management | הרשאות רגישות דרך Role inheritance | GRANTED_ROLES + GRANTED_PRIVILEGES | מומלץ | Role-Based Access | תפקיד רגיש הוקצה; תפקיד הוקצה ל-PUBLIC; קלט GRANTED_ROLES חסר | מיושם |
| Password Policy | מדיניות סיסמאות בטבלת HANA | M_PASSWORD_POLICY | חובה | Password Policy | חריגה במדיניות סיסמאות; מדיניות סיסמאות תקינה | מיושם |
| Password Policy | פרמטרי סיסמאות ברמת INI | M_INIFILE_CONTENTS | חובה | Configuration Hardening | אורך סיסמה מינימלי; חובת החלפת סיסמה ראשונית; היסטוריית סיסמאות; ניסיונות התחברות שגויים | מיושם |
| Audit Logging | קיום והפעלה של Audit Policies | AUDIT_POLICIES | חובה | Audit Config | מדיניות ניטור פעילה; מדיניות ניטור מושבתת; מדיניות ניטור אינה מוגדרת | מיושם |
| Audit Logging | ראיות Audit בפועל מתקופת הביקורת | AUDIT_TRAIL | מומלץ | Audit Evidence | נמצאו אירועי Audit קריטיים ביומן; אירוע Audit חריג; קלט AUDIT_TRAIL חסר | מיושם |
| Configuration Hardening | Audit global state | M_INIFILE_CONTENTS | חובה | Configuration Hardening | Audit trail גלובלי חייב להיות פעיל | מיושם |
| Configuration Hardening | Log mode | M_INIFILE_CONTENTS | חובה | Configuration Hardening | Log mode חייב להיות NORMAL | מיושם |
| Configuration Hardening | Detailed error on connect | M_INIFILE_CONTENTS | חובה | Configuration Hardening | אין לחשוף הודעות שגיאה מפורטות בהתחברות | מיושם |
| Configuration Hardening | Password lock for system user | M_INIFILE_CONTENTS | חובה | Configuration Hardening | נעילת משתמשי SYSTEM חייבת להיות פעילה | מיושם |
| Configuration Hardening | Missing evidence handling | M_INIFILE_CONTENTS / GRANTED_ROLES / AUDIT_TRAIL | חובה/מומלץ | Configuration Hardening / Role-Based Access / Audit Evidence | קלט חסר עבור מקור נדרש או מומלץ | מיושם |
| User Access Review | סקירת משתמשים, חריגים, ואישור מנהל | USERS + GRANTED_PRIVILEGES | תומך בקרה | User Review / Access | חריג במסגרת סקירת משתמשים; החלטת מנהל; נדרש בירור | מיושם |

## מקורות קלט נדרשים

### מקורות חובה
- USERS
- M_PASSWORD_POLICY
- GRANTED_PRIVILEGES
- AUDIT_POLICIES
- M_INIFILE_CONTENTS

### מקורות מומלצים
- GRANTED_ROLES
- AUDIT_TRAIL

## מיפוי לקבצים במערכת

| מקור קלט | מיקום מימוש |
|---|---|
| USERS / GRANTED_PRIVILEGES / AUDIT_POLICIES / M_INIFILE_CONTENTS | [core/analyzer.py](core/analyzer.py) |
| טעינת קבצים, ולידציה, תצוגה למשתמש | [gui/app_new.py](gui/app_new.py) |
| הגדרות baseline וערכי סף | [config/settings.json](config/settings.json) |
| בדיקות רגרסיה | [tests/test_analyzer_extended.py](tests/test_analyzer_extended.py) |

## מסקנה
הכלי מכסה כעת את שכבות הבקרה המרכזיות עבור SAP HANA DB ברמת EY-oriented review: גישות, סיסמאות, Audit, הקשחת תצורה, והרשאות דרך תפקידים. בנוסף, הכלי מתעד גם פערי ראיות כאשר קובצי קלט מומלצים או חובה אינם זמינים.
