import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any

class DatabaseManager:
    """
    מנהל את הקשר עם בסיס הנתונים SQLite.
    אחראי על יצירת טבלאות, שמירת ממצאים וניהול לוגים.
    """
    
    def __init__(self, db_path: str = "audit_system.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _ensure_column(self, cursor, table_name: str, column_name: str, column_definition: str):
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = {row[1] for row in cursor.fetchall()}
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")

    def _init_db(self):
        """יצירת טבלאות בסיס הנתונים במידה ואינן קיימות"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # טבלת ממצאי ביקורת
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_id TEXT,
                    category TEXT,
                    title TEXT,
                    description TEXT,
                    risk_level TEXT,
                    status TEXT,
                    source_slot TEXT,
                    source_file TEXT,
                    extract_date TEXT,
                    remediation_owner TEXT,
                    evidence_ref TEXT,
                    created_at TEXT
                )
            ''')
            self._ensure_column(cursor, "findings", "source_slot", "TEXT")
            self._ensure_column(cursor, "findings", "source_file", "TEXT")
            self._ensure_column(cursor, "findings", "extract_date", "TEXT")
            
            # טבלת מטריצת בקרות
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS controls (
                    control_number TEXT PRIMARY KEY,
                    process TEXT,
                    risk TEXT,
                    description TEXT,
                    is_key INTEGER,
                    nature TEXT,
                    frequency TEXT
                )
            ''')
            
            # טבלת לוג פעילות
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    action TEXT,
                    details TEXT,
                    user TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ipe_loads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slot_key TEXT,
                    original_filename TEXT,
                    extract_date TEXT,
                    row_count INTEGER,
                    file_path TEXT,
                    loaded_at TEXT,
                    user TEXT
                )
            ''')
            
            # טבלת החרגות (Whitelist)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    object_type TEXT,
                    object_name TEXT,
                    justification TEXT,
                    approved_by TEXT,
                    approval_date TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_access_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_id TEXT,
                    user_name TEXT,
                    review_date TEXT,
                    extract_date TEXT,
                    user_type TEXT,
                    active_status TEXT,
                    last_login TEXT,
                    days_since_login TEXT,
                    critical_privileges TEXT,
                    has_exception TEXT,
                    exception_reason TEXT,
                    review_status TEXT,
                    manager_decision TEXT,
                    action_required TEXT,
                    manager_comments TEXT,
                    updated_at TEXT,
                    UNIQUE(period_id, user_name)
                )
            ''')
            conn.commit()

    def log_activity(self, action: str, details: str, user: str = "System"):
        """רישום פעולה בלוג המערכת"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO activity_log (timestamp, action, details, user) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), action, details, user)
            )
            conn.commit()

    def save_findings(self, findings: List[Dict[str, Any]]):
        """שמירת רשימת ממצאים לבסיס הנתונים"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for f in findings:
                cursor.execute('''
                    INSERT INTO findings 
                    (period_id, category, title, description, risk_level, status, source_slot, source_file, extract_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f.get('period_id'), f.get('category'), f.get('title'),
                    f.get('description'), f.get('risk_level'), f.get('status'),
                    f.get('source_slot'), f.get('source_file'), f.get('extract_date'),
                    datetime.now().isoformat()
                ))
            conn.commit()
            self.log_activity("Save Findings", f"Saved {len(findings)} new findings to database.")

    def save_ipe_load(self, slot_key: str, original_filename: str, extract_date: str, row_count: int, file_path: str, user: str = "User"):
        """שמירת טעינת קובץ IPE לבסיס הנתונים"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                    INSERT INTO ipe_loads
                    (slot_key, original_filename, extract_date, row_count, file_path, loaded_at, user)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (slot_key, original_filename, extract_date, row_count, file_path, datetime.now().isoformat(), user)
            )
            conn.commit()

    def get_all_findings(self) -> List[Dict]:
        """משיכת כל הממצאים מהדאטהבייס"""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_whitelist(self) -> List[Dict]:
        """משיכת רשימת ההחרגות"""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM whitelist")
            return [dict(row) for row in cursor.fetchall()]

    def save_user_review_rows(self, rows: List[Dict[str, Any]]):
        """שמירה/עדכון של שורות סקירת משתמשים"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for row in rows:
                cursor.execute(
                    '''
                        INSERT INTO user_access_reviews (
                            period_id, user_name, review_date, extract_date, user_type, active_status,
                            last_login, days_since_login, critical_privileges, has_exception,
                            exception_reason, review_status, manager_decision, action_required,
                            manager_comments, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(period_id, user_name) DO UPDATE SET
                            review_date=excluded.review_date,
                            extract_date=excluded.extract_date,
                            user_type=excluded.user_type,
                            active_status=excluded.active_status,
                            last_login=excluded.last_login,
                            days_since_login=excluded.days_since_login,
                            critical_privileges=excluded.critical_privileges,
                            has_exception=excluded.has_exception,
                            exception_reason=excluded.exception_reason,
                            review_status=excluded.review_status,
                            manager_decision=excluded.manager_decision,
                            action_required=excluded.action_required,
                            manager_comments=excluded.manager_comments,
                            updated_at=excluded.updated_at
                    ''',
                    (
                        row.get('period_id'), row.get('user_name'), row.get('review_date'), row.get('extract_date'),
                        row.get('user_type'), row.get('active_status'), row.get('last_login'), str(row.get('days_since_login', '')),
                        row.get('critical_privileges'), row.get('has_exception'), row.get('exception_reason'),
                        row.get('review_status'), row.get('manager_decision'), row.get('action_required'),
                        row.get('manager_comments'), datetime.now().isoformat()
                    )
                )
            conn.commit()

    def get_user_review_rows(self, period_id: str) -> Dict[str, Dict[str, Any]]:
        """טעינת החלטות סקירה שמורות לפי תקופה"""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_access_reviews WHERE period_id = ?", (period_id,))
            return {row['user_name']: dict(row) for row in cursor.fetchall()}