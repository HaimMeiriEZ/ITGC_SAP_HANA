import copy
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

if sys.platform != "win32" and not os.environ.get("DISPLAY"):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QDate, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QTabWidget,
)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR if (BASE_DIR / "core").exists() else BASE_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from DataClasses import Finding
    from DatabaseManager import DatabaseManager
    from core.importer import DataImporter
    from core.analyzer import AuditAnalyzer
    from core.support_logger import SupportLogger
    from core.user_review import (
        build_user_review_report,
        export_user_review_to_excel,
        export_user_review_to_pdf,
    )
except ImportError as e:
    print(f"שגיאת ייבוא: וודא שכל הקבצים נמצאים בנתיב הנכון. פירוט: {e}")
    raise


class SimpleVar:
    def __init__(self, value=None):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class AuditGUI:
    DEFAULT_SETTINGS = {
        "critical_users": ["SYSTEM", "SAPHANADB", "SYS", "_SYS_REPO", "XSSQLCC_AUTO_USER"],
        "critical_roles": ["SAP_INTERNAL_HANA_SUPPORT", "PUBLIC"],
        "critical_privileges": [
            "AUDIT ADMIN",
            "AUDIT OPERATOR",
            "DATA ADMIN",
            "INIFILE ADMIN",
            "LOG ADMIN",
            "ROLE ADMIN",
            "SERVICE ADMIN",
            "TRUST ADMIN",
            "USER ADMIN",
            "BACKUP ADMIN",
        ],
        "password_policy_defaults": {
            "minimal_password_length": 8,
            "force_first_password_change": "TRUE",
            "password_lock_time": 1440,
            "password_layout": "A1a",
            "last_used_passwords": 5,
            "maximum_invalid_connect_attempts": 6,
            "minimal_password_lifetime": 1,
            "maximum_password_lifetime": 182,
            "maximum_unused_initial_password_lifetime": 7,
            "maximum_unused_productive_password_lifetime": 365,
            "password_expire_warning_time": 14,
            "password_lock_for_system_user": "TRUE",
            "detailed_error_on_connect": "FALSE",
        },
        "file_mappings": {
            "USERS": "users_export.csv",
            "M_PASSWORD_POLICY": "password_policy.csv",
            "GRANTED_PRIVILEGES": "privileges.csv",
            "GRANTED_ROLES": "granted_roles.csv",
            "AUDIT_POLICIES": "audit_policies.csv",
            "AUDIT_TRAIL": "audit_trail.csv",
            "M_INIFILE_CONTENTS": "m_inifile_contents.csv",
        },
        "audit_event_keywords": [
            "CREATE USER",
            "ALTER USER",
            "DROP USER",
            "CREATE ROLE",
            "DROP ROLE",
            "GRANT ROLE",
            "GRANT PRIVILEGE",
            "REVOKE",
            "ALTER SYSTEM",
            "AUDIT POLICY",
            "LOGIN",
        ],
        "ini_security_defaults": [
            {
                "file_name": "global.ini",
                "section": "auditing configuration",
                "key": "global_auditing_state",
                "expected_value": "true",
                "comparison_rule": "Exact",
                "risk_level": "High",
                "title": "Audit trail גלובלי חייב להיות פעיל",
            },
            {
                "file_name": "global.ini",
                "section": "persistence",
                "key": "log_mode",
                "expected_value": "normal",
                "comparison_rule": "Exact",
                "risk_level": "High",
                "title": "Log mode חייב להיות NORMAL",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "detailed_error_on_connect",
                "expected_value": "false",
                "comparison_rule": "Exact",
                "risk_level": "Medium",
                "title": "אין לחשוף הודעות שגיאה מפורטות בהתחברות",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "password_lock_for_system_user",
                "expected_value": "true",
                "comparison_rule": "Exact",
                "risk_level": "High",
                "title": "נעילת משתמשי SYSTEM חייבת להיות פעילה",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "force_first_password_change",
                "expected_value": "true",
                "comparison_rule": "Exact",
                "risk_level": "Medium",
                "title": "חובת החלפת סיסמה ראשונית חייבת להיות פעילה",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "minimal_password_length",
                "expected_value": 8,
                "comparison_rule": "Minimum",
                "risk_level": "High",
                "title": "אורך סיסמה מינימלי חייב להיות לפחות 8",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "maximum_invalid_connect_attempts",
                "expected_value": 6,
                "comparison_rule": "Maximum",
                "risk_level": "Medium",
                "title": "מספר ניסיונות התחברות שגויים חייב להיות מוגבל",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "last_used_passwords",
                "expected_value": 5,
                "comparison_rule": "Minimum",
                "risk_level": "Medium",
                "title": "היסטוריית סיסמאות חייבת לכלול לפחות 5 ערכים",
            },
            {
                "file_name": "indexserver.ini",
                "section": "password policy",
                "key": "password_expire_warning_time",
                "expected_value": 14,
                "comparison_rule": "Minimum",
                "risk_level": "Low",
                "title": "יש להתריע מראש לפני פקיעת סיסמה",
            },
        ],
        "inactive_days_threshold": 120,
        "user_review_period": {
            "start_date": "2026-01-01",
            "end_date": "2026-06-30",
        },
        "user_type_rules": {
            "Dialog": ["DIALOG", "DIA", "ENDUSER"],
            "Generic": ["GENERIC", "SHARED", "COMMON", "FIRE", "EMERGENCY"],
            "Technical": ["_SYS", "SYSTEM", "TECH", "SERVICE", "BATCH", "ADMIN"],
            "Application": [],
        },
    }

    def __init__(self, root=None):
        self.app = QApplication.instance() or QApplication(sys.argv)
        self.app.setLayoutDirection(Qt.RightToLeft)

        self.window = root if isinstance(root, QMainWindow) else QMainWindow()
        self.window.setWindowTitle("מערכת ביקורת SAP HANA ITGC - PySide6")
        self.window.resize(1150, 900)
        self.window.setMinimumSize(1050, 800)
        self.window.setStyleSheet(
            """
            QMainWindow, QWidget { background-color: #f8f9fa; }
            QGroupBox {
                font-weight: 600;
                margin-top: 18px;
                padding-top: 12px;
                border: 1px solid #cfd6de;
                border-radius: 6px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 12px;
                color: #1f2d3d;
                background-color: #f8f9fa;
            }
            QLabel[class="section"] { font-size: 16px; font-weight: 700; }
            QLabel[class="sectionTitle"] { font-size: 14px; font-weight: 700; color: #1f2d3d; }
            QLabel[class="hint"] { color: #5f6b7a; }
            QTableWidget, QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QDateEdit {
                background-color: white;
                border: 1px solid #d7dce2;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton { padding: 6px 12px; }
            """
        )
        self.support_logger = SupportLogger(log_dir=PROJECT_ROOT / "logs")

        self.loaded_dataframes = {}
        self.loaded_files = {}
        self.loaded_extract_dates = {}
        self.ipe_records = []
        self.current_findings = []
        self.displayed_findings = []
        self.user_review_report = None
        self.user_review_df = pd.DataFrame()
        self.selected_user_review_index = None
        self.user_review_dirty_rows = set()
        self.user_review_visible_indices = []
        self.user_review_inline_editor = None
        self.settings_widgets = {}
        self.boolean_fields = {}
        self.slot_extract_date_vars = {}
        self.slot_extract_date_widgets = {}
        self.slot_status_labels = {}
        self.risk_filter_var = SimpleVar("הכל")
        self.category_filter_var = SimpleVar("הכל")
        self.source_filter_var = SimpleVar("הכל")
        self.sort_column = "risk"
        self.sort_reverse = False
        self.slot_metadata = {
            "USERS": {
                "label": "משתמשים (טבלת USERS)",
                "required": ["USER_NAME"],
                "required_any": [("LAST_SUCCESSFUL_CONNECT", "LAST_SUCCESSFUL_CONNECT_DATE")],
            },
            "M_PASSWORD_POLICY": {
                "label": "מדיניות סיסמאות (טבלת M_PASSWORD_POLICY)",
                "required": ["PROPERTY", "VALUE"],
                "required_any": [],
            },
            "GRANTED_PRIVILEGES": {
                "label": "הרשאות (טבלת GRANTED_PRIVILEGES)",
                "required": ["GRANTEE", "PRIVILEGE"],
                "required_any": [],
            },
            "GRANTED_ROLES": {
                "label": "הקצאות תפקידים (טבלת GRANTED_ROLES)",
                "required": [],
                "required_any": [
                    ("GRANTEE", "GRANTEE_NAME", "USER_NAME", "USER"),
                    ("ROLE_NAME", "ROLE", "GRANTED_ROLE_NAME", "GRANTED_ROLE"),
                ],
            },
            "AUDIT_POLICIES": {
                "label": "מדיניות ניטור (טבלת AUDIT_POLICIES)",
                "required": ["AUDIT_POLICY_NAME", "IS_AUDIT_POLICY_ACTIVE"],
                "required_any": [],
            },
            "AUDIT_TRAIL": {
                "label": "ראיות Audit בפועל (Audit Trail)",
                "required": [],
                "required_any": [
                    ("ACTION", "ACTION_NAME", "EVENT_ACTION", "EVENT", "STATEMENT_STRING", "COMMAND_TEXT"),
                ],
            },
            "M_INIFILE_CONTENTS": {
                "label": "הקשחת תצורה (טבלת M_INIFILE_CONTENTS)",
                "required": [],
                "required_any": [
                    ("SECTION", "SECTION_NAME"),
                    ("KEY", "KEY_NAME", "PARAMETER_NAME", "PROPERTY"),
                    ("VALUE", "CONFIGURED_VALUE", "CURRENT_VALUE"),
                ],
            },
        }

        self.settings_path = PROJECT_ROOT / "config" / "settings.json"
        try:
            self.db = DatabaseManager()
            self.importer = DataImporter(config_path=str(self.settings_path))
        except Exception as e:
            self.db = DatabaseManager()
            self.importer = None
            print(f"Error: {e}")

        self.summary_vars = {
            "total": SimpleVar("0"),
            "high": SimpleVar("0"),
            "status": SimpleVar("ממתין לנתונים"),
        }
        self.period_var = SimpleVar(f"{datetime.now().year}-Q{(datetime.now().month - 1) // 3 + 1}")
        self.review_summary_vars = {
            "total_users": SimpleVar("0"),
            "in_scope_users": SimpleVar("0"),
            "exception_users": SimpleVar("0"),
            "privileged_users": SimpleVar("0"),
        }
        self.show_only_exceptions_var = SimpleVar(False)
        self.show_only_unreviewed_var = SimpleVar(False)
        self.show_only_privileged_var = SimpleVar(False)
        self.show_only_active_in_period_var = SimpleVar(False)

        self._setup_ui()
        self._load_settings_into_form(self._current_config())
        self._update_review_period_info_label()

    def show(self):
        self.window.show()

    def _current_config(self):
        if self.importer is not None and getattr(self.importer, "config", None):
            return self.importer.config
        if self.settings_path.exists():
            with open(self.settings_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return copy.deepcopy(self.DEFAULT_SETTINGS)

    def _setup_ui(self):
        central = QWidget()
        self.window.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.notebook = QTabWidget()
        layout.addWidget(self.notebook)

        self.import_tab = QWidget()
        self.user_review_tab = QWidget()
        self.audit_tab = QWidget()
        self.settings_tab = QWidget()

        self.notebook.addTab(self.import_tab, "טעינת נתונים (IPE)")
        self.notebook.addTab(self.user_review_tab, "דוח סקירת משתמשים")
        self.notebook.addTab(self.audit_tab, "ניתוח וממצאים")
        self.notebook.addTab(self.settings_tab, "הגדרות מערכת")

        self._build_import_tab()
        self._build_user_review_tab()
        self._build_audit_tab()
        self._build_settings_tab()

    def _rtl_hebrew_only(self, text):
        return "" if text is None else str(text)

    def _build_import_tab(self):
        outer_layout = QVBoxLayout(self.import_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(10)

        header_layout = QHBoxLayout()
        title = QLabel("ניהול מקורות מידע ומהימנות נתונים (IPE)")
        title.setProperty("class", "section")
        title.setWordWrap(True)
        self.export_ipe_btn = QPushButton("ייצוא לוג IPE ל-Excel")
        self.export_ipe_btn.clicked.connect(self._export_ipe_log)
        header_layout.addWidget(self.export_ipe_btn)
        header_layout.addStretch(1)
        header_layout.addWidget(title)
        layout.addLayout(header_layout)

        slots = [
            ("USERS", "משתמשים (טבלת USERS)", "מקור חובה: רשימת משתמשים ותאריכי התחברות אחרונים"),
            ("M_PASSWORD_POLICY", "מדיניות סיסמאות (טבלת M_PASSWORD_POLICY)", "מקור חובה: פרמטרים והגדרות אבטחת סיסמה"),
            ("GRANTED_PRIVILEGES", "הרשאות (טבלת GRANTED_PRIVILEGES)", "מקור חובה: מיפוי הרשאות מערכת למשתמשים"),
            ("GRANTED_ROLES", "הקצאות תפקידים (טבלת GRANTED_ROLES)", "מקור מומלץ: זיהוי הרשאות רגישות דרך Role inheritance"),
            ("AUDIT_POLICIES", "מדיניות ניטור (טבלת AUDIT_POLICIES)", "מקור חובה: הגדרות לוגים ובקרות ניטור מערכתיות"),
            ("AUDIT_TRAIL", "ראיות Audit בפועל (Audit Trail)", "מקור מומלץ: אימות פעולות מנהליות רגישות בפועל"),
            ("M_INIFILE_CONTENTS", "הקשחת תצורה (טבלת M_INIFILE_CONTENTS)", "מקור חובה: הגדרות קונפיגורציה קריטיות ברמת INI של SAP HANA"),
        ]

        self.slot_delete_btns = {}
        for slot_key, label, desc in slots:
            box = QGroupBox(label)
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(12, 12, 12, 12)
            box_layout.setSpacing(8)

            controls_layout = QHBoxLayout()
            controls_layout.setSpacing(10)

            choose_btn = QPushButton("בחר קובץ...")
            choose_btn.setMinimumSize(110, 32)
            choose_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            choose_btn.clicked.connect(lambda _checked=False, sk=slot_key: self._load_file(sk))

            delete_btn = QPushButton("מחיקה")
            delete_btn.setMinimumSize(80, 32)
            delete_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            delete_btn.setEnabled(False)
            delete_btn.clicked.connect(lambda _checked=False, sk=slot_key: self._delete_file(sk))
            self.slot_delete_btns[slot_key] = delete_btn

            date_label = QLabel("תאריך הפקה:")
            date_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
            date_edit = QDateEdit()
            date_edit.setLayoutDirection(Qt.LeftToRight)
            date_edit.setCalendarPopup(True)
            date_edit.setDisplayFormat("yyyy-MM-dd")
            date_edit.setMinimumSize(140, 32)
            date_edit.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            date_edit.setDate(QDate.currentDate())
            date_edit.dateChanged.connect(lambda _value, sk=slot_key: self._normalize_extract_date(sk, show_message=False))
            self.slot_extract_date_widgets[slot_key] = date_edit
            self.slot_extract_date_vars[slot_key] = SimpleVar(self._get_today_date())

            controls_layout.addWidget(delete_btn, 0, Qt.AlignRight)
            controls_layout.addWidget(choose_btn, 0, Qt.AlignRight)
            controls_layout.addWidget(date_label, 0, Qt.AlignRight)
            controls_layout.addWidget(date_edit, 0, Qt.AlignRight)
            controls_layout.addStretch(1)
            box_layout.addLayout(controls_layout)

            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            box_layout.addWidget(desc_label)

            status_label = QLabel("ממתין לטעינה...")
            status_label.setStyleSheet("color: #7f8c8d;")
            status_label.setWordWrap(True)
            status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.slot_status_labels[slot_key] = status_label
            box_layout.addWidget(status_label)

            layout.addWidget(box)

        ipe_box = QGroupBox("תיעוד דגימות (IPE Artifacts)")
        ipe_layout = QVBoxLayout(ipe_box)
        cols = ["סלוט", "שם קובץ", "תאריך הפקה", "שורות", "זמן טעינה"]
        self.ipe_tree = QTableWidget(0, len(cols))
        self.ipe_tree.setHorizontalHeaderLabels(cols)
        self._configure_table(self.ipe_tree)
        self.ipe_tree.setMinimumHeight(220)
        ipe_layout.addWidget(self.ipe_tree)
        layout.addWidget(ipe_box)
        layout.addStretch(1)

    def _build_user_review_tab(self):
        layout = QVBoxLayout(self.user_review_tab)

        header_layout = QHBoxLayout()
        title = QLabel("דוח סקירת משתמשים למנהלים")
        title.setProperty("class", "section")

        self.export_review_pdf_btn = QPushButton("ייצוא ל-PDF")
        self.export_review_pdf_btn.clicked.connect(self._export_user_review_pdf)
        self.export_review_excel_btn = QPushButton("ייצוא לאקסל")
        self.export_review_excel_btn.clicked.connect(self._export_user_review_excel)
        self.save_review_btn = QPushButton("שמור כל השינויים")
        self.save_review_btn.clicked.connect(self._save_all_user_review_changes)
        self.edit_review_btn = QPushButton("עדכן החלטת מנהל")
        self.edit_review_btn.clicked.connect(self._open_user_review_editor)
        self.generate_review_btn = QPushButton("בנה דוח סקירה")
        self.generate_review_btn.clicked.connect(self._generate_user_review)

        self.review_date_widget = QDateEdit()
        self.review_date_widget.setLayoutDirection(Qt.LeftToRight)
        self.review_date_widget.setCalendarPopup(True)
        self.review_date_widget.setDisplayFormat("yyyy-MM-dd")
        self.review_date_widget.setMinimumWidth(130)
        self.review_date_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.review_date_widget.setDate(QDate.currentDate())
        self.review_date_var = SimpleVar(self._get_today_date())
        self.review_date_widget.dateChanged.connect(lambda value: self.review_date_var.set(value.toPython().isoformat()))

        for widget in [self.export_review_pdf_btn, self.export_review_excel_btn, self.save_review_btn, self.edit_review_btn, self.generate_review_btn, QLabel("תאריך סקירה:"), self.review_date_widget]:
            header_layout.addWidget(widget)
        header_layout.addStretch(1)
        header_layout.addWidget(title)
        layout.addLayout(header_layout)

        self.review_period_info_label = QLabel("טווח בחינה: -")
        self.review_period_info_label.setProperty("class", "hint")
        layout.addWidget(self.review_period_info_label)

        filter_layout = QHBoxLayout()
        self.active_period_checkbox = self._make_checkbox("רק פעילים בתקופת הביקורת", self.show_only_active_in_period_var)
        self.privileged_checkbox = self._make_checkbox("רק בעלי הרשאות קריטיות", self.show_only_privileged_var)
        self.unreviewed_checkbox = self._make_checkbox("רק לא נסקרו", self.show_only_unreviewed_var)
        self.exceptions_checkbox = self._make_checkbox("רק חריגים", self.show_only_exceptions_var)
        for checkbox in [self.active_period_checkbox, self.privileged_checkbox, self.unreviewed_checkbox, self.exceptions_checkbox]:
            filter_layout.addWidget(checkbox)
        filter_layout.addStretch(1)
        layout.addLayout(filter_layout)

        info_box = QGroupBox("מטא-דאטה ותקציר")
        info_layout = QVBoxLayout(info_box)
        summary_layout = QHBoxLayout()
        self.review_summary_labels = {}
        summary_items = [
            ("סה\"כ משתמשים", "total_users"),
            ("באוכלוסיית הסקירה", "in_scope_users"),
            ("חריגים", "exception_users"),
            ("משתמשים עם הרשאות קריטיות", "privileged_users"),
        ]
        for label_text, key in summary_items:
            cell = QVBoxLayout()
            label = QLabel(label_text)
            value_label = QLabel("0")
            value_label.setStyleSheet("font-size: 16px; font-weight: 700;")
            value_label.setAlignment(Qt.AlignCenter)
            label.setAlignment(Qt.AlignCenter)
            cell.addWidget(label)
            cell.addWidget(value_label)
            wrapper = QWidget()
            wrapper.setLayout(cell)
            self.review_summary_labels[key] = value_label
            summary_layout.addWidget(wrapper)
        info_layout.addLayout(summary_layout)

        info_layout.addWidget(QLabel("חלוקה לפי סוגי משתמשים"))
        self.user_type_tree = QTableWidget(0, 2)
        self.user_type_tree.setHorizontalHeaderLabels(["סוג משתמש", "כמות"])
        self._configure_table(self.user_type_tree)
        info_layout.addWidget(self.user_type_tree)
        layout.addWidget(info_box)

        report_box = QGroupBox("רשימת משתמשים לסקירה")
        report_layout = QVBoxLayout(report_box)
        self.user_review_columns = [
            "user_name", "in_scope", "active_status", "active_in_period", "last_login", "days_since_login", "user_type",
            "password_policy_exempt_status", "password_policy_exempt_reason", "system_table_access_status", "critical_privileges", "has_exception", "exception_reason", "review_status", "manager_decision",
            "action_required", "manager_comments",
        ]
        headers = [
            "שם משתמש", "באוכלוסייה", "סטטוס", "פעיל בתקופה", "התחברות אחרונה", "ימים מאז התחברות", "סוג משתמש",
            "החרגת סיסמה", "סיבת החרגה", "גישה לטבלאות מערכת", "הרשאות קריטיות", "חריג", "סיבת חריג", "סטטוס סקירה", "החלטת מנהל", "נדרש להסרה / מאושר להשאיר", "הערות",
        ]
        self.user_review_tree = QTableWidget(0, len(headers))
        self.user_review_tree.setHorizontalHeaderLabels(headers)
        self._configure_table(self.user_review_tree)
        self.user_review_tree.cellDoubleClicked.connect(lambda _row, _col: self._open_user_review_editor())
        self.user_review_tree.itemSelectionChanged.connect(self._handle_user_review_selection)
        report_layout.addWidget(self.user_review_tree)
        layout.addWidget(report_box, 1)

    def _build_audit_tab(self):
        layout = QVBoxLayout(self.audit_tab)

        ctrl_layout = QHBoxLayout()
        title = QLabel("ביצוע ניתוח בקרות ITGC")
        title.setProperty("class", "section")
        self.export_findings_btn = QPushButton("ייצוא ממצאים ל-Excel")
        self.export_findings_btn.clicked.connect(self._export_findings_to_excel)
        self.open_logs_btn = QPushButton("פתח תיקיית לוגים")
        self.open_logs_btn.clicked.connect(self._open_logs_folder)
        self.run_btn = QPushButton("הרץ ניתוח")
        self.run_btn.clicked.connect(self._run_audit)
        self.period_input = QLineEdit(self.period_var.get())
        self.period_input.setLayoutDirection(Qt.LeftToRight)
        self.period_input.setMinimumWidth(100)
        self.period_input.setMaximumWidth(120)
        self.period_input.textChanged.connect(self.period_var.set)

        for widget in [self.export_findings_btn, self.open_logs_btn, self.run_btn, QLabel("תקופה:"), self.period_input]:
            ctrl_layout.addWidget(widget)
        ctrl_layout.addStretch(1)
        ctrl_layout.addWidget(title)
        layout.addLayout(ctrl_layout)

        filter_box = QGroupBox("סינון מהיר")
        filter_layout = QHBoxLayout(filter_box)
        self.source_filter_combo = QComboBox()
        self.category_filter_combo = QComboBox()
        self.risk_filter_combo = QComboBox()
        self.source_filter_combo.currentTextChanged.connect(lambda value: self._set_filter_var(self.source_filter_var, value))
        self.category_filter_combo.currentTextChanged.connect(lambda value: self._set_filter_var(self.category_filter_var, value))
        self.risk_filter_combo.currentTextChanged.connect(lambda value: self._set_filter_var(self.risk_filter_var, value))
        filter_layout.addWidget(self.source_filter_combo)
        filter_layout.addWidget(QLabel("קובץ מקור:"))
        filter_layout.addWidget(self.category_filter_combo)
        filter_layout.addWidget(QLabel("קטגוריה:"))
        filter_layout.addWidget(self.risk_filter_combo)
        filter_layout.addWidget(QLabel("רמת סיכון:"))
        filter_layout.addStretch(1)
        layout.addWidget(filter_box)

        results_box = QGroupBox("ממצאי הביקורת")
        results_layout = QVBoxLayout(results_box)
        self.findings_column_order = ["source", "extract_date", "cat", "risk", "title", "rule", "actual", "expected", "status"]
        headers = ["קובץ מקור", "תאריך הפקה", "קטגוריה", "סיכון", "תיאור", "סוג בדיקה", "ערך בפועל", "ערך מצופה", "סטטוס"]
        self.tree = QTableWidget(0, len(headers))
        self.tree.setHorizontalHeaderLabels(headers)
        self._configure_table(self.tree)
        self.tree.cellDoubleClicked.connect(lambda _row, _col: self._open_finding_details())
        self.tree.horizontalHeader().sectionClicked.connect(self._on_findings_header_clicked)
        results_layout.addWidget(self.tree)
        layout.addWidget(results_box, 1)

        self._reset_filter_options()

    def _build_settings_tab(self):
        outer_layout = QVBoxLayout(self.settings_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(12)

        title = QLabel("הגדרות מערכת לביקורת")
        title.setProperty("class", "section")
        title.setWordWrap(True)
        layout.addWidget(title)
        hint = QLabel("הטופס מאפשר לעדכן את ההגדרות בצורה ידידותית ולשמור ישירות לקובץ ההגדרות.")
        hint.setProperty("class", "hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        btn_layout = QHBoxLayout()
        reset_btn = QPushButton("טען ברירות מחדל")
        reset_btn.clicked.connect(self._reset_settings_form)
        save_btn = QPushButton("שמור הגדרות")
        save_btn.clicked.connect(self._save_settings)
        export_btn = QPushButton("ייצוא מיפוי בקרות")
        export_btn.clicked.connect(self._export_control_mapping_report)
        btn_layout.addWidget(reset_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(export_btn)
        btn_layout.addStretch(1)
        layout.addLayout(btn_layout)

        layout.addWidget(self._build_review_period_section())
        layout.addWidget(self._build_text_list_section("critical_users", "משתמשים קריטיים", "רשימה מופרדת שורות"))
        layout.addWidget(self._build_text_list_section("critical_roles", "תפקידים קריטיים", "רשימה מופרדת שורות"))
        layout.addWidget(self._build_text_list_section("critical_privileges", "הרשאות קריטיות", "רשימה מופרדת שורות"))
        layout.addWidget(self._build_password_policy_section())
        layout.addWidget(self._build_user_type_rules_section())
        layout.addWidget(self._build_text_list_section("audit_event_keywords", "מילות מפתח לאירועי Audit", "רשימה מופרדת שורות"))
        layout.addWidget(self._build_file_mapping_section())
        layout.addWidget(self._build_ini_rules_section())

        threshold_box, threshold_layout = self._build_group_box(
            "הגדרות נוספות",
            "סף חוסר השימוש משמש לזיהוי משתמשים חריגים במסגרת סקירת משתמשים.",
        )
        threshold_form = QFormLayout()
        threshold_form.setLabelAlignment(Qt.AlignRight)
        threshold_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        threshold_input = QLineEdit()
        self.settings_widgets["inactive_days_threshold"] = threshold_input
        threshold_form.addRow("סף חוסר שימוש (ימים)", threshold_input)
        threshold_layout.addLayout(threshold_form)
        layout.addWidget(threshold_box)
        layout.addStretch(1)

    def _build_group_box(self, title, description=None):
        box = QGroupBox("")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(8)

        header = QLabel(title)
        header.setProperty("class", "sectionTitle")
        header.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header.setWordWrap(True)
        header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(header)

        if description:
            description_label = QLabel(description)
            description_label.setProperty("class", "hint")
            description_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            description_label.setWordWrap(True)
            description_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            layout.addWidget(description_label)

        return box, layout

    def _build_review_period_section(self):
        box, layout = self._build_group_box(
            "טווח בחינה לסקירת משתמשים",
            "בחר תאריך התחלה ותאריך סיום של תקופת הסקירה.",
        )
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        form.setFormAlignment(Qt.AlignRight | Qt.AlignTop)
        form.setHorizontalSpacing(16)

        start_widget = QDateEdit()
        start_widget.setLayoutDirection(Qt.LeftToRight)
        start_widget.setCalendarPopup(True)
        start_widget.setDisplayFormat("yyyy-MM-dd")
        start_widget.setMinimumSize(140, 32)
        start_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        end_widget = QDateEdit()
        end_widget.setLayoutDirection(Qt.LeftToRight)
        end_widget.setCalendarPopup(True)
        end_widget.setDisplayFormat("yyyy-MM-dd")
        end_widget.setMinimumSize(140, 32)
        end_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.settings_widgets["user_review_period.start_date"] = start_widget
        self.settings_widgets["user_review_period.end_date"] = end_widget
        form.addRow("מתאריך", start_widget)
        form.addRow("עד תאריך", end_widget)
        layout.addLayout(form)
        return box

    def _build_text_list_section(self, key, title, description):
        box, layout = self._build_group_box(title, description)
        editor = QPlainTextEdit()
        editor.setMinimumHeight(90)
        self.settings_widgets[key] = editor
        layout.addWidget(editor)
        return box

    def _build_file_mapping_section(self):
        box, layout = self._build_group_box(
            "מיפוי קבצים",
            "הגדר את שמות הקבצים הצפויים לכל מקור מידע במקום לערוך JSON ידנית.",
        )
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        mapping_labels = {
            "USERS": "משתמשים (USERS)",
            "M_PASSWORD_POLICY": "מדיניות סיסמה",
            "GRANTED_PRIVILEGES": "הרשאות",
            "GRANTED_ROLES": "הקצאות תפקידים",
            "AUDIT_POLICIES": "מדיניות ניטור",
            "AUDIT_TRAIL": "Audit Trail",
            "M_INIFILE_CONTENTS": "INI Hardening",
        }
        self.file_mapping_order = list(mapping_labels.keys())
        for key in self.file_mapping_order:
            widget = QLineEdit()
            widget.setLayoutDirection(Qt.LeftToRight)
            self.settings_widgets[f"file_mappings.{key}"] = widget
            form.addRow(mapping_labels[key], widget)
        layout.addLayout(form)
        return box

    def _build_ini_rules_section(self):
        box, layout = self._build_group_box(
            "כללי הקשחת INI",
            "כל שורה מייצגת כלל הקשחה אחד. ניתן להוסיף, לערוך ולמחוק שורות בקלות.",
        )

        actions_layout = QHBoxLayout()
        add_btn = QPushButton("הוסף כלל")
        remove_btn = QPushButton("מחק כלל נבחר")
        actions_layout.addWidget(add_btn)
        actions_layout.addWidget(remove_btn)
        actions_layout.addStretch(1)
        layout.addLayout(actions_layout)

        self.ini_rule_keys = ["file_name", "section", "key", "expected_value", "comparison_rule", "risk_level", "title"]
        headers = ["קובץ INI", "Section", "Key", "ערך צפוי", "כלל השוואה", "רמת סיכון", "כותרת"]
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.AllEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setMinimumHeight(240)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.settings_widgets["ini_security_defaults"] = table

        add_btn.clicked.connect(self._add_ini_rule_row)
        remove_btn.clicked.connect(self._delete_selected_ini_rule)

        layout.addWidget(table)
        return box

    def _add_ini_rule_row(self, values=None):
        table = self.settings_widgets.get("ini_security_defaults")
        if table is None:
            return

        values = values or ["", "", "", "", "Exact", "Medium", ""]
        row = table.rowCount()
        table.insertRow(row)
        for column, value in enumerate(values):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            table.setItem(row, column, item)

    def _delete_selected_ini_rule(self):
        table = self.settings_widgets.get("ini_security_defaults")
        if table is None:
            return

        selected_rows = sorted({item.row() for item in table.selectedItems()}, reverse=True)
        for row in selected_rows:
            table.removeRow(row)

    def _build_password_policy_section(self):
        box, layout = self._build_group_box("ברירות מחדל למדיניות סיסמה")
        grid = QGridLayout()
        fields = [
            "minimal_password_length",
            "force_first_password_change",
            "password_lock_time",
            "password_layout",
            "last_used_passwords",
            "maximum_invalid_connect_attempts",
            "minimal_password_lifetime",
            "maximum_password_lifetime",
            "maximum_unused_initial_password_lifetime",
            "maximum_unused_productive_password_lifetime",
            "password_expire_warning_time",
            "password_lock_for_system_user",
            "detailed_error_on_connect",
        ]
        for index, field_name in enumerate(fields):
            row = index // 2
            col = (index % 2) * 2
            label = QLabel(field_name)
            label.setWordWrap(True)
            if field_name in {"force_first_password_change", "password_lock_for_system_user", "detailed_error_on_connect"}:
                widget = QComboBox()
                widget.addItems(["TRUE", "FALSE"])
                self.boolean_fields[field_name] = widget
            else:
                widget = QLineEdit()
            self.settings_widgets[f"password_policy_defaults.{field_name}"] = widget
            grid.addWidget(label, row, col)
            grid.addWidget(widget, row, col + 1)
        layout.addLayout(grid)
        return box

    def _build_user_type_rules_section(self):
        box, layout = self._build_group_box("כללי סיווג משתמשים")
        for key in ["Dialog", "Generic", "Technical", "Application"]:
            label = QLabel(key)
            editor = QPlainTextEdit()
            editor.setMinimumHeight(60)
            self.settings_widgets[f"user_type_rules.{key}"] = editor
            layout.addWidget(label)
            layout.addWidget(editor)
        return box

    def _configure_table(self, table):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)

    def _make_checkbox(self, text, bound_var):
        checkbox = QCheckBox(text)
        checkbox.setChecked(bool(bound_var.get()))
        checkbox.stateChanged.connect(lambda state, var=bound_var: self._on_checkbox_changed(var, state))
        return checkbox

    def _on_checkbox_changed(self, var, state):
        var.set(state == Qt.Checked)
        self._refresh_user_review_table()

    def _set_filter_var(self, var, value):
        if value:
            var.set(value)
        self._refresh_findings_table()

    def _set_combo_values(self, combo, values, current_value):
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(values)
        index = combo.findText(current_value)
        combo.setCurrentIndex(index if index >= 0 else 0)
        combo.blockSignals(False)

    def _set_table_row(self, table, row_index, values, background=None, foreground=None):
        table.insertRow(row_index)
        for column, value in enumerate(values):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setTextAlignment(Qt.AlignCenter if column != 0 else Qt.AlignRight | Qt.AlignVCenter)
            if background is not None:
                item.setBackground(background)
            if foreground is not None:
                item.setForeground(foreground)
            table.setItem(row_index, column, item)

    def _show_info(self, title, text):
        QMessageBox.information(self.window, title, text)

    def _show_warning(self, title, text):
        QMessageBox.warning(self.window, title, text)

    def _show_error(self, title, text):
        QMessageBox.critical(self.window, title, text)

    def _ask_yes_no(self, title, text):
        return QMessageBox.question(self.window, title, text) == QMessageBox.Yes

    def _get_open_file(self, caption, file_filter):
        file_path, _ = QFileDialog.getOpenFileName(self.window, caption, "", file_filter)
        return file_path

    def _get_save_file(self, caption, file_filter, initial_name):
        file_path, _ = QFileDialog.getSaveFileName(self.window, caption, str(PROJECT_ROOT / initial_name), file_filter)
        return file_path

    def _get_today_date(self):
        return datetime.now().strftime("%Y-%m-%d")

    def _parse_extract_date(self, raw_value):
        normalized_value = raw_value.strip()
        if not normalized_value:
            raise ValueError("יש להזין תאריך הפקה בפורמט YYYY-MM-DD.")
        return datetime.strptime(normalized_value, "%Y-%m-%d").date().isoformat()

    def _normalize_extract_date(self, slot_key, show_message=False):
        try:
            normalized_value = self.slot_extract_date_widgets[slot_key].date().toPython().isoformat()
            self.slot_extract_date_vars[slot_key].set(normalized_value)
            return normalized_value
        except Exception:
            if show_message:
                self._show_error("תאריך הפקה לא תקין", "יש להזין תאריך תקין בפורמט YYYY-MM-DD, לדוגמה 2026-04-09.")
            return None

    def _attach_findings_source_metadata(self, findings):
        for finding in findings:
            source_slot = getattr(finding, "source_slot", None)
            setattr(finding, "source_file", self._get_source_file_name(finding))
            setattr(finding, "extract_date", self.loaded_extract_dates.get(source_slot, "-"))
        return findings

    def _read_source_file(self, file_path):
        df = pd.read_csv(
            file_path,
            sep=None,
            engine="python",
            encoding="utf-8-sig",
            quotechar='"',
            skipinitialspace=True,
        )
        first_column = str(df.columns[0]).strip().upper()
        if first_column == "" or first_column.startswith("UNNAMED"):
            df = df.iloc[:, 1:]
        df.columns = [str(col).strip().upper().replace('"', "") for col in df.columns]
        df = df.map(lambda value: value.strip().replace('"', "") if isinstance(value, str) else value)
        return df

    def _validate_loaded_dataframe(self, slot_key, df):
        metadata = self.slot_metadata[slot_key]
        missing_columns = [column for column in metadata["required"] if column not in df.columns]
        alternative_groups = []
        for group in metadata["required_any"]:
            if not any(column in df.columns for column in group):
                alternative_groups.append(group)
        return missing_columns, alternative_groups

    def _format_validation_message(self, slot_key, file_name, missing_columns, alternative_groups, suggested_slots=None):
        metadata = self.slot_metadata[slot_key]
        details = []
        if missing_columns:
            details.append("עמודות חובה חסרות: " + ", ".join(missing_columns))
        for group in alternative_groups:
            details.append("נדרשת לפחות אחת מהעמודות: " + " / ".join(group))
        if suggested_slots:
            suggested_labels = [self.slot_metadata[item]["label"] for item in suggested_slots if item in self.slot_metadata]
            if suggested_labels:
                details.append("נראה שהקובץ מתאים יותר ל: " + " | ".join(suggested_labels))
        details_text = "\n".join(details)
        return (
            f"הקובץ '{file_name}' שויך לסלוט {metadata['label']}, אך מבנה העמודות שלו אינו תקין.\n\n"
            f"פירוט:\n{details_text}\n\n"
            "בדוק שהקובץ שיוצא מ-SAP HANA תואם לטבלה הנכונה וששורת הכותרות לא שונתה."
        )

    def _find_compatible_slots(self, df):
        compatible_slots = []
        for candidate_slot in self.slot_metadata:
            missing_columns, alternative_groups = self._validate_loaded_dataframe(candidate_slot, df)
            if not missing_columns and not alternative_groups:
                compatible_slots.append(candidate_slot)
        return compatible_slots

    def _persist_loaded_slot(self, slot_key, df, filename, extract_date, file_path):
        self.loaded_dataframes[slot_key] = df
        self.loaded_files[slot_key] = filename
        self.loaded_extract_dates[slot_key] = extract_date

        if slot_key == "GRANTED_PRIVILEGES":
            self.loaded_dataframes["EFFECTIVE_PRIVILEGE_GRANTEES"] = df
            self.loaded_files["EFFECTIVE_PRIVILEGE_GRANTEES"] = filename
            self.loaded_extract_dates["EFFECTIVE_PRIVILEGE_GRANTEES"] = extract_date
        elif slot_key == "GRANTED_ROLES":
            self.loaded_dataframes["EFFECTIVE_ROLES"] = df
            self.loaded_files["EFFECTIVE_ROLES"] = filename
            self.loaded_extract_dates["EFFECTIVE_ROLES"] = extract_date
        elif slot_key == "AUDIT_TRAIL":
            self.loaded_dataframes["AUDIT_LOG"] = df
            self.loaded_files["AUDIT_LOG"] = filename
            self.loaded_extract_dates["AUDIT_LOG"] = extract_date

        rows = len(df)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.ipe_records.append(
            {
                "סלוט במערכת": slot_key,
                "שם קובץ מקורי": filename,
                "תאריך הפקה": extract_date,
                "כמות רשומות": rows,
                "זמן טעינה": timestamp,
                "נתיב מלא": file_path,
            }
        )
        self.db.save_ipe_load(slot_key, filename, extract_date, rows, file_path)
        self.slot_status_labels[slot_key].setText(f"✅ נטען: {filename}")
        self.slot_delete_btns[slot_key].setEnabled(True)
        self._set_table_row(self.ipe_tree, self.ipe_tree.rowCount(), [slot_key, filename, extract_date, rows, timestamp])
        self.db.log_activity("IPE Load", f"Slot: {slot_key}, File: {filename}, Extract Date: {extract_date}, Rows: {rows}", "User")

    def _validate_all_sources_before_analysis(self):
        required_slots = ["USERS", "M_PASSWORD_POLICY", "GRANTED_PRIVILEGES", "AUDIT_POLICIES", "M_INIFILE_CONTENTS"]
        missing_slots = [slot_key for slot_key in required_slots if slot_key not in self.loaded_dataframes]
        if missing_slots:
            slot_labels = [self.slot_metadata[slot_key]["label"] for slot_key in missing_slots]
            return False, "לא ניתן להריץ ניתוח לפני שכל חמשת מקורות החובה נטענו.\n\nמקורות חסרים:\n- " + "\n- ".join(slot_labels)

        validation_errors = []
        for slot_key in required_slots:
            df = self.loaded_dataframes.get(slot_key)
            missing_columns, alternative_groups = self._validate_loaded_dataframe(slot_key, df)
            if missing_columns or alternative_groups:
                file_name = self.loaded_files.get(slot_key, "קובץ לא מזוהה")
                validation_errors.append(self._format_validation_message(slot_key, file_name, missing_columns, alternative_groups))

        if validation_errors:
            return False, "\n\n--------------------\n\n".join(validation_errors)
        return True, ""

    def _load_file(self, slot_key):
        extract_date = self._normalize_extract_date(slot_key, show_message=True)
        if not extract_date:
            return

        file_path = self._get_open_file("בחר קובץ", "Data files (*.csv *.txt)")
        if not file_path:
            return

        filename = os.path.basename(file_path)
        self._log("החל ניסיון טעינת קובץ", slot=slot_key, filename=filename, file_path=file_path)

        try:
            df = self._read_source_file(file_path)
            target_slot = slot_key
            missing_columns, alternative_groups = self._validate_loaded_dataframe(target_slot, df)
            if missing_columns or alternative_groups:
                compatible_slots = [candidate for candidate in self._find_compatible_slots(df) if candidate != slot_key]
                if len(compatible_slots) == 1:
                    detected_slot = compatible_slots[0]
                    selected_label = self.slot_metadata[slot_key]["label"]
                    detected_label = self.slot_metadata[detected_slot]["label"]
                    should_redirect = self._ask_yes_no(
                        "זוהה קובץ עבור סלוט אחר",
                        f"הקובץ '{filename}' לא מתאים לסלוט {selected_label}, אך נראה מתאים לסלוט {detected_label}.\n\nהאם לטעון אותו אוטומטית לסלוט המתאים?",
                    )
                    if should_redirect:
                        target_slot = detected_slot
                        redirected_extract_date = self._normalize_extract_date(detected_slot, show_message=False)
                        if redirected_extract_date:
                            extract_date = redirected_extract_date
                        missing_columns, alternative_groups = self._validate_loaded_dataframe(target_slot, df)

                if missing_columns or alternative_groups:
                    raise ValueError(self._format_validation_message(target_slot, filename, missing_columns, alternative_groups, compatible_slots))

            self._persist_loaded_slot(target_slot, df, filename, extract_date, file_path)
            self._log("טעינת הקובץ הושלמה בהצלחה", slot=target_slot, filename=filename, rows=len(df))
        except Exception as e:
            self.loaded_dataframes.pop(slot_key, None)
            self.loaded_files.pop(slot_key, None)
            self.loaded_extract_dates.pop(slot_key, None)
            self.slot_status_labels[slot_key].setText(f"❌ שגיאה בטעינת: {filename}")
            self.slot_delete_btns[slot_key].setEnabled(False)
            self._log_error("שגיאה בטעינת קובץ מקור", e, requested_slot=slot_key, filename=filename, file_path=file_path)
            self._show_error(
                "שגיאת טעינה",
                f"לא ניתן לטעון את הקובץ '{filename}' לסלוט {self.slot_metadata[slot_key]['label']}.\n\nסיבה:\n{str(e)}\n\nפירוט מלא נשמר בתיקיית הלוגים עבור צוות התמיכה.",
            )

    def _delete_file(self, slot_key):
        if slot_key in self.loaded_dataframes:
            filename = self.loaded_files.get(slot_key, "-")
            del self.loaded_dataframes[slot_key]
            self.loaded_files.pop(slot_key, None)
            self.loaded_extract_dates.pop(slot_key, None)

            if slot_key == "GRANTED_PRIVILEGES":
                self.loaded_dataframes.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
                self.loaded_files.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
                self.loaded_extract_dates.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
            elif slot_key == "GRANTED_ROLES":
                self.loaded_dataframes.pop("EFFECTIVE_ROLES", None)
                self.loaded_files.pop("EFFECTIVE_ROLES", None)
                self.loaded_extract_dates.pop("EFFECTIVE_ROLES", None)
            elif slot_key == "AUDIT_TRAIL":
                self.loaded_dataframes.pop("AUDIT_LOG", None)
                self.loaded_files.pop("AUDIT_LOG", None)
                self.loaded_extract_dates.pop("AUDIT_LOG", None)

            self.slot_status_labels[slot_key].setText("ממתין לטעינה...")
            self.slot_delete_btns[slot_key].setEnabled(False)
            self.db.log_activity("IPE Clear", f"Cleared data slot: {slot_key} (Previous file: {filename})", "User")
            self._log(f"הנתונים בסלוט {slot_key} נמחקו מהזיכרון.")

    def _export_ipe_log(self):
        if not self.ipe_records:
            self._show_warning("אין נתונים", "טרם נטענו קבצים למערכת.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("שמור דוח IPE", "Excel Workbook (*.xlsx)", f"IPE_Log_{self.period_var.get()}_{timestamp}.xlsx")
        if save_path:
            try:
                pd.DataFrame(self.ipe_records).to_excel(save_path, index=False)
                self._show_info("הצלחה", "דוח IPE יוצא בהצלחה.")
            except Exception as e:
                self._show_error("שגיאה", f"כשל בייצוא: {e}")

    def _handle_user_review_selection(self):
        self.selected_user_review_index = self._get_selected_user_review_index()

    def _get_user_review_filtered_df(self):
        if self.user_review_df.empty:
            return self.user_review_df
        filtered_df = self.user_review_df
        if self.show_only_active_in_period_var.get() and "active_in_period" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["active_in_period"] == "כן"]
        if self.show_only_exceptions_var.get():
            filtered_df = filtered_df[filtered_df["has_exception"] == "כן"]
        if self.show_only_unreviewed_var.get():
            filtered_df = filtered_df[filtered_df["review_status"] == "טרם נסקר"]
        if self.show_only_privileged_var.get():
            filtered_df = filtered_df[filtered_df["critical_privileges"] != "-"]
        return filtered_df

    def _apply_user_review_changes(self, row_index, updates):
        original_user_name = self.user_review_df.at[row_index, "user_name"]
        for key, value in updates.items():
            self.user_review_df.at[row_index, key] = value
        if self.user_review_df.at[row_index, "has_exception"] != "כן":
            self.user_review_df.at[row_index, "exception_reason"] = "-"
        if self.user_review_df.at[row_index, "has_exception"] == "כן" and not str(self.user_review_df.at[row_index, "exception_reason"]).strip():
            self.user_review_df.at[row_index, "exception_reason"] = "חריג שסומן ידנית"

        self.user_review_df["status_sort"] = self.user_review_df["has_exception"].apply(lambda value: 0 if value == "כן" else 1)
        self.user_review_df = self.user_review_df.sort_values(by=["status_sort", "user_name"], ascending=[True, True]).reset_index(drop=True)
        self.user_review_dirty_rows.add(original_user_name)

        if self.user_review_report is not None:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            self.user_review_report["summary"]["exception_users"] = int((self.user_review_df["has_exception"] == "כן").sum())

        self._update_user_review_summary()
        self._refresh_user_review_table()

    def _begin_inline_user_review_edit(self, *_args):
        self._open_user_review_editor()

    def _cancel_inline_user_review_edit(self):
        self.user_review_inline_editor = None

    def _commit_inline_user_review_edit(self):
        self.user_review_inline_editor = None

    def _save_all_user_review_changes(self):
        if self.user_review_df.empty:
            self._show_warning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return
        if not self.user_review_dirty_rows:
            self._show_info("ללא שינויים", "אין שינויים חדשים לשמירה.")
            return

        rows_to_save = self.user_review_df[self.user_review_df["user_name"].isin(self.user_review_dirty_rows)]
        self.db.save_user_review_rows(rows_to_save.to_dict("records"))
        saved_count = len(rows_to_save.index)
        self.user_review_dirty_rows.clear()
        self._show_info("הצלחה", f"נשמרו {saved_count} שורות בדוח הסקירה.")

    def _validate_user_review_sources(self):
        required_slots = ["USERS", "GRANTED_PRIVILEGES"]
        missing_slots = [slot_key for slot_key in required_slots if slot_key not in self.loaded_dataframes]
        if missing_slots:
            slot_labels = [self.slot_metadata[slot_key]["label"] for slot_key in missing_slots]
            return False, "לא ניתן לבנות דוח סקירה לפני טעינת מקורות החובה הבאים:\n- " + "\n- ".join(slot_labels)

        validation_errors = []
        for slot_key in required_slots:
            df = self.loaded_dataframes.get(slot_key)
            missing_columns, alternative_groups = self._validate_loaded_dataframe(slot_key, df)
            if missing_columns or alternative_groups:
                file_name = self.loaded_files.get(slot_key, "קובץ לא מזוהה")
                validation_errors.append(self._format_validation_message(slot_key, file_name, missing_columns, alternative_groups))

        if validation_errors:
            return False, "\n\n--------------------\n\n".join(validation_errors)
        return True, ""

    def _update_user_review_summary(self):
        if not self.user_review_report:
            for variable in self.review_summary_vars.values():
                variable.set("0")
            for label in self.review_summary_labels.values():
                label.setText("0")
            self.user_type_tree.setRowCount(0)
            return

        summary = self.user_review_report["summary"]
        for key in ["total_users", "in_scope_users", "exception_users", "privileged_users"]:
            value = str(summary[key])
            self.review_summary_vars[key].set(value)
            self.review_summary_labels[key].setText(value)

        self.user_type_tree.setRowCount(0)
        for user_type, count in sorted(summary["type_distribution"].items()):
            self._set_table_row(self.user_type_tree, self.user_type_tree.rowCount(), [user_type, count])

    def _refresh_user_review_table(self):
        self.user_review_tree.setRowCount(0)
        if self.user_review_df.empty:
            self.user_review_visible_indices = []
            return

        filtered_df = self._get_user_review_filtered_df()
        self.user_review_visible_indices = list(filtered_df.index)

        for row_index, (_, row) in zip(self.user_review_visible_indices, filtered_df.iterrows()):
            background = None
            if row.get("has_exception") == "כן":
                background = QColor("#fde2e1")
            elif row.get("review_status") and row.get("review_status") != "טרם נסקר":
                background = QColor("#e8f4ea")
            if row.get("user_name") in self.user_review_dirty_rows:
                background = QColor("#fff3cd")

            values = [row.get(column_name, "") for column_name in self.user_review_columns]
            self._set_table_row(self.user_review_tree, self.user_review_tree.rowCount(), values, background=background)

    def _generate_user_review(self):
        is_valid, validation_message = self._validate_user_review_sources()
        if not is_valid:
            self._show_error("בדיקת תקינות נכשלה", validation_message)
            return

        try:
            review_date = self.review_date_widget.date().toPython()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            existing_reviews = self.db.get_user_review_rows(self.period_var.get())
            config = self._current_config()
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=config,
                extract_dates=self.loaded_extract_dates,
                period_id=self.period_var.get(),
                review_date=review_date,
                review_period_start=review_period_start,
                review_period_end=review_period_end,
                existing_reviews=existing_reviews,
            )
            self.user_review_df = self.user_review_report["dataframe"].copy()
            self.user_review_dirty_rows.clear()
            if not self.user_review_df.empty:
                self.db.save_user_review_rows(self.user_review_df.to_dict("records"))
            self._update_user_review_summary()
            self._refresh_user_review_table()
            self._show_info("הושלם", f"דוח הסקירה נבנה בהצלחה עבור {len(self.user_review_df)} משתמשים.")
        except Exception as error:
            self._show_error("שגיאה בבניית דוח סקירה", str(error))

    def _get_user_review_period_from_config(self):
        period_config = self._current_config().get("user_review_period", {})
        start_raw = str(period_config.get("start_date", "")).strip()
        end_raw = str(period_config.get("end_date", "")).strip()
        if not start_raw or not end_raw:
            raise ValueError("יש להגדיר טווח בחינה מלא (תאריך התחלה ותאריך סיום) בלשונית ההגדרות.")
        try:
            start_date = datetime.strptime(start_raw, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_raw, "%Y-%m-%d").date()
        except ValueError as error:
            raise ValueError("טווח הבחינה בהגדרות חייב להיות בפורמט YYYY-MM-DD.") from error
        if end_date < start_date:
            raise ValueError("תאריך סיום טווח הבחינה חייב להיות גדול או שווה לתאריך ההתחלה.")
        return start_date, end_date

    def _update_review_period_info_label(self):
        try:
            start_date, end_date = self._get_user_review_period_from_config()
            self.review_period_info_label.setText(f"טווח בחינה פעיל לדוח: {start_date.isoformat()} עד {end_date.isoformat()}")
        except Exception:
            self.review_period_info_label.setText("טווח בחינה פעיל לדוח: לא הוגדר או לא תקין")

    def _get_selected_user_review_index(self):
        row = self.user_review_tree.currentRow()
        if row < 0 or row >= len(self.user_review_visible_indices):
            return None
        return self.user_review_visible_indices[row]

    def _open_user_review_editor(self, _event=None):
        row_index = self._get_selected_user_review_index()
        if row_index is None or self.user_review_df.empty:
            self._show_warning("לא נבחר משתמש", "בחר שורה מתוך דוח הסקירה כדי לעדכן החלטת מנהל.")
            return

        row = self.user_review_df.iloc[row_index]
        self.selected_user_review_index = row_index

        dialog = QDialog(self.window)
        dialog.setWindowTitle("עדכון החלטת מנהל")
        dialog.resize(620, 460)
        layout = QVBoxLayout(dialog)

        title = QLabel(f"משתמש: {row['user_name']}")
        title.setProperty("class", "section")
        layout.addWidget(title)

        metadata_text = (
            f"סוג משתמש: {row['user_type']}\n"
            f"סטטוס: {row['active_status']}\n"
            f"החרגת סיסמה: {row.get('password_policy_exempt_status', '-')}\n"
            f"סיבת החרגה: {row.get('password_policy_exempt_reason', '-')}\n"
            f"גישה לטבלאות מערכת: {row.get('system_table_access_status', '-')}\n"
            f"חריג: {row['has_exception']}\n"
            f"סיבת חריג: {row['exception_reason']}"
        )
        metadata = QLabel(metadata_text)
        metadata.setWordWrap(True)
        layout.addWidget(metadata)

        form = QFormLayout()
        review_status_box = QComboBox()
        review_status_box.addItems(["טרם נסקר", "נסקר", "דורש מעקב"])
        review_status_box.setCurrentText(str(row.get("review_status", "טרם נסקר")))
        manager_decision_box = QComboBox()
        manager_decision_box.addItems(["", "מאושר", "לא מאושר", "נדרש בירור"])
        manager_decision_box.setCurrentText(str(row.get("manager_decision", "")))
        action_required_box = QComboBox()
        action_required_box.addItems(["", "נדרש להסרה", "מאושר להשאיר"])
        action_required_box.setCurrentText(str(row.get("action_required", "")))
        has_exception_box = QComboBox()
        has_exception_box.addItems(["כן", "לא"])
        has_exception_box.setCurrentText(str(row.get("has_exception", "לא")))
        exception_reason_input = QLineEdit("" if row.get("exception_reason") == "-" else str(row.get("exception_reason", "")))
        comments_text = QTextEdit()
        comments_text.setPlainText(str(row.get("manager_comments", "")))

        form.addRow("סטטוס סקירה", review_status_box)
        form.addRow("החלטת מנהל", manager_decision_box)
        form.addRow("נדרש להסרה / מאושר להשאיר", action_required_box)
        form.addRow("חריג", has_exception_box)
        form.addRow("סיבת חריג", exception_reason_input)
        form.addRow("הערות", comments_text)
        layout.addLayout(form)

        button_layout = QHBoxLayout()
        save_btn = QPushButton("שמור")
        cancel_btn = QPushButton("ביטול")
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        button_layout.addStretch(1)
        layout.addLayout(button_layout)

        def save_changes():
            updates = {
                "review_status": review_status_box.currentText().strip() or "טרם נסקר",
                "manager_decision": manager_decision_box.currentText().strip(),
                "action_required": action_required_box.currentText().strip(),
                "has_exception": has_exception_box.currentText().strip() or "לא",
                "exception_reason": exception_reason_input.text().strip() or "-",
                "manager_comments": comments_text.toPlainText().strip(),
            }
            self._apply_user_review_changes(row_index, updates)
            refreshed_index = next((index for index, (_, current_row) in enumerate(self.user_review_df.iterrows()) if current_row.get("user_name") == row.get("user_name")), None)
            if refreshed_index is not None:
                self.selected_user_review_index = refreshed_index
            dialog.accept()
            self._show_info("הצלחה", "השינויים בדוח נשמרו.")

        save_btn.clicked.connect(save_changes)
        cancel_btn.clicked.connect(dialog.reject)
        dialog.exec()

    def _export_user_review_excel(self):
        if self.user_review_report is None or self.user_review_df.empty:
            self._show_warning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("ייצוא דוח סקירה", "Excel Workbook (*.xlsx)", f"User_Review_{self.period_var.get()}_{timestamp}.xlsx")
        if not save_path:
            return
        try:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            export_user_review_to_excel(self.user_review_report, save_path)
            self._show_info("הצלחה", f"דוח הסקירה יוצא בהצלחה ל-Excel.\n\n{save_path}")
        except Exception as error:
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את דוח הסקירה ל-Excel.\n\n{error}")

    def _export_user_review_pdf(self):
        if self.user_review_report is None or self.user_review_df.empty:
            self._show_warning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("ייצוא דוח סקירה", "PDF Files (*.pdf)", f"User_Review_{self.period_var.get()}_{timestamp}.pdf")
        if not save_path:
            return
        try:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            export_user_review_to_pdf(self.user_review_report, save_path)
            self._show_info("הצלחה", f"דוח הסקירה יוצא בהצלחה ל-PDF.\n\n{save_path}")
        except Exception as error:
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את דוח הסקירה ל-PDF.\n\n{error}")

    def _get_source_file_name(self, finding):
        source_slot = getattr(finding, "source_slot", None)
        if not source_slot:
            return "לא זוהה"
        return self.loaded_files.get(source_slot, source_slot)

    def _reset_filter_options(self):
        values = ["הכל"]
        self._set_combo_values(self.risk_filter_combo, values, "הכל")
        self._set_combo_values(self.category_filter_combo, values, "הכל")
        self._set_combo_values(self.source_filter_combo, values, "הכל")
        self.risk_filter_var.set("הכל")
        self.category_filter_var.set("הכל")
        self.source_filter_var.set("הכל")

    def _update_filter_options(self):
        risk_values = sorted({finding.risk_level for finding in self.current_findings if getattr(finding, "risk_level", None)})
        category_values = sorted({finding.category for finding in self.current_findings if getattr(finding, "category", None)})
        source_values = sorted({self._get_source_file_name(finding) for finding in self.current_findings})

        self._set_combo_values(self.risk_filter_combo, ["הכל"] + risk_values, self.risk_filter_var.get())
        self._set_combo_values(self.category_filter_combo, ["הכל"] + category_values, self.category_filter_var.get())
        self._set_combo_values(self.source_filter_combo, ["הכל"] + source_values, self.source_filter_var.get())

    def _on_filter_change(self, _event=None):
        self._refresh_findings_table()

    def _get_column_display_value(self, finding, column):
        mapping = {
            "source": self._get_source_file_name(finding),
            "extract_date": getattr(finding, "extract_date", "-"),
            "cat": finding.category,
            "risk": finding.risk_level,
            "title": finding.title,
            "rule": getattr(finding, "comparison_rule", None) or "-",
            "actual": getattr(finding, "actual_value", None) or "-",
            "expected": getattr(finding, "expected_value", None) or "-",
            "status": finding.status,
        }
        return mapping[column]

    def _get_filtered_findings(self):
        filtered = []
        for finding in self.current_findings:
            if self.risk_filter_var.get() != "הכל" and finding.risk_level != self.risk_filter_var.get():
                continue
            if self.category_filter_var.get() != "הכל" and finding.category != self.category_filter_var.get():
                continue
            if self.source_filter_var.get() != "הכל" and self._get_source_file_name(finding) != self.source_filter_var.get():
                continue
            filtered.append(finding)
        return filtered

    def _get_sort_key(self, finding, column):
        if column == "risk":
            priority = {"High": 0, "Medium": 1, "Low": 2}
            return priority.get(finding.risk_level, 99)
        return str(self._get_column_display_value(finding, column)).casefold()

    def _sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self._refresh_findings_table()

    def _on_findings_header_clicked(self, section_index):
        if 0 <= section_index < len(self.findings_column_order):
            self._sort_by_column(self.findings_column_order[section_index])

    def _refresh_findings_table(self):
        self.displayed_findings = self._get_filtered_findings()
        self.displayed_findings.sort(key=lambda finding: self._get_sort_key(finding, self.sort_column), reverse=self.sort_reverse)
        self.tree.setRowCount(0)

        for finding in self.displayed_findings:
            background = None
            foreground = None
            if finding.risk_level == "High":
                background = QColor("#f8d7da")
            elif finding.risk_level == "Medium":
                background = QColor("#fff3cd")
            elif finding.status == "Compliant":
                background = QColor("#dff5e3")
            if finding.category == "Password Policy":
                foreground = QColor("#0f4c81")

            values = [
                self._get_source_file_name(finding),
                getattr(finding, "extract_date", "-"),
                finding.category,
                finding.risk_level,
                finding.title,
                getattr(finding, "comparison_rule", None) or "-",
                getattr(finding, "actual_value", None) or "-",
                getattr(finding, "expected_value", None) or "-",
                finding.status,
            ]
            self._set_table_row(self.tree, self.tree.rowCount(), values, background=background, foreground=foreground)

    def _export_findings_to_excel(self):
        if not self.displayed_findings:
            self._show_warning("אין נתונים", "אין ממצאים לייצוא בטבלה הנוכחית.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("ייצוא ממצאים", "Excel Workbook (*.xlsx)", f"Audit_Findings_{self.period_var.get()}_{timestamp}.xlsx")
        if not save_path:
            return
        try:
            export_rows = []
            for finding in self.displayed_findings:
                export_rows.append(
                    {
                        "קובץ מקור": self._get_source_file_name(finding),
                        "תאריך הפקה": getattr(finding, "extract_date", "-"),
                        "קטגוריה": finding.category,
                        "רמת סיכון": finding.risk_level,
                        "תיאור": finding.title,
                        "סוג בדיקה": getattr(finding, "comparison_rule", None) or "-",
                        "ערך בפועל": getattr(finding, "actual_value", None) or "-",
                        "ערך מצופה": getattr(finding, "expected_value", None) or "-",
                        "סטטוס": finding.status,
                        "תיאור מלא": finding.description,
                    }
                )
            pd.DataFrame(export_rows).to_excel(save_path, index=False)
            self._show_info("הצלחה", f"טבלת הממצאים יוצאה בהצלחה ל-Excel.\n\n{save_path}")
        except Exception as error:
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את הממצאים ל-Excel.\n\n{error}")

    def _format_finding_detail_value(self, value):
        if value is None or value == "":
            return "-"
        return str(value)

    def _open_finding_details(self, _event=None):
        row = self.tree.currentRow()
        if row < 0 or row >= len(self.displayed_findings):
            return
        finding = self.displayed_findings[row]

        dialog = QDialog(self.window)
        dialog.setWindowTitle("פירוט ממצא")
        dialog.resize(700, 520)
        layout = QVBoxLayout(dialog)

        title = QLabel(finding.title)
        title.setWordWrap(True)
        title.setProperty("class", "section")
        layout.addWidget(title)

        form_box = QGroupBox("פרטי הממצא")
        form = QFormLayout(form_box)
        detail_rows = [
            ("קטגוריה", finding.category),
            ("רמת סיכון", finding.risk_level),
            ("סטטוס", finding.status),
            ("קובץ מקור", self._get_source_file_name(finding)),
            ("תאריך הפקה", getattr(finding, "extract_date", None)),
            ("סוג בדיקה", getattr(finding, "comparison_rule", None)),
            ("ערך בפועל", getattr(finding, "actual_value", None)),
            ("ערך מצופה", getattr(finding, "expected_value", None)),
        ]
        for label_text, value in detail_rows:
            form.addRow(label_text, QLabel(self._format_finding_detail_value(value)))
        layout.addWidget(form_box)

        description_box = QGroupBox("תיאור מלא")
        desc_layout = QVBoxLayout(description_box)
        description_text = QTextEdit()
        description_text.setReadOnly(True)
        description_text.setPlainText(self._format_finding_detail_value(finding.description))
        desc_layout.addWidget(description_text)
        layout.addWidget(description_box, 1)

        close_btn = QPushButton("סגירה")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignLeft)
        dialog.exec()

    def _run_audit(self):
        if not self.loaded_dataframes:
            self._show_warning("חסר מידע", "אנא טען קבצי מקור בלשונית ה-IPE.")
            return

        is_valid, validation_message = self._validate_all_sources_before_analysis()
        if not is_valid:
            self._log("הרצת ניתוח נחסמה עקב כשל בבדיקת תקינות", period=self.period_var.get())
            self._show_error("בדיקת תקינות נכשלה", validation_message)
            return

        loaded_slots = ", ".join(sorted(self.loaded_dataframes.keys()))
        try:
            self.run_btn.setEnabled(False)
            self._log("החל ניתוח ITGC", period=self.period_var.get(), loaded_slots=loaded_slots)
            config = self._current_config()
            analyzer = AuditAnalyzer(config=config, whitelist=self.db.get_whitelist())
            findings = analyzer.run_all_checks(self.loaded_dataframes, period_id=self.period_var.get())
            findings.extend(self._build_findings_from_user_review())
            findings = self._attach_findings_source_metadata(findings)
            self.current_findings = findings
            self.summary_vars["total"].set(str(len(findings)))
            self.summary_vars["high"].set(str(sum(1 for finding in findings if getattr(finding, "risk_level", "") == "High")))
            self.summary_vars["status"].set("הושלם")
            self._update_filter_options()
            self._refresh_findings_table()
            self._log("ניתוח ITGC הושלם", period=self.period_var.get(), findings_count=len(findings))
            self._show_info("הושלם", f"נמצאו {len(findings)} חריגות.")
        except Exception as e:
            self._log_error("שגיאה בהרצת ניתוח ITGC", e, period=self.period_var.get(), loaded_slots=loaded_slots)
            self._show_error(
                "שגיאה בהרצת ניתוח",
                "הניתוח נכשל לאחר טעינת הקבצים.\n\n"
                f"פירוט טכני:\n{str(e)}\n\n"
                "אם השגיאה נמשכת, בדוק שהקבצים נטענו לסלוטים הנכונים ושהכותרות בהם תואמות להגדרות המערכת.\n"
                "לצוות התמיכה נשמרו פרטים מלאים בתיקיית הלוגים.",
            )
        finally:
            self.run_btn.setEnabled(True)

    def _build_findings_from_user_review(self):
        review_df = self._ensure_user_review_report_for_audit()
        if review_df is None or review_df.empty:
            return []

        findings = []
        exception_rows = review_df[review_df["has_exception"] == "כן"]
        for _, row in exception_rows.iterrows():
            username = row.get("user_name", "-")
            reason = row.get("exception_reason", "-")
            findings.append(
                Finding(
                    period_id=self.period_var.get(),
                    category="User Review",
                    title=f"חריג בסקירת משתמשים: {username}",
                    description=f"זוהה חריג במסגרת סקירת משתמשים. סיבה: {reason}",
                    risk_level="High" if "קריטי" in str(reason) or "Generic" in str(reason) else "Medium",
                    status="Non-Compliant",
                    source_slot="USERS",
                    actual_value=str(reason),
                    expected_value="לא נדרש חריג / קיימת הצדקה מתועדת",
                    comparison_rule="סקירת משתמשים",
                )
            )
        return findings

    def _ensure_user_review_report_for_audit(self):
        if self.user_review_report is not None and not self.user_review_df.empty:
            current_period = str(self.user_review_report.get("metadata", {}).get("period_id", ""))
            if current_period == self.period_var.get():
                return self.user_review_df

        required_slots = ["USERS", "GRANTED_PRIVILEGES"]
        if not all(slot in self.loaded_dataframes for slot in required_slots):
            return None

        try:
            review_date = self.review_date_widget.date().toPython()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            existing_reviews = self.db.get_user_review_rows(self.period_var.get())
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=self._current_config(),
                extract_dates=self.loaded_extract_dates,
                period_id=self.period_var.get(),
                review_date=review_date,
                review_period_start=review_period_start,
                review_period_end=review_period_end,
                existing_reviews=existing_reviews,
            )
            self.user_review_df = self.user_review_report["dataframe"].copy()
            return self.user_review_df
        except Exception:
            return None

    def _coerce_config_value(self, value):
        text = "" if value is None else str(value).strip()
        if not text:
            return ""
        if text.lstrip("-").isdigit():
            return int(text)
        try:
            if "." in text:
                return float(text)
        except ValueError:
            pass
        return text

    def _load_settings_into_form(self, config):
        config = config or copy.deepcopy(self.DEFAULT_SETTINGS)
        self.settings_widgets["critical_users"].setPlainText("\n".join(config.get("critical_users", [])))
        self.settings_widgets["critical_roles"].setPlainText("\n".join(config.get("critical_roles", [])))
        self.settings_widgets["critical_privileges"].setPlainText("\n".join(config.get("critical_privileges", [])))
        self.settings_widgets["audit_event_keywords"].setPlainText("\n".join(config.get("audit_event_keywords", [])))
        self.settings_widgets["inactive_days_threshold"].setText(str(config.get("inactive_days_threshold", 120)))

        period_cfg = config.get("user_review_period", {})
        self.settings_widgets["user_review_period.start_date"].setDate(QDate.fromString(period_cfg.get("start_date", self._get_today_date()), "yyyy-MM-dd"))
        self.settings_widgets["user_review_period.end_date"].setDate(QDate.fromString(period_cfg.get("end_date", self._get_today_date()), "yyyy-MM-dd"))

        file_mappings = config.get("file_mappings", {})
        for mapping_key in getattr(self, "file_mapping_order", []):
            widget = self.settings_widgets.get(f"file_mappings.{mapping_key}")
            if widget is not None:
                widget.setText(str(file_mappings.get(mapping_key, "")))

        ini_rules_table = self.settings_widgets.get("ini_security_defaults")
        if ini_rules_table is not None:
            ini_rules_table.setRowCount(0)
            for rule in config.get("ini_security_defaults", []):
                self._add_ini_rule_row(
                    [
                        rule.get("file_name", ""),
                        rule.get("section", ""),
                        rule.get("key", ""),
                        rule.get("expected_value", ""),
                        rule.get("comparison_rule", "Exact"),
                        rule.get("risk_level", "Medium"),
                        rule.get("title", ""),
                    ]
                )
            if ini_rules_table.rowCount() == 0:
                self._add_ini_rule_row()

        for key, value in config.get("password_policy_defaults", {}).items():
            widget = self.settings_widgets.get(f"password_policy_defaults.{key}")
            if widget is None:
                continue
            if isinstance(widget, QComboBox):
                widget.setCurrentText(str(value))
            else:
                widget.setText(str(value))

        for rule_type, items in config.get("user_type_rules", {}).items():
            editor = self.settings_widgets.get(f"user_type_rules.{rule_type}")
            if editor is not None:
                editor.setPlainText("\n".join(items))

    def _collect_settings_from_form(self):
        def lines_from_editor(editor):
            return [line.strip() for line in editor.toPlainText().splitlines() if line.strip()]

        password_policy = {}
        int_fields = {
            "minimal_password_length",
            "password_lock_time",
            "last_used_passwords",
            "maximum_invalid_connect_attempts",
            "minimal_password_lifetime",
            "maximum_password_lifetime",
            "maximum_unused_initial_password_lifetime",
            "maximum_unused_productive_password_lifetime",
            "password_expire_warning_time",
        }
        for key, widget in self.settings_widgets.items():
            if not key.startswith("password_policy_defaults."):
                continue
            field_name = key.split(".", 1)[1]
            if isinstance(widget, QComboBox):
                value = widget.currentText().strip()
            else:
                value = widget.text().strip()
            if field_name in int_fields:
                value = int(value)
            password_policy[field_name] = value

        user_type_rules = {}
        for rule_type in ["Dialog", "Generic", "Technical", "Application"]:
            user_type_rules[rule_type] = lines_from_editor(self.settings_widgets[f"user_type_rules.{rule_type}"])

        file_mappings = {}
        for mapping_key in getattr(self, "file_mapping_order", []):
            widget = self.settings_widgets.get(f"file_mappings.{mapping_key}")
            if widget is not None:
                file_mappings[mapping_key] = widget.text().strip()

        ini_security_defaults = []
        table = self.settings_widgets.get("ini_security_defaults")
        if table is not None:
            for row in range(table.rowCount()):
                rule = {}
                has_value = False
                for column, key in enumerate(getattr(self, "ini_rule_keys", [])):
                    item = table.item(row, column)
                    cell_text = item.text().strip() if item else ""
                    if cell_text:
                        has_value = True
                    if key == "expected_value":
                        rule[key] = self._coerce_config_value(cell_text)
                    else:
                        rule[key] = cell_text
                if has_value:
                    ini_security_defaults.append(rule)

        return {
            "critical_users": lines_from_editor(self.settings_widgets["critical_users"]),
            "critical_roles": lines_from_editor(self.settings_widgets["critical_roles"]),
            "critical_privileges": lines_from_editor(self.settings_widgets["critical_privileges"]),
            "password_policy_defaults": password_policy,
            "file_mappings": file_mappings,
            "audit_event_keywords": lines_from_editor(self.settings_widgets["audit_event_keywords"]),
            "ini_security_defaults": ini_security_defaults,
            "inactive_days_threshold": int(self.settings_widgets["inactive_days_threshold"].text().strip()),
            "user_review_period": {
                "start_date": self.settings_widgets["user_review_period.start_date"].date().toPython().isoformat(),
                "end_date": self.settings_widgets["user_review_period.end_date"].date().toPython().isoformat(),
            },
            "user_type_rules": user_type_rules,
        }

    def _reset_settings_form(self):
        self._load_settings_into_form(copy.deepcopy(self.DEFAULT_SETTINGS))
        self._update_review_period_info_label()

    def _save_settings(self):
        try:
            config = self._collect_settings_from_form()
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.settings_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, ensure_ascii=False, indent=4)
            if self.importer is not None:
                self.importer.config = config
            self._update_review_period_info_label()
            self._show_info("הצלחה", "ההגדרות עודכנו.")
        except Exception as e:
            self._show_error("שגיאת הגדרות", str(e))

    def _export_control_mapping_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("ייצוא מיפוי בקרות", "Excel Workbook (*.xlsx)", f"EY_Control_Mapping_{timestamp}.xlsx")
        if not save_path:
            return
        try:
            csv_path = PROJECT_ROOT / "docs" / "ey_control_mapping_report.csv"
            md_path = PROJECT_ROOT / "docs" / "ey_control_mapping_report.md"
            if csv_path.exists():
                pd.read_csv(csv_path, encoding="utf-8-sig").to_excel(save_path, index=False)
            elif md_path.exists():
                pd.DataFrame({"content": [md_path.read_text(encoding="utf-8")]}).to_excel(save_path, index=False)
            else:
                raise FileNotFoundError("לא נמצא קובץ מיפוי בקרות בתיקיית docs")
            self._show_info("הצלחה", "דוח מיפוי הבקרות יוצא בהצלחה.")
        except Exception as error:
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את דוח מיפוי הבקרות.\n\nפירוט: {error}")

    def _open_logs_folder(self):
        log_dir = PROJECT_ROOT / "logs"
        log_dir.mkdir(exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(log_dir))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(log_dir)], check=False)
            else:
                subprocess.run(["xdg-open", str(log_dir)], check=False)
        except Exception as error:
            self._log_error("לא ניתן לפתוח את תיקיית הלוגים", error, log_dir=str(log_dir))
            self._show_error("שגיאת לוגים", f"לא ניתן לפתוח את תיקיית הלוגים.\n\n{error}\n\nהנתיב הוא:\n{log_dir}")

    def _log(self, msg, **context):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        support_logger = getattr(self, "support_logger", None)
        if support_logger is not None:
            support_logger.process(msg, **context)

    def _log_error(self, msg, error=None, **context):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {msg} | {error}")
        support_logger = getattr(self, "support_logger", None)
        if support_logger is not None:
            support_logger.error(msg, exception=error, **context)


def launch():
    gui = AuditGUI()
    gui.show()
    return gui.app.exec()


if __name__ == "__main__":
    raise SystemExit(launch())
