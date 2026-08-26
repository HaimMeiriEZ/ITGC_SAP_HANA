import copy
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

if sys.platform != "win32" and not os.environ.get("DISPLAY"):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QDate, Qt
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
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
    from core.process_logger import (
        close_active_run,
        get_process_logger,
        install_excepthook,
        register_atexit_close,
        setup_process_logging,
    )
    from core.user_review import (
        REVIEW_COMPLETION_COMPARISON_RULE,
        UNREVIEWED_USER_COMPARISON_RULE,
        build_review_completion_finding,
        build_unreviewed_user_findings,
        build_user_review_report,
        compute_review_progress,
        merge_existing_review_decisions,
        export_user_review_to_excel,
        export_user_review_to_pdf,
        import_user_review_from_excel,
    )
    from core.findings_master_detail import (
        aggregate_findings_by_control,
        build_summary_row_values,
        detail_findings_for_control,
        details_by_control,
        display_control_id,
        ensure_finding_control_id,
        sorted_summary_rows,
    )
    from core.ipe_evidence import (
        IpeEvidenceRepository,
        collect_missing_ipe_slots,
        controls_for_slot,
        primary_slot_for_control,
    )
    from src.reporting.working_paper_report import safe_working_paper_filename, write_control_working_paper
    from src.persistence.controls_catalog_loader import (
        load_and_apply_catalog,
        load_catalog,
        load_controls_catalog,
        save_catalog,
    )
    from core.compensating_control_repository import CompensatingControlRepository
    from core.compensating_control_service import (
        build_compensating_control_rows,
        DEFAULT_COMPENSATING_COLUMN_WIDTHS,
        DEFAULT_COMPENSATING_ROW_HEIGHT,
    )
    from src.pipeline import get_controls_catalog_summary, run_audit_analysis
    from src.readers.hana_export_reader import read_hana_export
except ImportError as e:
    print(f"שגיאת ייבוא: וודא שכל הקבצים נמצאים בנתיב הנכון. פירוט: {e}")
    raise


class SortableTableWidgetItem(QTableWidgetItem):
    SORT_ROLE = Qt.UserRole + 2
    DF_INDEX_ROLE = Qt.UserRole

    def __lt__(self, other: object) -> bool:
        if isinstance(other, QTableWidgetItem):
            self_sort_value = self.data(self.SORT_ROLE)
            other_sort_value = other.data(self.SORT_ROLE)
            if self_sort_value is not None or other_sort_value is not None:
                left = "" if self_sort_value is None else str(self_sort_value)
                right = "" if other_sort_value is None else str(other_sort_value)
                return left < right
            return super().__lt__(other)
        return NotImplemented


class UserReviewRowDialog(QDialog):
    """Read-only detail view for a single user-review row."""

    def __init__(self, parent=None, *, row: dict):
        super().__init__(parent)
        self.setWindowTitle("פרטי רשומת סקירת משתמשים")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"משתמש: {row.get('user_name', '-')}"))

        hint = QLabel("החלטות סקירה מתעדכנות רק באמצעות ייבוא קובץ Excel לאחר הסקירה.")
        hint.setWordWrap(True)
        hint.setProperty("class", "hint")
        layout.addWidget(hint)

        form = QFormLayout()
        fields = [
            ("סטטוס", row.get("active_status", "-")),
            ("סוג משתמש", row.get("user_type", "-")),
            ("החרגת סיסמה", row.get("password_policy_exempt_status", "-")),
            ("סיבת החרגה", row.get("password_policy_exempt_reason", "-")),
            ("גישה לטבלאות מערכת", row.get("system_table_access_status", "-")),
            ("חריג", row.get("has_exception", "-")),
            ("סיבת חריג", row.get("exception_reason", "-")),
            ("סטטוס סקירה", row.get("review_status", "-")),
            ("החלטת מנהל", row.get("manager_decision", "-") or "-"),
            ("נדרש להסרה / מאושר להשאיר", row.get("action_required", "-") or "-"),
            ("הערות", row.get("manager_comments", "-") or "-"),
        ]
        for label_text, value in fields:
            value_label = QLabel("" if value is None else str(value))
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            form.addRow(label_text, value_label)
        layout.addLayout(form)

        buttons = QDialogButtonBox()
        buttons.addButton("סגור", QDialogButtonBox.RejectRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class ImportReviewConfirmDialog(QDialog):
    """Confirmation before applying an imported user-review Excel file."""

    MODE_ALL = "all"
    MODE_PRESERVE_NOTES = "preserve_notes"

    def __init__(
        self,
        parent=None,
        *,
        total_in_file: int,
        matched: int,
        unmatched: list[str],
        notes_cleared: list[str],
    ):
        super().__init__(parent)
        self.setWindowTitle("אישור ייבוא סקירת משתמשים")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setMinimumWidth(520)
        self._mode = self.MODE_ALL

        layout = QVBoxLayout(self)
        summary = QLabel(
            f"נמצאו <b>{total_in_file}</b> רשומות בקובץ. "
            f"יתאימו לדוח הנוכחי: <b>{matched}</b>."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        has_issues = bool(unmatched or notes_cleared)
        self._radio_all = None
        self._radio_preserve = None
        if has_issues:
            warn_box = QGroupBox("התראות")
            warn_layout = QVBoxLayout(warn_box)
            if unmatched:
                warn_layout.addWidget(
                    QLabel(
                        f"{len(unmatched)} משתמשים בקובץ אינם בדוח הנוכחי (ידולגו): "
                        + ", ".join(unmatched[:8])
                        + ("..." if len(unmatched) > 8 else "")
                    )
                )
            if notes_cleared:
                warn_layout.addWidget(
                    QLabel(
                        f"{len(notes_cleared)} רשומות עם הערות קיימות יתרוקנו אם תבחר 'כל השינויים'."
                    )
                )
            layout.addWidget(warn_box)
            layout.addWidget(QLabel("כיצד ברצונך להמשיך?"))
            self._radio_all = QRadioButton("המשך עם כל השינויים (הערות ריקות בקובץ יימחקו)")
            self._radio_all.setChecked(True)
            self._radio_preserve = QRadioButton(
                "המשך ושמור הערות קיימות (הערות לא יימחקו אם הקובץ ריק בשדה זה)"
            )
            layout.addWidget(self._radio_all)
            layout.addWidget(self._radio_preserve)

        buttons = QDialogButtonBox()
        buttons.addButton("אשר ייבוא", QDialogButtonBox.AcceptRole)
        buttons.addButton("ביטול", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._on_confirm)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_confirm(self):
        if self._radio_preserve is not None and self._radio_preserve.isChecked():
            self._mode = self.MODE_PRESERVE_NOTES
        else:
            self._mode = self.MODE_ALL
        self.accept()

    @property
    def selected_mode(self) -> str:
        return self._mode


class SimpleVar:
    def __init__(self, value=None):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class AuditGUI:
    use_src_reader = True

    DEFAULT_SETTINGS = {
        "critical_users": ["SYSTEM", "SAPHANADB", "SYS", "_SYS_REPO", "XSSQLCC_AUTO_USER"],
        "critical_roles": ["SAP_INTERNAL_HANA_SUPPORT", "PUBLIC"],
        "critical_privileges": [
            "AUDIT ADMIN",
            "AUDIT OPERATOR",
            "BACKUP ADMIN",
            "CREATE ANY",
            "CREATE CONNECTION",
            "CREATE REMOTE SOURCE",
            "CREATE SCHEMA",
            "CREATE STRUCTURED PRIVILEGE",
            "DATA ADMIN",
            "DATABASE ADMIN",
            "EXPORT",
            "IMPORT",
            "INIFILE ADMIN",
            "LICENSE ADMIN",
            "LOG ADMIN",
            "MONITOR ADMIN",
            "PRIVILEGE ADMIN",
            "RESOURCE ADMIN",
            "ROLE ADMIN",
            "SERVICE ADMIN",
            "STRUCTURED PRIVILEGE ADMIN",
            "TRACE ADMIN",
            "TRUST ADMIN",
            "USER ADMIN",
            "WORKLOAD CAPTURE ADMIN",
            "WORKLOAD REPLAY ADMIN",
        ],
        "privilege_rules": {
            "flag_grant_option_on_critical": True,
            "business_schema_patterns": ["SYS_BIC", "*HDI*", "HDI_*"],
            "business_object_privileges": ["SELECT", "INSERT", "UPDATE", "DELETE"],
            "exclude_schema_patterns": ["_SYS_*", "SYS", "SYSTEM"],
        },
        "password_policy_defaults": {
            "minimal_password_length": 8,
            "force_first_password_change": "TRUE",
            "password_lock_time": 1440,
            "password_layout": "A1a",
            "last_used_passwords": 5,
            "maximum_invalid_connect_attempts": 6,
            "minimal_password_lifetime": 1,
            "maximum_password_lifetime": 90,
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
            "EFFECTIVE_PRIVILEGE_GRANTEES": "effective_privilege_grantees.csv",
            "GRANTED_ROLES": "granted_roles.csv",
            "AUDIT_POLICIES": "audit_policies.csv",
            "AUDIT_TRAIL": "audit_trail.csv",
            "M_INIFILE_CONTENTS": "m_inifile_contents.csv",
            "CONFIGURATION_PARAMETER_PROPERTIES": "configuration_parameter_properties.csv",
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
        "technical_owner_email": "",
        "business_owner_email": "",
    }

    def __init__(self, root=None):
        self.app = QApplication.instance() or QApplication(sys.argv)
        self.app.setLayoutDirection(Qt.RightToLeft)

        self.window = root if isinstance(root, QMainWindow) else QMainWindow()
        self.window.setWindowTitle("כלי להערכת בקרות ITGC בסביבת SAP HANA DB")
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
            QTableWidget::item:selected {
                background-color: #305496;
                color: #ffffff;
            }
            QTableWidget::item:selected:active {
                background-color: #305496;
                color: #ffffff;
            }
            QPushButton { padding: 6px 12px; }
            QTabBar::tab {
                background-color: #e9eef7;
                color: #16325c;
                border: 1px solid #b7c4d8;
                border-bottom: none;
                padding: 6px 12px;
                margin-left: 2px;
                min-width: 120px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #700030;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #c7cfda;
                top: -1px;
                background: #f8f9fa;
            }
            """
        )
        self.loaded_dataframes = {}
        self.loaded_files = {}
        self.loaded_extract_dates = {}
        self.ipe_records = []
        self.ipe_evidence_repo = IpeEvidenceRepository(
            output_dir=PROJECT_ROOT / "data" / "output",
            base_dir=PROJECT_ROOT,
        )
        # Do not restore prior-session IPE screenshots — require fresh upload each run.
        self.ipe_evidence_data = self.ipe_evidence_repo.clear_all()
        self.slot_ipe_buttons = {}
        self.slot_ipe_thumb_layouts = {}
        self.slot_group_boxes = {}
        self.control_to_slot_key = {}
        self.control_to_slot_rows = {}
        self.current_findings = []
        self.displayed_findings = []
        self.findings_summary_records = {}
        self.findings_details_by_control = {}
        self.compensating_controls_repository = CompensatingControlRepository(
            output_dir=PROJECT_ROOT / "data" / "output",
            base_dir=PROJECT_ROOT,
        )
        self.compensating_controls_data = self.compensating_controls_repository.load()
        self.compensating_controls_table: QTableWidget | None = None
        self.selected_finding_control_id = None
        self._suppress_findings_selection = False
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
            "EFFECTIVE_PRIVILEGE_GRANTEES": {
                "label": "הרשאות אפקטיביות (טבלת EFFECTIVE_PRIVILEGE_GRANTEES)",
                "required": ["GRANTEE", "PRIVILEGE", "OBJECT_TYPE"],
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
            "CONFIGURATION_PARAMETER_PROPERTIES": {
                "label": "מטא-דאטה פרמטרים (טבלת CONFIGURATION_PARAMETER_PROPERTIES)",
                "required": ["SECTION", "KEY", "DEFAULT_VALUE"],
                "required_any": [],
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
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        title_container = QWidget()
        title_container.setLayoutDirection(Qt.LeftToRight)
        title_row = QHBoxLayout(title_container)
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(12)

        logo_path = Path(__file__).resolve().parent / "assets" / "ayalon_logo.png"
        if logo_path.exists():
            logo_pixmap = QPixmap(str(logo_path))
            if not logo_pixmap.isNull():
                logo_label = QLabel()
                logo_label.setPixmap(logo_pixmap.scaledToHeight(36, Qt.SmoothTransformation))
                logo_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                logo_label.setContentsMargins(0, 0, 0, 0)
                title_row.addWidget(logo_label)

        title_row.addStretch(1)
        self.app_title_label = QLabel("כלי להערכת בקרות ITGC בסביבת SAP HANA DB")
        self.app_title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #16325c;")
        self.app_title_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        title_row.addWidget(self.app_title_label)
        layout.addWidget(title_container)

        self.notebook = QTabWidget()
        self.notebook.setLayoutDirection(Qt.RightToLeft)
        self.notebook.setDocumentMode(True)
        self.notebook.setMovable(False)
        layout.addWidget(self.notebook)

        self.controls_catalog_tab = QWidget()
        self.settings_tab = QWidget()
        self.import_tab = QWidget()
        self.user_review_tab = QWidget()
        self.audit_tab = QWidget()
        self.compensating_controls_tab = QWidget()

        self.notebook.addTab(self.controls_catalog_tab, "רשימת בקרות לניתוח")
        self.notebook.addTab(self.settings_tab, "הגדרות מערכת")
        self.notebook.addTab(self.import_tab, "טעינת נתונים (IPE)")
        self.notebook.addTab(self.user_review_tab, "דוח סקירת משתמשים")
        self.notebook.addTab(self.audit_tab, "ניתוח וממצאים")
        self.notebook.addTab(self.compensating_controls_tab, "בקרות מפצות")

        self._build_controls_catalog_tab()
        self._build_settings_tab()
        self._build_import_tab()
        self._build_user_review_tab()
        self._build_audit_tab()
        self._build_compensating_controls_tab()

    @staticmethod
    def _make_section_title(text: str, *, word_wrap: bool = False) -> QLabel:
        title = QLabel(text)
        title.setProperty("class", "section")
        title.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        if word_wrap:
            title.setWordWrap(True)
        return title

    def _rtl_hebrew_only(self, text):
        return "" if text is None else str(text)

    @staticmethod
    def _style_wrapping_action_button(button: QPushButton) -> None:
        button.setMinimumHeight(52)
        button.setMinimumWidth(170)
        button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        button.setStyleSheet(
            """
            QPushButton {
                padding: 8px 14px;
                text-align: center;
            }
            """
        )

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
        title = self._make_section_title("ניהול מקורות מידע ומהימנות נתונים (IPE)", word_wrap=True)
        self.export_ipe_btn = QPushButton("ייצוא לוג IPE ל-Excel")
        self.export_ipe_btn.clicked.connect(self._export_ipe_log)
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        header_layout.addWidget(self.export_ipe_btn)
        layout.addLayout(header_layout)

        slots = [
            ("USERS", "משתמשים (טבלת USERS)", "מקור חובה: רשימת משתמשים ותאריכי התחברות אחרונים"),
            ("M_PASSWORD_POLICY", "מדיניות סיסמאות (טבלת M_PASSWORD_POLICY)", "מקור חובה: פרמטרים והגדרות אבטחת סיסמה"),
            ("GRANTED_PRIVILEGES", "הרשאות (טבלת GRANTED_PRIVILEGES)", "מקור חובה: מיפוי הרשאות מערכת למשתמשים"),
            ("EFFECTIVE_PRIVILEGE_GRANTEES", "הרשאות אפקטיביות (טבלת EFFECTIVE_PRIVILEGE_GRANTEES)", "מקור מומלץ: הרשאות אפקטיביות כולל ירושה דרך roles"),
            ("GRANTED_ROLES", "הקצאות תפקידים (טבלת GRANTED_ROLES)", "מקור מומלץ: זיהוי הרשאות רגישות דרך Role inheritance"),
            ("AUDIT_POLICIES", "מדיניות ניטור (טבלת AUDIT_POLICIES)", "מקור חובה: הגדרות לוגים ובקרות ניטור מערכתיות"),
            ("AUDIT_TRAIL", "ראיות Audit בפועל (Audit Trail)", "מקור מומלץ: אימות פעולות מנהליות רגישות בפועל"),
            ("M_INIFILE_CONTENTS", "הקשחת תצורה (טבלת M_INIFILE_CONTENTS)", "מקור חובה: הגדרות קונפיגורציה קריטיות ברמת INI של SAP HANA"),
            ("CONFIGURATION_PARAMETER_PROPERTIES", "מטא-דאטה פרמטרים (CONFIGURATION_PARAMETER_PROPERTIES)", "מקור מומלץ: ברירות מחדל, טיפוסים והגבלות לפרמטרי תצורה"),
        ]

        self.slot_delete_btns = {}
        for slot_key, label, desc in slots:
            box = QGroupBox(label)
            self.slot_group_boxes[slot_key] = box
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(12, 12, 12, 12)
            box_layout.setSpacing(8)

            controls_layout = QHBoxLayout()
            controls_layout.setSpacing(10)

            choose_btn = QPushButton("בחר קובץ...")
            choose_btn.setMinimumSize(110, 32)
            choose_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            choose_btn.clicked.connect(lambda _checked=False, sk=slot_key: self._load_file(sk))

            ipe_btn = QPushButton("ראיה (IPE)")
            ipe_btn.setMinimumSize(110, 32)
            ipe_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            ipe_btn.setToolTip("צרף תמונת מסך כראיית שליפה אותנטית (IPE)")
            ipe_btn.clicked.connect(lambda _checked=False, sk=slot_key: self._add_ipe_evidence(sk))
            self.slot_ipe_buttons[slot_key] = ipe_btn

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
            controls_layout.addWidget(ipe_btn, 0, Qt.AlignRight)
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

            thumbs = QWidget()
            thumbs_layout = QHBoxLayout(thumbs)
            thumbs_layout.setContentsMargins(0, 0, 0, 0)
            thumbs_layout.setSpacing(6)
            thumbs_layout.addStretch(1)
            self.slot_ipe_thumb_layouts[slot_key] = thumbs_layout
            box_layout.addWidget(thumbs)

            layout.addWidget(box)
            self._refresh_slot_ipe_thumbnails(slot_key)
            self._update_slot_ipe_indicator(slot_key)

        ipe_box = QGroupBox("תיעוד דגימות (IPE Artifacts)")
        ipe_layout = QVBoxLayout(ipe_box)
        cols = ["סלוט", "שם קובץ", "תאריך הפקה", "שורות", "ראיות IPE", "זמן טעינה"]
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
        title = self._make_section_title("דוח סקירת משתמשים למנהלים")

        self.export_review_pdf_btn = QPushButton("ייצוא ל-PDF")
        self.export_review_pdf_btn.clicked.connect(self._export_user_review_pdf)
        self.export_review_excel_btn = QPushButton("ייצוא לאקסל")
        self.export_review_excel_btn.clicked.connect(self._export_user_review_excel)
        self.import_review_excel_btn = QPushButton("ייבוא סקירה מאקסל")
        self.import_review_excel_btn.clicked.connect(self._import_user_review_excel)
        self.email_review_technical_btn = QPushButton("שליחה במייל\nלגורם טכנולוגי")
        self.email_review_technical_btn.clicked.connect(self._draft_user_review_email_to_technical)
        self._style_wrapping_action_button(self.email_review_technical_btn)
        self.email_review_business_btn = QPushButton("שליחה במייל\nלגורם עסקי")
        self.email_review_business_btn.clicked.connect(self._draft_user_review_email_to_business)
        self._style_wrapping_action_button(self.email_review_business_btn)
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

        header_layout.addWidget(title)
        header_layout.addStretch(1)
        for widget in [
            self.export_review_pdf_btn,
            self.export_review_excel_btn,
            self.import_review_excel_btn,
            self.generate_review_btn,
            QLabel("תאריך סקירה:"),
            self.review_date_widget,
        ]:
            header_layout.addWidget(widget)
        layout.addLayout(header_layout)

        email_row = QHBoxLayout()
        email_row.addWidget(self.email_review_technical_btn)
        email_row.addWidget(self.email_review_business_btn)
        email_row.addStretch(1)
        layout.addLayout(email_row)

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

        progress_content = QWidget()
        progress_layout = QVBoxLayout(progress_content)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.setSpacing(6)
        counts_row = QHBoxLayout()
        self.user_review_total_label = QLabel('סה"כ משתמשים בדוח: 0')
        self.user_review_total_label.setStyleSheet("font-weight: bold;")
        self.user_review_reviewed_label = QLabel("משתמשים שנסקרו: 0")
        self.user_review_reviewed_label.setStyleSheet("font-weight: bold; color: #2e7d32;")
        self.user_review_unreviewed_label = QLabel("משתמשים שטרם נסקרו: 0")
        self.user_review_unreviewed_label.setStyleSheet("font-weight: bold; color: #1565c0;")
        for label in (
            self.user_review_total_label,
            self.user_review_reviewed_label,
            self.user_review_unreviewed_label,
        ):
            counts_row.addWidget(label)
        counts_row.addStretch(1)
        progress_layout.addLayout(counts_row)

        self.user_review_progress_bar = QProgressBar()
        self.user_review_progress_bar.setMinimum(0)
        self.user_review_progress_bar.setMaximum(100)
        self.user_review_progress_bar.setValue(0)
        self.user_review_progress_bar.setTextVisible(True)
        self.user_review_progress_bar.setFormat("0%")
        self.user_review_progress_bar.setStyleSheet(
            "QProgressBar { border: 1px solid #90caf9; border-radius: 4px; text-align: center; height: 18px; }"
            "QProgressBar::chunk { background-color: #42a5f5; }"
        )
        progress_layout.addWidget(self.user_review_progress_bar)

        self.user_review_progress_percent_label = QLabel("התקדמות השלמת סקירה: 0%")
        self.user_review_progress_percent_label.setStyleSheet("font-weight: bold; color: #0d47a1;")
        progress_layout.addWidget(self.user_review_progress_percent_label)
        layout.addWidget(self._make_collapsible_section("סיכום התקדמות סקירה", progress_content))

        info_content = QWidget()
        info_layout = QVBoxLayout(info_content)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(6)
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
            cell.setSpacing(2)
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
        self.user_type_tree.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        self.user_type_tree.verticalHeader().setDefaultSectionSize(24)
        self.user_type_tree.setMaximumHeight(110)
        self._fit_user_type_tree_height()
        info_layout.addWidget(self.user_type_tree)
        layout.addWidget(self._make_collapsible_section("מטא-דאטה ותקציר", info_content))

        report_content = QWidget()
        report_layout = QVBoxLayout(report_content)
        report_layout.setContentsMargins(0, 0, 0, 0)
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
        self.user_review_tree.setSortingEnabled(True)
        self.user_review_tree.itemSelectionChanged.connect(self._handle_user_review_selection)
        self.user_review_tree.cellDoubleClicked.connect(self._on_user_review_double_clicked)
        report_layout.addWidget(self.user_review_tree)
        layout.addWidget(
            self._make_collapsible_section(
                "רשימת משתמשים לסקירה",
                report_content,
                stretch_body=True,
            ),
            1,
        )

    def _make_collapsible_section(
        self,
        title: str,
        content: QWidget,
        *,
        collapsed: bool = False,
        stretch_body: bool = False,
    ) -> QWidget:
        container = QWidget()
        container.setLayoutDirection(Qt.RightToLeft)
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 4, 0, 4)
        outer.setSpacing(0)

        toggle = QToolButton()
        toggle.setText(title)
        toggle.setCheckable(True)
        toggle.setChecked(not collapsed)
        toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        toggle.setArrowType(Qt.DownArrow if not collapsed else Qt.LeftArrow)
        toggle.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        toggle.setCursor(Qt.PointingHandCursor)
        toggle.setStyleSheet(
            """
            QToolButton {
                border: 1px solid #cfd6de;
                border-radius: 6px;
                background-color: #eef3fb;
                padding: 8px 12px;
                font-weight: 700;
                font-size: 13px;
                color: #1f2d3d;
                text-align: right;
            }
            QToolButton:hover {
                background-color: #e0eaf8;
            }
            QToolButton:checked {
                border-bottom-left-radius: 0;
                border-bottom-right-radius: 0;
            }
            """
        )

        body = QFrame()
        body.setObjectName("collapsibleBody")
        body.setStyleSheet(
            """
            QFrame#collapsibleBody {
                border: 1px solid #cfd6de;
                border-top: none;
                border-bottom-left-radius: 6px;
                border-bottom-right-radius: 6px;
                background-color: #f8f9fa;
            }
            """
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(10, 8, 10, 10)
        body_layout.setSpacing(6)
        body_layout.addWidget(content)
        body.setVisible(not collapsed)

        def _on_toggled(checked: bool) -> None:
            body.setVisible(checked)
            toggle.setArrowType(Qt.DownArrow if checked else Qt.LeftArrow)

        toggle.toggled.connect(_on_toggled)
        outer.addWidget(toggle)
        outer.addWidget(body, 1 if stretch_body else 0)
        return container

    def _fit_user_type_tree_height(self) -> None:
        table = getattr(self, "user_type_tree", None)
        if table is None:
            return
        rows = max(table.rowCount(), 1)
        header_h = max(table.horizontalHeader().height(), 28)
        row_h = max(table.verticalHeader().defaultSectionSize(), 24)
        height = header_h + (row_h * rows) + 6
        table.setFixedHeight(min(max(height, 56), 110))

    def _build_audit_tab(self):
        layout = QVBoxLayout(self.audit_tab)

        ctrl_layout = QHBoxLayout()
        title = self._make_section_title("ביצוע ניתוח בקרות ITGC")
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

        ctrl_layout.addWidget(title)
        ctrl_layout.addStretch(1)
        for widget in [self.export_findings_btn, self.open_logs_btn, self.run_btn, QLabel("תקופה:"), self.period_input]:
            ctrl_layout.addWidget(widget)
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

        splitter = QSplitter(Qt.Vertical)

        summary_box = QGroupBox("ממצאי ביקורת כללי - ריכוז")
        summary_layout = QVBoxLayout(summary_box)
        self.findings_summary_columns = [
            "control_id",
            "title_he",
            "check_type",
            "risk_level",
            "valid_records",
            "finding_records",
            "total_records",
            "working_paper",
            "send_email",
            "source_file",
            "extraction_date",
            "risk_description",
            "description",
        ]
        summary_headers = [
            "מזהה בקרה",
            "כותרת בקרה",
            "סוג בדיקה",
            "רמת סיכון",
            "רשומות תקינות",
            "רשומות עם ממצא",
            'סה"כ רשומות',
            "צור נייר עבודה",
            "שלח מייל",
            "קובץ מקור",
            "תאריך הפקה",
            "תיאור הסיכון",
            "תיאור בקרה",
        ]
        self.findings_summary_table = QTableWidget(0, len(summary_headers))
        self.findings_summary_table.setHorizontalHeaderLabels(summary_headers)
        self._configure_table(self.findings_summary_table)
        summary_hdr = self.findings_summary_table.horizontalHeader()
        summary_hdr.setSectionResizeMode(QHeaderView.Interactive)
        summary_hdr.setStretchLastSection(False)
        self.findings_summary_table.setColumnWidth(7, 120)  # צור נייר עבודה
        self.findings_summary_table.setColumnWidth(8, 90)   # שלח מייל
        self.findings_summary_table.setColumnWidth(11, 220)  # תיאור הסיכון
        self.findings_summary_table.setColumnWidth(12, 220)  # תיאור בקרה
        self.findings_summary_table.setSortingEnabled(True)
        self.findings_summary_finding_count_col = 5
        self.findings_summary_table.itemSelectionChanged.connect(self._refresh_selected_finding_detail)
        summary_layout.addWidget(self.findings_summary_table)
        splitter.addWidget(summary_box)

        detail_box = QGroupBox("פירוט ממצאי ביקורת")
        detail_layout = QVBoxLayout(detail_box)
        self.findings_column_order = ["source", "extract_date", "cat", "risk", "title", "rule", "actual", "expected", "status"]
        detail_headers = ["קובץ מקור", "תאריך הפקה", "קטגוריה", "סיכון", "תיאור", "סוג בדיקה", "ערך בפועל", "ערך מצופה", "סטטוס"]
        self.findings_detail_table = QTableWidget(0, len(detail_headers))
        self.findings_detail_table.setHorizontalHeaderLabels(detail_headers)
        self._configure_table(self.findings_detail_table)
        self.findings_detail_table.setSortingEnabled(True)
        self.findings_detail_table.cellDoubleClicked.connect(lambda _row, _col: self._open_finding_details())
        self.findings_detail_table.horizontalHeader().sectionClicked.connect(self._on_findings_header_clicked)
        detail_layout.addWidget(self.findings_detail_table)
        splitter.addWidget(detail_box)

        # Keep legacy alias used by older helpers that still reference self.tree
        self.tree = self.findings_detail_table

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self._reset_filter_options()

    def _build_controls_catalog_tab(self):
        layout = QVBoxLayout(self.controls_catalog_tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        hint = QLabel(
            "כל 11 הבקרות מחוברות ל-validators לפי הקטלוג. "
            "לחיצה כפולה על שורה פותחת חלון עריכה. "
            "מזהה הבקרה המוצג הוא control_id_ayalon (מפתח פנימי נשמר ברקע). "
            "עמודות המייל נגזרות מהכתובות בהגדרות המערכת ומהסימון לכל בקרה "
            "(גורם טכנולוגי / גורם עסקי / שניהם). "
            "ניתן לגרור את גובה השורות משמאל כדי להרחיב ולראות תיאור מלא."
        )
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignRight | Qt.AlignTop)
        hint.setStyleSheet("color: #444; font-size: 11px; padding: 4px 0;")
        layout.addWidget(hint)

        self.controls_catalog_table = QTableWidget()
        self.controls_catalog_table.setLayoutDirection(Qt.RightToLeft)
        headers = [
            "מזהה בקרה",
            "כותרת",
            "בסקופ",
            "תיאור הסיכון",
            "תיאור הבקרה",
            "גורם טכנולוגי",
            "גורם עסקי",
            "דומיין",
            "slots נדרשים",
            "סטטוס",
        ]
        self.controls_catalog_table.setColumnCount(len(headers))
        self.controls_catalog_table.setHorizontalHeaderLabels(headers)
        self.controls_catalog_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.controls_catalog_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.controls_catalog_table.setAlternatingRowColors(True)
        self.controls_catalog_table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.controls_catalog_table.setWordWrap(True)
        self.controls_catalog_table.setTextElideMode(Qt.ElideNone)
        hdr = self.controls_catalog_table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        hdr.setDefaultAlignment(Qt.AlignRight | Qt.AlignVCenter | Qt.AlignAbsolute)
        self.controls_catalog_table.setColumnWidth(0, 160)
        self.controls_catalog_table.setColumnWidth(1, 180)
        self.controls_catalog_table.setColumnWidth(2, 70)
        self.controls_catalog_table.setColumnWidth(3, 240)
        self.controls_catalog_table.setColumnWidth(4, 280)
        self.controls_catalog_table.setColumnWidth(5, 160)
        self.controls_catalog_table.setColumnWidth(6, 160)
        self.controls_catalog_table.setColumnWidth(7, 100)
        self.controls_catalog_table.setColumnWidth(8, 180)
        vhdr = self.controls_catalog_table.verticalHeader()
        vhdr.setVisible(True)
        vhdr.setSectionResizeMode(QHeaderView.Interactive)
        vhdr.setDefaultSectionSize(72)
        vhdr.setMinimumSectionSize(28)
        self.controls_catalog_table.cellDoubleClicked.connect(self._on_catalog_row_double_clicked)
        layout.addWidget(self.controls_catalog_table, 1)

        btn_bar = QHBoxLayout()
        refresh_btn = QPushButton("רענון רשימה")
        refresh_btn.clicked.connect(self._refresh_controls_catalog_table)
        expand_rows_btn = QPushButton("הרחב שורות לתיאור מלא")
        expand_rows_btn.clicked.connect(self._expand_controls_catalog_rows)
        collapse_rows_btn = QPushButton("כווץ שורות")
        collapse_rows_btn.clicked.connect(self._collapse_controls_catalog_rows)
        btn_bar.addWidget(refresh_btn)
        btn_bar.addWidget(expand_rows_btn)
        btn_bar.addWidget(collapse_rows_btn)
        btn_bar.addStretch(1)
        layout.addLayout(btn_bar)

        self._refresh_controls_catalog_table()

    def _expand_controls_catalog_rows(self):
        if not hasattr(self, "controls_catalog_table"):
            return
        self.controls_catalog_table.resizeRowsToContents()

    def _collapse_controls_catalog_rows(self):
        if not hasattr(self, "controls_catalog_table"):
            return
        default_height = self.controls_catalog_table.verticalHeader().defaultSectionSize()
        for row_idx in range(self.controls_catalog_table.rowCount()):
            self.controls_catalog_table.setRowHeight(row_idx, default_height)

    def _refresh_controls_catalog_table(self):
        if not hasattr(self, "controls_catalog_table"):
            return
        rows = get_controls_catalog_summary()
        tech_email = self._get_owner_email("technical")
        biz_email = self._get_owner_email("business")
        self.controls_catalog_table.setRowCount(len(rows))
        for row_idx, entry in enumerate(rows):
            control_id = str(entry.get("control_id", "") or "")
            ayalon_id = str(entry.get("control_id_ayalon", "") or "").strip()
            display_id = ayalon_id or control_id
            risk_text = str(entry.get("risk_description", "") or "")
            desc_text = str(entry.get("description", "") or "")
            in_scope_raw = entry.get("in_scope", True)
            if isinstance(in_scope_raw, str):
                in_scope = in_scope_raw.strip().lower() not in {"false", "0", "no"}
            else:
                in_scope = bool(in_scope_raw)
            scope_label = "כן" if in_scope else "לא"
            notify_tech = bool(entry.get("notify_technical", False))
            notify_biz = bool(entry.get("notify_business", False))
            tech_display = tech_email if notify_tech and tech_email else ("כן" if notify_tech else "—")
            biz_display = biz_email if notify_biz and biz_email else ("כן" if notify_biz else "—")
            values = [
                display_id,
                self._rtl_hebrew_only(entry.get("title_he", "")),
                scope_label,
                self._rtl_hebrew_only(risk_text),
                self._rtl_hebrew_only(desc_text),
                tech_display,
                biz_display,
                entry.get("domain", ""),
                entry.get("required_slots", ""),
                entry.get("status", ""),
            ]
            for col_idx, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                # AlignAbsolute: keep visual right alignment under RTL table layout.
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter | Qt.AlignAbsolute)
                if col_idx == 0:
                    item.setData(Qt.UserRole, control_id)
                    if ayalon_id and ayalon_id != control_id:
                        item.setToolTip(f"מזהה פנימי: {control_id}")
                elif col_idx == 2:
                    # Background tint only — ForegroundRole would override selected white text.
                    item.setBackground(QColor("#d4edda" if in_scope else "#f8d7da"))
                elif col_idx in (3, 4):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignTop | Qt.AlignAbsolute)
                    if value:
                        item.setToolTip(str(value))
                elif col_idx == 5:
                    if notify_tech:
                        item.setToolTip(tech_email or "כתובת מייל לגורם טכנולוגי תוגדר בהגדרות מערכת")
                elif col_idx == 6:
                    if notify_biz:
                        item.setToolTip(biz_email or "כתובת מייל לגורם עסקי תוגדר בהגדרות מערכת")
                self.controls_catalog_table.setItem(row_idx, col_idx, item)
        self.controls_catalog_table.resizeRowsToContents()

    def _on_catalog_row_double_clicked(self, row: int, _column: int):
        item = self.controls_catalog_table.item(row, 0)
        if item is None:
            return
        control_id = item.data(Qt.UserRole) or item.text()
        if control_id:
            self._show_control_edit_dialog(str(control_id))

    def _show_control_edit_dialog(self, control_id: str):
        catalog = load_controls_catalog()
        entry = catalog.get(control_id)
        if entry is None:
            self._show_warning("אין נתונים", f"לא נמצאה בקרה {control_id} בקטלוג.")
            return

        dlg = QDialog(self.window)
        dlg.setWindowTitle(f"עריכת בקרה — {control_id}")
        dlg.setLayoutDirection(Qt.RightToLeft)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumWidth(580)
        dlg.resize(640, 620)

        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(16, 14, 16, 14)
        dlg_layout.setSpacing(6)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        form_widget = QWidget()
        form_widget.setLayoutDirection(Qt.RightToLeft)
        form_layout = QFormLayout(form_widget)
        form_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        form_layout.setSpacing(10)
        scroll.setWidget(form_widget)

        def _ro(text: str) -> QLabel:
            lbl = QLabel(f"<b>{text}</b>")
            lbl.setStyleSheet("color: #555;")
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            return lbl

        required_slots = entry.get("required_slots") or []
        if isinstance(required_slots, list):
            slots_text = ", ".join(str(s) for s in required_slots)
        else:
            slots_text = str(required_slots or "")

        form_layout.addRow("מזהה פנימי:", _ro(control_id))
        form_layout.addRow("דומיין:", _ro(str(entry.get("domain", "") or "-")))
        form_layout.addRow("slots נדרשים:", _ro(slots_text or "-"))
        form_layout.addRow(
            "סטטוס מימוש:",
            _ro(str(entry.get("implementation_status", "") or "-")),
        )
        form_layout.addRow(
            "validator_ref:",
            _ro(str(entry.get("validator_ref", "") or "-")),
        )

        ayalon_edit = QLineEdit(str(entry.get("control_id_ayalon", "") or ""))
        ayalon_edit.setLayoutDirection(Qt.RightToLeft)
        form_layout.addRow("מזהה Ayalon:", ayalon_edit)

        title_edit = QLineEdit(str(entry.get("title_he", "") or ""))
        title_edit.setLayoutDirection(Qt.RightToLeft)
        form_layout.addRow("כותרת:", title_edit)

        process_edit = QLineEdit(str(entry.get("process", "") or ""))
        process_edit.setLayoutDirection(Qt.RightToLeft)
        form_layout.addRow("תהליך:", process_edit)

        in_scope_raw = entry.get("in_scope", True)
        if isinstance(in_scope_raw, str):
            in_scope_checked = in_scope_raw.strip().lower() not in {"false", "0", "no"}
        else:
            in_scope_checked = bool(in_scope_raw)

        scope_box = QGroupBox("בסקופ לביקורת")
        scope_box.setLayoutDirection(Qt.RightToLeft)
        scope_box.setStyleSheet(self._catalog_edit_group_stylesheet())
        scope_layout = QHBoxLayout(scope_box)
        scope_layout.setContentsMargins(8, 12, 8, 8)
        scope_layout.setSpacing(10)
        scope_yes_radio = self._make_filled_radio("כן — כלול בניתוח ובממצאים")
        scope_no_radio = self._make_filled_radio("לא — מחוץ לסקופ (לא ינותח)")
        scope_group = QButtonGroup(dlg)
        scope_group.setExclusive(True)
        scope_group.addButton(scope_yes_radio)
        scope_group.addButton(scope_no_radio)
        if in_scope_checked:
            scope_yes_radio.setChecked(True)
        else:
            scope_no_radio.setChecked(True)
        scope_layout.addWidget(scope_yes_radio, 1)
        scope_layout.addWidget(scope_no_radio, 1)
        form_layout.addRow(scope_box)

        notify_tech_raw = entry.get("notify_technical", False)
        notify_biz_raw = entry.get("notify_business", False)
        if isinstance(notify_tech_raw, str):
            notify_tech_checked = notify_tech_raw.strip().lower() not in {"false", "0", "no"}
        else:
            notify_tech_checked = bool(notify_tech_raw)
        if isinstance(notify_biz_raw, str):
            notify_biz_checked = notify_biz_raw.strip().lower() not in {"false", "0", "no"}
        else:
            notify_biz_checked = bool(notify_biz_raw)

        recipients_box = QGroupBox("נמעני דיווח (מייל)")
        recipients_box.setLayoutDirection(Qt.RightToLeft)
        recipients_box.setStyleSheet(self._catalog_edit_group_stylesheet())
        recipients_layout = QVBoxLayout(recipients_box)
        recipients_layout.setContentsMargins(8, 12, 8, 8)
        recipients_layout.setSpacing(8)
        tech_email = self._get_owner_email("technical") or "(לא הוגדר בהגדרות מערכת)"
        biz_email = self._get_owner_email("business") or "(לא הוגדר בהגדרות מערכת)"
        notify_tech_radio = self._make_filled_radio(f"גורם טכנולוגי — {tech_email}")
        notify_biz_radio = self._make_filled_radio(f"גורם עסקי — {biz_email}")
        notify_both_radio = self._make_filled_radio("שניהם — טכנולוגי ועסקי")
        notify_none_radio = self._make_filled_radio("ללא נמען")
        recipients_group = QButtonGroup(dlg)
        recipients_group.setExclusive(True)
        for radio in (
            notify_tech_radio,
            notify_biz_radio,
            notify_both_radio,
            notify_none_radio,
        ):
            recipients_group.addButton(radio)
            recipients_layout.addWidget(radio)
        if notify_tech_checked and notify_biz_checked:
            notify_both_radio.setChecked(True)
        elif notify_tech_checked:
            notify_tech_radio.setChecked(True)
        elif notify_biz_checked:
            notify_biz_radio.setChecked(True)
        else:
            notify_none_radio.setChecked(True)
        recipients_hint = QLabel(
            "הכתובות נלקחות מהגדרות המערכת. בחירה בכחול = נבחר; רקע לבן = לא נבחר."
        )
        recipients_hint.setWordWrap(True)
        recipients_hint.setStyleSheet("color: #666; font-size: 11px;")
        recipients_layout.addWidget(recipients_hint)
        form_layout.addRow(recipients_box)

        risk_edit = QTextEdit()
        risk_edit.setLayoutDirection(Qt.RightToLeft)
        risk_edit.setPlainText(str(entry.get("risk_description", "") or ""))
        risk_edit.setMinimumHeight(70)
        risk_edit.setMaximumHeight(110)
        form_layout.addRow("תיאור הסיכון:", risk_edit)

        desc_edit = QTextEdit()
        desc_edit.setLayoutDirection(Qt.RightToLeft)
        desc_edit.setPlainText(str(entry.get("description", "") or ""))
        desc_edit.setMinimumHeight(70)
        desc_edit.setMaximumHeight(110)
        form_layout.addRow("תיאור הבקרה:", desc_edit)

        steps_edit = QTextEdit()
        steps_edit.setLayoutDirection(Qt.RightToLeft)
        steps_edit.setPlainText(str(entry.get("test_steps_override", "") or ""))
        steps_edit.setMinimumHeight(60)
        steps_edit.setMaximumHeight(100)
        form_layout.addRow("צעדי טסט:", steps_edit)

        notes_edit = QLineEdit(str(entry.get("notes", "") or ""))
        notes_edit.setLayoutDirection(Qt.RightToLeft)
        form_layout.addRow("הערות:", notes_edit)

        dlg_layout.addWidget(scroll, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setText("שמירה")
        buttons.button(QDialogButtonBox.Cancel).setText("ביטול")
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        dlg_layout.addWidget(buttons)

        if dlg.exec() != QDialog.Accepted:
            return

        try:
            controls = load_catalog()
            updated = False
            for item in controls:
                if str(item.get("control_id", "")).strip() == control_id:
                    item["control_id_ayalon"] = ayalon_edit.text().strip()
                    item["title_he"] = title_edit.text().strip()
                    item["process"] = process_edit.text().strip()
                    item["risk_description"] = risk_edit.toPlainText().strip()
                    item["description"] = desc_edit.toPlainText().strip()
                    item["test_steps_override"] = steps_edit.toPlainText().strip()
                    item["notes"] = notes_edit.text().strip()
                    item["in_scope"] = bool(scope_yes_radio.isChecked())
                    if notify_both_radio.isChecked():
                        item["notify_technical"] = True
                        item["notify_business"] = True
                    elif notify_tech_radio.isChecked():
                        item["notify_technical"] = True
                        item["notify_business"] = False
                    elif notify_biz_radio.isChecked():
                        item["notify_technical"] = False
                        item["notify_business"] = True
                    else:
                        item["notify_technical"] = False
                        item["notify_business"] = False
                    updated = True
                    break
            if not updated:
                self._show_warning("אין נתונים", f"לא נמצאה רשומה לעדכון עבור {control_id}.")
                return
            save_catalog(controls)
            load_and_apply_catalog()
            self._refresh_controls_catalog_table()
            self._show_info("הצלחה", f"הבקרה {control_id} נשמרה בקטלוג.")
            self._log("עודכן קטלוג בקרות", control_id=control_id)
        except Exception as error:
            self._show_error("שגיאת שמירה", f"לא ניתן לשמור את הבקרה.\n\n{error}")

    @staticmethod
    def _catalog_edit_group_stylesheet() -> str:
        return """
            QGroupBox {
                font-weight: 700;
                color: #1f2d3d;
                border: 2px solid #305496;
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px 8px 8px 8px;
                background-color: #eef3fb;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top right;
                padding: 0 8px;
                background-color: #eef3fb;
            }
        """

    @staticmethod
    def _make_filled_radio(label: str) -> QPushButton:
        """Exclusive choice button: blue fill + white text when selected, white when not."""
        button = QPushButton(label)
        button.setCheckable(True)
        button.setAutoExclusive(False)
        button.setLayoutDirection(Qt.RightToLeft)
        button.setMinimumHeight(40)
        button.setCursor(Qt.PointingHandCursor)
        button.setStyleSheet(
            """
            QPushButton {
                text-align: right;
                padding: 8px 14px;
                border: 2px solid #305496;
                border-radius: 6px;
                background-color: #ffffff;
                color: #1f2d3d;
                font-size: 13px;
            }
            QPushButton:hover:!checked {
                background-color: #e8eef8;
            }
            QPushButton:checked {
                background-color: #305496;
                color: #ffffff;
                font-weight: 700;
            }
            QPushButton:pressed {
                background-color: #264578;
                color: #ffffff;
            }
            """
        )
        return button

    def _build_settings_tab(self):
        outer_layout = QVBoxLayout(self.settings_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(12)

        title = self._make_section_title("הגדרות מערכת לביקורת", word_wrap=True)
        layout.addWidget(title)
        hint = QLabel("הטופס מאפשר לעדכן את ההגדרות בצורה ידידותית ולשמור ישירות לקובץ ההגדרות.")
        hint.setProperty("class", "hint")
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
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

        layout.addWidget(self._build_notification_emails_section())
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

    def _build_notification_emails_section(self):
        box, layout = self._build_group_box(
            "כתובות מייל לנמענים",
            "כתובות אלה ישמשו ברשימת הבקרות ובשליחת דוח סקירת משתמשים "
            "לגורם טכנולוגי או לגורם עסקי.",
        )
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        form.setFormAlignment(Qt.AlignRight | Qt.AlignTop)
        form.setHorizontalSpacing(16)

        technical_email = QLineEdit()
        technical_email.setPlaceholderText("example@company.com")
        technical_email.setLayoutDirection(Qt.LeftToRight)
        self.settings_widgets["technical_owner_email"] = technical_email
        form.addRow("גורם טכנולוגי", technical_email)

        business_email = QLineEdit()
        business_email.setPlaceholderText("example@company.com")
        business_email.setLayoutDirection(Qt.LeftToRight)
        self.settings_widgets["business_owner_email"] = business_email
        form.addRow("גורם עסקי", business_email)

        layout.addLayout(form)
        return box

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
            "EFFECTIVE_PRIVILEGE_GRANTEES": "הרשאות אפקטיביות",
            "GRANTED_ROLES": "הקצאות תפקידים",
            "AUDIT_POLICIES": "מדיניות ניטור",
            "AUDIT_TRAIL": "Audit Trail",
            "M_INIFILE_CONTENTS": "INI Hardening",
            "CONFIGURATION_PARAMETER_PROPERTIES": "מטא-דאטה פרמטרי תצורה",
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
        if getattr(self, "use_src_reader", False):
            result = read_hana_export(file_path)
            if result.df is None:
                reason = "; ".join(result.warnings) if result.warnings else "לא ניתן לקרוא את הקובץ"
                raise ValueError(reason)
            return result.df

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

        if slot_key == "GRANTED_PRIVILEGES" and "EFFECTIVE_PRIVILEGE_GRANTEES" not in self.loaded_dataframes:
            # Backward compatible fallback: analyzer prefers EFFECTIVE when present.
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
        evidence_count = len(self.ipe_evidence_data.get(slot_key, []))
        evidence_names = ", ".join(
            entry.get("original_filename", "") for entry in self.ipe_evidence_data.get(slot_key, [])
        ) or "-"
        self.ipe_records.append(
            {
                "סלוט במערכת": slot_key,
                "שם קובץ מקורי": filename,
                "תאריך הפקה": extract_date,
                "כמות רשומות": rows,
                "ראיות IPE": f"{evidence_count}: {evidence_names}",
                "זמן טעינה": timestamp,
                "נתיב מלא": file_path,
            }
        )
        self.db.save_ipe_load(slot_key, filename, extract_date, rows, file_path)
        self.slot_status_labels[slot_key].setText(f"✅ נטען: {filename}")
        self.slot_delete_btns[slot_key].setEnabled(True)
        self._set_table_row(
            self.ipe_tree,
            self.ipe_tree.rowCount(),
            [slot_key, filename, extract_date, rows, evidence_count, timestamp],
        )
        self.db.log_activity("IPE Load", f"Slot: {slot_key}, File: {filename}, Extract Date: {extract_date}, Rows: {rows}", "User")
        self._update_slot_ipe_indicator(slot_key)

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

        ipe_errors = self._missing_ipe_messages(list(self.loaded_dataframes.keys()))
        if ipe_errors:
            validation_errors.extend(ipe_errors)

        if validation_errors:
            return False, "\n\n--------------------\n\n".join(validation_errors)
        return True, ""

    def _missing_ipe_messages(self, slot_keys):
        labels = {
            key: meta.get("label", key)
            for key, meta in self.slot_metadata.items()
        }
        return collect_missing_ipe_slots(
            list(slot_keys),
            self.ipe_evidence_data,
            loaded_files=self.loaded_files,
            slot_labels=labels,
        )

    def _load_file(self, slot_key):
        extract_date = self._normalize_extract_date(slot_key, show_message=True)
        if not extract_date:
            return

        file_path = self._get_open_file("בחר קובץ", "Data files (*.csv *.txt)")
        if not file_path:
            return

        filename = os.path.basename(file_path)
        plog = get_process_logger()
        if plog is not None:
            plog.info("Slot intake start", f"slot={slot_key}; file={filename}")
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
            if plog is not None:
                plog.info("Slot intake end", f"slot={target_slot}; rows={len(df)}")
            self._log("טעינת הקובץ הושלמה בהצלחה", slot=target_slot, filename=filename, rows=len(df))
        except Exception as e:
            self.loaded_dataframes.pop(slot_key, None)
            self.loaded_files.pop(slot_key, None)
            self.loaded_extract_dates.pop(slot_key, None)
            self.slot_status_labels[slot_key].setText(f"❌ שגיאה בטעינת: {filename}")
            self.slot_delete_btns[slot_key].setEnabled(False)
            if plog is not None:
                plog.fail("Slot intake", f"slot={slot_key}; file={filename}", exc=e)
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
                if self.loaded_files.get("EFFECTIVE_PRIVILEGE_GRANTEES") == filename:
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
            self.ipe_evidence_repo.clear_slot(slot_key, self.ipe_evidence_data)
            self._refresh_slot_ipe_thumbnails(slot_key)
            self._update_slot_ipe_indicator(slot_key)
            self.db.log_activity("IPE Clear", f"Cleared data slot: {slot_key} (Previous file: {filename})", "User")
            self._log(f"הנתונים בסלוט {slot_key} נמחקו מהזיכרון.")

    def _add_ipe_evidence(self, slot_key):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self.window,
            f"בחירת תמונות ראיה עבור {slot_key}",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif);;All files (*.*)",
        )
        if not file_paths:
            return
        control_ids = controls_for_slot(slot_key)
        for file_path in file_paths:
            self.ipe_evidence_repo.add_image(
                slot_key,
                Path(file_path),
                control_ids,
                self.ipe_evidence_data,
            )
        self._refresh_slot_ipe_thumbnails(slot_key)
        self._update_slot_ipe_indicator(slot_key)
        self._log("נוספה ראיית IPE", slot=slot_key, files=len(file_paths))

    def _remove_ipe_evidence(self, slot_key, image_id):
        self.ipe_evidence_repo.remove_image(slot_key, image_id, self.ipe_evidence_data)
        self._refresh_slot_ipe_thumbnails(slot_key)
        self._update_slot_ipe_indicator(slot_key)

    def _refresh_slot_ipe_thumbnails(self, slot_key):
        layout = self.slot_ipe_thumb_layouts.get(slot_key)
        if layout is None:
            return
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for entry in self.ipe_evidence_data.get(slot_key, []):
            card = QWidget()
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(4, 4, 4, 4)
            card_layout.setSpacing(2)
            thumb = QLabel()
            thumb.setFixedSize(72, 54)
            thumb.setAlignment(Qt.AlignCenter)
            stored = Path(str(entry.get("stored_path", "")))
            pixmap = QPixmap(str(stored)) if stored.exists() else QPixmap()
            if not pixmap.isNull():
                thumb.setPixmap(pixmap.scaled(72, 54, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                thumb.setText("IPE")
            name = QLabel(str(entry.get("original_filename", ""))[:18])
            name.setAlignment(Qt.AlignCenter)
            remove_btn = QPushButton("הסר")
            remove_btn.setFixedHeight(24)
            remove_btn.setToolTip("הסר ראיה")
            remove_btn.clicked.connect(
                lambda _checked=False, sk=slot_key, image_id=entry.get("id"): self._remove_ipe_evidence(sk, image_id)
            )
            card_layout.addWidget(thumb)
            card_layout.addWidget(name)
            card_layout.addWidget(remove_btn)
            layout.addWidget(card)
        layout.addStretch(1)

    def _update_slot_ipe_indicator(self, slot_key):
        box = self.slot_group_boxes.get(slot_key)
        if box is None:
            return
        has_file = slot_key in self.loaded_dataframes
        has_ipe = bool(self.ipe_evidence_data.get(slot_key))
        if has_file and has_ipe:
            box.setStyleSheet("QGroupBox { border: 2px solid #2e7d32; border-radius: 6px; margin-top: 8px; }")
        elif has_file and not has_ipe:
            box.setStyleSheet("QGroupBox { border: 2px solid #ef6c00; border-radius: 6px; margin-top: 8px; }")
        else:
            box.setStyleSheet("")

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

    def _on_user_review_double_clicked(self, _row, _column):
        self._open_user_review_row_dialog()

    def _open_user_review_row_dialog(self):
        row_index = self._get_selected_user_review_index()
        if row_index is None or self.user_review_df.empty:
            self._show_warning("לא נבחר משתמש", "בחר שורה מתוך דוח הסקירה כדי לצפות בפרטים.")
            return

        row = self.user_review_df.iloc[row_index].to_dict()
        dialog = UserReviewRowDialog(self.window, row=row)
        dialog.exec()

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
            if "user_type" in self.user_review_df.columns:
                type_counts = self.user_review_df["user_type"].fillna("").astype(str).value_counts().to_dict()
                self.user_review_report["summary"]["type_distribution"] = {
                    str(user_type): int(count) for user_type, count in type_counts.items() if str(user_type).strip()
                }

        self._update_user_review_summary()
        self._refresh_user_review_table()

    def _begin_inline_user_review_edit(self, *_args):
        return

    def _cancel_inline_user_review_edit(self):
        self.user_review_inline_editor = None

    def _commit_inline_user_review_edit(self):
        self.user_review_inline_editor = None

    def _import_user_review_excel(self):
        if self.user_review_report is None or self.user_review_df.empty:
            self._show_warning("אין נתונים", "בנה תחילה דוח סקירת משתמשים לפני ייבוא החלטות.")
            return

        file_path = self._get_open_file(
            "ייבוא סקירת משתמשים מאקסל",
            "Excel files (*.xlsx *.xlsm);;All files (*.*)",
        )
        if not file_path:
            return

        try:
            preview = import_user_review_from_excel(
                file_path,
                self.user_review_df.copy(),
                preserve_empty_notes=False,
            )
        except Exception as error:
            self._log_error("שגיאה בייבוא סקירת משתמשים", error, file_path=file_path)
            self._show_error("שגיאת ייבוא", f"לא ניתן לקרוא את קובץ הסקירה.\n\n{error}")
            return

        dialog = ImportReviewConfirmDialog(
            self.window,
            total_in_file=preview["total_in_file"],
            matched=preview["matched"],
            unmatched=preview["unmatched"],
            notes_cleared=preview["notes_cleared"],
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        preserve_notes = dialog.selected_mode == ImportReviewConfirmDialog.MODE_PRESERVE_NOTES
        try:
            result = import_user_review_from_excel(
                file_path,
                self.user_review_df,
                preserve_empty_notes=preserve_notes,
            )
            self.user_review_df = result["updated_df"]
            if self.user_review_report is not None:
                self.user_review_report["dataframe"] = self.user_review_df.copy()
                if "has_exception" in self.user_review_df.columns:
                    self.user_review_report["summary"]["exception_users"] = int(
                        (self.user_review_df["has_exception"] == "כן").sum()
                    )
            self.user_review_dirty_rows.clear()
            if not self.user_review_df.empty:
                self.db.save_user_review_rows(self.user_review_df.to_dict("records"))
            self._update_user_review_summary()
            self._refresh_user_review_table()
            self._sync_user_review_completion_finding()
            mode_label = "שמירת הערות קיימות" if preserve_notes else "כל השינויים"
            unmatched_note = ""
            if result["unmatched"]:
                unmatched_note = f"\nדולגו {len(result['unmatched'])} משתמשים שלא נמצאו בדוח."
            self._show_info(
                "ייבוא הושלם",
                f"עודכנו {result['matched']} רשומות ({mode_label}).{unmatched_note}",
            )
            self._log(
                "ייבוא סקירת משתמשים מאקסל",
                period=self.period_var.get(),
                matched=result["matched"],
                unmatched=len(result["unmatched"]),
                mode=mode_label,
            )
        except Exception as error:
            self._log_error("שגיאה ביישום ייבוא סקירת משתמשים", error)
            self._show_error("שגיאת ייבוא", f"הייבוא נכשל.\n\n{error}")

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

        ipe_errors = self._missing_ipe_messages(required_slots)
        if ipe_errors:
            validation_errors.extend(ipe_errors)

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
            self._fit_user_type_tree_height()
            self._update_user_review_progress_summary()
            return

        summary = self.user_review_report["summary"]
        for key in ["total_users", "in_scope_users", "exception_users", "privileged_users"]:
            value = str(summary[key])
            self.review_summary_vars[key].set(value)
            self.review_summary_labels[key].setText(value)

        self.user_type_tree.setRowCount(0)
        for user_type, count in sorted(summary["type_distribution"].items()):
            self._set_table_row(self.user_type_tree, self.user_type_tree.rowCount(), [user_type, count])
        self._fit_user_type_tree_height()
        self._update_user_review_progress_summary()

    def _update_user_review_progress_summary(self):
        progress = compute_review_progress(getattr(self, "user_review_df", None))
        total = progress["total"]
        reviewed = progress["reviewed"]
        unreviewed = progress["unreviewed"]
        percent = progress["percent"]

        self.user_review_total_label.setText(f'סה"כ משתמשים בדוח: {total}')
        self.user_review_reviewed_label.setText(f"משתמשים שנסקרו: {reviewed}")
        self.user_review_unreviewed_label.setText(f"משתמשים שטרם נסקרו: {unreviewed}")
        self.user_review_progress_percent_label.setText(f"התקדמות השלמת סקירה: {percent}%")
        self.user_review_progress_bar.setMaximum(100)
        self.user_review_progress_bar.setValue(percent)
        self.user_review_progress_bar.setFormat(f"{percent}%")

    def _refresh_user_review_table(self):
        was_sorting = self.user_review_tree.isSortingEnabled()
        self.user_review_tree.setSortingEnabled(False)
        self.user_review_tree.setRowCount(0)
        if self.user_review_df.empty:
            self.user_review_visible_indices = []
            self.user_review_tree.setSortingEnabled(was_sorting)
            return

        filtered_df = self._get_user_review_filtered_df()
        self.user_review_visible_indices = list(filtered_df.index)

        for df_index, (_, row) in zip(self.user_review_visible_indices, filtered_df.iterrows()):
            background = None
            if row.get("has_exception") == "כן":
                background = QColor("#fde2e1")
            elif row.get("review_status") and row.get("review_status") != "טרם נסקר":
                background = QColor("#e8f4ea")
            if row.get("user_name") in self.user_review_dirty_rows:
                background = QColor("#fff3cd")

            values = [row.get(column_name, "") for column_name in self.user_review_columns]
            table_row = self.user_review_tree.rowCount()
            self.user_review_tree.insertRow(table_row)
            for column, (column_name, value) in enumerate(zip(self.user_review_columns, values)):
                display = "" if value is None else str(value)
                item = SortableTableWidgetItem(display)
                item.setTextAlignment(Qt.AlignCenter if column != 0 else Qt.AlignRight | Qt.AlignVCenter)
                item.setData(SortableTableWidgetItem.DF_INDEX_ROLE, int(df_index))
                item.setData(SortableTableWidgetItem.SORT_ROLE, self._user_review_sort_key(column_name, value))
                if background is not None:
                    item.setBackground(background)
                self.user_review_tree.setItem(table_row, column, item)

        self.user_review_tree.setSortingEnabled(was_sorting)

    def _user_review_sort_key(self, column_name, value):
        if value is None:
            return ""
        if column_name == "days_since_login":
            text = str(value).strip()
            if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
                return f"{int(text):010d}"
            return f"~{text}"
        return str(value)

    def _generate_user_review(self):
        is_valid, validation_message = self._validate_user_review_sources()
        if not is_valid:
            self._show_error("בדיקת תקינות נכשלה", validation_message)
            return

        try:
            review_date = self.review_date_widget.date().toPython()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            period = self._audit_period_id()
            existing_reviews = self.db.get_user_review_rows(period)
            config = self._current_config()
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=config,
                extract_dates=self.loaded_extract_dates,
                period_id=period,
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
            self._sync_user_review_completion_finding()
            self._show_info("הושלם", f"דוח הסקירה נבנה בהצלחה עבור {len(self.user_review_df)} משתמשים.")
        except Exception as error:
            self._log_error("שגיאה בבניית דוח סקירה", error)
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
        if row < 0:
            return None
        item = self.user_review_tree.item(row, 0)
        if item is None:
            return None
        df_index = item.data(SortableTableWidgetItem.DF_INDEX_ROLE)
        if df_index is None:
            if row >= len(self.user_review_visible_indices):
                return None
            return self.user_review_visible_indices[row]
        return int(df_index)

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
            self._log_error("שגיאה בייצוא דוח סקירה ל-Excel", error)
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
            self._log_error("שגיאה בייצוא דוח סקירה ל-PDF", error)
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
        self._refresh_selected_finding_detail()

    def _on_findings_header_clicked(self, section_index):
        if 0 <= section_index < len(self.findings_column_order):
            self._sort_by_column(self.findings_column_order[section_index])

    def _refresh_findings_table(self):
        self._rebuild_findings_master_detail()

    def _rebuild_findings_master_detail(self):
        filtered = self._get_filtered_findings()
        catalog = load_controls_catalog()
        self.findings_details_by_control = details_by_control(filtered)
        self.findings_summary_records = aggregate_findings_by_control(
            filtered,
            catalog,
            source_file_getter=self._get_source_file_name,
        )

        previous_control = self.selected_finding_control_id
        was_sorting = self.findings_summary_table.isSortingEnabled()
        self._suppress_findings_selection = True
        self.findings_summary_table.setSortingEnabled(False)
        self.findings_summary_table.setRowCount(0)

        for row_data in sorted_summary_rows(self.findings_summary_records):
            values = build_summary_row_values(row_data)
            table_row = self.findings_summary_table.rowCount()
            self.findings_summary_table.insertRow(table_row)
            control_id_value = str(row_data.get("control_id", ""))
            # Text cols 0-6, buttons at 7-8, remaining text at 9+
            for source_index, value in enumerate(values):
                target_col = source_index if source_index < 7 else source_index + 2
                item = SortableTableWidgetItem("" if value is None else str(value))
                item.setTextAlignment(Qt.AlignCenter if target_col != 0 else Qt.AlignRight | Qt.AlignVCenter)
                item.setData(SortableTableWidgetItem.DF_INDEX_ROLE, control_id_value)
                item.setData(SortableTableWidgetItem.SORT_ROLE, self._summary_sort_key(source_index, value))
                if target_col == 0:
                    item.setData(Qt.UserRole, control_id_value)
                    display_id = str(row_data.get("control_id_display") or "")
                    if display_id and display_id != control_id_value:
                        item.setToolTip(f"מזהה פנימי: {control_id_value}")
                risk = str(row_data.get("risk_level", ""))
                if risk == "High":
                    item.setBackground(QColor("#f8d7da"))
                elif risk == "Medium":
                    item.setBackground(QColor("#fff3cd"))
                self.findings_summary_table.setItem(table_row, target_col, item)

            wp_button = QPushButton("צור נייר עבודה")
            wp_button.setToolTip("ייצוא נייר עבודה לאקסל עבור הבקרה")
            wp_button.clicked.connect(
                lambda _checked=False, cid=control_id_value: self._export_control_working_paper(cid)
            )
            self.findings_summary_table.setCellWidget(table_row, 7, wp_button)

            has_findings = int(row_data.get("finding_records", 0) or 0) > 0
            email_button = QPushButton("שלח מייל")
            email_button.setToolTip("פתיחת טיוטת Outlook לגורמים הרלוונטיים לבקרה")
            email_button.setEnabled(has_findings)
            email_button.clicked.connect(
                lambda _checked=False, cid=control_id_value: self._send_control_finding_email(cid)
            )
            self.findings_summary_table.setCellWidget(table_row, 8, email_button)

        self.findings_summary_table.setSortingEnabled(was_sorting)
        if was_sorting:
            self.findings_summary_table.sortByColumn(
                self.findings_summary_finding_count_col,
                Qt.SortOrder.DescendingOrder,
            )
        self._suppress_findings_selection = False

        target_row = 0
        if previous_control:
            for row in range(self.findings_summary_table.rowCount()):
                item = self.findings_summary_table.item(row, 0)
                if item and str(item.data(Qt.UserRole) or item.text()) == previous_control:
                    target_row = row
                    break

        if self.findings_summary_table.rowCount() > 0:
            self.findings_summary_table.selectRow(target_row)
            self._refresh_selected_finding_detail()
        else:
            self.selected_finding_control_id = None
            self.displayed_findings = []
            self.findings_detail_table.setRowCount(0)

    def _summary_sort_key(self, column, value):
        text = "" if value is None else str(value).strip()
        if column in {4, 5, 6}:
            if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
                return f"{int(text):010d}"
        if column == 3:
            priority = {"High": "0", "Medium": "1", "Low": "2"}
            return priority.get(text, f"9{text}")
        return text

    def _get_selected_finding_control_id(self):
        row = self.findings_summary_table.currentRow()
        if row < 0:
            return None
        item = self.findings_summary_table.item(row, 0)
        if item is None:
            return None
        return str(item.data(Qt.UserRole) or item.text() or "").strip() or None

    def _refresh_selected_finding_detail(self):
        if self._suppress_findings_selection:
            return
        control_id = self._get_selected_finding_control_id()
        self.selected_finding_control_id = control_id
        detail_findings = list(self.findings_details_by_control.get(control_id, [])) if control_id else []
        # User-review control: detail shows only unreviewed users (not UAR/exception rows).
        detail_findings = detail_findings_for_control(control_id or "", detail_findings)
        detail_findings.sort(
            key=lambda finding: self._get_sort_key(finding, self.sort_column),
            reverse=self.sort_reverse,
        )
        self.displayed_findings = detail_findings

        was_sorting = self.findings_detail_table.isSortingEnabled()
        self.findings_detail_table.setSortingEnabled(False)
        self.findings_detail_table.setRowCount(0)
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
            table_row = self.findings_detail_table.rowCount()
            self.findings_detail_table.insertRow(table_row)
            for column, value in enumerate(values):
                item = SortableTableWidgetItem("" if value is None else str(value))
                item.setTextAlignment(Qt.AlignCenter if column != 0 else Qt.AlignRight | Qt.AlignVCenter)
                item.setData(SortableTableWidgetItem.DF_INDEX_ROLE, table_row)
                item.setData(
                    SortableTableWidgetItem.SORT_ROLE,
                    self._get_sort_key(finding, self.findings_column_order[column]),
                )
                if background is not None:
                    item.setBackground(background)
                if foreground is not None:
                    item.setForeground(foreground)
                self.findings_detail_table.setItem(table_row, column, item)
        self.findings_detail_table.setSortingEnabled(was_sorting)

    def _export_findings_to_excel(self):
        export_findings = self._get_filtered_findings()
        if not export_findings:
            self._show_warning("אין נתונים", "אין ממצאים לייצוא בטבלה הנוכחית.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self._get_save_file("ייצוא ממצאים", "Excel Workbook (*.xlsx)", f"Audit_Findings_{self.period_var.get()}_{timestamp}.xlsx")
        if not save_path:
            return
        try:
            export_rows = []
            catalog = load_controls_catalog()
            for finding in export_findings:
                ensure_finding_control_id(finding)
                control_id = getattr(finding, "control_id", None) or "-"
                export_rows.append(
                    {
                        "מזהה בקרה": display_control_id(control_id, catalog.get(control_id, {})),
                        "מזהה פנימי": control_id,
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
            self._log_error("שגיאה בייצוא ממצאים ל-Excel", error)
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את הממצאים ל-Excel.\n\n{error}")

    def _format_finding_detail_value(self, value):
        if value is None or value == "":
            return "-"
        return str(value)

    def _open_finding_details(self, _event=None):
        row = self.findings_detail_table.currentRow()
        if row < 0:
            return
        item = self.findings_detail_table.item(row, 0)
        if item is None:
            return
        stored = item.data(SortableTableWidgetItem.DF_INDEX_ROLE)
        if stored is None:
            if row >= len(self.displayed_findings):
                return
            finding = self.displayed_findings[row]
        else:
            index = int(stored)
            if index < 0 or index >= len(self.displayed_findings):
                return
            finding = self.displayed_findings[index]

        dialog = QDialog(self.window)
        dialog.setWindowTitle("פירוט ממצא")
        dialog.resize(700, 520)
        layout = QVBoxLayout(dialog)

        title = self._make_section_title(finding.title, word_wrap=True)
        layout.addWidget(title)

        form_box = QGroupBox("פרטי הממצא")
        form = QFormLayout(form_box)
        catalog = load_controls_catalog()
        finding_control_id = ensure_finding_control_id(finding)
        finding_display_id = display_control_id(finding_control_id, catalog.get(finding_control_id, {}))
        detail_rows = [
            ("מזהה בקרה", finding_display_id),
            ("מזהה פנימי", finding_control_id if finding_display_id != finding_control_id else None),
            ("קטגוריה", finding.category),
            ("רמת סיכון", finding.risk_level),
            ("סטטוס", finding.status),
            ("קובץ מקור", self._get_source_file_name(finding)),
            ("תאריך הפקה", getattr(finding, "extract_date", None)),
            ("סוג בדיקה", getattr(finding, "comparison_rule", None)),
            ("ערך בפועל", getattr(finding, "actual_value", None)),
            ("ערך מצופה", getattr(finding, "expected_value", None)),
        ]
        for label, value in detail_rows:
            if value is None:
                continue
            form.addRow(label, QLabel(self._format_finding_detail_value(value)))
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

    def _capture_control_populations(self, max_rows: int = 5000):
        catalog = load_controls_catalog()
        self.control_to_slot_key = {}
        self.control_to_slot_rows = {}
        for control_id in set(getattr(finding, "control_id", None) for finding in self.current_findings):
            if not control_id:
                continue
            slot_key = primary_slot_for_control(control_id, catalog)
            if not slot_key or slot_key not in self.loaded_dataframes:
                continue
            df = self.loaded_dataframes[slot_key]
            sample = df.head(max_rows) if len(df.index) > max_rows else df
            self.control_to_slot_key[control_id] = slot_key
            self.control_to_slot_rows[control_id] = sample.fillna("").astype(str).to_dict("records")

    def _ipe_entries_for_control(self, control_id: str) -> list[dict]:
        entries = []
        for slot_key, slot_entries in self.ipe_evidence_data.items():
            for entry in slot_entries:
                control_ids = entry.get("control_ids") or []
                if control_id in control_ids or control_id == "DB-SUPPLEMENTAL":
                    enriched = dict(entry)
                    enriched["slot_key"] = slot_key
                    entries.append(enriched)
        if entries:
            return entries
        # Fallback: primary slot evidence even if mapping empty
        slot_key = self.control_to_slot_key.get(control_id) or primary_slot_for_control(control_id)
        if slot_key:
            return list(self.ipe_evidence_data.get(slot_key, []))
        return []

    def _finding_to_detail_dict(self, finding) -> dict:
        return {
            "category": finding.category,
            "risk_level": finding.risk_level,
            "title": finding.title,
            "comparison_rule": getattr(finding, "comparison_rule", None),
            "actual_value": getattr(finding, "actual_value", None),
            "expected_value": getattr(finding, "expected_value", None),
            "status": finding.status,
            "source_file": self._get_source_file_name(finding),
            "source_slot": getattr(finding, "source_slot", None),
            "extract_date": getattr(finding, "extract_date", None),
            "description": finding.description,
            "user_name": getattr(finding, "actual_value", None),
        }

    # ------------------------------------------------------------------
    # טאב בקרות מפצות
    # ------------------------------------------------------------------

    def _build_compensating_controls_tab(self):
        layout = QVBoxLayout(self.compensating_controls_tab)

        header_layout = QHBoxLayout()
        title = self._make_section_title("בקרות מפצות – בקרות בסקופ עם ממצאים", word_wrap=True)
        refresh_btn = QPushButton("רענון רשימה")
        refresh_btn.clicked.connect(self._refresh_compensating_controls_table)
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        header_layout.addWidget(refresh_btn)
        layout.addLayout(header_layout)

        headers = ["מספר בקרה", "תיאור הסיכון", "תיאור הבקרה", "סיכום ממצאים", "תיעוד בקרה מפצה"]
        self.compensating_controls_table = QTableWidget()
        self.compensating_controls_table.setLayoutDirection(Qt.RightToLeft)
        self.compensating_controls_table.setColumnCount(len(headers))
        self.compensating_controls_table.setHorizontalHeaderLabels(headers)
        self.compensating_controls_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.compensating_controls_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.compensating_controls_table.setAlternatingRowColors(True)
        col_widths = DEFAULT_COMPENSATING_COLUMN_WIDTHS
        for col_idx, width in col_widths.items():
            self.compensating_controls_table.setColumnWidth(int(col_idx), width)
        hdr = self.compensating_controls_table.horizontalHeader()
        hdr.setStretchLastSection(True)
        self.compensating_controls_table.verticalHeader().setDefaultSectionSize(
            DEFAULT_COMPENSATING_ROW_HEIGHT
        )
        layout.addWidget(self.compensating_controls_table)

    def _refresh_compensating_controls_table(self):
        if self.compensating_controls_table is None:
            return
        catalog = load_controls_catalog()

        def get_meta(control_id: str) -> dict:
            entry = catalog.get(control_id, {})
            return {
                "risk_description": entry.get("risk_description", "-"),
                "description": entry.get("description", "-"),
                "control_id_ayalon": entry.get("control_id_ayalon", ""),
            }

        def is_in_scope(control_id: str) -> bool:
            return control_id in self.findings_summary_records

        rows = build_compensating_control_rows(
            summary_records=self.findings_summary_records,
            details_by_control=self.findings_details_by_control,
            compensating_state=self.compensating_controls_data,
            get_meta_cb=get_meta,
            is_in_scope_cb=is_in_scope,
        )
        table = self.compensating_controls_table
        table.setRowCount(0)
        for row_data in rows:
            row_idx = table.rowCount()
            table.insertRow(row_idx)
            control_id_val = str(row_data["control_id"])
            entry = catalog.get(control_id_val, {})
            display_id = display_control_id(control_id_val, entry)
            id_item = QTableWidgetItem(display_id)
            id_item.setData(Qt.UserRole, control_id_val)
            if display_id != control_id_val:
                id_item.setToolTip(f"מזהה פנימי: {control_id_val}")
            table.setItem(row_idx, 0, id_item)
            table.setItem(row_idx, 1, QTableWidgetItem(str(row_data["risk_description"])))
            table.setItem(row_idx, 2, QTableWidgetItem(str(row_data["description"])))
            table.setItem(row_idx, 3, QTableWidgetItem(str(row_data["findings_brief"])))

            attachment = row_data.get("attachment")
            cell_widget = QWidget()
            btn_layout = QHBoxLayout(cell_widget)
            btn_layout.setContentsMargins(2, 2, 2, 2)
            btn_layout.setSpacing(4)
            if attachment:
                fname = attachment.get("original_filename", "קובץ מצורף")
                lbl = QLabel(fname)
                lbl.setToolTip(str(attachment.get("stored_path", "")))
                remove_btn = QPushButton("הסר")
                remove_btn.setFixedWidth(54)
                remove_btn.clicked.connect(
                    lambda _checked=False, cid=control_id_val: self._remove_compensating_control(cid)
                )
                btn_layout.addWidget(remove_btn)
                btn_layout.addWidget(lbl)
            else:
                upload_btn = QPushButton("העלאת קובץ")
                upload_btn.clicked.connect(
                    lambda _checked=False, cid=control_id_val: self._upload_compensating_control(cid)
                )
                btn_layout.addWidget(upload_btn)
            btn_layout.addStretch(1)
            table.setCellWidget(row_idx, 4, cell_widget)

    def _upload_compensating_control(self, control_id: str):
        path_str, _ = QFileDialog.getOpenFileName(
            self.window, "בחר קובץ תיעוד", "", "כל הקבצים (*.*)"
        )
        if not path_str:
            return
        source = Path(path_str)
        try:
            self.compensating_controls_repository.attach_file(
                control_id, source, self.compensating_controls_data
            )
            self._refresh_compensating_controls_table()
            self._show_info("הצלחה", f"הקובץ {source.name} נשמר לבקרה {control_id}.")
        except Exception as err:
            self._show_error("שגיאת העלאה", str(err))

    def _remove_compensating_control(self, control_id: str):
        try:
            self.compensating_controls_repository.remove_file(
                control_id, self.compensating_controls_data
            )
            self._refresh_compensating_controls_table()
        except Exception as err:
            self._show_error("שגיאת הסרה", str(err))

    def _export_control_working_paper(self, control_id: str, silent_output_path: Path | None = None):
        if not control_id:
            return None
        catalog = load_controls_catalog()
        summary_record = self.findings_summary_records.get(control_id)
        if summary_record is None:
            if silent_output_path is None:
                self._show_warning("אין נתונים", "לא נמצאה שורת ריכוז עבור הבקרה שנבחרה.")
            return None

        catalog_entry = catalog.get(control_id, {})
        if silent_output_path is not None:
            save_path = Path(silent_output_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = safe_working_paper_filename(
                display_control_id(control_id, catalog_entry),
                timestamp,
            )
            save_path = self._get_save_file("שמירת נייר עבודה", "Excel Workbook (*.xlsx)", default_name)
            if not save_path:
                return None

        plog = get_process_logger()
        if plog is not None:
            plog.info("Working paper export start", f"control={control_id}")

        detail_findings = detail_findings_for_control(
            control_id,
            self.findings_details_by_control.get(control_id, []),
        )
        detail_rows = [self._finding_to_detail_dict(finding) for finding in detail_findings]
        raw_rows = list(self.control_to_slot_rows.get(control_id, []))
        if not raw_rows:
            self._capture_control_populations()
            raw_rows = list(self.control_to_slot_rows.get(control_id, []))
        note = None
        if not raw_rows:
            note = "לא נטענה אוכלוסייה גולמית לסלוט הראשי של הבקרה."

        try:
            _cc_entry = self.compensating_controls_data.get(control_id)
            final_path = write_control_working_paper(
                control_id=control_id,
                catalog_entry=catalog_entry,
                summary_record=summary_record,
                detail_rows=detail_rows,
                raw_population_rows=raw_rows,
                ipe_entries=self._ipe_entries_for_control(control_id),
                output_path=Path(save_path),
                raw_population_note=note,
                compensating_control_entry=_cc_entry,
            )
            if silent_output_path is None:
                self._show_info("הצלחה", f"נייר העבודה נשמר:\n{final_path}")
            if plog is not None:
                plog.info("Working paper export end", f"control={control_id}")
            self._log("יוצא נייר עבודה", control_id=control_id, path=str(final_path))
            return Path(final_path)
        except Exception as error:
            if plog is not None:
                plog.fail("Working paper export", f"control={control_id}", exc=error)
            self._log_error("שגיאה בייצוא נייר עבודה", error, control_id=control_id)
            if silent_output_path is None:
                self._show_error("שגיאת ייצוא", f"לא ניתן ליצור נייר עבודה.\n\n{error}")
            return None

    def _recipients_for_control(self, control_id: str) -> list[str]:
        catalog = load_controls_catalog()
        entry = catalog.get(control_id, {})
        recipients: list[str] = []
        if bool(entry.get("notify_technical", False)):
            email = self._get_owner_email("technical")
            if self._validate_email_address(email) and email not in recipients:
                recipients.append(email)
        if bool(entry.get("notify_business", False)):
            email = self._get_owner_email("business")
            if self._validate_email_address(email) and email not in recipients:
                recipients.append(email)
        return recipients

    def _send_control_finding_email(self, control_id: str) -> None:
        """Open an Outlook draft for one control to its configured technical/business owners."""
        if not control_id:
            return
        summary = self.findings_summary_records.get(control_id) or {}
        if int(summary.get("finding_records", 0) or 0) <= 0:
            self._show_warning("אין ממצאים", "לבקרה זו אין ממצאים לשליחה במייל.")
            return

        recipients = self._recipients_for_control(control_id)
        display_id = str(summary.get("control_id_display") or control_id)
        if not recipients:
            self._show_warning(
                "לא הוגדרו כתובות מייל",
                f"לבקרה {display_id} לא הוגדרו נמענים.\n"
                "סמן גורם טכנולוגי / עסקי בקטלוג הבקרות והגדר כתובות בהגדרות מערכת.",
            )
            return

        if not sys.platform.startswith("win"):
            self._show_warning("מערכת לא נתמכת", "יצירת טיוטת מייל נתמכת כרגע ב-Windows בלבד.")
            return

        wp_dir = PROJECT_ROOT / "data" / "output" / "working_papers"
        wp_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[\\/*?:\[\]&]", "_", display_id)
        auto_path = wp_dir / f"{safe_id}_working_paper.xlsx"
        wp_path = self._export_control_working_paper(control_id, silent_output_path=auto_path)
        if wp_path is None or not wp_path.exists():
            self._show_error("שגיאת ייצוא", "לא ניתן ליצור נייר עבודה לצירוף למייל.")
            return

        title = str(summary.get("title_he") or display_id)
        subject = f"ממצאי ביקורת SAP HANA DB ITGC — {display_id} — {title}"
        try:
            import win32com.client  # type: ignore

            outlook = win32com.client.Dispatch("Outlook.Application")
            mail = outlook.CreateItem(0)
            mail.To = "; ".join(recipients)
            mail.Subject = subject
            mail.HTMLBody = (
                "<div dir='rtl' style='text-align:right; font-family:Arial, sans-serif; font-size:12pt;'>"
                "<p>שלום,</p>"
                "<p>מצורף נייר עבודה לבקרה שנמצאו בה ממצאים:</p>"
                f"<p>&#8226; {display_id} — {title}</p>"
                "<p>בברכה</p>"
                "</div>"
            )
            mail.Attachments.Add(str(wp_path.resolve()))
            mail.Display()
            self._log(
                "נוצרה טיוטת מייל לממצאי בקרה",
                control_id=control_id,
                recipients="; ".join(recipients),
            )
            self._show_info(
                "טיוטת מייל נוצרה",
                f"נוצרה טיוטה עבור {display_id}\nנמענים: {', '.join(recipients)}",
            )
        except Exception as error:
            self._log_error("שגיאה ביצירת טיוטת מייל לממצא", error, control_id=control_id)
            self._show_error("שגיאת מייל", f"לא ניתן ליצור טיוטה.\n\n{error}")

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
        plog = get_process_logger()
        try:
            self.run_btn.setEnabled(False)
            if plog is not None:
                plog.info("Analysis start", f"period={self.period_var.get()}; slots={loaded_slots}")
            self._log("החל ניתוח ITGC", period=self.period_var.get(), loaded_slots=loaded_slots)
            config = self._current_config()
            findings, validator_warnings = run_audit_analysis(
                self.loaded_dataframes,
                config,
                whitelist=self.db.get_whitelist(),
                period_id=self.period_var.get(),
            )
            for warning in validator_warnings:
                self._log(warning, period=self.period_var.get())
            uar_findings = self._build_findings_from_user_review()
            if not uar_findings:
                # Keep prior UAR findings when the review report cannot be rebuilt this run.
                uar_findings = [
                    finding
                    for finding in (self.current_findings or [])
                    if (
                        str(getattr(finding, "control_id", "") or "") == "DB-AM-01_PLACEHOLDER"
                        or str(getattr(finding, "category", "") or "") == "User Review"
                        or str(getattr(finding, "comparison_rule", "") or "")
                        == REVIEW_COMPLETION_COMPARISON_RULE
                    )
                ]
            findings.extend(uar_findings)
            findings = self._attach_findings_source_metadata(findings)
            self.current_findings = findings
            self._capture_control_populations()
            self.summary_vars["total"].set(str(len(findings)))
            self.summary_vars["high"].set(str(sum(1 for finding in findings if getattr(finding, "risk_level", "") == "High")))
            self.summary_vars["status"].set("הושלם")
            self._update_filter_options()
            self._refresh_findings_table()
            self._refresh_compensating_controls_table()
            if plog is not None:
                plog.info("Analysis end", f"findings={len(findings)}")
            self._log("ניתוח ITGC הושלם", period=self.period_var.get(), findings_count=len(findings))
            self._show_info("הושלם", f"נמצאו {len(findings)} חריגות.")
        except Exception as e:
            if plog is not None:
                plog.fail("Analysis", f"period={self.period_var.get()}", exc=e)
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
        memory_snapshot = None
        prior_progress = {"reviewed": 0}
        if not getattr(self, "user_review_df", pd.DataFrame()).empty:
            memory_snapshot = self.user_review_df.copy()
            prior_progress = compute_review_progress(memory_snapshot)

        review_df = self._ensure_user_review_report_for_audit()
        if review_df is None or review_df.empty:
            return []

        post_progress = compute_review_progress(review_df)
        if (
            memory_snapshot is not None
            and prior_progress.get("reviewed", 0) > 0
            and post_progress.get("reviewed", 0) < prior_progress.get("reviewed", 0)
        ):
            review_df = memory_snapshot
            self.user_review_df = memory_snapshot.copy()
            if self.user_review_report is not None:
                self.user_review_report["dataframe"] = memory_snapshot.copy()

        findings = []
        period = self._audit_period_id()
        completion_finding = build_review_completion_finding(period, review_df)
        if completion_finding is not None:
            findings.append(completion_finding)
        # Detail / working paper for this control show only unreviewed users.
        findings.extend(build_unreviewed_user_findings(period, review_df))
        return findings

    def _audit_period_id(self) -> str:
        return str(self.period_var.get() or "").strip()

    def _sync_user_review_completion_finding(self):
        if not hasattr(self, "current_findings") or self.current_findings is None:
            return

        replace_rules = {REVIEW_COMPLETION_COMPARISON_RULE, UNREVIEWED_USER_COMPARISON_RULE}
        self.current_findings = [
            finding
            for finding in self.current_findings
            if getattr(finding, "comparison_rule", None) not in replace_rules
        ]
        review_df = getattr(self, "user_review_df", None)
        period = self._audit_period_id()
        completion_finding = build_review_completion_finding(period, review_df)
        if completion_finding is not None:
            self.current_findings.append(completion_finding)
        self.current_findings.extend(build_unreviewed_user_findings(period, review_df))
        if hasattr(self, "tree"):
            self._refresh_findings_table()

    @staticmethod
    def _is_review_completion_summary_finding(finding) -> bool:
        return getattr(finding, "comparison_rule", None) == REVIEW_COMPLETION_COMPARISON_RULE

    def _ensure_user_review_report_for_audit(self):
        period = self._audit_period_id()
        metadata_period = ""
        if self.user_review_report is not None:
            metadata_period = str(self.user_review_report.get("metadata", {}).get("period_id", "")).strip()
        df_periods = set()
        if not getattr(self, "user_review_df", pd.DataFrame()).empty and "period_id" in self.user_review_df.columns:
            df_periods = {
                str(value).strip()
                for value in self.user_review_df["period_id"].dropna().unique()
            }
        if not self.user_review_df.empty:
            if metadata_period == period or period in df_periods:
                return self.user_review_df

        required_slots = ["USERS", "GRANTED_PRIVILEGES"]
        if not all(slot in self.loaded_dataframes for slot in required_slots):
            return None

        try:
            review_date = self.review_date_widget.date().toPython()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            existing_reviews = self.db.get_user_review_rows(period)
            existing_reviews = merge_existing_review_decisions(
                existing_reviews,
                getattr(self, "user_review_df", None),
                period,
            )
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=self._current_config(),
                extract_dates=self.loaded_extract_dates,
                period_id=period,
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
        self.settings_widgets["technical_owner_email"].setText(str(config.get("technical_owner_email", "") or ""))
        self.settings_widgets["business_owner_email"].setText(str(config.get("business_owner_email", "") or ""))

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
            "technical_owner_email": self.settings_widgets["technical_owner_email"].text().strip(),
            "business_owner_email": self.settings_widgets["business_owner_email"].text().strip(),
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
            config = dict(self._current_config())
            config.update(self._collect_settings_from_form())
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.settings_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, ensure_ascii=False, indent=4)
            if self.importer is not None:
                self.importer.config = config
            self._update_review_period_info_label()
            self._refresh_controls_catalog_table()
            self._show_info("הצלחה", "ההגדרות עודכנו.")
        except Exception as e:
            self._log_error("שגיאה בשמירת הגדרות", e, settings_path=str(self.settings_path))
            self._show_error("שגיאת הגדרות", str(e))

    def _get_owner_email(self, owner_kind: str) -> str:
        key = "technical_owner_email" if owner_kind == "technical" else "business_owner_email"
        widget = self.settings_widgets.get(key)
        if widget is not None:
            return widget.text().strip()
        return str(self._current_config().get(key, "") or "").strip()

    @staticmethod
    def _validate_email_address(email_value: str) -> bool:
        normalized = email_value.strip()
        return bool(normalized and "@" in normalized and "." in normalized.split("@")[-1])

    def _draft_user_review_email_to_technical(self):
        self._create_outlook_user_review_draft(
            recipient_email=self._get_owner_email("technical"),
            role_label="גורם טכנולוגי",
        )

    def _draft_user_review_email_to_business(self):
        self._create_outlook_user_review_draft(
            recipient_email=self._get_owner_email("business"),
            role_label="גורם עסקי",
        )

    def _create_outlook_user_review_draft(self, recipient_email: str, role_label: str) -> None:
        if not self._validate_email_address(recipient_email):
            self._show_warning(
                "מייל לא מוגדר",
                f"לא הוגדרה כתובת מייל תקינה עבור {role_label} במסך הגדרות מערכת.",
            )
            return
        if self.user_review_report is None or self.user_review_df.empty:
            self._show_warning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return
        if not sys.platform.startswith("win"):
            self._show_warning("מערכת לא נתמכת", "יצירת טיוטת מייל נתמכת כרגע ב-Windows בלבד.")
            return

        output_dir = PROJECT_ROOT / "data" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_role = re.sub(r"[^\w\-]+", "_", role_label, flags=re.UNICODE)
        export_path = output_dir / f"User_Review_{safe_role}_{timestamp}.xlsx"
        try:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            export_user_review_to_excel(self.user_review_report, str(export_path))
        except Exception as error:
            self._show_error("שגיאת ייצוא", f"לא ניתן לייצא את דוח הסקירה לצירוף למייל.\n\n{error}")
            return

        try:
            import win32com.client  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            install_command = f'"{sys.executable}" -m pip install pywin32'
            self._show_warning(
                "רכיב חסר ל-Outlook",
                "לא ניתן ליצור טיוטת Outlook כי חסרה חבילת pywin32.\n\n"
                f"יש להריץ פעם אחת בסביבת העבודה:\n{install_command}",
            )
            return
        except Exception as error:
            self._show_warning("Outlook לא זמין", f"לא ניתן לטעון Outlook COM ליצירת טיוטה:\n{error}")
            return

        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            mail_item = outlook.CreateItem(0)
            mail_item.To = recipient_email
            mail_item.Subject = f"סקירת דוח משתמשים - {datetime.now().strftime('%Y-%m-%d')}"
            mail_item.HTMLBody = (
                "<div dir='rtl' style='text-align:right; font-family:Arial, sans-serif; font-size:12pt;'>"
                "<p>שלום,</p>"
                "<p>מצורף דוח סקירת משתמשים עדכני מתוך המערכת.</p>"
                "<p>נא לעבור על הממצאים ולעדכן סטטוס/הערות בהתאם.</p>"
                "<p>בברכה,<br>מערכת בקרות ITGC</p>"
                "</div>"
            )
            mail_item.Attachments.Add(str(export_path))
            mail_item.Display(False)
        except Exception as error:
            self._show_warning("שגיאת מייל", f"יצירת טיוטת מייל נכשלה:\n{error}")
            return

        self._show_info(
            "טיוטת מייל נוצרה",
            f"נוצרה טיוטה ל-{role_label} עם קובץ מצורף:\n{export_path}",
        )

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
        log_dir = PROJECT_ROOT / "data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
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

    @staticmethod
    def _format_log_result(**context) -> str:
        parts = []
        for key, value in sorted(context.items()):
            if value is None:
                continue
            parts.append(f"{key}={value}")
        summary = "; ".join(parts)
        if len(summary) <= 240:
            return summary
        return summary[:237] + "..."

    def _log(self, msg, **context):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        plog = get_process_logger()
        if plog is not None:
            step = str(msg) if len(str(msg)) <= 120 else str(msg)[:117] + "..."
            plog.info(step, self._format_log_result(**context))

    def _log_error(self, msg, error=None, **context):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {msg} | {error}")
        plog = get_process_logger()
        if plog is not None:
            result_parts = [self._format_log_result(**context)]
            if error is not None:
                result_parts.append(f"{type(error).__name__}: {error}")
            result = " | ".join(p for p in result_parts if p)
            if len(result) > 240:
                result = result[:237] + "..."
            step = str(msg) if len(str(msg)) <= 120 else str(msg)[:117] + "..."
            plog.fail(step, result, exc=error if isinstance(error, BaseException) else None)


def launch():
    setup_process_logging(PROJECT_ROOT, triggered_by="Desktop UI")
    install_excepthook()
    register_atexit_close()
    gui = AuditGUI()
    gui.show()
    try:
        return gui.app.exec()
    finally:
        close_active_run(None)


if __name__ == "__main__":
    raise SystemExit(launch())
