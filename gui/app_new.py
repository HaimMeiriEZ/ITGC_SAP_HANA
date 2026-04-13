import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import re
import sys
import json
import copy
from pathlib import Path
from datetime import datetime
import pandas as pd
from tkcalendar import DateEntry

# הגדרת נתיב השורש בצורה בטוחה
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR if (BASE_DIR / "core").exists() else BASE_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from DataClasses import Finding
    from DatabaseManager import DatabaseManager
    from core.importer import DataImporter
    from core.analyzer import AuditAnalyzer
    from core.user_review import build_user_review_report, export_user_review_to_excel, export_user_review_to_pdf
except ImportError as e:
    print(f"שגיאת ייבוא: וודא שכל הקבצים נמצאים בנתיב הנכון. פירוט: {e}")

class AuditGUI:
    DEFAULT_SETTINGS = {
        "critical_users": ["SYSTEM", "SAPHANADB", "SYS", "_SYS_REPO", "XSSQLCC_AUTO_USER"],
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
            "AUDIT_POLICIES": "audit_policies.csv",
        },
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

    def __init__(self, root):
        self.root = root
        self.root.title("מערכת ביקורת SAP HANA ITGC - מבוססת IPE")
        self.root.geometry("1150x900")
        self.root.minsize(1050, 800)
        self.root.configure(bg="#f8f9fa")

        # נכסי נתונים
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
        self.risk_filter_var = tk.StringVar(value="הכל")
        self.category_filter_var = tk.StringVar(value="הכל")
        self.source_filter_var = tk.StringVar(value="הכל")
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
            "AUDIT_POLICIES": {
                "label": "מדיניות ניטור (טבלת AUDIT_POLICIES)",
                "required": ["AUDIT_POLICY_NAME", "IS_AUDIT_POLICY_ACTIVE"],
                "required_any": [],
            },
        }
        
        # אתחול רכיבים
        self.settings_path = PROJECT_ROOT / "config" / "settings.json"
        try:
            self.db = DatabaseManager()
            self.importer = DataImporter(config_path=str(self.settings_path))
        except Exception as e:
            print(f"Error: {e}")

        # משתני ממשק
        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "high": tk.StringVar(value="0"),
            "status": tk.StringVar(value="ממתין לנתונים"),
        }
        self.period_var = tk.StringVar(value=f"{datetime.now().year}-Q{(datetime.now().month-1)//3 + 1}")
        self.review_summary_vars = {
            "total_users": tk.StringVar(value="0"),
            "in_scope_users": tk.StringVar(value="0"),
            "exception_users": tk.StringVar(value="0"),
            "privileged_users": tk.StringVar(value="0"),
        }
        self.show_only_exceptions_var = tk.BooleanVar(value=False)
        self.show_only_unreviewed_var = tk.BooleanVar(value=False)
        self.show_only_privileged_var = tk.BooleanVar(value=False)
        self.show_only_active_in_period_var = tk.BooleanVar(value=False)

        self._setup_ui()

    def _setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("SectionHeader.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("FieldLabel.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", font=("Segoe UI", 9), foreground="#5f6b7a")
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab 1: Settings
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text=" הגדרות מערכת ")
        self._build_settings_tab()

        # Tab 2: IPE Load
        self.import_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.import_tab, text=" טעינת נתונים (IPE) ")
        self._build_import_tab()

        # Tab 3: User Review Report
        self.user_review_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.user_review_tab, text=" דוח סקירת משתמשים ")
        self._build_user_review_tab()

        # Tab 4: Audit & Results
        self.audit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.audit_tab, text=" ניתוח וממצאים ")
        self._build_audit_tab()

    def _rtl_hebrew_only(self, text):
        raw_text = "" if text is None else str(text)
        if re.search(r"[A-Za-z]", raw_text):
            return raw_text
        return f"\u200f{raw_text}\u200f"



    def _build_import_tab(self):
        container = ttk.Frame(self.import_tab, padding="20")
        container.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(container)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="ניהול מקורות מידע ומהימנות נתונים (IPE)", font=("Segoe UI", 16, "bold")).pack(side=tk.RIGHT)
        self.export_ipe_btn = ttk.Button(header_frame, text="ייצוא לוג IPE ל-Excel 📥", command=self._export_ipe_log)
        self.export_ipe_btn.pack(side=tk.LEFT)

        slots = [
            ("USERS", "משתמשים (טבלת USERS)", "רשימת משתמשים ותאריכי התחברות אחרונים"),
            ("M_PASSWORD_POLICY", "מדיניות סיסמאות (טבלת M_PASSWORD_POLICY)", "פרמטרים והגדרות אבטחת סיסמה"),
            ("GRANTED_PRIVILEGES", "הרשאות (טבלת GRANTED_PRIVILEGES)", "מיפוי הרשאות מערכת למשתמשים"),
            ("AUDIT_POLICIES", "מדיניות ניטור (טבלת AUDIT_POLICIES)", "הגדרות לוגים ובקרות ניטור מערכתיות"),
        ]

        self.slot_status_vars = {}
        self.slot_delete_btns = {}

        for slot_key, label, desc in slots:
            frame = ttk.LabelFrame(container, text=f" {label} ", padding="10")
            frame.pack(fill=tk.X, pady=5)
            
            # תיאור וסטטוס
            status_var = tk.StringVar(value="ממתין לטעינה...")
            self.slot_status_vars[slot_key] = status_var
            extract_date_var = tk.StringVar(value=self._get_today_date())
            self.slot_extract_date_vars[slot_key] = extract_date_var
            
            ttk.Label(frame, text=desc, font=("Segoe UI", 9, "italic")).pack(side=tk.RIGHT, padx=10)
            ttk.Label(frame, textvariable=status_var, foreground="#7f8c8d", width=35, anchor="e").pack(side=tk.RIGHT, padx=10)

            date_frame = ttk.Frame(frame)
            date_frame.pack(side=tk.LEFT, padx=8)
            date_entry = DateEntry(
                date_frame,
                textvariable=extract_date_var,
                width=12,
                justify="center",
                date_pattern="yyyy-mm-dd",
            )
            date_entry.set_date(datetime.now().date())
            date_entry.pack(side=tk.LEFT)
            date_entry.bind("<FocusOut>", lambda _event, sk=slot_key: self._normalize_extract_date(sk, show_message=True))
            self.slot_extract_date_widgets[slot_key] = date_entry
            ttk.Label(date_frame, text="תאריך הפקה:").pack(side=tk.LEFT, padx=(0, 6))
            
            # כפתור טעינה
            ttk.Button(frame, text="בחר קובץ...", command=lambda sk=slot_key: self._load_file(sk)).pack(side=tk.LEFT, padx=2)
            
            # כפתור מחיקה
            del_btn = ttk.Button(frame, text="🗑️ מחיקה", state=tk.DISABLED, command=lambda sk=slot_key: self._delete_file(sk))
            del_btn.pack(side=tk.LEFT, padx=2)
            self.slot_delete_btns[slot_key] = del_btn

        ipe_frame = ttk.LabelFrame(container, text=" תיעוד דגימות (IPE Artifacts) ", padding="10")
        ipe_frame.pack(fill=tk.BOTH, expand=True, pady=15)
        cols = ("table", "filename", "extract_date", "rows", "time")
        self.ipe_tree = ttk.Treeview(ipe_frame, columns=cols, show="headings", height=6)
        for col, head in zip(cols, ["סלוט", "שם קובץ", "תאריך הפקה", "שורות", "זמן טעינה"]):
            self.ipe_tree.heading(col, text=head)
        self.ipe_tree.pack(fill=tk.BOTH, expand=True)

    def _get_today_date(self):
        return datetime.now().strftime("%Y-%m-%d")

    def _parse_extract_date(self, raw_value):
        normalized_value = raw_value.strip()
        if not normalized_value:
            raise ValueError("יש להזין תאריך הפקה בפורמט YYYY-MM-DD.")
        return datetime.strptime(normalized_value, "%Y-%m-%d").date().isoformat()

    def _normalize_extract_date(self, slot_key, show_message=False):
        try:
            normalized_value = self.slot_extract_date_widgets[slot_key].get_date().isoformat()
            self.slot_extract_date_vars[slot_key].set(normalized_value)
            return normalized_value
        except (ValueError, tk.TclError):
            if show_message:
                messagebox.showerror(
                    "תאריך הפקה לא תקין",
                    "יש להזין תאריך תקין בפורמט YYYY-MM-DD, לדוגמה 2026-04-09.",
                )
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

        df.columns = [str(col).strip().upper().replace('"', '') for col in df.columns]
        df = df.map(lambda value: value.strip().replace('"', '') if isinstance(value, str) else value)
        return df

    def _validate_loaded_dataframe(self, slot_key, df):
        metadata = self.slot_metadata[slot_key]
        missing_columns = [column for column in metadata["required"] if column not in df.columns]
        alternative_groups = []

        for group in metadata["required_any"]:
            if not any(column in df.columns for column in group):
                alternative_groups.append(group)

        return missing_columns, alternative_groups

    def _format_validation_message(self, slot_key, file_name, missing_columns, alternative_groups):
        metadata = self.slot_metadata[slot_key]
        details = []

        if missing_columns:
            details.append("עמודות חובה חסרות: " + ", ".join(missing_columns))

        for group in alternative_groups:
            details.append("נדרשת לפחות אחת מהעמודות: " + " / ".join(group))

        details_text = "\n".join(details)
        return (
            f"הקובץ '{file_name}' שויך לסלוט {metadata['label']}, אך מבנה העמודות שלו אינו תקין.\n\n"
            f"פירוט:\n{details_text}\n\n"
            "בדוק שהקובץ שיוצא מ-SAP HANA תואם לטבלה הנכונה וששורת הכותרות לא שונתה."
        )

    def _validate_all_sources_before_analysis(self):
        required_slots = ["USERS", "M_PASSWORD_POLICY", "GRANTED_PRIVILEGES", "AUDIT_POLICIES"]
        missing_slots = [slot_key for slot_key in required_slots if slot_key not in self.loaded_dataframes]
        if missing_slots:
            slot_labels = [self.slot_metadata[slot_key]["label"] for slot_key in missing_slots]
            return (
                False,
                "לא ניתן להריץ ניתוח לפני שכל ארבעת מקורות החובה נטענו.\n\n"
                + "מקורות חסרים:\n- "
                + "\n- ".join(slot_labels)
            )

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

        file_path = filedialog.askopenfilename(filetypes=[("Data files", "*.csv *.txt")])
        if not file_path:
            return

        filename = os.path.basename(file_path)

        try:
            df = self._read_source_file(file_path)
            missing_columns, alternative_groups = self._validate_loaded_dataframe(slot_key, df)
            if missing_columns or alternative_groups:
                raise ValueError(self._format_validation_message(slot_key, filename, missing_columns, alternative_groups))

            self.loaded_dataframes[slot_key] = df
            self.loaded_files[slot_key] = filename
            self.loaded_extract_dates[slot_key] = extract_date

            # Backward compatibility: analyzer still expects EFFECTIVE_PRIVILEGE_GRANTEES.
            if slot_key == "GRANTED_PRIVILEGES":
                self.loaded_dataframes["EFFECTIVE_PRIVILEGE_GRANTEES"] = df
                self.loaded_files["EFFECTIVE_PRIVILEGE_GRANTEES"] = filename
                self.loaded_extract_dates["EFFECTIVE_PRIVILEGE_GRANTEES"] = extract_date
            
            rows = len(df)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            self.ipe_records.append({
                "סלוט במערכת": slot_key, "שם קובץ מקורי": filename,
                "תאריך הפקה": extract_date, "כמות רשומות": rows, "זמן טעינה": timestamp, "נתיב מלא": file_path
            })
            self.db.save_ipe_load(slot_key, filename, extract_date, rows, file_path)
            
            self.slot_status_vars[slot_key].set(f"✅ נטען: {filename}")
            self.slot_delete_btns[slot_key].config(state=tk.NORMAL)
            self.ipe_tree.insert("", tk.END, values=(slot_key, filename, extract_date, rows, timestamp))
            self.db.log_activity("IPE Load", f"Slot: {slot_key}, File: {filename}, Extract Date: {extract_date}, Rows: {rows}", "User")
            
        except Exception as e:
            self.loaded_dataframes.pop(slot_key, None)
            self.loaded_files.pop(slot_key, None)
            self.loaded_extract_dates.pop(slot_key, None)
            self.slot_status_vars[slot_key].set(f"❌ שגיאה בטעינת: {filename}")
            self.slot_delete_btns[slot_key].config(state=tk.DISABLED)
            messagebox.showerror(
                "שגיאת טעינה",
                f"לא ניתן לטעון את הקובץ '{filename}' לסלוט {self.slot_metadata[slot_key]['label']}.\n\nסיבה:\n{str(e)}",
            )

    def _delete_file(self, slot_key):
        """מחיקת הנתונים הטעונים מהסלוט הספציפי"""
        if slot_key in self.loaded_dataframes:
            filename = self.slot_status_vars[slot_key].get().replace("✅ נטען: ", "")
            del self.loaded_dataframes[slot_key]
            self.loaded_files.pop(slot_key, None)
            self.loaded_extract_dates.pop(slot_key, None)

            if slot_key == "GRANTED_PRIVILEGES":
                self.loaded_dataframes.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
                self.loaded_files.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
                self.loaded_extract_dates.pop("EFFECTIVE_PRIVILEGE_GRANTEES", None)
            
            # עדכון ממשק
            self.slot_status_vars[slot_key].set("ממתין לטעינה...")
            self.slot_delete_btns[slot_key].config(state=tk.DISABLED)
            
            # רישום מחיקה בלוג (לצורך שקיפות IPE)
            self.db.log_activity("IPE Clear", f"Cleared data slot: {slot_key} (Previous file: {filename})", "User")
            self._log(f"הנתונים בסלוט {slot_key} נמחקו מהזיכרון.")
            
            # הערה: אנחנו לא מוחקים מה-IPE Tree כי הוא מייצג היסטוריית פעולות (Audit Trail)
            # אבל הנתונים לא ייכללו בניתוח הבא.

    def _export_ipe_log(self):
        if not self.ipe_records:
            messagebox.showwarning("אין נתונים", "טרם נטענו קבצים למערכת.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            initialfile=f"IPE_Log_{self.period_var.get()}_{timestamp}.xlsx",
        )
        if save_path:
            try:
                pd.DataFrame(self.ipe_records).to_excel(save_path, index=False)
                messagebox.showinfo("הצלחה", "דוח IPE יוצא בהצלחה.")
            except Exception as e:
                messagebox.showerror("שגיאה", f"כשל בייצוא: {e}")

    def _build_user_review_tab(self):
        container = ttk.Frame(self.user_review_tab, padding="20")
        container.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(container)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(header_frame, text="דוח סקירת משתמשים למנהלים", font=("Segoe UI", 16, "bold")).pack(side=tk.RIGHT)

        self.review_date_var = tk.StringVar(value=self._get_today_date())
        self.export_review_pdf_btn = ttk.Button(header_frame, text="ייצוא ל-PDF", command=self._export_user_review_pdf)
        self.export_review_pdf_btn.pack(side=tk.LEFT, padx=6)
        self.export_review_excel_btn = ttk.Button(header_frame, text="ייצוא לאקסל", command=self._export_user_review_excel)
        self.export_review_excel_btn.pack(side=tk.LEFT, padx=6)
        self.save_review_btn = ttk.Button(header_frame, text="שמור כל השינויים", command=self._save_all_user_review_changes)
        self.save_review_btn.pack(side=tk.LEFT, padx=6)
        self.edit_review_btn = ttk.Button(header_frame, text="עדכן החלטת מנהל", command=self._open_user_review_editor)
        self.edit_review_btn.pack(side=tk.LEFT, padx=6)
        self.generate_review_btn = ttk.Button(header_frame, text="בנה דוח סקירה", command=self._generate_user_review)
        self.generate_review_btn.pack(side=tk.LEFT, padx=6)
        self.review_date_widget = DateEntry(header_frame, textvariable=self.review_date_var, width=12, justify="center", date_pattern="yyyy-mm-dd")
        self.review_date_widget.set_date(datetime.now().date())
        self.review_date_widget.pack(side=tk.LEFT, padx=6)
        ttk.Label(header_frame, text="תאריך סקירה:").pack(side=tk.LEFT)

        self.review_period_info_var = tk.StringVar(value="טווח בחינה: -")
        ttk.Label(container, textvariable=self.review_period_info_var, style="Hint.TLabel").pack(anchor="e", pady=(0, 8))
        self._update_review_period_info_label()

        filter_frame = ttk.Frame(container)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Checkbutton(
            filter_frame,
            text="רק חריגים",
            variable=self.show_only_exceptions_var,
            command=self._refresh_user_review_table,
        ).pack(side=tk.RIGHT)
        ttk.Checkbutton(
            filter_frame,
            text="רק לא נסקרו",
            variable=self.show_only_unreviewed_var,
            command=self._refresh_user_review_table,
        ).pack(side=tk.RIGHT, padx=(0, 10))
        ttk.Checkbutton(
            filter_frame,
            text="רק בעלי הרשאות קריטיות",
            variable=self.show_only_privileged_var,
            command=self._refresh_user_review_table,
        ).pack(side=tk.RIGHT, padx=(0, 10))
        ttk.Checkbutton(
            filter_frame,
            text="רק פעילים בתקופת הביקורת",
            variable=self.show_only_active_in_period_var,
            command=self._refresh_user_review_table,
        ).pack(side=tk.RIGHT, padx=(0, 10))

        info_frame = ttk.LabelFrame(container, text=" מטא-דאטה ותקציר ", padding="12")
        info_frame.pack(fill=tk.X, pady=(0, 12))
        info_frame.columnconfigure(0, weight=1)
        summary_text = ttk.Frame(info_frame)
        summary_text.grid(row=0, column=0, sticky="ew")
        summary_items = [
            ("סה\"כ משתמשים", "total_users"),
            ("באוכלוסיית הסקירה", "in_scope_users"),
            ("חריגים", "exception_users"),
            ("משתמשים עם הרשאות קריטיות", "privileged_users"),
        ]
        for column_index, (label_text, key) in enumerate(summary_items):
            cell = ttk.Frame(summary_text)
            cell.grid(row=0, column=column_index, padx=12, sticky="w")
            ttk.Label(cell, text=label_text, style="FieldLabel.TLabel").pack(anchor="center")
            ttk.Label(cell, textvariable=self.review_summary_vars[key], font=("Segoe UI", 14, "bold")).pack(anchor="center")

        distribution_frame = ttk.Frame(info_frame)
        distribution_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(distribution_frame, text="חלוקה לפי סוגי משתמשים", style="FieldLabel.TLabel").pack(anchor="e")
        self.user_type_tree = ttk.Treeview(distribution_frame, columns=("user_type", "count"), show="headings", height=4)
        self.user_type_tree.heading("user_type", text="סוג משתמש")
        self.user_type_tree.heading("count", text="כמות")
        self.user_type_tree.column("user_type", width=220, anchor="e")
        self.user_type_tree.column("count", width=120, anchor="center")
        self.user_type_tree.pack(fill=tk.X, pady=(6, 0))

        report_frame = ttk.LabelFrame(container, text=" רשימת משתמשים לסקירה ", padding="10")
        report_frame.pack(fill=tk.BOTH, expand=True)
        columns = (
            "user_name", "in_scope", "active_status", "active_in_period", "last_login", "days_since_login", "user_type",
            "password_policy_exempt_status", "password_policy_exempt_reason", "system_table_access_status", "critical_privileges", "has_exception", "exception_reason", "review_status", "manager_decision",
            "action_required", "manager_comments"
        )
        headers = [
            "שם משתמש", "באוכלוסייה", "סטטוס", "פעיל בתקופה", "התחברות אחרונה", "ימים מאז התחברות", "סוג משתמש",
            "החרגת סיסמה", "סיבת החרגה", "גישה לטבלאות מערכת", "הרשאות קריטיות", "חריג", "סיבת חריג", "סטטוס סקירה", "החלטת מנהל", "נדרש להסרה / מאושר להשאיר", "הערות"
        ]
        self.user_review_tree = ttk.Treeview(report_frame, columns=columns, show="headings")
        for column_name, heading in zip(columns, headers):
            self.user_review_tree.heading(column_name, text=heading)
        self.user_review_tree.column("user_name", width=140, anchor="e")
        self.user_review_tree.column("in_scope", width=85, anchor="center")
        self.user_review_tree.column("active_status", width=160, anchor="e")
        self.user_review_tree.column("active_in_period", width=95, anchor="center")
        self.user_review_tree.column("last_login", width=110, anchor="center")
        self.user_review_tree.column("days_since_login", width=120, anchor="center")
        self.user_review_tree.column("user_type", width=110, anchor="center")
        self.user_review_tree.column("password_policy_exempt_status", width=110, anchor="center")
        self.user_review_tree.column("password_policy_exempt_reason", width=200, anchor="e")
        self.user_review_tree.column("system_table_access_status", width=150, anchor="center")
        self.user_review_tree.column("critical_privileges", width=220, anchor="e")
        self.user_review_tree.column("has_exception", width=70, anchor="center")
        self.user_review_tree.column("exception_reason", width=260, anchor="e")
        self.user_review_tree.column("review_status", width=110, anchor="center")
        self.user_review_tree.column("manager_decision", width=110, anchor="center")
        self.user_review_tree.column("action_required", width=170, anchor="center")
        self.user_review_tree.column("manager_comments", width=220, anchor="e")
        self.user_review_tree.tag_configure("Exception", background="#fde2e1")
        self.user_review_tree.tag_configure("Reviewed", background="#e8f4ea")
        self.user_review_tree.tag_configure("Dirty", foreground="#8a4b08", font=("Segoe UI", 9, "bold"))
        self.user_review_tree.bind("<Double-1>", self._begin_inline_user_review_edit)
        self.user_review_tree.bind("<<TreeviewSelect>>", self._handle_user_review_selection)

        scroll_y = ttk.Scrollbar(report_frame, orient=tk.VERTICAL, command=self.user_review_tree.yview)
        scroll_x = ttk.Scrollbar(report_frame, orient=tk.HORIZONTAL, command=self.user_review_tree.xview)
        self.user_review_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.user_review_tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        report_frame.rowconfigure(0, weight=1)
        report_frame.columnconfigure(0, weight=1)

    def _handle_user_review_selection(self, _event=None):
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

    def _begin_inline_user_review_edit(self, event):
        if self.user_review_df.empty:
            return

        row_id = self.user_review_tree.identify_row(event.y)
        column_id = self.user_review_tree.identify_column(event.x)
        if not row_id or not column_id:
            return

        column_index = int(column_id.replace("#", "")) - 1
        column_name = self.user_review_tree["columns"][column_index]
        editable_columns = {
            "has_exception": ["כן", "לא"],
            "exception_reason": None,
            "review_status": ["טרם נסקר", "נסקר", "דורש מעקב"],
            "manager_decision": ["", "מאושר", "לא מאושר", "נדרש בירור"],
            "action_required": ["", "נדרש להסרה", "מאושר להשאיר"],
            "manager_comments": None,
        }
        if column_name not in editable_columns:
            self._open_user_review_editor()
            return

        if self.user_review_inline_editor is not None:
            self._commit_inline_user_review_edit()

        try:
            row_index = int(row_id)
        except ValueError:
            return

        bbox = self.user_review_tree.bbox(row_id, column_id)
        if not bbox:
            return

        x, y, width, height = bbox
        current_value = self.user_review_df.iloc[row_index].get(column_name, "")
        editor_parent = self.user_review_tree

        if editable_columns[column_name] is None:
            editor = ttk.Entry(editor_parent, justify="right")
            if current_value == "-":
                current_value = ""
            editor.insert(0, str(current_value))
        else:
            editor = ttk.Combobox(editor_parent, values=editable_columns[column_name], state="readonly", justify="right")
            editor.set(str(current_value))

        editor.place(x=x, y=y, width=width, height=height)
        editor.focus_set()
        editor.bind("<Return>", lambda _event: self._commit_inline_user_review_edit())
        editor.bind("<Escape>", lambda _event: self._cancel_inline_user_review_edit())
        editor.bind("<FocusOut>", lambda _event: self._commit_inline_user_review_edit())
        self.user_review_inline_editor = {
            "widget": editor,
            "row_index": row_index,
            "column_name": column_name,
        }

    def _cancel_inline_user_review_edit(self):
        if self.user_review_inline_editor is None:
            return
        self.user_review_inline_editor["widget"].destroy()
        self.user_review_inline_editor = None

    def _commit_inline_user_review_edit(self):
        if self.user_review_inline_editor is None:
            return

        editor_details = self.user_review_inline_editor
        widget = editor_details["widget"]
        row_index = editor_details["row_index"]
        column_name = editor_details["column_name"]
        new_value = widget.get().strip()
        widget.destroy()
        self.user_review_inline_editor = None

        if column_name == "has_exception":
            new_value = new_value or "לא"
        elif column_name == "exception_reason":
            new_value = new_value or "-"

        self._apply_user_review_changes(row_index, {column_name: new_value})
        self.selected_user_review_index = next(
            (index for index, (_, row) in enumerate(self.user_review_df.iterrows()) if row.get("user_name") == self.user_review_df.iloc[row_index].get("user_name")),
            None,
        )

    def _save_all_user_review_changes(self):
        if self.user_review_df.empty:
            messagebox.showwarning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return

        if self.user_review_inline_editor is not None:
            self._commit_inline_user_review_edit()

        if not self.user_review_dirty_rows:
            messagebox.showinfo("ללא שינויים", "אין שינויים חדשים לשמירה.")
            return

        rows_to_save = self.user_review_df[self.user_review_df["user_name"].isin(self.user_review_dirty_rows)]
        self.db.save_user_review_rows(rows_to_save.to_dict("records"))
        saved_count = len(rows_to_save.index)
        self.user_review_dirty_rows.clear()
        messagebox.showinfo("הצלחה", f"נשמרו {saved_count} שורות בדוח הסקירה.")

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
            for item in self.user_type_tree.get_children():
                self.user_type_tree.delete(item)
            return

        summary = self.user_review_report["summary"]
        self.review_summary_vars["total_users"].set(str(summary["total_users"]))
        self.review_summary_vars["in_scope_users"].set(str(summary["in_scope_users"]))
        self.review_summary_vars["exception_users"].set(str(summary["exception_users"]))
        self.review_summary_vars["privileged_users"].set(str(summary["privileged_users"]))

        for item in self.user_type_tree.get_children():
            self.user_type_tree.delete(item)
        for user_type, count in sorted(summary["type_distribution"].items()):
            self.user_type_tree.insert("", tk.END, values=(user_type, count))

    def _refresh_user_review_table(self):
        if self.user_review_inline_editor is not None:
            self._cancel_inline_user_review_edit()

        for item in self.user_review_tree.get_children():
            self.user_review_tree.delete(item)

        if self.user_review_df.empty:
            self.user_review_visible_indices = []
            return

        filtered_df = self._get_user_review_filtered_df()
        self.user_review_visible_indices = list(filtered_df.index)

        for row_index, (_, row) in zip(self.user_review_visible_indices, filtered_df.iterrows()):
            tags = []
            if row.get("has_exception") == "כן":
                tags.append("Exception")
            if row.get("review_status") and row.get("review_status") != "טרם נסקר":
                tags.append("Reviewed")
            if row.get("user_name") in self.user_review_dirty_rows:
                tags.append("Dirty")

            self.user_review_tree.insert(
                "",
                tk.END,
                iid=str(row_index),
                values=(
                    row.get("user_name", ""),
                    row.get("in_scope", ""),
                    row.get("active_status", ""),
                    row.get("active_in_period", ""),
                    row.get("last_login", ""),
                    row.get("days_since_login", ""),
                    row.get("user_type", ""),
                    row.get("password_policy_exempt_status", ""),
                    row.get("password_policy_exempt_reason", ""),
                    row.get("system_table_access_status", ""),
                    row.get("critical_privileges", ""),
                    row.get("has_exception", ""),
                    row.get("exception_reason", ""),
                    row.get("review_status", ""),
                    row.get("manager_decision", ""),
                    row.get("action_required", ""),
                    row.get("manager_comments", ""),
                ),
                tags=tuple(tags),
            )

    def _generate_user_review(self):
        is_valid, validation_message = self._validate_user_review_sources()
        if not is_valid:
            messagebox.showerror("בדיקת תקינות נכשלה", validation_message)
            return

        try:
            review_date = self.review_date_widget.get_date()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            existing_reviews = self.db.get_user_review_rows(self.period_var.get())
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=self.importer.config,
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
            messagebox.showinfo("הושלם", f"דוח הסקירה נבנה בהצלחה עבור {len(self.user_review_df)} משתמשים.")
        except Exception as error:
            messagebox.showerror("שגיאה בבניית דוח סקירה", str(error))

    def _get_user_review_period_from_config(self):
        period_config = self.importer.config.get("user_review_period", {})
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
        if not hasattr(self, "review_period_info_var"):
            return
        try:
            start_date, end_date = self._get_user_review_period_from_config()
            self.review_period_info_var.set(f"טווח בחינה פעיל לדוח: {start_date.isoformat()} עד {end_date.isoformat()}")
        except Exception:
            self.review_period_info_var.set("טווח בחינה פעיל לדוח: לא הוגדר או לא תקין")

    def _get_selected_user_review_index(self):
        selected_items = self.user_review_tree.selection()
        if not selected_items:
            return None
        try:
            return int(selected_items[0])
        except ValueError:
            return None

    def _open_user_review_editor(self, _event=None):
        row_index = self._get_selected_user_review_index()
        if row_index is None or self.user_review_df.empty:
            messagebox.showwarning("לא נבחר משתמש", "בחר שורה מתוך דוח הסקירה כדי לעדכן החלטת מנהל.")
            return

        row = self.user_review_df.iloc[row_index]
        self.selected_user_review_index = row_index
        dialog = tk.Toplevel(self.root)
        dialog.title("עדכון החלטת מנהל")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("620x420")

        container = ttk.Frame(dialog, padding="16")
        container.pack(fill=tk.BOTH, expand=True)
        ttk.Label(container, text=f"משתמש: {row['user_name']}", style="SectionHeader.TLabel").pack(anchor="e", pady=(0, 12))

        metadata_text = (
            f"סוג משתמש: {row['user_type']}\n"
            f"סטטוס: {row['active_status']}\n"
            f"החרגת סיסמה: {row.get('password_policy_exempt_status', '-')}\n"
            f"סיבת החרגה: {row.get('password_policy_exempt_reason', '-')}\n"
            f"גישה לטבלאות מערכת: {row.get('system_table_access_status', '-')}\n"
            f"חריג: {row['has_exception']}\n"
            f"סיבת חריג: {row['exception_reason']}"
        )
        ttk.Label(container, text=metadata_text, justify="right").pack(anchor="e", pady=(0, 12))

        review_status_var = tk.StringVar(value=row.get("review_status", "טרם נסקר"))
        manager_decision_var = tk.StringVar(value=row.get("manager_decision", ""))
        action_required_var = tk.StringVar(value=row.get("action_required", ""))
        has_exception_var = tk.StringVar(value=row.get("has_exception", "לא"))
        exception_reason_var = tk.StringVar(value="" if row.get("exception_reason") == "-" else row.get("exception_reason", ""))

        for label_text, variable, options in [
            ("סטטוס סקירה", review_status_var, ["טרם נסקר", "נסקר", "דורש מעקב"]),
            ("החלטת מנהל", manager_decision_var, ["", "מאושר", "לא מאושר", "נדרש בירור"]),
            ("נדרש להסרה / מאושר להשאיר", action_required_var, ["", "נדרש להסרה", "מאושר להשאיר"]),
            ("חריג", has_exception_var, ["כן", "לא"]),
        ]:
            row_frame = ttk.Frame(container)
            row_frame.pack(fill=tk.X, pady=4)
            ttk.Combobox(row_frame, textvariable=variable, values=options, state="readonly", justify="right").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))
            ttk.Label(row_frame, text=label_text, style="FieldLabel.TLabel").pack(side=tk.RIGHT)

        exception_reason_frame = ttk.Frame(container)
        exception_reason_frame.pack(fill=tk.X, pady=4)
        ttk.Entry(exception_reason_frame, textvariable=exception_reason_var, justify="right").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))
        ttk.Label(exception_reason_frame, text="סיבת חריג", style="FieldLabel.TLabel").pack(side=tk.RIGHT)

        ttk.Label(container, text="הערות", style="FieldLabel.TLabel").pack(anchor="e", pady=(12, 4))
        comments_text = tk.Text(container, height=8, wrap=tk.WORD, font=("Segoe UI", 10))
        comments_text.pack(fill=tk.BOTH, expand=True)
        comments_text.insert("1.0", row.get("manager_comments", ""))

        def save_changes():
            updates = {
                "review_status": review_status_var.get().strip() or "טרם נסקר",
                "manager_decision": manager_decision_var.get().strip(),
                "action_required": action_required_var.get().strip(),
                "has_exception": has_exception_var.get().strip() or "לא",
                "exception_reason": exception_reason_var.get().strip() or "-",
                "manager_comments": comments_text.get("1.0", tk.END).strip(),
            }
            self._apply_user_review_changes(row_index, updates)
            refreshed_index = next((index for index, (_, current_row) in enumerate(self.user_review_df.iterrows()) if current_row.get("user_name") == row.get("user_name")), None)
            if refreshed_index is not None:
                self.selected_user_review_index = refreshed_index
            dialog.destroy()
            messagebox.showinfo("הצלחה", "השינויים בדוח נשמרו.")

        button_frame = ttk.Frame(container)
        button_frame.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(button_frame, text="שמור", command=save_changes).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="ביטול", command=dialog.destroy).pack(side=tk.LEFT, padx=6)

    def _export_user_review_excel(self):
        if self.user_review_report is None or self.user_review_df.empty:
            messagebox.showwarning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile=f"User_Review_{self.period_var.get()}_{timestamp}.xlsx",
        )
        if not save_path:
            return

        try:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            export_user_review_to_excel(self.user_review_report, save_path)
            messagebox.showinfo("הצלחה", f"דוח הסקירה יוצא בהצלחה ל-Excel.\n\n{save_path}")
        except Exception as error:
            messagebox.showerror("שגיאת ייצוא", f"לא ניתן לייצא את דוח הסקירה ל-Excel.\n\n{error}")

    def _export_user_review_pdf(self):
        if self.user_review_report is None or self.user_review_df.empty:
            messagebox.showwarning("אין נתונים", "בנה תחילה דוח סקירת משתמשים.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
            initialfile=f"User_Review_{self.period_var.get()}_{timestamp}.pdf",
        )
        if not save_path:
            return

        try:
            self.user_review_report["dataframe"] = self.user_review_df.copy()
            export_user_review_to_pdf(self.user_review_report, save_path)
            messagebox.showinfo("הצלחה", f"דוח הסקירה יוצא בהצלחה ל-PDF.\n\n{save_path}")
        except Exception as error:
            messagebox.showerror("שגיאת ייצוא", f"לא ניתן לייצא את דוח הסקירה ל-PDF.\n\n{error}")

    def _build_audit_tab(self):
        container = ttk.Frame(self.audit_tab, padding="20")
        container.pack(fill=tk.BOTH, expand=True)
        ctrl_frame = ttk.Frame(container)
        ctrl_frame.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(ctrl_frame, text="ביצוע ניתוח בקרות ITGC", font=("Segoe UI", 16, "bold")).pack(side=tk.RIGHT)
        self.export_findings_btn = ttk.Button(ctrl_frame, text="ייצוא ממצאים ל-Excel", command=self._export_findings_to_excel)
        self.export_findings_btn.pack(side=tk.LEFT, padx=10)
        self.run_btn = ttk.Button(ctrl_frame, text="הרץ ניתוח ⚡", command=self._run_audit)
        self.run_btn.pack(side=tk.LEFT, padx=10)
        ttk.Entry(ctrl_frame, textvariable=self.period_var, width=12).pack(side=tk.LEFT)
        ttk.Label(ctrl_frame, text="תקופה:").pack(side=tk.LEFT, padx=5)

        filter_frame = ttk.LabelFrame(container, text=" סינון מהיר ", padding="10")
        filter_frame.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(filter_frame, text="קובץ מקור:").pack(side=tk.RIGHT, padx=(10, 4))
        self.source_filter_combo = ttk.Combobox(filter_frame, textvariable=self.source_filter_var, state="readonly", width=24, justify="right")
        self.source_filter_combo.pack(side=tk.RIGHT, padx=(0, 16))
        ttk.Label(filter_frame, text="קטגוריה:").pack(side=tk.RIGHT, padx=(10, 4))
        self.category_filter_combo = ttk.Combobox(filter_frame, textvariable=self.category_filter_var, state="readonly", width=18, justify="right")
        self.category_filter_combo.pack(side=tk.RIGHT, padx=(0, 16))
        ttk.Label(filter_frame, text="רמת סיכון:").pack(side=tk.RIGHT, padx=(10, 4))
        self.risk_filter_combo = ttk.Combobox(filter_frame, textvariable=self.risk_filter_var, state="readonly", width=14, justify="right")
        self.risk_filter_combo.pack(side=tk.RIGHT)
        for combo in (self.source_filter_combo, self.category_filter_combo, self.risk_filter_combo):
            combo.bind("<<ComboboxSelected>>", self._on_filter_change)
        self._reset_filter_options()

        res_frame = ttk.LabelFrame(container, text=" ממצאי הביקורת ", padding="10")
        res_frame.pack(fill=tk.BOTH, expand=True)
        cols = ("source", "extract_date", "cat", "risk", "title", "rule", "actual", "expected", "status")
        self.tree = ttk.Treeview(res_frame, columns=cols, show="headings")
        for col, head in zip(cols, ["קובץ מקור", "תאריך הפקה", "קטגוריה", "סיכון", "תיאור", "סוג בדיקה", "ערך בפועל", "ערך מצופה", "סטטוס"]):
            self.tree.heading(col, text=head, command=lambda c=col: self._sort_by_column(c))
        self.tree.column("source", width=180, anchor="e")
        self.tree.column("extract_date", width=110, anchor="center")
        self.tree.column("cat", width=130, anchor="e")
        self.tree.column("risk", width=90, anchor="center")
        self.tree.column("title", width=320, anchor="e")
        self.tree.column("rule", width=110, anchor="center")
        self.tree.column("actual", width=110, anchor="center")
        self.tree.column("expected", width=120, anchor="center")
        self.tree.column("status", width=120, anchor="e")
        self.tree.tag_configure("High", background="#f8d7da")
        self.tree.tag_configure("Medium", background="#fff3cd")
        self.tree.tag_configure("Compliant", background="#dff5e3")
        self.tree.tag_configure("PasswordPolicy", foreground="#0f4c81", font=("Segoe UI", 9, "bold"))
        self.tree.bind("<Double-1>", self._open_finding_details)
        findings_scroll_x = ttk.Scrollbar(res_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=findings_scroll_x.set)
        self.tree.pack(fill=tk.BOTH, expand=True)
        findings_scroll_x.pack(fill=tk.X)

    def _get_source_file_name(self, finding):
        source_slot = getattr(finding, "source_slot", None)
        if not source_slot:
            return "לא זוהה"
        return self.loaded_files.get(source_slot, source_slot)

    def _reset_filter_options(self):
        default_values = ["הכל"]
        self.risk_filter_combo["values"] = default_values
        self.category_filter_combo["values"] = default_values
        self.source_filter_combo["values"] = default_values
        self.risk_filter_var.set("הכל")
        self.category_filter_var.set("הכל")
        self.source_filter_var.set("הכל")

    def _update_filter_options(self):
        risk_values = sorted({finding.risk_level for finding in self.current_findings if getattr(finding, "risk_level", None)})
        category_values = sorted({finding.category for finding in self.current_findings if getattr(finding, "category", None)})
        source_values = sorted({self._get_source_file_name(finding) for finding in self.current_findings})

        self.risk_filter_combo["values"] = ["הכל"] + risk_values
        self.category_filter_combo["values"] = ["הכל"] + category_values
        self.source_filter_combo["values"] = ["הכל"] + source_values

        for variable, values in (
            (self.risk_filter_var, self.risk_filter_combo["values"]),
            (self.category_filter_var, self.category_filter_combo["values"]),
            (self.source_filter_var, self.source_filter_combo["values"]),
        ):
            if variable.get() not in values:
                variable.set("הכל")

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
        value = self._get_column_display_value(finding, column)
        return str(value).casefold()

    def _sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self._refresh_findings_table()

    def _refresh_findings_table(self):
        self.displayed_findings = self._get_filtered_findings()
        self.displayed_findings.sort(key=lambda finding: self._get_sort_key(finding, self.sort_column), reverse=self.sort_reverse)

        for item in self.tree.get_children():
            self.tree.delete(item)

        for index, finding in enumerate(self.displayed_findings):
            tags = []
            if finding.risk_level in {"High", "Medium"}:
                tags.append(finding.risk_level)
            if finding.status == "Compliant":
                tags.append("Compliant")
            if finding.category == "Password Policy":
                tags.append("PasswordPolicy")

            self.tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    self._get_source_file_name(finding),
                    getattr(finding, "extract_date", "-"),
                    finding.category,
                    finding.risk_level,
                    finding.title,
                    getattr(finding, "comparison_rule", None) or "-",
                    getattr(finding, "actual_value", None) or "-",
                    getattr(finding, "expected_value", None) or "-",
                    finding.status,
                ),
                tags=tuple(tags),
            )

    def _export_findings_to_excel(self):
        if not self.displayed_findings:
            messagebox.showwarning("אין נתונים", "אין ממצאים לייצוא בטבלה הנוכחית.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile=f"Audit_Findings_{self.period_var.get()}_{timestamp}.xlsx",
        )
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
            messagebox.showinfo("הצלחה", f"טבלת הממצאים יוצאה בהצלחה ל-Excel.\n\n{save_path}")
        except Exception as error:
            messagebox.showerror("שגיאת ייצוא", f"לא ניתן לייצא את הממצאים ל-Excel.\n\n{error}")

    def _format_finding_detail_value(self, value):
        if value is None or value == "":
            return "-"
        return str(value)

    def _open_finding_details(self, _event=None):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        item_id = selected_items[0]
        try:
            finding = self.displayed_findings[int(item_id)]
        except (ValueError, IndexError):
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("פירוט ממצא")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("700x520")
        dialog.minsize(620, 460)

        container = ttk.Frame(dialog, padding="18")
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)

        ttk.Label(container, text=finding.title, style="SectionHeader.TLabel", anchor="e", justify="right").grid(row=0, column=0, sticky="e", pady=(0, 10))

        details_frame = ttk.Frame(container)
        details_frame.grid(row=1, column=0, sticky="nsew")
        details_frame.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)

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

        for row_index, (label_text, value) in enumerate(detail_rows):
            row_frame = ttk.Frame(details_frame)
            row_frame.grid(row=row_index, column=0, sticky="ew", pady=3)
            row_frame.columnconfigure(0, weight=1)
            value_label = ttk.Label(row_frame, text=self._format_finding_detail_value(value), anchor="e", justify="right")
            value_label.grid(row=0, column=0, sticky="e", padx=(0, 10))
            if label_text in {"ערך בפועל", "ערך מצופה", "סוג בדיקה"} and getattr(finding, "category", "") == "Password Policy":
                value_label.configure(foreground="#0f4c81")
            ttk.Label(row_frame, text=label_text, style="FieldLabel.TLabel", anchor="e", justify="right").grid(row=0, column=1, sticky="e")

        description_frame = ttk.LabelFrame(container, text=" תיאור מלא ", padding="10")
        description_frame.grid(row=2, column=0, sticky="nsew", pady=(14, 10))
        description_frame.columnconfigure(0, weight=1)
        description_frame.rowconfigure(0, weight=1)
        description_text = tk.Text(description_frame, height=8, wrap=tk.WORD, font=("Segoe UI", 10))
        description_text.grid(row=0, column=0, sticky="nsew")
        description_text.insert("1.0", self._format_finding_detail_value(finding.description))
        description_text.config(state=tk.DISABLED)

        ttk.Button(container, text="סגירה", command=dialog.destroy).grid(row=3, column=0, sticky="w")

    def _run_audit(self):
        if not self.loaded_dataframes:
            messagebox.showwarning("חסר מידע", "אנא טען קבצי מקור בלשונית ה-IPE.")
            return

        is_valid, validation_message = self._validate_all_sources_before_analysis()
        if not is_valid:
            messagebox.showerror("בדיקת תקינות נכשלה", validation_message)
            return

        try:
            self.run_btn.config(state=tk.DISABLED)
            analyzer = AuditAnalyzer(config=self.importer.config, whitelist=self.db.get_whitelist())
            findings = analyzer.run_all_checks(self.loaded_dataframes, period_id=self.period_var.get())
            findings.extend(self._build_findings_from_user_review())
            findings = self._attach_findings_source_metadata(findings)
            self.current_findings = findings
            self._update_filter_options()
            self._refresh_findings_table()
            if findings: self.db.save_findings([vars(f) for f in findings])
            messagebox.showinfo("הושלם", f"נמצאו {len(findings)} חריגות.")
        except Exception as e:
            messagebox.showerror(
                "שגיאה בהרצת ניתוח",
                "הניתוח נכשל לאחר טעינת הקבצים.\n\n"
                f"פירוט טכני:\n{str(e)}\n\n"
                "אם השגיאה נמשכת, בדוק שהקבצים נטענו לסלוטים הנכונים ושהכותרות בהם תואמות להגדרות המערכת.",
            )
        finally:
            self.run_btn.config(state=tk.NORMAL)

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
            review_date = self.review_date_widget.get_date()
            review_period_start, review_period_end = self._get_user_review_period_from_config()
            existing_reviews = self.db.get_user_review_rows(self.period_var.get())
            self.user_review_report = build_user_review_report(
                users_df=self.loaded_dataframes["USERS"],
                privileges_df=self.loaded_dataframes.get("GRANTED_PRIVILEGES"),
                config=self.importer.config,
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

    def _build_settings_tab(self):
        outer_container = ttk.Frame(self.settings_tab)
        outer_container.pack(fill=tk.BOTH, expand=True)

        settings_canvas = tk.Canvas(outer_container, highlightthickness=0, bg="#f8f9fa")
        settings_scrollbar = ttk.Scrollbar(outer_container, orient=tk.VERTICAL, command=settings_canvas.yview)
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)

        settings_scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        settings_canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        container = ttk.Frame(settings_canvas, padding="20")
        canvas_window_id = settings_canvas.create_window((0, 0), window=container, anchor="nw")

        def _update_settings_scroll_region(_event=None):
            settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))

        def _resize_settings_content(event):
            settings_canvas.itemconfigure(canvas_window_id, width=event.width)

        def _on_settings_mousewheel(event):
            settings_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_settings_mousewheel(_event=None):
            settings_canvas.bind_all("<MouseWheel>", _on_settings_mousewheel)

        def _unbind_settings_mousewheel(_event=None):
            settings_canvas.unbind_all("<MouseWheel>")

        container.bind("<Configure>", _update_settings_scroll_region)
        settings_canvas.bind("<Configure>", _resize_settings_content)
        settings_canvas.bind("<Enter>", _bind_settings_mousewheel)
        settings_canvas.bind("<Leave>", _unbind_settings_mousewheel)

        ttk.Label(container, text="הגדרות מערכת לביקורת", style="SectionHeader.TLabel").pack(anchor="e")
        ttk.Label(
            container,
            text=self._rtl_hebrew_only("הטופס מתרגם את ההגדרות ל-JSON מאחורי הקלעים. ניתן לשנות ערכים ולשמור בכל עת."),
            style="Hint.TLabel",
        ).pack(anchor="e", pady=(4, 12))

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="טען ברירות מחדל", command=self._reset_settings_form).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="שמור הגדרות 💾", command=self._save_settings).pack(side=tk.LEFT, padx=5)

        form_frame = ttk.Frame(container)
        form_frame.pack(fill=tk.BOTH, expand=True)
        form_frame.columnconfigure(0, weight=1)

        self._build_review_period_section(form_frame, 0)

        self._build_list_section(
            form_frame,
            1,
            "critical_users",
            "משתמשים קריטיים",
            "שם משתמש אחד בכל שורה.",
            height=4,
        )
        self._build_list_section(
            form_frame,
            2,
            "critical_privileges",
            "הרשאות קריטיות",
            "הרשאה אחת בכל שורה.",
            height=5,
        )
        self._build_password_policy_section(form_frame, 3)
        self._build_file_mapping_section(form_frame, 4)
        self._build_user_review_settings_section(form_frame, 5)

        self._load_settings()
        _update_settings_scroll_region()

    def _create_section_frame(self, parent, row, title, description):
        section = ttk.LabelFrame(parent, text=f" {title} ", padding="12")
        section.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        section.columnconfigure(0, weight=1)
        ttk.Label(section, text=self._rtl_hebrew_only(description), style="Hint.TLabel", wraplength=900, justify="right").grid(row=0, column=0, sticky="e", pady=(0, 8))
        return section

    def _build_list_section(self, parent, row, key, title, description, height):
        section = self._create_section_frame(parent, row, title, description)
        text_widget = tk.Text(section, height=height, font=("Segoe UI", 10), wrap=tk.WORD)
        text_widget.grid(row=1, column=0, sticky="ew")
        self.settings_widgets[key] = text_widget

    def _build_review_period_section(self, parent, row):
        section = self._create_section_frame(
            parent,
            row,
            "תקופת בחינה לדוח סקירת משתמשים",
            "טווח תאריכים לקביעת משתמשים פעילים בדוח הסקירה.",
        )
        self.settings_widgets["user_review_period"] = {}
        period_frame = ttk.Frame(section)
        period_frame.grid(row=1, column=0, sticky="ew", pady=2)
        period_frame.columnconfigure(1, weight=0)
        period_frame.columnconfigure(3, weight=0)

        ttk.Label(period_frame, text="מתאריך", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="e", padx=(0, 6))
        start_entry = ttk.Entry(period_frame, width=14, justify="center")
        start_entry.grid(row=0, column=1, sticky="w", padx=(0, 14))

        ttk.Label(period_frame, text="עד תאריך", style="FieldLabel.TLabel").grid(row=0, column=2, sticky="e", padx=(0, 6))
        end_entry = ttk.Entry(period_frame, width=14, justify="center")
        end_entry.grid(row=0, column=3, sticky="w")

        ttk.Label(section, text=self._rtl_hebrew_only("פורמט: YYYY-MM-DD"), style="Hint.TLabel").grid(row=2, column=0, sticky="e", pady=(2, 0))

        self.settings_widgets["user_review_period"]["start_date"] = start_entry
        self.settings_widgets["user_review_period"]["end_date"] = end_entry

    def _build_password_policy_section(self, parent, row):
        section = self._create_section_frame(
            parent,
            row,
            "ברירות מחדל למדיניות סיסמאות",
            "ערכים אלה משמשים כבסיס להשוואה מול טבלת M_PASSWORD_POLICY בעת הניתוח.",
        )
        self.settings_widgets["password_policy_defaults"] = {}

        numeric_policy_fields = [
            ("minimal_password_length", "אורך סיסמה מינימלי", "מספר תווים מינימלי בסיסמה. כלל: מינימום."),
            ("password_lock_time", "משך נעילת סיסמה", "זמן נעילה (בדקות) לאחר ניסיונות כושלים. כלל: מינימום."),
            ("last_used_passwords", "היסטוריית סיסמאות", "כמה סיסמאות אחרונות אסור למחזר. כלל: מינימום."),
            ("maximum_invalid_connect_attempts", "ניסיונות התחברות כושלים", "כמות ניסיונות שגויים מותרת לפני נעילה. כלל: מקסימום."),
            ("minimal_password_lifetime", "חיי סיסמה מינימליים", "מספר הימים המינימלי לפני החלפת סיסמה נוספת. כלל: מינימום."),
            ("maximum_password_lifetime", "חיי סיסמה מקסימליים", "מספר הימים המקסימלי לתוקף סיסמה. כלל: מקסימום."),
            ("maximum_unused_initial_password_lifetime", "תוקף סיסמה ראשונית לא מנוצלת", "ימים מקסימליים לשימוש בסיסמה ראשונית. כלל: מקסימום."),
            ("maximum_unused_productive_password_lifetime", "תוקף סיסמה פרודוקטיבית לא מנוצלת", "ימים מקסימליים ללא שימוש בסיסמה בסביבת ייצור. כלל: מקסימום."),
            ("password_expire_warning_time", "התראה לפני פקיעת סיסמה", "כמה ימים מראש המשתמש יקבל התראה. כלל: מינימום."),
        ]

        for row_index, (field_name, label_text, hint_text) in enumerate(numeric_policy_fields, start=1):
            field_frame = ttk.Frame(section)
            field_frame.grid(row=row_index, column=0, sticky="ew", pady=4)
            field_frame.columnconfigure(0, weight=1)
            entry = ttk.Entry(field_frame, width=20, justify="right")
            entry.grid(row=0, column=0, sticky="w", padx=(0, 12))
            label_container = ttk.Frame(field_frame)
            label_container.grid(row=0, column=1, sticky="e")
            ttk.Label(label_container, text=label_text, style="FieldLabel.TLabel").pack(anchor="e")
            ttk.Label(label_container, text=self._rtl_hebrew_only(hint_text), style="Hint.TLabel").pack(anchor="e")
            self.settings_widgets["password_policy_defaults"][field_name] = entry

        text_frame = ttk.Frame(section)
        text_frame.grid(row=len(numeric_policy_fields) + 1, column=0, sticky="ew", pady=4)
        text_frame.columnconfigure(0, weight=1)
        layout_entry = ttk.Entry(text_frame, width=20, justify="right")
        layout_entry.grid(row=0, column=0, sticky="w", padx=(0, 12))
        label_container = ttk.Frame(text_frame)
        label_container.grid(row=0, column=1, sticky="e")
        ttk.Label(label_container, text="מבנה סיסמה נדרש", style="FieldLabel.TLabel").pack(anchor="e")
        ttk.Label(label_container, text=self._rtl_hebrew_only("תבנית מורכבות, לדוגמה A1a (אות גדולה, ספרה ואות קטנה). כלל: התאמה מדויקת."), style="Hint.TLabel", wraplength=760, justify="right").pack(anchor="e")
        self.settings_widgets["password_policy_defaults"]["password_layout"] = layout_entry

        boolean_fields = [
            ("force_first_password_change", "חובת החלפת סיסמה ראשונה", "אם משתמש חייב לשנות סיסמה בכניסה הראשונה. כלל: התאמה מדויקת."),
            ("password_lock_for_system_user", "נעילה גם למשתמשי מערכת", "האם נעילה בעקבות כשלי התחברות חלה גם על משתמשי SYSTEM. כלל: התאמה מדויקת."),
            ("detailed_error_on_connect", "הודעות שגיאה מפורטות בהתחברות", "מומלץ FALSE כדי לא לחשוף מידע לתוקף. כלל: התאמה מדויקת."),
        ]

        for offset, (field_name, label_text, hint_text) in enumerate(boolean_fields, start=2):
            boolean_frame = ttk.Frame(section)
            boolean_frame.grid(row=len(numeric_policy_fields) + offset, column=0, sticky="ew", pady=4)
            boolean_frame.columnconfigure(0, weight=1)
            boolean_combobox = ttk.Combobox(boolean_frame, values=["TRUE", "FALSE"], state="readonly", width=18, justify="right")
            boolean_combobox.grid(row=0, column=0, sticky="w", padx=(0, 12))
            label_container = ttk.Frame(boolean_frame)
            label_container.grid(row=0, column=1, sticky="e")
            ttk.Label(label_container, text=label_text, style="FieldLabel.TLabel").pack(anchor="e")
            ttk.Label(label_container, text=self._rtl_hebrew_only(hint_text), style="Hint.TLabel", wraplength=760, justify="right").pack(anchor="e")
            self.settings_widgets["password_policy_defaults"][field_name] = boolean_combobox
            self.boolean_fields[field_name] = boolean_combobox

    def _build_file_mapping_section(self, parent, row):
        section = self._create_section_frame(
            parent,
            row,
            "שמות קבצים צפויים",
            "הגדר שמות קבצים ברירת מחדל לטעינה אוטומטית או לזיהוי מהיר של קבצי המקור.",
        )
        mapping_fields = [
            ("USERS", "קובץ משתמשים", "לדוגמה: users_export.csv"),
            ("M_PASSWORD_POLICY", "קובץ מדיניות סיסמאות", "לדוגמה: password_policy.csv"),
            ("GRANTED_PRIVILEGES", "קובץ הרשאות", "לדוגמה: privileges.csv"),
            ("AUDIT_POLICIES", "קובץ מדיניות Audit", "לדוגמה: audit_policies.csv"),
        ]
        self.settings_widgets["file_mappings"] = {}

        for row_index, (field_name, label_text, hint_text) in enumerate(mapping_fields, start=1):
            field_frame = ttk.Frame(section)
            field_frame.grid(row=row_index, column=0, sticky="ew", pady=4)
            field_frame.columnconfigure(0, weight=1)
            entry = ttk.Entry(field_frame, justify="right")
            entry.grid(row=0, column=0, sticky="ew", padx=(0, 12))
            label_container = ttk.Frame(field_frame)
            label_container.grid(row=0, column=1, sticky="e")
            ttk.Label(label_container, text=label_text, style="FieldLabel.TLabel").pack(anchor="e")
            ttk.Label(label_container, text=self._rtl_hebrew_only(hint_text), style="Hint.TLabel").pack(anchor="e")
            self.settings_widgets["file_mappings"][field_name] = entry

    def _build_user_review_settings_section(self, parent, row):
        section = self._create_section_frame(
            parent,
            row,
            "כללי סקירת משתמשים",
            "סף אי-שימוש וכללי סיווג למשתמשים.",
        )

        threshold_frame = ttk.Frame(section)
        threshold_frame.grid(row=1, column=0, sticky="ew", pady=4)
        threshold_frame.columnconfigure(0, weight=1)
        threshold_entry = ttk.Entry(threshold_frame, width=20, justify="right")
        threshold_entry.grid(row=0, column=0, sticky="w", padx=(0, 12))
        label_container = ttk.Frame(threshold_frame)
        label_container.grid(row=0, column=1, sticky="e")
        ttk.Label(label_container, text="סף חוסר שימוש (ימים)", style="FieldLabel.TLabel").pack(anchor="e")
        ttk.Label(label_container, text=self._rtl_hebrew_only("מעל סף זה משתמש Dialog עם הרשאות יסומן כחריג."), style="Hint.TLabel", wraplength=760, justify="right").pack(anchor="e")
        self.settings_widgets["inactive_days_threshold"] = threshold_entry

        self.settings_widgets["user_type_rules"] = {}
        for row_index, (field_name, label_text, hint_text) in enumerate(
            [
                ("Dialog", "כללי סיווג ל-Dialog", "מילת מפתח אחת בכל שורה. אם שם המשתמש מכיל אחת מהן הוא יסווג כ-Dialog."),
                ("Generic", "כללי סיווג ל-Generic", "לדוגמה: SHARED, GENERIC, FIRE, COMMON."),
                ("Technical", "כללי סיווג ל-Technical", "לדוגמה: _SYS, TECH, SERVICE, BATCH, ADMIN."),
                ("Application", "כללי סיווג ל-Application", "אופציונלי. אם אין התאמה לכלל אחר, ברירת המחדל היא Application."),
            ],
            start=2,
        ):
            rules_frame = ttk.Frame(section)
            rules_frame.grid(row=row_index, column=0, sticky="ew", pady=4)
            rules_frame.columnconfigure(0, weight=1)
            text_widget = tk.Text(rules_frame, height=2, font=("Segoe UI", 10), wrap=tk.WORD)
            text_widget.grid(row=0, column=0, sticky="ew", padx=(0, 12))
            label_container = ttk.Frame(rules_frame)
            label_container.grid(row=0, column=1, sticky="ne")
            ttk.Label(label_container, text=label_text, style="FieldLabel.TLabel").pack(anchor="e")
            ttk.Label(label_container, text=self._rtl_hebrew_only(hint_text), style="Hint.TLabel", wraplength=760, justify="right").pack(anchor="e")
            self.settings_widgets["user_type_rules"][field_name] = text_widget

    def _get_settings_defaults(self):
        defaults = copy.deepcopy(self.DEFAULT_SETTINGS)
        if self.settings_path.exists():
            with open(self.settings_path, 'r', encoding='utf-8') as settings_file:
                loaded_config = json.load(settings_file)
            defaults.update({key: value for key, value in loaded_config.items() if key in defaults})
            if "password_policy_defaults" in loaded_config:
                defaults["password_policy_defaults"].update(loaded_config["password_policy_defaults"])
                # Backward compatibility for previous key name.
                if (
                    "maximum_password_lifetime" not in defaults["password_policy_defaults"]
                    and "maximum_password_validity" in loaded_config["password_policy_defaults"]
                ):
                    defaults["password_policy_defaults"]["maximum_password_lifetime"] = loaded_config["password_policy_defaults"]["maximum_password_validity"]
            if "file_mappings" in loaded_config:
                defaults["file_mappings"].update(loaded_config["file_mappings"])
                # Backward compatibility for previous key naming.
                if (
                    "GRANTED_PRIVILEGES" not in defaults["file_mappings"]
                    and "EFFECTIVE_PRIVILEGE_GRANTEES" in loaded_config["file_mappings"]
                ):
                    defaults["file_mappings"]["GRANTED_PRIVILEGES"] = loaded_config["file_mappings"]["EFFECTIVE_PRIVILEGE_GRANTEES"]
            if "user_review_period" in loaded_config:
                defaults["user_review_period"].update(loaded_config["user_review_period"])
            if "user_type_rules" in loaded_config:
                defaults["user_type_rules"].update(loaded_config["user_type_rules"])
        return defaults

    def _load_settings(self):
        settings_data = self._get_settings_defaults()
        self._populate_settings_form(settings_data)
        self._update_review_period_info_label()

    def _populate_settings_form(self, settings_data):
        for list_key in ("critical_users", "critical_privileges"):
            widget = self.settings_widgets[list_key]
            widget.delete("1.0", tk.END)
            widget.insert("1.0", "\n".join(settings_data.get(list_key, [])))

        for field_name, entry in self.settings_widgets["password_policy_defaults"].items():
            value = settings_data.get("password_policy_defaults", {}).get(field_name, "")
            if isinstance(entry, ttk.Combobox):
                entry.set(str(value).upper())
            else:
                entry.delete(0, tk.END)
                entry.insert(0, str(value))

        for field_name, entry in self.settings_widgets["file_mappings"].items():
            value = settings_data.get("file_mappings", {}).get(field_name, "")
            entry.delete(0, tk.END)
            entry.insert(0, value)

        inactive_days_entry = self.settings_widgets["inactive_days_threshold"]
        inactive_days_entry.delete(0, tk.END)
        inactive_days_entry.insert(0, str(settings_data.get("inactive_days_threshold", 120)))

        for field_name, entry in self.settings_widgets["user_review_period"].items():
            value = settings_data.get("user_review_period", {}).get(field_name, "")
            entry.delete(0, tk.END)
            entry.insert(0, str(value))

        for field_name, widget in self.settings_widgets["user_type_rules"].items():
            widget.delete("1.0", tk.END)
            widget.insert("1.0", "\n".join(settings_data.get("user_type_rules", {}).get(field_name, [])))

    def _collect_settings_from_form(self):
        settings_data = copy.deepcopy(self.DEFAULT_SETTINGS)

        for list_key in ("critical_users", "critical_privileges"):
            raw_text = self.settings_widgets[list_key].get("1.0", tk.END)
            settings_data[list_key] = [line.strip() for line in raw_text.splitlines() if line.strip()]

        numeric_fields = {
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
        boolean_fields = {
            "force_first_password_change",
            "password_lock_for_system_user",
            "detailed_error_on_connect",
        }
        for field_name, entry in self.settings_widgets["password_policy_defaults"].items():
            value = entry.get().strip()
            if field_name in numeric_fields:
                if not value.isdigit():
                    raise ValueError(f"השדה '{field_name}' חייב להכיל מספר שלם.")
                settings_data["password_policy_defaults"][field_name] = int(value)
            elif field_name in boolean_fields:
                normalized_value = value.upper()
                if normalized_value not in {"TRUE", "FALSE"}:
                    raise ValueError(f"השדה '{field_name}' חייב להיות TRUE או FALSE.")
                settings_data["password_policy_defaults"][field_name] = normalized_value
            else:
                if not value:
                    raise ValueError(f"השדה '{field_name}' אינו יכול להיות ריק.")
                settings_data["password_policy_defaults"][field_name] = value

        for field_name, entry in self.settings_widgets["file_mappings"].items():
            value = entry.get().strip()
            if not value:
                raise ValueError(f"יש להזין ערך עבור מיפוי הקובץ '{field_name}'.")
            settings_data["file_mappings"][field_name] = value

        inactive_days_value = self.settings_widgets["inactive_days_threshold"].get().strip()
        if not inactive_days_value.isdigit():
            raise ValueError("סף חוסר שימוש חייב להיות מספר שלם.")
        settings_data["inactive_days_threshold"] = int(inactive_days_value)

        settings_data["user_review_period"] = {}
        for field_name, entry in self.settings_widgets["user_review_period"].items():
            raw_value = entry.get().strip()
            try:
                parsed_value = datetime.strptime(raw_value, "%Y-%m-%d").date().isoformat()
            except ValueError as error:
                raise ValueError(f"השדה '{field_name}' חייב להיות בפורמט YYYY-MM-DD.") from error
            settings_data["user_review_period"][field_name] = parsed_value

        if settings_data["user_review_period"]["end_date"] < settings_data["user_review_period"]["start_date"]:
            raise ValueError("תאריך סיום תקופת הבחינה חייב להיות גדול או שווה לתאריך ההתחלה.")

        settings_data["user_type_rules"] = {}
        for field_name, widget in self.settings_widgets["user_type_rules"].items():
            raw_text = widget.get("1.0", tk.END)
            settings_data["user_type_rules"][field_name] = [line.strip() for line in raw_text.splitlines() if line.strip()]

        return settings_data

    def _reset_settings_form(self):
        self._populate_settings_form(copy.deepcopy(self.DEFAULT_SETTINGS))

    def _save_settings(self):
        try:
            new_config = self._collect_settings_from_form()
            with open(self.settings_path, 'w', encoding='utf-8') as f:
                json.dump(new_config, f, indent=4, ensure_ascii=False)
            self.importer.config = new_config
            self._update_review_period_info_label()
            messagebox.showinfo("הצלחה", "ההגדרות עודכנו.")
        except Exception as e:
            messagebox.showerror("שגיאת הגדרות", str(e))

    def _log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuditGUI(root)
    root.mainloop()


