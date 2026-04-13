import tkinter as tk
from tkinter import filedialog, ttk
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from DatabaseManager import DatabaseManager
from core.importer import DataImporter
from core.analyzer import AuditAnalyzer


class AuditGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("כלי ביקורת ITGC עבור SAP HANA")
        self.root.geometry("980x760")
        self.root.minsize(900, 680)
        self.root.configure(bg="#f3f6fb")

        self.db = DatabaseManager()
        self.importer = DataImporter(config_path="config/settings.json")
        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "high": tk.StringVar(value="0"),
            "status": tk.StringVar(value="מוכן להרצה"),
        }

        self._setup_ui()

    def _setup_ui(self):
        """הגדרת רכיבי הממשק עם פריסה מותאמת לעברית."""
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("App.TFrame", background="#f3f6fb")
        style.configure(
            "Panel.TLabelframe",
            background="#ffffff",
            borderwidth=1,
            relief="solid",
        )
        style.configure(
            "Panel.TLabelframe.Label",
            background="#ffffff",
            foreground="#1f2a44",
            font=("Segoe UI Semibold", 11),
            anchor="e",
            justify="right",
        )
        style.configure(
            "Header.TLabel",
            background="#f3f6fb",
            foreground="#10233f",
            font=("Segoe UI Semibold", 19),
            anchor="e",
            justify="right",
        )
        style.configure(
            "HeaderAccent.TLabel",
            background="#f3f6fb",
            foreground="#10233f",
            font=("Segoe UI Semibold", 19),
            anchor="e",
            justify="right",
        )
        style.configure(
            "HeaderLatin.TLabel",
            background="#f3f6fb",
            foreground="#10233f",
            font=("Segoe UI Semibold", 19),
            anchor="e",
            justify="right",
        )
        style.configure(
            "HeaderDash.TLabel",
            background="#f3f6fb",
            foreground="#10233f",
            font=("Segoe UI Semibold", 19),
            anchor="e",
            justify="right",
        )
        style.configure(
            "SubHeader.TLabel",
            background="#f3f6fb",
            foreground="#5b6b82",
            font=("Segoe UI", 11),
            anchor="e",
            justify="right",
        )
        style.configure(
            "SectionTitle.TLabel",
            background="#f3f6fb",
            foreground="#1f2a44",
            font=("Segoe UI Semibold", 12),
            anchor="e",
            justify="right",
        )
        style.configure(
            "RTL.TLabel",
            background="#ffffff",
            foreground="#22324d",
            font=("Segoe UI", 10),
            anchor="e",
            justify="right",
        )
        style.configure(
            "MetricTitle.TLabel",
            background="#eaf1ff",
            foreground="#51637d",
            font=("Segoe UI", 10),
            anchor="e",
            justify="right",
        )
        style.configure(
            "MetricValue.TLabel",
            background="#eaf1ff",
            foreground="#10233f",
            font=("Segoe UI Semibold", 20),
            anchor="e",
            justify="right",
        )
        style.configure(
            "Primary.TButton",
            font=("Segoe UI Semibold", 10),
            padding=(16, 10),
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#dfe9ff")],
            foreground=[("active", "#10233f")],
        )
        style.configure(
            "Findings.Treeview",
            rowheight=30,
            fieldbackground="#ffffff",
            background="#ffffff",
            foreground="#1d2b44",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Findings.Treeview.Heading",
            background="#dfe9ff",
            foreground="#10233f",
            font=("Segoe UI Semibold", 10),
            relief="flat",
            anchor="e",
        )
        style.map("Findings.Treeview.Heading", background=[("active", "#d4e0fb")])

        main_frame = ttk.Frame(self.root, style="App.TFrame", padding=(24, 20, 24, 20))
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        main_frame.rowconfigure(8, weight=1)

        self._build_header(main_frame, 0)

        subtitle = ttk.Label(
            main_frame,
            text="טעינת קבצי CSV, הרצת בדיקות בקרות והפקת ממצאים בפורמט מותאם לעברית.",
            style="SubHeader.TLabel",
        )
        subtitle.grid(row=1, column=0, sticky="e", pady=(4, 18))

        self._add_section_title(main_frame, 2, "הגדרות הרצה")

        settings_frame = ttk.LabelFrame(main_frame, text="", style="Panel.TLabelframe", padding=(18, 16))
        settings_frame.grid(row=3, column=0, sticky="ew")
        settings_frame.columnconfigure(1, weight=1)

        ttk.Label(settings_frame, text="תיקיית קבצי CSV", style="RTL.TLabel").grid(
            row=0, column=2, sticky="e", pady=8, padx=(12, 0)
        )
        self.path_var = tk.StringVar(value=os.path.abspath("data_input"))
        self.path_entry = ttk.Entry(settings_frame, textvariable=self.path_var, justify="right", font=("Segoe UI", 10))
        self.path_entry.grid(row=0, column=1, sticky="ew", pady=8)
        ttk.Button(settings_frame, text="בחירת תיקייה", command=self._browse_folder).grid(row=0, column=0, sticky="w", padx=(0, 12))

        ttk.Label(settings_frame, text="תקופת ביקורת", style="RTL.TLabel").grid(
            row=1, column=2, sticky="e", pady=8, padx=(12, 0)
        )
        self.period_var = tk.StringVar(value="2025-Q1")
        self.period_entry = ttk.Entry(settings_frame, textvariable=self.period_var, justify="right", width=24, font=("Segoe UI", 10))
        self.period_entry.grid(row=1, column=1, sticky="e", pady=8)

        action_frame = ttk.Frame(main_frame, style="App.TFrame")
        action_frame.grid(row=4, column=0, sticky="ew", pady=(18, 14))
        action_frame.columnconfigure(0, weight=1)

        self.run_btn = ttk.Button(action_frame, text="הרצת ניתוח בקרות", style="Primary.TButton", command=self._run_audit)
        self.run_btn.grid(row=0, column=1, sticky="e")

        metrics_frame = ttk.Frame(action_frame, style="App.TFrame")
        metrics_frame.grid(row=0, column=0, sticky="w")
        self._build_metric_card(metrics_frame, 0, "סטטוס", self.summary_vars["status"], 240)
        self._build_metric_card(metrics_frame, 1, "סך ממצאים", self.summary_vars["total"], 150)
        self._build_metric_card(metrics_frame, 2, "סיכון גבוה", self.summary_vars["high"], 150)

        self._add_section_title(main_frame, 5, "ממצאי ביקורת")

        results_frame = ttk.LabelFrame(main_frame, text="", style="Panel.TLabelframe", padding=(14, 14))
        results_frame.grid(row=6, column=0, sticky="nsew", pady=(0, 14))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        columns = ("status", "risk", "category", "title")
        self.results_table = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            style="Findings.Treeview",
        )
        headings = {
            "status": ("סטטוס", 150),
            "risk": ("רמת סיכון", 120),
            "category": ("קטגוריה", 180),
            "title": ("כותרת ממצא", 420),
        }
        for column_name in columns:
            title, width = headings[column_name]
            self.results_table.heading(column_name, text=title, anchor="e")
            self.results_table.column(column_name, width=width, anchor="e", stretch=True)

        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_table.yview)
        self.results_table.configure(yscrollcommand=results_scrollbar.set)
        self.results_table.grid(row=0, column=0, sticky="nsew")
        results_scrollbar.grid(row=0, column=1, sticky="ns")
        self.results_table.tag_configure("high", background="#fff1f1")
        self.results_table.tag_configure("medium", background="#fff8e7")
        self.results_table.tag_configure("low", background="#eef8f1")

        self._add_section_title(main_frame, 7, "לוג פעילות")

        log_frame = ttk.LabelFrame(main_frame, text="", style="Panel.TLabelframe", padding=(14, 14))
        log_frame.grid(row=8, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            height=8,
            state=tk.DISABLED,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            bg="#ffffff",
            fg="#22324d",
            relief="flat",
            padx=12,
            pady=12,
            insertbackground="#22324d",
        )
        self.log_text.tag_configure("rtl", justify="right", rmargin=12, spacing1=4, spacing3=4)
        self.log_text.grid(row=0, column=0, sticky="nsew")

        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.grid(row=0, column=1, sticky="ns")

    def _add_section_title(self, parent, row, text):
        title = ttk.Label(parent, text=text, style="SectionTitle.TLabel")
        title.grid(row=row, column=0, sticky="e", pady=(0, 6))

    def _build_header(self, parent, row):
        header_frame = ttk.Frame(parent, style="App.TFrame")
        header_frame.grid(row=row, column=0, sticky="e")
        title_row = ttk.Frame(header_frame, style="App.TFrame")
        title_row.grid(row=0, column=0, sticky="e")

        header_parts = [
            ("SAP HANA", "HeaderLatin.TLabel", (0, 0)),
            ("ל-", "HeaderDash.TLabel", (0, 6)),
            ("ITGC", "HeaderAccent.TLabel", (0, 8)),
            ("מערכת ביקורת", "Header.TLabel", (0, 10)),
        ]
        for column_index, (text, style_name, padding) in enumerate(header_parts):
            ttk.Label(title_row, text=text, style=style_name).grid(
                row=0,
                column=column_index,
                sticky="e",
                padx=padding,
            )

    def _build_metric_card(self, parent, column, title, variable, width):
        card = tk.Frame(parent, bg="#eaf1ff", bd=0, highlightthickness=0, width=width, padx=16, pady=12)
        card.grid(row=0, column=column, padx=(0, 12))
        card.grid_propagate(False)
        ttk.Label(card, text=title, style="MetricTitle.TLabel").pack(anchor="e")
        ttk.Label(card, textvariable=variable, style="MetricValue.TLabel").pack(anchor="e", pady=(4, 0))

    def _log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{message} [*]\n", ("rtl",))
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update_idletasks()

    def _show_dialog(self, title, message, variant="info"):
        colors = {
            "info": {"bg": "#eff5ff", "fg": "#10233f", "button": "#dfe9ff"},
            "success": {"bg": "#eef9f0", "fg": "#14381f", "button": "#d8efdc"},
            "error": {"bg": "#fff1f1", "fg": "#611a15", "button": "#ffdedd"},
        }
        palette = colors.get(variant, colors["info"])

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=palette["bg"])
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        container = tk.Frame(dialog, bg=palette["bg"], padx=24, pady=20)
        container.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            container,
            text=title,
            bg=palette["bg"],
            fg=palette["fg"],
            font=("Segoe UI Semibold", 15),
            anchor="e",
            justify="right",
        ).pack(fill=tk.X)
        tk.Label(
            container,
            text=message,
            bg=palette["bg"],
            fg=palette["fg"],
            font=("Segoe UI", 11),
            anchor="e",
            justify="right",
            wraplength=360,
        ).pack(fill=tk.X, pady=(10, 18))

        tk.Button(
            container,
            text="סגירה",
            command=dialog.destroy,
            bg=palette["button"],
            fg=palette["fg"],
            relief="flat",
            font=("Segoe UI Semibold", 10),
            padx=20,
            pady=8,
        ).pack(anchor="e")

        dialog.update_idletasks()
        x_pos = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y_pos = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x_pos, 0)}+{max(y_pos, 0)}")
        self.root.wait_window(dialog)

    def _update_summary(self, findings):
        total = len(findings)
        high_risk = sum(1 for finding in findings if getattr(finding, "risk_level", "") == "High")
        if total:
            status = "נמצאו חריגות" if total else "ללא חריגות"
        else:
            status = "ללא ממצאים"
        self.summary_vars["total"].set(str(total))
        self.summary_vars["high"].set(str(high_risk))
        self.summary_vars["status"].set(status)

    def _clear_findings_table(self):
        for item_id in self.results_table.get_children():
            self.results_table.delete(item_id)

    def _populate_findings_table(self, findings):
        self._clear_findings_table()
        for finding in findings:
            risk_level = getattr(finding, "risk_level", "")
            tag = risk_level.lower() if risk_level else ""
            self.results_table.insert(
                "",
                tk.END,
                values=(finding.status, risk_level, finding.category, finding.title),
                tags=(tag,),
            )

    def _browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_var.set(folder)

    def _set_busy(self, is_busy):
        state = tk.DISABLED if is_busy else tk.NORMAL
        self.run_btn.config(state=state)
        self.root.config(cursor="watch" if is_busy else "")
        self.root.update_idletasks()

    def _run_audit(self):
        """הרצת לוגיקת הביקורת והצגת התוצאות בממשק RTL."""
        data_dir = self.path_var.get().strip()
        period = self.period_var.get().strip()

        if not os.path.exists(data_dir):
            self._show_dialog("שגיאה", "תיקיית הקלט לא קיימת. נא לבחור נתיב תקין.", variant="error")
            return

        self._set_busy(True)
        self.summary_vars["status"].set("הרצה בתהליך")
        self._log(f"מתחיל ייבוא מתיקייה: {data_dir}")

        try:
            data_frames = self.importer.identify_and_load(data_dir)

            if not data_frames:
                self._clear_findings_table()
                self._update_summary([])
                self._log("לא נמצאו קבצים מתאימים לייבוא.")
                self.db.log_activity("GUI Audit", "Failed: No data", "User")
                self._show_dialog("לא נמצאו קבצים", "לא נמצאו קבצי CSV שתואמים להגדרות המיפוי בקובץ התצורה.", variant="info")
                return

            self._log("מריץ בדיקות לוגיות...")
            whitelist = self.db.get_whitelist()
            analyzer = AuditAnalyzer(config=self.importer.config, whitelist=whitelist)
            findings = analyzer.run_all_checks(data_frames, period_id=period)

            self._populate_findings_table(findings)
            self._update_summary(findings)

            if findings:
                self._log(f"נמצאו {len(findings)} חריגות.")
                findings_data = [vars(finding) for finding in findings]
                self.db.save_findings(findings_data)

                output_path = PROJECT_ROOT / f"audit_report_{period}.csv"
                pd.DataFrame(findings_data).to_csv(output_path, index=False, encoding="utf-8-sig")
                self._log(f"הדוח נשמר בכתובת: {output_path}")
                self._show_dialog(
                    "הניתוח הושלם",
                    f"הבדיקה הסתיימה בהצלחה. נמצאו {len(findings)} ממצאים והדוח נשמר לקובץ CSV.",
                    variant="success",
                )
            else:
                self._log("לא נמצאו חריגות. המערכת תקינה.")
                self._show_dialog("הניתוח הושלם", "הבדיקה הסתיימה ללא ממצאים חריגים.", variant="success")

        except Exception as error:
            self.summary_vars["status"].set("שגיאה בהרצה")
            self._log(f"שגיאה קריטית: {error}")
            self._show_dialog("שגיאה", f"ההרצה נכשלה: {error}", variant="error")

        finally:
            self._set_busy(False)


if __name__ == "__main__":
    root = tk.Tk()
    app = AuditGUI(root)
    root.mainloop()