import os
import argparse
import pandas as pd
from DatabaseManager import DatabaseManager
from core.importer import DataImporter
from core.analyzer import AuditAnalyzer
from core.support_logger import SupportLogger

def main():
    support_logger = SupportLogger()

    # הגדרת ארגומנטים משורת הפקודה (CLI)
    parser = argparse.ArgumentParser(description="SAP HANA ITGC Audit Tool (Python CLI)")
    parser.add_argument("--data_dir", type=str, default="data_input", help="Path to the directory containing CSV exports")
    parser.add_argument("--period", type=str, default="2025-Q1", help="Audit period identifier (e.g., 2025-Q1)")
    parser.add_argument("--output", type=str, default="audit_report.csv", help="Output file name for the findings")
    
    args = parser.parse_args()

    print("--- SAP HANA ITGC Audit Engine Started ---")
    support_logger.process("CLI audit engine started", data_dir=args.data_dir, period=args.period, output=args.output)

    try:
        # 1. אתחול רכיבים
        db = DatabaseManager()
        importer = DataImporter(config_path="config/settings.json")
        
        # 2. שליפת נתוני תשתית (החרגות והגדרות)
        whitelist = db.get_whitelist()
        config = importer.config
        
        # 3. ייבוא נתונים מ-SAP HANA
        print(f"[*] Importing CSV files from: {args.data_dir}")
        data_frames = importer.identify_and_load(args.data_dir)
        support_logger.process("CSV import completed", loaded_sources=len(data_frames), source_names=", ".join(sorted(data_frames.keys())))
        
        if not data_frames:
            print("[!] No data loaded. Please check the data_dir and file mappings.")
            db.log_activity("Run Audit", "Failed: No data loaded", "System")
            support_logger.error("Audit run stopped: no data loaded", details="No compatible CSV files were loaded")
            return

        # 4. הרצת ניתוח
        print("[*] Running audit checks...")
        analyzer = AuditAnalyzer(config=config, whitelist=whitelist)
        findings = analyzer.run_all_checks(data_frames, period_id=args.period)
        
        # 5. עיבוד תוצאות
        if findings:
            print(f"[!] Found {len(findings)} issues.")
            
            # המרה למילונים לצורך שמירה ב-DB וייצוא
            findings_data = [vars(f) for f in findings]
            
            # שמירה בבסיס הנתונים
            db.save_findings(findings_data)
            
            # ייצוא לקובץ CSV (כפי שנתבקש)
            df_findings = pd.DataFrame(findings_data)
            df_findings.to_csv(args.output, index=False, encoding='utf-8-sig')
            
            print(f"[+] Audit report saved to: {args.output}")
            db.log_activity("Run Audit", f"Completed: {len(findings)} findings saved.", "System")
            support_logger.process("Audit completed with findings", findings_count=len(findings), output_path=args.output)
        else:
            print("[+] Audit completed. No issues found.")
            db.log_activity("Run Audit", "Completed: No findings found.", "System")
            support_logger.process("Audit completed with no findings", output_path=args.output)

        print("--- Process Finished ---")
    except Exception as error:
        support_logger.error("Unhandled CLI exception during audit run", exception=error, data_dir=args.data_dir, period=args.period)
        raise

if __name__ == "__main__":
    # וודא שתיקיות הבסיס קיימות
    if not os.path.exists("data_input"):
        os.makedirs("data_input")
        print("[Info] Created 'data_input' directory. Place your HANA CSVs there.")
        
    main()