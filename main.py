import os
import argparse
import pandas as pd
from pathlib import Path

from DatabaseManager import DatabaseManager
from core.importer import DataImporter
from core.analyzer import AuditAnalyzer
from core.process_logger import (
    close_active_run,
    get_process_logger,
    install_excepthook,
    register_atexit_close,
    setup_process_logging,
)

PROJECT_ROOT = Path(__file__).resolve().parent


def main():
    setup_process_logging(PROJECT_ROOT, triggered_by="CLI")
    install_excepthook()
    register_atexit_close()
    plog = get_process_logger()

    parser = argparse.ArgumentParser(description="SAP HANA ITGC Audit Tool (Python CLI)")
    parser.add_argument("--data_dir", type=str, default="data_input", help="Path to the directory containing CSV exports")
    parser.add_argument("--period", type=str, default="2025-Q1", help="Audit period identifier (e.g., 2025-Q1)")
    parser.add_argument("--output", type=str, default="audit_report.csv", help="Output file name for the findings")

    args = parser.parse_args()

    print("--- SAP HANA ITGC Audit Engine Started ---")
    if plog is not None:
        plog.info(
            "CLI audit engine started",
            f"data_dir={args.data_dir}; period={args.period}; output={args.output}",
        )

    try:
        db = DatabaseManager()
        importer = DataImporter(config_path="config/settings.json")

        whitelist = db.get_whitelist()
        config = importer.config

        print(f"[*] Importing CSV files from: {args.data_dir}")
        data_frames = importer.identify_and_load(args.data_dir)
        if plog is not None:
            plog.info(
                "CSV import completed",
                f"loaded={len(data_frames)}; sources={', '.join(sorted(data_frames.keys()))}",
            )

        if not data_frames:
            print("[!] No data loaded. Please check the data_dir and file mappings.")
            db.log_activity("Run Audit", "Failed: No data loaded", "System")
            if plog is not None:
                plog.fail("Audit run", "No compatible CSV files were loaded")
            close_active_run("Fail")
            return

        print("[*] Running audit checks...")
        if plog is not None:
            plog.info("Analysis start", f"period={args.period}")
        analyzer = AuditAnalyzer(config=config, whitelist=whitelist)
        findings = analyzer.run_all_checks(data_frames, period_id=args.period)

        if findings:
            print(f"[!] Found {len(findings)} issues.")

            findings_data = [vars(f) for f in findings]

            db.save_findings(findings_data)

            df_findings = pd.DataFrame(findings_data)
            df_findings.to_csv(args.output, index=False, encoding="utf-8-sig")

            print(f"[+] Audit report saved to: {args.output}")
            db.log_activity("Run Audit", f"Completed: {len(findings)} findings saved.", "System")
            if plog is not None:
                plog.info("Analysis end", f"findings={len(findings)}; output={args.output}")
        else:
            print("[+] Audit completed. No issues found.")
            db.log_activity("Run Audit", "Completed: No findings found.", "System")
            if plog is not None:
                plog.info("Analysis end", f"findings=0; output={args.output}")

        print("--- Process Finished ---")
        close_active_run("Success")
    except Exception as error:
        if plog is not None:
            plog.fail(
                "Unhandled CLI exception during audit run",
                f"period={args.period}",
                exc=error,
            )
        close_active_run("Fail")
        raise


if __name__ == "__main__":
    if not os.path.exists("data_input"):
        os.makedirs("data_input")
        print("[Info] Created 'data_input' directory. Place your HANA CSVs there.")

    main()
