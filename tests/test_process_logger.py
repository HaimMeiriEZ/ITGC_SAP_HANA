"""Tests for methodology process logger (format, retention, job_history)."""
from __future__ import annotations

import csv
import json
import os
import re
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from core import process_logger as pl
from core.process_logger import (
    ProcessLogger,
    close_active_run,
    get_process_logger,
    load_logging_config,
    purge_old_logs,
    setup_process_logging,
)


class TestProcessLogger(unittest.TestCase):
    def tearDown(self) -> None:
        close_active_run(None)
        pl._active_logger = None

    def _seed_install(self, root: Path, **overrides: object) -> Path:
        cfg = {
            "process_name": "ITGC_SAP_DB",
            "environment": "test",
            "log_folder_path": "data/logs",
            "log_retention_days": 90,
            "min_log_level": "INFO",
            "email_recipients_on_failure": [],
        }
        cfg.update(overrides)
        (root / "data" / "config").mkdir(parents=True, exist_ok=True)
        (root / "data" / "logs").mkdir(parents=True, exist_ok=True)
        (root / "data" / "job_history").mkdir(parents=True, exist_ok=True)
        (root / "data" / "config" / "logging_config.json").write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return root

    def test_header_and_success_fail_body_format(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = self._seed_install(Path(temp_dir))
            logger = setup_process_logging(root, triggered_by="CLI")
            self.assertIsInstance(logger, ProcessLogger)
            self.assertIs(get_process_logger(), logger)

            logger.info("Intake start", "USERS")
            try:
                raise ValueError("boom")
            except ValueError as exc:
                logger.fail("Intake", "slot failed", exc=exc)

            text = logger.log_path.read_text(encoding="utf-8")
            lines = [ln for ln in text.splitlines() if ln.strip()]
            self.assertGreaterEqual(len(lines), 3)

            header = lines[0]
            self.assertRegex(
                header,
                r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| Server: .+ \| "
                r"Triggered by: CLI \| Process: ITGC_SAP_DB \| Environment: test$",
            )

            success_lines = [ln for ln in lines[1:] if "Status: Success" in ln]
            self.assertTrue(success_lines)
            self.assertRegex(
                success_lines[0],
                r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| Step: .+ \| "
                r"Status: Success \| Level: INFO \| Result: .+$",
            )

            fail_lines = [ln for ln in lines if "Status: Fail" in ln]
            self.assertTrue(fail_lines)
            self.assertRegex(
                fail_lines[0],
                r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| Step: .+ \| "
                r"Status: Fail \| Level: ERROR \| Result: .+ \| Location: .+:\d+$",
            )
            self.assertIn("Location:", fail_lines[0])
            self.assertTrue(re.search(r"Location: [^|]+?:\d+", fail_lines[0]))

            self.assertTrue(logger.log_path.name.startswith("ITGC_SAP_DB_"))
            self.assertRegex(logger.log_path.name, r"^ITGC_SAP_DB_\d{8}_\d{6}\.txt$")
            self.assertEqual(
                logger.run_id,
                logger.log_path.stem.replace("ITGC_SAP_DB_", "", 1),
            )

            logger.close_run("Fail")

    def test_min_log_level_filters_debug(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = self._seed_install(Path(temp_dir), min_log_level="WARNING")
            logger = setup_process_logging(root, triggered_by="Desktop UI")
            logger.debug("hidden", "should not appear")
            logger.info("also hidden", "nope")
            logger.warning("visible", "warn me")
            text = logger.log_path.read_text(encoding="utf-8")
            self.assertNotIn("hidden", text)
            self.assertNotIn("also hidden", text)
            self.assertIn("visible", text)
            logger.close_run("Success")

    def test_purge_old_logs_only(self) -> None:
        with TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            log_dir.mkdir()
            old_file = log_dir / "ITGC_SAP_DB_20200101_120000.txt"
            new_file = log_dir / "ITGC_SAP_DB_20990101_120000.txt"
            old_file.write_text("old\n", encoding="utf-8")
            new_file.write_text("new\n", encoding="utf-8")
            old_mtime = (datetime.now() - timedelta(days=120)).timestamp()
            new_mtime = datetime.now().timestamp()

            os.utime(old_file, (old_mtime, old_mtime))
            os.utime(new_file, (new_mtime, new_mtime))

            deleted = purge_old_logs(log_dir, 90)
            self.assertEqual(deleted, 1)
            self.assertFalse(old_file.exists())
            self.assertTrue(new_file.exists())

    def test_job_history_columns_and_run_id(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = self._seed_install(Path(temp_dir))
            logger = setup_process_logging(root, triggered_by="CLI")
            run_id = logger.run_id
            log_path = logger.log_path
            logger.info("step", "ok")
            logger.close_run("Success")

            month = logger.run_started.strftime("%Y-%m")
            history_path = root / "data" / "job_history" / f"job_history_{month}.csv"
            self.assertTrue(history_path.is_file())
            with history_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            expected_cols = [
                "Run ID",
                "Date/Time",
                "Process Name",
                "Environment",
                "Status",
                "Log File Path",
                "Mail Sent",
                "Run Duration",
            ]
            self.assertEqual(list(row.keys()), expected_cols)
            self.assertEqual(row["Run ID"], run_id)
            self.assertEqual(row["Process Name"], "ITGC_SAP_DB")
            self.assertEqual(row["Environment"], "test")
            self.assertEqual(row["Status"], "Success")
            self.assertEqual(row["Log File Path"], str(log_path))
            self.assertEqual(row["Mail Sent"], "No")

    def test_load_logging_config(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = self._seed_install(Path(temp_dir), environment="prod", min_log_level="ERROR")
            cfg = load_logging_config(root)
            self.assertEqual(cfg["environment"], "prod")
            self.assertEqual(cfg["min_log_level"], "ERROR")


if __name__ == "__main__":
    unittest.main()
