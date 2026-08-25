"""Process logger aligned with Ez-ROI methodology (section 8 — log standards).

One log file per application run:
  ``{process_name}_{run_id}.txt`` under ``data/logs/``

Line format (body):
  ``YYYY-MM-DD HH:MM:SS | Step: … | Status: Success|Fail | Level: … | Result: …``
  Fail lines also include ``| Location: file:line``.

Do not write full PII in Result — callers should pass short summaries.
"""
from __future__ import annotations

import atexit
import csv
import json
import shutil
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

_LEVEL_ORDER = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

_FAIL_LEVELS = frozenset({"ERROR", "CRITICAL"})

_JOB_HISTORY_COLUMNS = [
    "Run ID",
    "Date/Time",
    "Process Name",
    "Environment",
    "Status",
    "Log File Path",
    "Mail Sent",
    "Run Duration",
]

_DEFAULT_CONFIG: dict[str, Any] = {
    "process_name": "ITGC_SAP_DB",
    "environment": "prod",
    "log_folder_path": "data/logs",
    "log_retention_days": 90,
    "min_log_level": "INFO",
    "email_recipients_on_failure": [],
}

_lock = threading.RLock()
_active_logger: "ProcessLogger | None" = None


def _now() -> datetime:
    return datetime.now()


def _format_ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _run_id_from(moment: datetime) -> str:
    return moment.strftime("%Y%m%d_%H%M%S")


def _location_from_exc(exc: BaseException | None = None) -> str:
    if exc is not None and exc.__traceback__ is not None:
        frames = traceback.extract_tb(exc.__traceback__)
        if frames:
            last = frames[-1]
            return f"{Path(last.filename).name}:{last.lineno}"
    frames = traceback.extract_stack()
    for frame in reversed(frames[:-1]):
        name = Path(frame.filename).name
        if name != "process_logger.py":
            return f"{name}:{frame.lineno}"
    return "unknown:0"


def get_install_root() -> Path:
    """Writable application root: folder of the EXE when frozen, else project root."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def ensure_logging_runtime(install_root: Path | None = None) -> Path:
    """Create logging dirs and seed logging_config.json once (never overwrite)."""
    root = Path(install_root) if install_root is not None else get_install_root()
    data_dir = root / "data"
    for sub in ("logs", "job_history", "config", "knowledge_base"):
        (data_dir / sub).mkdir(parents=True, exist_ok=True)

    kb_seed = data_dir / "knowledge_base" / "logging_config.json"
    dest_logging = data_dir / "config" / "logging_config.json"
    if not dest_logging.exists():
        if kb_seed.is_file():
            shutil.copy2(kb_seed, dest_logging)
        else:
            dest_logging.write_text(
                json.dumps(_DEFAULT_CONFIG, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    return root


def load_logging_config(install_root: Path) -> dict[str, Any]:
    """Load logging_config.json from data/config (seeded) or defaults."""
    candidates = [
        install_root / "data" / "config" / "logging_config.json",
        install_root / "data" / "knowledge_base" / "logging_config.json",
    ]
    merged = dict(_DEFAULT_CONFIG)
    for path in candidates:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(raw, dict):
            merged.update({k: v for k, v in raw.items() if v is not None})
            break
    return merged


def purge_old_logs(log_dir: Path, retention_days: int | None) -> int:
    """Delete ``*.txt`` log files older than *retention_days*. Returns count deleted."""
    if retention_days is None:
        return 0
    try:
        days = int(retention_days)
    except (TypeError, ValueError):
        return 0
    if days < 0:
        return 0
    if not log_dir.is_dir():
        return 0
    cutoff = _now() - timedelta(days=days)
    deleted = 0
    for path in log_dir.glob("*.txt"):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            continue
        if mtime < cutoff:
            try:
                path.unlink()
                deleted += 1
            except OSError:
                pass
    return deleted


class ProcessLogger:
    """Session-scoped methodology logger (one file per run)."""

    def __init__(
        self,
        *,
        install_root: Path,
        config: dict[str, Any],
        triggered_by: str,
        run_started: datetime,
        run_id: str,
        log_path: Path,
        handle: TextIO,
    ) -> None:
        self.install_root = Path(install_root)
        self.config = config
        self.triggered_by = triggered_by
        self.run_started = run_started
        self.run_id = run_id
        self.log_path = Path(log_path)
        self._handle = handle
        self._min_level = str(config.get("min_log_level") or "INFO").upper()
        self._closed = False
        self._had_failure = False
        self._fail_rows: list[str] = []
        self._mail_sent = "No"

    @property
    def process_name(self) -> str:
        return str(self.config.get("process_name") or "ITGC_SAP_DB")

    @property
    def environment(self) -> str:
        return str(self.config.get("environment") or "prod")

    def _should_write(self, level: str) -> bool:
        return _LEVEL_ORDER.get(level.upper(), 20) >= _LEVEL_ORDER.get(self._min_level, 20)

    def log_step(
        self,
        step: str,
        *,
        level: str = "INFO",
        result: str = "",
        status: str | None = None,
        location: str | None = None,
    ) -> None:
        """Append a methodology body line. Status defaults from level."""
        with _lock:
            if self._closed:
                return
            level_u = str(level or "INFO").upper()
            if level_u not in _LEVEL_ORDER:
                level_u = "INFO"
            if not self._should_write(level_u):
                return
            if status is None:
                status = "Fail" if level_u in _FAIL_LEVELS else "Success"
            status_norm = "Fail" if str(status).lower().startswith("fail") else "Success"
            if status_norm == "Fail":
                self._had_failure = True
                if not location:
                    location = _location_from_exc()
            parts = [
                _format_ts(_now()),
                f"Step: {step}",
                f"Status: {status_norm}",
                f"Level: {level_u}",
                f"Result: {result}",
            ]
            if status_norm == "Fail" and location:
                parts.append(f"Location: {location}")
            line = " | ".join(parts)
            try:
                self._handle.write(line + "\n")
                self._handle.flush()
            except OSError:
                return
            if status_norm == "Fail":
                self._fail_rows.append(line)

    def fail(
        self,
        step: str,
        result: str,
        *,
        exc: BaseException | None = None,
        level: str = "ERROR",
    ) -> None:
        """Log a Fail line with Location from *exc* or current stack."""
        location = _location_from_exc(exc)
        level_u = "CRITICAL" if str(level).upper() == "CRITICAL" else "ERROR"
        self.log_step(
            step,
            level=level_u,
            result=result,
            status="Fail",
            location=location,
        )

    def debug(self, step: str, result: str = "") -> None:
        self.log_step(step, level="DEBUG", result=result)

    def info(self, step: str, result: str = "") -> None:
        self.log_step(step, level="INFO", result=result)

    def warning(self, step: str, result: str = "") -> None:
        self.log_step(step, level="WARNING", result=result)

    def _append_job_history(self, final_status: str, mail_sent: str) -> None:
        history_dir = self.install_root / "data" / "job_history"
        history_dir.mkdir(parents=True, exist_ok=True)
        old_dir = history_dir / "job_history_old_files"
        old_dir.mkdir(parents=True, exist_ok=True)

        month_key = self.run_started.strftime("%Y-%m")
        history_path = history_dir / f"job_history_{month_key}.csv"

        for path in history_dir.glob("job_history_*.csv"):
            if path.name == history_path.name:
                continue
            try:
                target = old_dir / path.name
                if not target.exists():
                    path.replace(target)
            except OSError:
                pass

        duration_sec = max(0, int((_now() - self.run_started).total_seconds()))
        row = {
            "Run ID": self.run_id,
            "Date/Time": _format_ts(self.run_started),
            "Process Name": self.process_name,
            "Environment": self.environment,
            "Status": final_status,
            "Log File Path": str(self.log_path),
            "Mail Sent": mail_sent,
            "Run Duration": str(duration_sec),
        }

        for attempt in range(5):
            try:
                write_header = not history_path.exists() or history_path.stat().st_size == 0
                with history_path.open("a", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=_JOB_HISTORY_COLUMNS)
                    if write_header:
                        writer.writeheader()
                    writer.writerow(row)
                return
            except OSError:
                time.sleep(0.15 * (attempt + 1))

    def _try_failure_mail(self) -> str:
        recipients = self.config.get("email_recipients_on_failure") or []
        if not isinstance(recipients, list):
            recipients = [recipients]
        emails = [str(x).strip() for x in recipients if str(x).strip()]
        if not emails or not self._fail_rows:
            return "No"
        try:
            import win32com.client  # type: ignore[import-untyped]
        except ImportError:
            return "No"
        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            mail = outlook.CreateItem(0)
            mail.To = "; ".join(emails)
            mail.Subject = (
                f"[ITGC_SAP_DB] Failure — {self.process_name} ({self.environment}) "
                f"run {self.run_id}"
            )
            body_lines = [
                f"Process: {self.process_name}",
                f"Environment: {self.environment}",
                f"Run ID: {self.run_id}",
                f"Started: {_format_ts(self.run_started)}",
                "",
                "Failed steps:",
                *self._fail_rows,
                "",
                f"Log file: {self.log_path}",
            ]
            mail.Body = "\n".join(body_lines)
            if self.log_path.is_file():
                mail.Attachments.Add(str(self.log_path.resolve()))
            mail.Display(False)  # draft — user/support can send
            return "Yes"
        except Exception:
            return "No"

    def close_run(self, final_status: str | None = None) -> None:
        """Close the run log and append job_history (idempotent)."""
        with _lock:
            if self._closed:
                return
            status = final_status
            if status is None:
                status = "Fail" if self._had_failure else "Success"
            status_norm = "Fail" if str(status).lower().startswith("fail") else "Success"
            try:
                self.log_step(
                    "Run completed",
                    level="INFO" if status_norm == "Success" else "ERROR",
                    result=f"Session ended with status {status_norm}",
                    status=status_norm if status_norm == "Success" else "Fail",
                    location=_location_from_exc() if status_norm == "Fail" else None,
                )
            except Exception:
                pass
            mail_sent = "No"
            if self._had_failure or status_norm == "Fail":
                mail_sent = self._try_failure_mail()
            self._mail_sent = mail_sent
            try:
                self._handle.flush()
                self._handle.close()
            except OSError:
                pass
            self._closed = True
            self._append_job_history(status_norm, mail_sent)


def setup_process_logging(
    install_root: Path | None = None,
    *,
    triggered_by: str = "Desktop UI",
) -> ProcessLogger:
    """Start a new methodology run log for this process (replaces any prior active logger)."""
    global _active_logger

    root = ensure_logging_runtime(install_root or get_install_root())
    config = load_logging_config(root)
    rel_log_folder = str(config.get("log_folder_path") or "data/logs").replace("\\", "/")
    log_dir = root / rel_log_folder if not Path(rel_log_folder).is_absolute() else Path(rel_log_folder)
    log_dir.mkdir(parents=True, exist_ok=True)

    retention = config.get("log_retention_days", None)
    if retention is not None:
        try:
            purge_old_logs(log_dir, int(retention))
        except (TypeError, ValueError):
            pass

    started = _now()
    run_id = _run_id_from(started)
    process_name = str(config.get("process_name") or "ITGC_SAP_DB")
    log_path = log_dir / f"{process_name}_{run_id}.txt"
    handle = log_path.open("a", encoding="utf-8", newline="\n")

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    try:
        ip = socket.gethostbyname(hostname)
    except OSError:
        ip = "127.0.0.1"

    environment = str(config.get("environment") or "prod")
    header = (
        f"{_format_ts(started)} | Server: {ip} ({hostname}) | "
        f"Triggered by: {triggered_by} | Process: {process_name} | "
        f"Environment: {environment}"
    )
    handle.write(header + "\n")
    handle.flush()

    logger = ProcessLogger(
        install_root=root,
        config=config,
        triggered_by=triggered_by,
        run_started=started,
        run_id=run_id,
        log_path=log_path,
        handle=handle,
    )
    with _lock:
        previous = _active_logger
        _active_logger = logger
    if previous is not None and not previous._closed:
        try:
            previous.close_run()
        except Exception:
            pass

    logger.info("Logging started", f"Log file {log_path.name}")
    return logger


def get_process_logger() -> ProcessLogger | None:
    """Return the active session logger, if any."""
    return _active_logger


def close_active_run(final_status: str | None = None) -> None:
    logger = get_process_logger()
    if logger is not None:
        logger.close_run(final_status)


def install_excepthook() -> None:
    """Route uncaught exceptions to the process logger."""
    previous = sys.excepthook

    def _hook(exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        logger = get_process_logger()
        if logger is not None and exc is not None:
            try:
                logger.fail(
                    "Unhandled exception",
                    f"{exc_type.__name__}: {exc}",
                    exc=exc,
                    level="CRITICAL",
                )
                logger.close_run("Fail")
            except Exception:
                pass
        previous(exc_type, exc, tb)

    sys.excepthook = _hook

    if hasattr(threading, "excepthook"):
        previous_thread = threading.excepthook

        def _thread_hook(args) -> None:  # type: ignore[no-untyped-def]
            logger = get_process_logger()
            exc = getattr(args, "exc_value", None)
            exc_type = getattr(args, "exc_type", type(exc) if exc else Exception)
            if logger is not None and exc is not None:
                try:
                    logger.fail(
                        "Unhandled thread exception",
                        f"{getattr(exc_type, '__name__', 'Exception')}: {exc}",
                        exc=exc,
                        level="CRITICAL",
                    )
                except Exception:
                    pass
            previous_thread(args)

        threading.excepthook = _thread_hook  # type: ignore[assignment]


def register_atexit_close() -> None:
    atexit.register(lambda: close_active_run(None))
