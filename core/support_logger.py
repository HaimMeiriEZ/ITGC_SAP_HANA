from __future__ import annotations

from datetime import datetime
from pathlib import Path
import traceback
from typing import Any, Optional


class SupportLogger:
    """Simple UTF-8 support logging for process tracing and error investigation."""

    def __init__(self, log_dir: Optional[Path | str] = None):
        base_dir = Path(__file__).resolve().parents[1]
        self.log_dir = Path(log_dir) if log_dir else base_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.process_log_path = self.log_dir / "process.log"
        self.error_log_path = self.log_dir / "error.log"

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _format_context(self, **context: Any) -> str:
        clean_items = []
        for key, value in sorted(context.items()):
            if value is None:
                continue
            clean_items.append(f'{key}="{value}"')
        return " | ".join(clean_items)

    def _append_line(self, target_path: Path, level: str, message: str, **context: Any) -> None:
        context_text = self._format_context(**context)
        line = f"[{self._timestamp()}] [{level}] {message}"
        if context_text:
            line = f"{line} | {context_text}"
        with open(target_path, "a", encoding="utf-8") as log_file:
            log_file.write(line + "\n")

    def process(self, message: str, **context: Any) -> None:
        self._append_line(self.process_log_path, "PROCESS", message, **context)

    def error(self, message: str, exception: Exception | None = None, **context: Any) -> None:
        error_context = dict(context)
        if exception is not None:
            error_context["exception_type"] = type(exception).__name__
            error_context["exception_message"] = str(exception)
        self._append_line(self.error_log_path, "ERROR", message, **error_context)

        if exception is not None:
            with open(self.error_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(traceback.format_exc().rstrip() + "\n")

    def get_log_paths(self) -> dict[str, str]:
        return {
            "process": str(self.process_log_path),
            "error": str(self.error_log_path),
        }
