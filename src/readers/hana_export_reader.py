"""Reader for SAP HANA semicolon-delimited export files."""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pandas as pd

from src.config import KNOWLEDGE_BASE_DIR, SLOT_KEYS


@dataclass
class ReadResult:
    slot_key: str | None
    df: pd.DataFrame | None
    warnings: list[str] = field(default_factory=list)
    source_path: str = ""


def _normalize_column_name(name: object) -> str:
    text = str(name).strip().replace('"', "").replace("\ufeff", "")
    return text.upper()


def _detect_delimiter(sample_text: str) -> str:
    first_line = sample_text.splitlines()[0] if sample_text else ""
    counts = {";": first_line.count(";"), ",": first_line.count(","), "\t": first_line.count("\t")}
    best = max(counts, key=counts.get)
    return best if counts[best] > 0 else ";"


def _load_slot_definitions() -> dict[str, dict]:
    path = KNOWLEDGE_BASE_DIR / "slot_definitions.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload.get("slots", {})
    except Exception:
        return {}


def _columns_satisfy_slot(df: pd.DataFrame, slot_def: dict) -> bool:
    columns = set(df.columns)
    required = slot_def.get("required_columns", [])
    if any(col not in columns for col in required):
        return False

    for group in slot_def.get("required_any_groups", []):
        if not any(col in columns for col in group):
            return False
    return True


def _match_filename_to_slot(file_path: Path, slot_defs: dict[str, dict]) -> str | None:
    stem = file_path.stem.lower()
    for slot_key, slot_def in slot_defs.items():
        for pattern in slot_def.get("filename_patterns", []):
            if fnmatch.fnmatch(stem, pattern.lower()):
                return slot_key
    return None


def detect_slot_from_dataframe(df: pd.DataFrame, file_path: Path | None = None) -> str | None:
    slot_defs = _load_slot_definitions()
    compatible: list[str] = []
    for slot_key, slot_def in slot_defs.items():
        if _columns_satisfy_slot(df, slot_def):
            compatible.append(slot_key)

    if len(compatible) == 1:
        return compatible[0]

    if file_path is not None:
        filename_slot = _match_filename_to_slot(file_path, slot_defs)
        if filename_slot and filename_slot in compatible:
            return filename_slot
        if filename_slot and not compatible:
            return filename_slot

    if compatible:
        return compatible[0]
    return None


def detect_slot_from_file(file_path: str | Path) -> str | None:
    result = read_hana_export(file_path)
    return result.slot_key


def _strip_leading_index_column(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    first_column = _normalize_column_name(df.columns[0])
    if first_column == "" or first_column.startswith("UNNAMED"):
        return df.iloc[:, 1:].copy()
    return df


def _clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [_normalize_column_name(col) for col in df.columns]
    df = _strip_leading_index_column(df)

    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(
                lambda value: value.strip().replace('"', "") if isinstance(value, str) else value
            )
    return df


def read_hana_export(file_path: str | Path) -> ReadResult:
    path = Path(file_path)
    warnings: list[str] = []

    if not path.exists():
        return ReadResult(slot_key=None, df=None, warnings=[f"קובץ לא נמצא: {path}"], source_path=str(path))

    raw_text = path.read_text(encoding="utf-8-sig", errors="replace")
    delimiter = _detect_delimiter(raw_text)

    try:
        df = pd.read_csv(
            path,
            sep=delimiter,
            engine="python",
            quotechar='"',
            skipinitialspace=True,
            encoding="utf-8-sig",
        )
    except Exception as exc:
        return ReadResult(
            slot_key=None,
            df=None,
            warnings=[f"שגיאת קריאה: {exc}"],
            source_path=str(path),
        )

    df = _clean_dataframe(df)
    if df.empty:
        warnings.append("הקובץ ריק לאחר ניקוי")

    slot_key = detect_slot_from_dataframe(df, path)
    if slot_key is None:
        warnings.append("לא זוהה slot תואם לקובץ")

    return ReadResult(slot_key=slot_key, df=df, warnings=warnings, source_path=str(path))


def read_exports(paths: Iterable[str | Path]) -> dict[str, ReadResult]:
    results: dict[str, ReadResult] = {}
    for file_path in paths:
        result = read_hana_export(file_path)
        if result.slot_key:
            results[result.slot_key] = result
    return results
