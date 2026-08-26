"""IPE screenshot evidence storage and slot→control mapping."""
from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class IpeEvidenceRepository:
    """Copy IPE screenshots under data/evidence and persist metadata JSON."""

    _EVIDENCE_JSON = "ipe_evidence.json"

    def __init__(self, output_dir: Path, base_dir: Path) -> None:
        self._output_dir = Path(output_dir)
        self._evidence_dir = Path(base_dir) / "data" / "evidence"

    def _json_path(self) -> Path:
        return self._output_dir / self._EVIDENCE_JSON

    def load(self) -> Dict[str, List[Dict[str, Any]]]:
        path = self._json_path()
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(key): list(value) for key, value in raw.items() if isinstance(value, list)}

    def save(self, data: Dict[str, List[Dict[str, Any]]]) -> None:
        path = self._json_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def add_image(
        self,
        slot_key: str,
        source_path: Path,
        control_ids: List[str],
        data: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        source_path = Path(source_path)
        slot_dir = self._evidence_dir / slot_key
        slot_dir.mkdir(parents=True, exist_ok=True)

        image_id = str(uuid.uuid4())
        dest_path = slot_dir / f"{image_id}_{source_path.name}"
        shutil.copy2(source_path, dest_path)

        entry: Dict[str, Any] = {
            "id": image_id,
            "original_filename": source_path.name,
            "stored_path": str(dest_path),
            "control_ids": list(control_ids),
            "added_at": datetime.now().isoformat(timespec="seconds"),
        }
        data.setdefault(slot_key, []).append(entry)
        self.save(data)
        return entry

    def remove_image(
        self,
        slot_key: str,
        image_id: str,
        data: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        entries = data.get(slot_key, [])
        to_remove = next((entry for entry in entries if entry.get("id") == image_id), None)
        if to_remove is None:
            return
        stored = Path(str(to_remove.get("stored_path", "")))
        if stored.exists():
            try:
                stored.unlink()
            except OSError:
                pass
        data[slot_key] = [entry for entry in entries if entry.get("id") != image_id]
        if not data[slot_key]:
            data.pop(slot_key, None)
        self.save(data)

    def clear_slot(self, slot_key: str, data: Dict[str, List[Dict[str, Any]]]) -> None:
        for entry in list(data.get(slot_key, [])):
            self.remove_image(slot_key, str(entry.get("id", "")), data)

    def clear_all(self, data: Dict[str, List[Dict[str, Any]]] | None = None) -> Dict[str, List[Dict[str, Any]]]:
        """Remove all IPE evidence files and reset metadata (used on app start)."""
        working = data if data is not None else self.load()
        for slot_key in list(working.keys()):
            self.clear_slot(slot_key, working)
        working.clear()

        if self._evidence_dir.exists():
            for child in self._evidence_dir.iterdir():
                try:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    elif child.is_file():
                        child.unlink(missing_ok=True)
                except OSError:
                    pass

        self.save(working)
        return working


def build_slot_to_controls_mapping(catalog_by_id: Dict[str, Dict[str, Any]] | None = None) -> Dict[str, List[str]]:
    """Invert catalog required_slots into slot_key → [control_id, ...]."""
    if catalog_by_id is None:
        from src.persistence.controls_catalog_loader import load_controls_catalog

        catalog_by_id = load_controls_catalog()

    mapping: Dict[str, List[str]] = {}
    for control_id, entry in (catalog_by_id or {}).items():
        slots = entry.get("required_slots") or []
        if isinstance(slots, str):
            slots = [slots]
        for slot_key in slots:
            key = str(slot_key).strip()
            if not key:
                continue
            mapping.setdefault(key, [])
            if control_id not in mapping[key]:
                mapping[key].append(str(control_id))
    return mapping


def controls_for_slot(slot_key: str, catalog_by_id: Dict[str, Dict[str, Any]] | None = None) -> List[str]:
    return list(build_slot_to_controls_mapping(catalog_by_id).get(slot_key, []))


def primary_slot_for_control(control_id: str, catalog_by_id: Dict[str, Dict[str, Any]] | None = None) -> str | None:
    if catalog_by_id is None:
        from src.persistence.controls_catalog_loader import load_controls_catalog

        catalog_by_id = load_controls_catalog()
    entry = (catalog_by_id or {}).get(control_id) or {}
    slots = entry.get("required_slots") or []
    if isinstance(slots, str):
        slots = [slots]
    for slot_key in slots:
        key = str(slot_key).strip()
        if key:
            return key
    return None


# Internal dataframe aliases created in _persist_loaded_slot (not separate UI slots).
IPE_SLOT_ALIASES = {
    "AUDIT_LOG": "AUDIT_TRAIL",
    "EFFECTIVE_ROLES": "GRANTED_ROLES",
}


def resolve_primary_ipe_slot(
    slot_key: str,
    loaded_files: Dict[str, str] | None = None,
) -> str:
    """Map internal alias slots to the UI slot that owns IPE evidence."""
    key = str(slot_key or "").strip()
    if key in IPE_SLOT_ALIASES:
        return IPE_SLOT_ALIASES[key]

    # EFFECTIVE_PRIVILEGE_GRANTEES is both a UI slot and a fallback alias of GRANTED_PRIVILEGES.
    if key == "EFFECTIVE_PRIVILEGE_GRANTEES" and loaded_files:
        effective_file = loaded_files.get("EFFECTIVE_PRIVILEGE_GRANTEES")
        granted_file = loaded_files.get("GRANTED_PRIVILEGES")
        if granted_file and effective_file and effective_file == granted_file:
            return "GRANTED_PRIVILEGES"
    return key


def collect_missing_ipe_slots(
    loaded_slot_keys: List[str],
    ipe_evidence_data: Dict[str, List[Dict[str, Any]]],
    *,
    loaded_files: Dict[str, str] | None = None,
    slot_labels: Dict[str, str] | None = None,
) -> List[str]:
    """Return Hebrew messages for primary slots that lack IPE evidence."""
    messages: List[str] = []
    checked: set[str] = set()
    labels = slot_labels or {}
    loaded = set(loaded_slot_keys)

    for slot_key in loaded_slot_keys:
        if slot_key not in loaded:
            continue
        primary = resolve_primary_ipe_slot(slot_key, loaded_files)
        if primary in checked:
            continue
        checked.add(primary)
        if primary not in loaded and primary != slot_key:
            continue
        if ipe_evidence_data.get(primary):
            continue
        label = labels.get(primary) or labels.get(slot_key) or primary
        messages.append(f"{label}: חסרה ראיה IPE (צילום מסך)")
    return messages
