"""Unit tests for CompensatingControlRepository and compensating_control_service."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.compensating_control_repository import CompensatingControlRepository
from core.compensating_control_service import (
    build_compensating_control_rows,
    control_has_findings,
    build_findings_brief_summary,
    build_findings_description,
)


# ---------------------------------------------------------------------------
# Repository tests
# ---------------------------------------------------------------------------

def _make_repo(tmp_path: Path) -> CompensatingControlRepository:
    return CompensatingControlRepository(
        output_dir=tmp_path / "output",
        base_dir=tmp_path,
    )


def test_repo_load_empty(tmp_path: Path):
    repo = _make_repo(tmp_path)
    assert repo.load() == {}


def test_repo_attach_file_copies_and_saves_json(tmp_path: Path):
    repo = _make_repo(tmp_path)
    source = tmp_path / "evidence.pdf"
    source.write_text("dummy content")

    data: dict = {}
    entry = repo.attach_file("DB-AM-01", source, data)

    assert entry["control_id"] == "DB-AM-01"
    assert entry["original_filename"] == "evidence.pdf"
    stored = Path(entry["stored_path"])
    assert stored.exists()
    assert stored.read_text() == "dummy content"

    json_path = tmp_path / "output" / "compensating_controls.json"
    assert json_path.exists()

    reloaded = repo.load()
    assert "DB-AM-01" in reloaded
    assert reloaded["DB-AM-01"]["original_filename"] == "evidence.pdf"


def test_repo_attach_file_replaces_previous(tmp_path: Path):
    repo = _make_repo(tmp_path)
    src1 = tmp_path / "v1.pdf"
    src2 = tmp_path / "v2.pdf"
    src1.write_text("v1")
    src2.write_text("v2")

    data: dict = {}
    entry1 = repo.attach_file("DB-AM-02", src1, data)
    old_stored = Path(entry1["stored_path"])

    entry2 = repo.attach_file("DB-AM-02", src2, data)

    assert not old_stored.exists(), "previous file should be deleted"
    assert Path(entry2["stored_path"]).read_text() == "v2"
    assert data["DB-AM-02"]["original_filename"] == "v2.pdf"


def test_repo_remove_file_deletes_and_updates_json(tmp_path: Path):
    repo = _make_repo(tmp_path)
    source = tmp_path / "doc.docx"
    source.write_text("content")

    data: dict = {}
    entry = repo.attach_file("DB-AM-03", source, data)
    stored = Path(entry["stored_path"])
    assert stored.exists()

    repo.remove_file("DB-AM-03", data)

    assert not stored.exists()
    assert "DB-AM-03" not in data
    assert "DB-AM-03" not in repo.load()


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------

def _finding(status: str, description: str = "some issue") -> SimpleNamespace:
    return SimpleNamespace(status=status, description=description)


def test_control_has_findings_compliant_only():
    assert not control_has_findings([_finding("Compliant"), _finding("Compliant")])


def test_control_has_findings_with_non_compliant():
    assert control_has_findings([_finding("Compliant"), _finding("Non-Compliant")])


def test_build_findings_brief_summary_no_findings():
    assert build_findings_brief_summary([_finding("Compliant")]) == "-"


def test_build_findings_brief_summary_counts_non_compliant():
    findings = [_finding("Non-Compliant"), _finding("Non-Compliant"), _finding("Compliant")]
    result = build_findings_brief_summary(findings)
    assert "2" in result


def test_build_findings_description_concatenates():
    findings = [
        _finding("Non-Compliant", "issue A"),
        _finding("Non-Compliant", "issue B"),
        _finding("Compliant", "ok"),
    ]
    desc = build_findings_description(findings)
    assert "issue A" in desc
    assert "issue B" in desc
    assert "ok" not in desc


def test_build_findings_description_deduplicates():
    findings = [_finding("Non-Compliant", "dup"), _finding("Non-Compliant", "dup")]
    desc = build_findings_description(findings)
    assert desc.count("dup") == 1


def test_build_compensating_control_rows_filters_compliant():
    summary = {"DB-AM-01": {}, "DB-AM-02": {}}
    details = {
        "DB-AM-01": [_finding("Non-Compliant", "problem")],
        "DB-AM-02": [_finding("Compliant")],
    }
    rows = build_compensating_control_rows(
        summary_records=summary,
        details_by_control=details,
        compensating_state={},
        get_meta_cb=lambda cid: {"risk_description": "risk", "description": "desc"},
        is_in_scope_cb=lambda cid: True,
    )
    control_ids = [r["control_id"] for r in rows]
    assert "DB-AM-01" in control_ids
    assert "DB-AM-02" not in control_ids


def test_build_compensating_control_rows_filters_out_of_scope():
    summary = {"DB-AM-01": {}}
    details = {"DB-AM-01": [_finding("Non-Compliant")]}
    rows = build_compensating_control_rows(
        summary_records=summary,
        details_by_control=details,
        compensating_state={},
        get_meta_cb=lambda cid: {"risk_description": "r", "description": "d"},
        is_in_scope_cb=lambda cid: False,
    )
    assert rows == []


def test_build_compensating_control_rows_includes_attachment():
    summary = {"DB-AM-01": {}}
    details = {"DB-AM-01": [_finding("Non-Compliant")]}
    attachment = {"control_id": "DB-AM-01", "original_filename": "doc.pdf"}
    rows = build_compensating_control_rows(
        summary_records=summary,
        details_by_control=details,
        compensating_state={"DB-AM-01": attachment},
        get_meta_cb=lambda cid: {"risk_description": "r", "description": "d"},
        is_in_scope_cb=lambda cid: True,
    )
    assert rows[0]["attachment"] == attachment
