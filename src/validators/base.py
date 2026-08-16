"""Shared validator contract for catalog-driven controls."""
from __future__ import annotations

from typing import Any, Callable, Protocol

import pandas as pd

from DataClasses import Finding

Frames = dict[str, pd.DataFrame]
Settings = dict[str, Any]
ControlMeta = dict[str, Any]


class ValidatorFn(Protocol):
    def __call__(
        self,
        frames: Frames,
        settings: Settings,
        control_meta: ControlMeta,
        *,
        whitelist: list[dict] | None = None,
        period_id: str = "",
    ) -> list[Finding]:
        ...


ValidatorCallable = Callable[..., list[Finding]]


def tag_findings(findings: list[Finding], control_meta: ControlMeta) -> list[Finding]:
    control_id = str(control_meta.get("control_id") or "").strip() or None
    analysis_type = str(control_meta.get("analysis_type") or "").strip() or None
    for finding in findings:
        if control_id and not finding.control_id:
            finding.control_id = control_id
        if analysis_type and not finding.analysis_type:
            finding.analysis_type = analysis_type
    return findings


def slot_loaded(frames: Frames, slot_key: str) -> bool:
    frame = frames.get(slot_key)
    return frame is not None and not frame.empty
