"""PP-01 — password policy baseline validator."""
from __future__ import annotations

from core.analyzer import AuditAnalyzer
from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, tag_findings


def validate_password_policy_baseline(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    analyzer = AuditAnalyzer(config=settings, whitelist=whitelist)
    analyzer.analyze_password_policy(frames.get("M_PASSWORD_POLICY"), period_id)
    return tag_findings(list(analyzer.findings), control_meta)
