"""AL-01 — audit policy enabled validator."""
from __future__ import annotations

from copy import deepcopy

from core.analyzer import AuditAnalyzer
from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, slot_loaded, tag_findings

_AUDIT_INI_KEYS = {"global_auditing_state"}


def validate_audit_policy_enabled(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    config = deepcopy(settings)
    ini_defaults = [
        entry
        for entry in config.get("ini_security_defaults", [])
        if str(entry.get("key", "")).strip().lower() in _AUDIT_INI_KEYS
    ]
    config["ini_security_defaults"] = ini_defaults

    analyzer = AuditAnalyzer(config=config, whitelist=whitelist)
    if slot_loaded(frames, "M_INIFILE_CONTENTS"):
        analyzer.analyze_ini_configuration(frames["M_INIFILE_CONTENTS"], period_id)
    else:
        analyzer.findings.append(
            Finding(
                period_id=period_id,
                category="Audit Config",
                title="קלט M_INIFILE_CONTENTS חסר",
                description="לא הוטען M_INIFILE_CONTENTS ולכן לא ניתן לאמת global_auditing_state.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="M_INIFILE_CONTENTS",
            )
        )

    if slot_loaded(frames, "AUDIT_POLICIES"):
        analyzer.analyze_audit_policies(frames["AUDIT_POLICIES"], period_id)
    else:
        analyzer.findings.append(
            Finding(
                period_id=period_id,
                category="Audit Config",
                title="קלט AUDIT_POLICIES חסר",
                description="לא הוטענו מדיניות Audit ולכן לא ניתן לאמת מדיניות פעילה.",
                risk_level="High",
                status="Missing Evidence",
                source_slot="AUDIT_POLICIES",
            )
        )

    # AUDIT_TRAIL is optional in Sprint 1 — enrich when present, skip hard failure when absent.
    if slot_loaded(frames, "AUDIT_TRAIL"):
        analyzer.analyze_audit_trail(frames["AUDIT_TRAIL"], period_id)

    return tag_findings(list(analyzer.findings), control_meta)
