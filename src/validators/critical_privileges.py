"""AM-04 — critical privileges validator."""
from __future__ import annotations

from core.analyzer import AuditAnalyzer
from DataClasses import Finding

from src.validators.base import ControlMeta, Frames, Settings, slot_loaded, tag_findings


def validate_critical_privileges(
    frames: Frames,
    settings: Settings,
    control_meta: ControlMeta,
    *,
    whitelist: list[dict] | None = None,
    period_id: str = "",
) -> list[Finding]:
    analyzer = AuditAnalyzer(config=settings, whitelist=whitelist)
    privilege_df = frames.get("EFFECTIVE_PRIVILEGE_GRANTEES")
    if privilege_df is None or privilege_df.empty:
        privilege_df = frames.get("GRANTED_PRIVILEGES")

    if privilege_df is None or privilege_df.empty:
        return tag_findings(
            [
                Finding(
                    period_id=period_id,
                    category="Access",
                    title="קלט הרשאות חסר",
                    description=(
                        "לא הוטען EFFECTIVE_PRIVILEGE_GRANTEES (או GRANTED_PRIVILEGES) "
                        "ולכן לא בוצעה בדיקת הרשאות קריטיות."
                    ),
                    risk_level="High",
                    status="Missing Evidence",
                    source_slot="EFFECTIVE_PRIVILEGE_GRANTEES",
                )
            ],
            control_meta,
        )

    analyzer.analyze_privileges(privilege_df, period_id)
    privilege_rules = analyzer._get_privilege_rules()
    if privilege_rules.get("flag_grant_option_on_critical", True):
        analyzer.analyze_grant_option_violations(privilege_df, period_id)
    analyzer.analyze_business_schema_privileges(privilege_df, period_id)

    # Optional role context when GRANTED_ROLES is loaded (catalog lists it as required).
    if slot_loaded(frames, "GRANTED_ROLES"):
        analyzer.analyze_role_assignments(frames["GRANTED_ROLES"], privilege_df, period_id)

    return tag_findings(list(analyzer.findings), control_meta)
