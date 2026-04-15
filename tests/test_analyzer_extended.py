import pandas as pd

from core.analyzer import AuditAnalyzer


BASE_CONFIG = {
    "critical_users": ["SYSTEM"],
    "critical_privileges": ["ROLE ADMIN", "USER ADMIN", "INIFILE ADMIN"],
    "password_policy_defaults": {},
    "ini_security_defaults": [],
    "critical_roles": [],
    "audit_event_keywords": ["CREATE USER", "ALTER USER", "GRANT ROLE", "AUDIT POLICY"],
}


def test_role_assignment_inheriting_critical_privilege_is_flagged():
    analyzer = AuditAnalyzer(config=BASE_CONFIG, whitelist=[])
    df_roles = pd.DataFrame([
        {"GRANTEE": "ALICE", "ROLE_NAME": "SECURITY_ROLE"}
    ])
    df_privs = pd.DataFrame([
        {"GRANTEE": "SECURITY_ROLE", "PRIVILEGE": "ROLE ADMIN"}
    ])

    findings = analyzer.run_all_checks(
        {
            "GRANTED_ROLES": df_roles,
            "EFFECTIVE_PRIVILEGE_GRANTEES": df_privs,
        },
        period_id="2026-Q2",
    )

    assert any(
        finding.source_slot == "GRANTED_ROLES" and "SECURITY_ROLE" in finding.title
        for finding in findings
    )


def test_audit_trail_with_admin_event_is_captured():
    analyzer = AuditAnalyzer(config=BASE_CONFIG, whitelist=[])
    df_audit_trail = pd.DataFrame([
        {"USER_NAME": "ADMIN1", "ACTION": "CREATE USER", "STATUS": "SUCCESS"}
    ])

    findings = analyzer.run_all_checks(
        {
            "AUDIT_TRAIL": df_audit_trail,
        },
        period_id="2026-Q2",
    )

    assert any(
        finding.source_slot == "AUDIT_TRAIL" and finding.status == "Compliant"
        for finding in findings
    )


def test_missing_recommended_sources_are_reported():
    analyzer = AuditAnalyzer(config=BASE_CONFIG, whitelist=[])
    findings = analyzer.run_all_checks({}, period_id="2026-Q2")

    assert any(
        finding.source_slot == "GRANTED_ROLES" and finding.status == "Missing Evidence"
        for finding in findings
    )
    assert any(
        finding.source_slot == "AUDIT_TRAIL" and finding.status == "Missing Evidence"
        for finding in findings
    )


def test_ini_minimum_rule_detects_non_compliance():
    config = dict(BASE_CONFIG)
    config["ini_security_defaults"] = [
        {
            "file_name": "indexserver.ini",
            "section": "password policy",
            "key": "minimal_password_length",
            "expected_value": 8,
            "comparison_rule": "Minimum",
            "risk_level": "High",
            "title": "Minimal password length must be at least 8",
        }
    ]

    analyzer = AuditAnalyzer(config=config, whitelist=[])
    df_ini = pd.DataFrame([
        {"FILE_NAME": "indexserver.ini", "SECTION": "password policy", "KEY": "minimal_password_length", "VALUE": 6}
    ])

    findings = analyzer.run_all_checks({"M_INIFILE_CONTENTS": df_ini}, period_id="2026-Q2")

    assert any(
        finding.source_slot == "M_INIFILE_CONTENTS" and finding.status == "Non-Compliant"
        for finding in findings
    )


def test_ini_extract_without_file_name_column_is_supported():
    config = dict(BASE_CONFIG)
    config["ini_security_defaults"] = [
        {
            "file_name": "global.ini",
            "section": "auditing configuration",
            "key": "global_auditing_state",
            "expected_value": "true",
            "comparison_rule": "Exact",
            "risk_level": "High",
            "title": "Global auditing must be enabled",
        }
    ]

    analyzer = AuditAnalyzer(config=config, whitelist=[])
    df_ini = pd.DataFrame([
        {"SECTION": "auditing configuration", "KEY": "global_auditing_state", "VALUE": "TRUE"}
    ])

    findings = analyzer.run_all_checks({"M_INIFILE_CONTENTS": df_ini}, period_id="2026-Q2")

    assert any(
        finding.source_slot == "M_INIFILE_CONTENTS" and finding.status == "Compliant"
        for finding in findings
    )
