import pandas as pd

from core.analyzer import AuditAnalyzer


BASE_CONFIG = {
    "critical_users": ["SYSTEM"],
    "critical_privileges": ["ROLE ADMIN", "USER ADMIN", "INIFILE ADMIN"],
    "privilege_rules": {
        "flag_grant_option_on_critical": True,
        "business_schema_patterns": ["SYS_BIC", "*HDI*", "HDI_*"],
        "business_object_privileges": ["SELECT", "INSERT", "UPDATE", "DELETE"],
        "exclude_schema_patterns": ["_SYS_*", "SYS", "SYSTEM"],
    },
    "password_policy_defaults": {},
    "ini_security_defaults": [],
    "critical_roles": [],
    "audit_event_keywords": ["CREATE USER", "ALTER USER", "GRANT ROLE", "AUDIT POLICY"],
}


def _run_privilege_checks(df_privs, extra_frames=None):
    analyzer = AuditAnalyzer(config=BASE_CONFIG, whitelist=[])
    frames = {"EFFECTIVE_PRIVILEGE_GRANTEES": df_privs}
    if extra_frames:
        frames.update(extra_frames)
    return analyzer.run_all_checks(frames, period_id="2026-Q2")


def test_critical_privilege_to_non_dba_is_flagged():
    df_privs = pd.DataFrame([
        {"GRANTEE": "ALICE", "PRIVILEGE": "USER ADMIN", "GRANTEE_TYPE": "USER", "IS_GRANTABLE": "FALSE"},
    ])
    findings = _run_privilege_checks(df_privs)
    assert any(
        "USER ADMIN" in finding.title and "ALICE" in finding.title and "ADMIN OPTION" not in finding.title
        for finding in findings
        if finding.status == "Non-Compliant"
    )


def test_critical_privilege_to_dba_is_not_flagged():
    df_privs = pd.DataFrame([
        {"GRANTEE": "SYSTEM", "PRIVILEGE": "USER ADMIN", "GRANTEE_TYPE": "USER", "IS_GRANTABLE": "FALSE"},
    ])
    findings = _run_privilege_checks(df_privs)
    assert not any(
        "USER ADMIN" in finding.title and finding.status == "Non-Compliant" and "ADMIN OPTION" not in finding.title
        for finding in findings
    )


def test_grant_option_on_critical_flags_dba_too():
    df_privs = pd.DataFrame([
        {"GRANTEE": "SYSTEM", "PRIVILEGE": "ROLE ADMIN", "GRANTEE_TYPE": "USER", "IS_GRANTABLE": "TRUE"},
    ])
    findings = _run_privilege_checks(df_privs)
    assert any(
        "ADMIN OPTION" in finding.title and "ROLE ADMIN" in finding.title and finding.status == "Non-Compliant"
        for finding in findings
    )


def test_business_schema_dml_flagged():
    df_privs = pd.DataFrame([
        {
            "GRANTEE": "ALICE",
            "PRIVILEGE": "SELECT",
            "GRANTEE_TYPE": "USER",
            "SCHEMA_NAME": "SYS_BIC",
            "IS_GRANTABLE": "FALSE",
        },
    ])
    findings = _run_privilege_checks(df_privs)
    assert any(
        "schema עסקי SYS_BIC" in finding.title and finding.status == "Non-Compliant"
        for finding in findings
    )


def test_internal_sys_schema_not_flagged():
    df_privs = pd.DataFrame([
        {
            "GRANTEE": "ALICE",
            "PRIVILEGE": "SELECT",
            "GRANTEE_TYPE": "USER",
            "SCHEMA_NAME": "_SYS_STATISTICS",
            "IS_GRANTABLE": "FALSE",
        },
    ])
    findings = _run_privilege_checks(df_privs)
    assert not any(
        "schema עסקי" in finding.title and finding.status == "Non-Compliant"
        for finding in findings
    )


def test_business_schema_dml_on_dba_not_flagged():
    df_privs = pd.DataFrame([
        {
            "GRANTEE": "SYSTEM",
            "PRIVILEGE": "INSERT",
            "GRANTEE_TYPE": "USER",
            "SCHEMA_NAME": "SYS_BIC",
            "IS_GRANTABLE": "FALSE",
        },
    ])
    findings = _run_privilege_checks(df_privs)
    assert not any(
        "schema עסקי SYS_BIC" in finding.title and finding.status == "Non-Compliant"
        for finding in findings
    )


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
