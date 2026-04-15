import pandas as pd

from gui.app_new import AuditGUI


def _build_test_app():
    app = AuditGUI.__new__(AuditGUI)
    app.slot_metadata = {
        "M_PASSWORD_POLICY": {
            "label": "מדיניות סיסמאות",
            "required": ["PROPERTY", "VALUE"],
            "required_any": [],
        },
        "M_INIFILE_CONTENTS": {
            "label": "הקשחת תצורה",
            "required": [],
            "required_any": [
                ("SECTION", "SECTION_NAME"),
                ("KEY", "KEY_NAME", "PARAMETER_NAME", "PROPERTY"),
                ("VALUE", "CONFIGURED_VALUE", "CURRENT_VALUE"),
            ],
        },
    }
    return app


def test_password_policy_file_is_detected_for_correct_slot():
    app = _build_test_app()
    df = pd.DataFrame([
        {"PROPERTY": "minimal_password_length", "VALUE": 8}
    ])

    compatible_slots = app._find_compatible_slots(df)

    assert "M_PASSWORD_POLICY" in compatible_slots
    assert "M_INIFILE_CONTENTS" not in compatible_slots


def test_ini_file_without_file_name_is_detected_for_ini_slot():
    app = _build_test_app()
    df = pd.DataFrame([
        {"SECTION": "auditing configuration", "KEY": "global_auditing_state", "VALUE": "TRUE"}
    ])

    compatible_slots = app._find_compatible_slots(df)

    assert "M_INIFILE_CONTENTS" in compatible_slots
