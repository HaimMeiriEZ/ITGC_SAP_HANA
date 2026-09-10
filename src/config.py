"""Project configuration — SAP HANA DB ITGC tool."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def is_frozen() -> bool:
    """True when running from a PyInstaller (or similar) bundled executable."""
    return bool(getattr(sys, "frozen", False))


def get_install_root() -> Path:
    """Writable application root: folder of the EXE when frozen, else project root."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_bundle_root() -> Path:
    """Read-only bundled resources (_MEIPASS when frozen, else project root)."""
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str | Path) -> Path:
    """Path to a bundled resource file (logo, seed JSON, etc.)."""
    return get_bundle_root().joinpath(*parts)


def knowledge_base_dir(install_root: Path | None = None) -> Path:
    """Writable knowledge_base under the install root (after seed)."""
    root = install_root or get_install_root()
    return root / "data" / "knowledge_base"


def default_db_path(install_root: Path | None = None) -> Path:
    """SQLite database next to the EXE / project root."""
    root = install_root or get_install_root()
    return root / "audit_system.db"


def ensure_runtime_data(install_root: Path | None = None) -> Path:
    """Create writable data dirs and seed knowledge_base / config / logging if missing.

    Does not overwrite existing client files.
    """
    root = install_root or get_install_root()
    data_dir = root / "data"
    for sub in (
        "input",
        "output",
        "evidence",
        "compensating_controls",
        "knowledge_base",
        "logs",
        "job_history",
        "config",
    ):
        (data_dir / sub).mkdir(parents=True, exist_ok=True)
    (root / "config").mkdir(parents=True, exist_ok=True)

    bundle = get_bundle_root()
    bundle_kb = bundle / "data" / "knowledge_base"
    dest_kb = data_dir / "knowledge_base"
    if bundle_kb.is_dir():
        for name in (
            "controls_catalog.json",
            "field_labels.json",
            "slot_definitions.json",
            "logging_config.json",
        ):
            src = bundle_kb / name
            dest = dest_kb / name
            if src.is_file() and not dest.exists():
                shutil.copy2(src, dest)

    logging_seed = dest_kb / "logging_config.json"
    if not logging_seed.exists():
        logging_seed = bundle_kb / "logging_config.json"
    dest_logging = data_dir / "config" / "logging_config.json"
    if logging_seed.is_file() and not dest_logging.exists():
        shutil.copy2(logging_seed, dest_logging)

    bundle_settings = bundle / "config" / "settings.json"
    dest_settings = root / "config" / "settings.json"
    if bundle_settings.is_file() and not dest_settings.exists():
        shutil.copy2(bundle_settings, dest_settings)

    return root


DOMAIN = "HANA_DB"

SLOT_KEYS = [
    "USERS",
    "M_PASSWORD_POLICY",
    "GRANTED_PRIVILEGES",
    "EFFECTIVE_PRIVILEGE_GRANTEES",
    "GRANTED_ROLES",
    "AUDIT_POLICIES",
    "AUDIT_TRAIL",
    "M_INIFILE_CONTENTS",
    "CONFIGURATION_PARAMETER_PROPERTIES",
]

# Lazy aliases so frozen installs resolve against the EXE folder after seed.
def __getattr__(name: str):
    if name == "PROJECT_ROOT":
        return get_install_root()
    if name == "KNOWLEDGE_BASE_DIR":
        return knowledge_base_dir()
    if name == "SAMPLES_DIR":
        return get_install_root() / "data" / "input" / "samples"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


SLOT_DEFAULT_CONTROLS: dict[str, list[str]] = {
    "USERS": [
        "DB-AM-01_PLACEHOLDER",
        "DB-AM-02_PLACEHOLDER",
        "DB-AM-03_PLACEHOLDER",
        "DB-AM-04_PLACEHOLDER",
        "DB-PP-02_PLACEHOLDER",
        "DB-UAR-01_PLACEHOLDER",
        "DB-UAR-02_PLACEHOLDER",
    ],
    "M_PASSWORD_POLICY": ["DB-PP-01_PLACEHOLDER"],
    "GRANTED_PRIVILEGES": ["DB-UAR-02_PLACEHOLDER"],
    "EFFECTIVE_PRIVILEGE_GRANTEES": [
        "DB-PP-02_PLACEHOLDER",
        "DB-AM-02_PLACEHOLDER",
        "DB-UAR-01_PLACEHOLDER",
        "DB-AM-04_PLACEHOLDER",
        "DB-AM-05_PLACEHOLDER",
        "DB-AM-06_PLACEHOLDER",
    ],
    "GRANTED_ROLES": ["DB-UAR-01_PLACEHOLDER", "DB-AM-04_PLACEHOLDER"],
    "AUDIT_POLICIES": ["DB-AL-01_PLACEHOLDER"],
    "AUDIT_TRAIL": ["DB-AL-01_PLACEHOLDER"],
    "M_INIFILE_CONTENTS": ["DB-AL-01_PLACEHOLDER"],
    "CONFIGURATION_PARAMETER_PROPERTIES": [],
}
