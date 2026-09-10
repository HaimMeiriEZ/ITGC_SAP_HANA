# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir spec — ITGC SAP HANA DB (Windows)."""
from pathlib import Path

SPECPATH = Path(SPECPATH).resolve()
ROOT = SPECPATH

datas: list = []
binaries: list = []
hiddenimports: list = [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "win32com",
    "win32com.client",
    "pythoncom",
    "pywintypes",
    "openpyxl",
    "reportlab",
    "reportlab.pdfbase",
    "reportlab.pdfbase.ttfonts",
    "bidi",
    "pandas",
]

kb_dir = ROOT / "data" / "knowledge_base"
if kb_dir.is_dir():
    datas.append((str(kb_dir), "data/knowledge_base"))

config_dir = ROOT / "config"
if config_dir.is_dir():
    datas.append((str(config_dir), "config"))

assets_dir = ROOT / "gui" / "assets"
if assets_dir.is_dir():
    datas.append((str(assets_dir), "gui/assets"))

a = Analysis(
    [str(ROOT / "gui" / "app_new.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.Qt3DInput",
        "PySide6.Qt3DLogic",
        "PySide6.Qt3DAnimation",
        "PySide6.Qt3DExtras",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtBluetooth",
        "PySide6.QtNfc",
        "PySide6.QtPositioning",
        "PySide6.QtSensors",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "tkinter",
        "tkcalendar",
        "matplotlib",
        "pytest",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

icon_path = ROOT / "gui" / "assets" / "ayalon_logo.ico"
exe_kwargs = dict(
    exclude_binaries=True,
    name="ITGC_SAP_DB",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
if icon_path.is_file():
    exe_kwargs["icon"] = str(icon_path)

exe = EXE(
    pyz,
    a.scripts,
    [],
    **exe_kwargs,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ITGC_SAP_DB",
)
