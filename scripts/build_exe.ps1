#Requires -Version 5.1
# Build Windows onedir package for ITGC SAP HANA DB (PyInstaller).
# Includes knowledge_base + config/settings.json.
# Excludes evidence, compensating controls, findings, and other runtime state.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "ITGC_SAP_DB.spec"))) {
    $Root = $PSScriptRoot
    if (-not (Test-Path (Join-Path $Root "ITGC_SAP_DB.spec"))) {
        $Root = (Get-Location).Path
    }
}

Set-Location $Root
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

Write-Host "==> Installing build dependency (pyinstaller)..."
& $Python -m pip install -q -r (Join-Path $Root "requirements-build.txt")

Write-Host "==> Cleaning previous build/dist for this app..."
$DistApp = Join-Path $Root "dist\ITGC_SAP_DB"
$BuildApp = Join-Path $Root "build\ITGC_SAP_DB"
if (Test-Path $DistApp) { Remove-Item -Recurse -Force $DistApp }
if (Test-Path $BuildApp) { Remove-Item -Recurse -Force $BuildApp }

Write-Host "==> Running PyInstaller (onedir)..."
& $Python -m PyInstaller --noconfirm --clean (Join-Path $Root "ITGC_SAP_DB.spec")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$DataRoot = Join-Path $DistApp "data"
$OutputDir = Join-Path $DataRoot "output"
$InputDir = Join-Path $DataRoot "input"
$EvidenceDir = Join-Path $DataRoot "evidence"
$CompDir = Join-Path $DataRoot "compensating_controls"
$KbDir = Join-Path $DataRoot "knowledge_base"
$LogsDir = Join-Path $DataRoot "logs"
$JobDir = Join-Path $DataRoot "job_history"
$ConfigDataDir = Join-Path $DataRoot "config"
$AppConfigDir = Join-Path $DistApp "config"
New-Item -ItemType Directory -Force -Path $OutputDir, $InputDir, $EvidenceDir, $CompDir, $KbDir, $LogsDir, $JobDir, $ConfigDataDir, $AppConfigDir | Out-Null

$SrcKb = Join-Path $Root "data\knowledge_base"
if (Test-Path $SrcKb) {
    foreach ($name in @("controls_catalog.json", "field_labels.json", "slot_definitions.json", "logging_config.json")) {
        $src = Join-Path $SrcKb $name
        if (Test-Path $src) {
            Copy-Item -Force $src (Join-Path $KbDir $name)
        }
    }
}

$SrcSettings = Join-Path $Root "config\settings.json"
if (Test-Path $SrcSettings) {
    Copy-Item -Force $SrcSettings (Join-Path $AppConfigDir "settings.json")
    Write-Host "==> Included config/settings.json"
} else {
    Write-Host "==> No config/settings.json found - client will start with defaults if seeded later"
}

$ExePath = Join-Path $DistApp "ITGC_SAP_DB.exe"
Write-Host ""
Write-Host "Build OK."
Write-Host "Package folder: $DistApp"
Write-Host "Run: $ExePath"
