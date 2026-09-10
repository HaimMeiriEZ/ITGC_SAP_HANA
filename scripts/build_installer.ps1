#Requires -Version 5.1
# Build onedir package, then compile Inno Setup installer (ITGC_SAP_DB_Setup.exe).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "ITGC_SAP_DB.spec"))) {
    $Root = $PSScriptRoot
    if (-not (Test-Path (Join-Path $Root "ITGC_SAP_DB.spec"))) {
        $Root = (Get-Location).Path
    }
}

Set-Location $Root

function Find-ISCC {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 5\ISCC.exe"),
        (Join-Path $env:LocalAppData "Programs\Inno Setup 6\ISCC.exe")
    )
    foreach ($path in $candidates) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }
    $fromPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }
    return $null
}

$Iscc = Find-ISCC
if (-not $Iscc) {
    Write-Host "ERROR: Inno Setup compiler (ISCC.exe) not found."
    Write-Host "Install Inno Setup 6 from: https://jrsoftware.org/isinfo.php"
    Write-Host "Then re-run this script."
    exit 1
}
Write-Host "==> Using ISCC: $Iscc"

Write-Host "==> Building onedir package first..."
& (Join-Path $Root "scripts\build_exe.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "build_exe.ps1 failed with exit code $LASTEXITCODE"
}

$ExePath = Join-Path $Root "dist\ITGC_SAP_DB\ITGC_SAP_DB.exe"
if (-not (Test-Path $ExePath)) {
    throw "Missing $ExePath after build_exe.ps1"
}

$IssPath = Join-Path $Root "scripts\ITGC_SAP_DB.iss"
Write-Host "==> Compiling installer..."
& $Iscc $IssPath
if ($LASTEXITCODE -ne 0) {
    throw "ISCC failed with exit code $LASTEXITCODE"
}

$SetupPath = Join-Path $Root "dist\ITGC_SAP_DB_Setup.exe"
if (-not (Test-Path $SetupPath)) {
    throw "Installer output not found: $SetupPath"
}

Write-Host ""
Write-Host "Installer OK."
Write-Host "Setup: $SetupPath"
Write-Host "Also available (folder copy): $(Join-Path $Root 'dist\ITGC_SAP_DB')"
