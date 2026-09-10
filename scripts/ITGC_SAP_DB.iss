; Inno Setup 6 script — installer for ITGC SAP HANA DB
; Builds Setup that installs the PyInstaller onedir package to Local AppData
; (writable data/ next to the EXE; no admin required).
;
; Compile from project root via scripts\build_installer.ps1
; or: ISCC.exe scripts\ITGC_SAP_DB.iss

#define MyAppName "ITGC SAP HANA DB"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Ayalon"
#define MyAppExeName "ITGC_SAP_DB.exe"
; Fixed AppId for upgrades (do not change between releases)
#define MyAppId "{{A3F8E2C1-9B47-4D6A-8E5F-2C1D0B9A7E64}}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/HaimMeiriEZ/ITGC_SAP_HANA
DefaultDirName={localappdata}\ITGC_SAP_DB
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=ITGC_SAP_DB_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
UsePreviousAppDir=yes
; Source paths are relative to this .iss file (scripts\)
SourceDir=.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Application binaries (overwrite on upgrade)
Source: "..\dist\ITGC_SAP_DB\ITGC_SAP_DB.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\ITGC_SAP_DB\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs

; Seed knowledge_base — do not overwrite client edits on upgrade
Source: "..\dist\ITGC_SAP_DB\data\knowledge_base\*"; DestDir: "{app}\data\knowledge_base"; Flags: onlyifdoesntexist recursesubdirs createallsubdirs

; Client settings seed — only on first install
Source: "..\dist\ITGC_SAP_DB\config\settings.json"; DestDir: "{app}\config"; Flags: onlyifdoesntexist skipifsourcedoesntexist

[Dirs]
Name: "{app}\data\input"
Name: "{app}\data\output"
Name: "{app}\data\evidence"
Name: "{app}\data\compensating_controls"
Name: "{app}\data\knowledge_base"
Name: "{app}\data\logs"
Name: "{app}\data\job_history"
Name: "{app}\data\config"
Name: "{app}\config"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
