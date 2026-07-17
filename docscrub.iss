; DocScrub Windows installer (Inno Setup 6 — free, jrsoftware.org)
; Compiled by build_windows.bat, which passes the version:
;   ISCC.exe /DMyAppVersion=0.5.0 docscrub.iss
; Produces: installer\DocScrub-Setup-<version>.exe

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppName "DocScrub"
#define MyAppPublisher "ValorOps"
#define MyAppURL "https://valorops.dev"
#define MyAppExeName "DocScrub.exe"

[Setup]
; Stable AppId so upgrades replace instead of duplicating
AppId={{7D1E9F2B-4C6A-4E8D-9B3F-2A8C51E04D7F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=installer
OutputBaseFilename=DocScrub-Setup-{#MyAppVersion}
SetupIconFile=assets\docscrub.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\DocScrub\*"; DestDir: "{app}"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
  Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; \
  Flags: nowait postinstall skipifsilent
