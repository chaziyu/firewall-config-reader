; Inno Setup script for Firewall Config Reader
; Builds a per-user (or optional all-users) Windows installer from the PyInstaller --onedir output.

#ifndef AppVersion
  #define AppVersion "2.4.0"
#endif

#define AppName "Firewall Config Reader"
#define AppPublisher "Firewall Config Reader"
#define AppExeName "FirewallConfigReader.exe"

[Setup]
; Stable GUID so newer installers upgrade the existing installation in-place.
AppId={{C4D7E8A1-3B52-4F69-9E18-7A2C6D4B8F30}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
DisableProgramGroupPage=yes
; Allow standard users to install to %LocalAppData%\Programs without admin rights,
; while still offering an "All users" choice when elevated.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
CloseApplicationsFilter={#AppExeName}
RestartApplications=no
OutputDir=..\..\dist
OutputBaseFilename=FirewallConfigReader-Setup-{#AppVersion}
SetupIconFile=..\..\scripts\assets\app.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Remove stale PyInstaller _internal files before installing an updated version.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\..\dist\FirewallConfigReader\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
