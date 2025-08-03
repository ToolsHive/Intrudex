#define MyAppName "Intrudex-Client"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ToolsHive, Inc."
#define MyAppURL "https://github.com/ToolsHive/Intrudex/"
#define MyAppExeName "Intrudex_Client.exe"
#define MyAppServiceName "IntrudexClientService"
#define MyAppAssocName MyAppName
#define MyAppAssocExt ".myp"
#define MyAppAssocKey StringChange(MyAppAssocName, " ", "") + MyAppAssocExt

[Setup]
AppId={{F599BB8F-FF0F-4965-B2C3-D46682D7DBF5}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesAssociations=yes
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=.
OutputBaseFilename=Intrudex-Client-Setup-v{#MyAppVersion}
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start Intrudex Client after installation"; GroupDescription: "Startup options:"; Flags: unchecked
Name: "registerservice"; Description: "Register Intrudex Client as a Windows Service (requires admin)"; GroupDescription: "Service Options:"; Flags: unchecked

[Files]
Source: "Intrudex-Client\build\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "Intrudex-Client\build\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Intrudex-Client\build\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Intrudex-Client\build\*.dll"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocExt}\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocKey}"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}"; ValueType: string; ValueName: ""; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; ValueType: string; ValueName: "UninstallString"; ValueData: """{uninstallexe}"""

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:ProgramOnTheWeb,{#MyAppName}}"; Filename: "{#MyAppURL}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Start the app if selected
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Intrudex Client now"; Flags: nowait postinstall skipifsilent; Tasks: autostart

; Register the EXE as a system service (if selected)
; Assumes the EXE can run as a service and doesn't terminate immediately
Filename: "sc.exe"; Parameters: "create {#MyAppServiceName} binPath= ""{app}\{#MyAppExeName}"" DisplayName= ""Intrudex Client Service"" start= auto"; StatusMsg: "Registering as system service..."; Flags: runhidden runascurrentuser; Tasks: registerservice