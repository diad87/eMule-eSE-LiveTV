; eSE — eMule Streaming Engine Installer
; Inno Setup 6+ script
; ZERO-SETUP philosophy: user downloads, double-clicks, everything works.
; No decisions. No config. Firewall + FFmpeg handled automatically.

#define AppName      "eSE - eMule Streaming Engine"
#define AppVersion   "0.70b-eSE6.2"
#define AppPublisher "eSE Project"
#define AppURL       "https://github.com/eSE-project"
#define AppExeName   "eSE.vbs"

[Setup]
AppId={{E5E-EMULE-STREAMING-ENGINE}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\eSE
DefaultGroupName={#AppName}
OutputDir=output
OutputBaseFilename=eSE_Setup_{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
SetupIconFile=..\srchybrid\res\Mule.ico
UninstallDisplayIcon={app}\emule.exe
LicenseFile=license.txt
DisableProgramGroupPage=yes
; Zero-setup: skip unnecessary wizard pages
DisableDirPage=auto
MinVersion=10.0

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Only cosmetic choice — desktop shortcut. Everything else is automatic.
Name: "desktopicon"; Description: "Crear acceso directo en el Escritorio"; GroupDescription: "Iconos adicionales:"; Flags: checked

[Files]
; eMule binary
Source: "..\srchybrid\x64\Release\emule.exe"; DestDir: "{app}"; Flags: ignoreversion

; Launcher
Source: "eSE.vbs"; DestDir: "{app}"; Flags: ignoreversion

; eSE server + UI
Source: "..\srchybrid\eSE\*.js"; DestDir: "{app}\eSE"; Flags: ignoreversion recursesubdirs
Source: "..\srchybrid\eSE\*.json"; DestDir: "{app}\eSE"; Flags: ignoreversion recursesubdirs
Source: "..\srchybrid\eSE\*.html"; DestDir: "{app}\eSE"; Flags: ignoreversion recursesubdirs
Source: "..\srchybrid\eSE\node_modules\*"; DestDir: "{app}\eSE\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Node.js portable
Source: "node\node.exe"; DestDir: "{app}\node"; Flags: ignoreversion

; Default config (only if first install — don't overwrite user's settings)
Source: "config\preferences.ini"; DestDir: "{app}\config"; Flags: onlyifdoesntexist

; FFmpeg bundled — zero-setup, no external download needed
Source: "ffmpeg\ffmpeg.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\eSE.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\emule.exe"
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\eSE.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\emule.exe"; Tasks: desktopicon

[Run]
; --- AUTOMATIC (always runs, no user choice) ---

; Firewall: allow eMule inbound
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""eSE eMule"" dir=in action=allow program=""{app}\emule.exe"" enable=yes profile=any"; StatusMsg: "Configurando firewall (eMule)..."; Flags: runhidden
; Firewall: allow Node inbound
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""eSE Node"" dir=in action=allow program=""{app}\node\node.exe"" enable=yes profile=any"; StatusMsg: "Configurando firewall (Node.js)..."; Flags: runhidden

; --- POST-INSTALL (user sees the final page) ---

; Launch eSE after install (checked by default — auto-opens browser via eSE.vbs)
Filename: "{sys}\wscript.exe"; Parameters: """{app}\eSE.vbs"""; Description: "Iniciar eSE ahora"; Flags: postinstall nowait skipifsilent; WorkingDir: "{app}"

[UninstallRun]
; Clean firewall rules on uninstall
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""eSE eMule"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""eSE Node"""; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}\eSE\node_modules"
Type: filesandordirs; Name: "{app}\node"

[Code]
// Kill running processes before install/uninstall to avoid file-lock errors
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec('taskkill', '/F /IM emule.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill', '/F /IM node.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec('taskkill', '/F /IM emule.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill', '/F /IM node.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
