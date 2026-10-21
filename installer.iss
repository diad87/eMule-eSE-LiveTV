[Setup]
AppName=eSE Live TV
AppVersion=9.1.0-beta.2
AppPublisher=eSE Project
DefaultDirName={localappdata}\eSE-Live
DefaultGroupName=eSE Live TV
UninstallDisplayIcon={app}\emule.exe
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir=.\Output
OutputBaseFilename=eSE-Live-Installer-x64
;SetupIconFile=compiler:SetupClassicIcon.ico
PrivilegesRequired=admin
DisableWelcomePage=no
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Files]
; Coge toda la carpeta eSE-Package (incluyendo node, ffmpeg, config, emule.exe, eSE...)
Source: "eSE-Package\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Acceso directo en Escritorio y Menu de Inicio
Name: "{autodesktop}\eSE Live TV"; Filename: "{app}\emule.exe"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\eSE Live TV"; Filename: "{app}\emule.exe"; WorkingDir: "{app}"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
; --- 1. CONFIGURACIÓN DEL FIREWALL SILENCIOSA ---
; eMule C++ Engine (TCP/UDP)
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""eSE Live TV Engine"" dir=in action=allow program=""{app}\emule.exe"" enable=yes"; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""eSE Live TV Engine"" dir=out action=allow program=""{app}\emule.exe"" enable=yes"; Flags: runhidden
; The dashboard binds to loopback by default. Do not create a broad firewall
; exception for Node; remote access is an explicit authenticated opt-in.

; --- 2. LANZAR eMule AL TERMINAR DE INSTALAR (el usuario pulsa el botón eSE para el panel web) ---
Filename: "{app}\emule.exe"; WorkingDir: "{app}"; Description: "Launch eSE Live TV Now"; Flags: nowait postinstall

[UninstallRun]
; --- 3. LIMPIEZA DE FIREWALL AL DESINSTALAR ---
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""eSE Live TV Engine"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""eSE Node Server"""; Flags: runhidden
