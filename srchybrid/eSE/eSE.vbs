' eSE Launcher — Double-click to start eMule Streaming Engine
' Starts eMule minimized to tray + eSE web server
' No console window, no popups, just works.

Option Explicit

Dim fso, shell, appDir, emulePath, nodePath, serverPath, ffmpegPath
Dim nodeProc, emuleProc

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

' Resolve paths relative to this script
appDir = fso.GetParentFolderName(WScript.ScriptFullName)
emulePath = fso.BuildPath(appDir, "emule.exe")
nodePath = fso.BuildPath(appDir, "node\node.exe")
serverPath = fso.BuildPath(appDir, "eSE\server.js")

' === First-run setup: unblock files + firewall rules ===
' Windows marks downloaded files as blocked; this silently unblocks them
' and adds firewall rules so eMule can connect to the network.
Dim markerFile
markerFile = fso.BuildPath(appDir, ".unblocked")
If Not fso.FileExists(markerFile) Then
    On Error Resume Next
    ' Unblock all EXE/DLL files (remove Zone.Identifier ADS)
    shell.Run "powershell -NoProfile -WindowStyle Hidden -Command ""Get-ChildItem -Path '" & appDir & "' -Recurse -Include *.exe,*.dll | Unblock-File""", 0, True
    
    ' Add Windows Firewall rules (requires elevation — silent fail if denied)
    Dim fwCmd
    fwCmd = "powershell -NoProfile -WindowStyle Hidden -Command ""Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile -Command " & _
            "netsh advfirewall firewall add rule name=""""eMule eSE TCP"""" dir=in action=allow program=""""" & emulePath & """""  protocol=tcp; " & _
            "netsh advfirewall firewall add rule name=""""eMule eSE UDP"""" dir=in action=allow program=""""" & emulePath & """""  protocol=udp; " & _
            "netsh advfirewall firewall add rule name=""""eSE Server"""" dir=in action=allow program=""""" & fso.BuildPath(appDir, "ese-server.exe") & """""  protocol=tcp' 2>$null"""
    shell.Run fwCmd, 0, True

    ' Create marker so we only do this once
    Dim markerStream
    Set markerStream = fso.CreateTextFile(markerFile, True)
    markerStream.WriteLine "Files unblocked + firewall configured on " & Now
    markerStream.Close
    Set markerStream = Nothing
    On Error GoTo 0
End If

' === Auto-create desktop-friendly shortcut with eMule icon ===
Dim shortcutPath
shortcutPath = fso.BuildPath(appDir, "eSE LiveTV.lnk")
If Not fso.FileExists(shortcutPath) Then
    On Error Resume Next
    Dim lnk
    Set lnk = shell.CreateShortcut(shortcutPath)
    lnk.TargetPath = "wscript.exe"
    lnk.Arguments = """" & WScript.ScriptFullName & """"
    lnk.WorkingDirectory = appDir
    lnk.IconLocation = emulePath & ",0"
    lnk.Description = "eSE Live TV - eMule Streaming Engine"
    lnk.WindowStyle = 7  ' Minimized
    lnk.Save
    Set lnk = Nothing
    On Error GoTo 0
End If

' === Verify required files ===
If Not fso.FileExists(emulePath) Then
    MsgBox "No se encuentra emule.exe" & vbCrLf & "Esperado en: " & emulePath, vbCritical, "eSE"
    WScript.Quit 1
End If

If Not fso.FileExists(nodePath) Then
    MsgBox "No se encuentra Node.js" & vbCrLf & "Esperado en: " & nodePath, vbCritical, "eSE"
    WScript.Quit 1
End If

If Not fso.FileExists(serverPath) Then
    MsgBox "No se encuentra el servidor eSE" & vbCrLf & "Esperado en: " & serverPath, vbCritical, "eSE"
    WScript.Quit 1
End If

' === Check if FFmpeg is available ===
ffmpegPath = FindFFmpeg()
If ffmpegPath = "" Then
    ' Download FFmpeg automatically
    Dim msg
    msg = MsgBox("FFmpeg no encontrado. Es necesario para el streaming." & vbCrLf & vbCrLf & _
                 "¿Descargar FFmpeg automaticamente? (~80 MB)", vbYesNo + vbQuestion, "eSE Setup")
    If msg = vbYes Then
        DownloadFFmpeg
    End If
End If

' === Check if already running ===
If IsProcessRunning("emule.exe") Then
    ' eMule already running, just start/restart the web server
    KillProcess "node.exe"  ' kill old node if any
    WScript.Sleep 1000
End If

' === Start eMule (minimized to tray) ===
If Not IsProcessRunning("emule.exe") Then
    On Error Resume Next
    shell.Run """" & emulePath & """ -AutoStart", 0, False
    If Err.Number <> 0 Then
        MsgBox "Could not start emule.exe" & vbCrLf & vbCrLf & _
               "Windows SmartScreen or your antivirus may have blocked it." & vbCrLf & _
               "Right-click emule.exe → Properties → Unblock, then try again." & vbCrLf & vbCrLf & _
               "Error: " & Err.Description, vbCritical, "eSE"
        WScript.Quit 1
    End If
    On Error GoTo 0
    WScript.Sleep 3000  ' Wait for eMule to initialize WebServer
End If

' === Start eSE Node server ===
shell.CurrentDirectory = appDir
shell.Run """" & nodePath & """ """ & serverPath & """", 0, False
WScript.Sleep 2000

' === Open browser ===
shell.Run "http://localhost:8080", 1, False

' === Done — script exits, processes keep running ===
WScript.Quit 0


' ============ HELPER FUNCTIONS ============

Function FindFFmpeg()
    FindFFmpeg = ""
    
    ' Check in app directory
    Dim localFF
    localFF = fso.BuildPath(appDir, "ffmpeg.exe")
    If fso.FileExists(localFF) Then
        FindFFmpeg = localFF
        Exit Function
    End If
    
    ' Check in PATH
    Dim result
    On Error Resume Next
    shell.Run "ffmpeg -version", 0, True
    If Err.Number = 0 Then
        FindFFmpeg = "ffmpeg"
    End If
    On Error GoTo 0
    
    ' Check winget install location
    Dim wingetDir
    wingetDir = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Microsoft\WinGet\Packages"
    If fso.FolderExists(wingetDir) Then
        Dim folder, subfolder, file
        For Each folder In fso.GetFolder(wingetDir).SubFolders
            If InStr(LCase(folder.Name), "ffmpeg") > 0 Then
                ' Search recursively for ffmpeg.exe
                Dim ff
                ff = SearchFile(folder.Path, "ffmpeg.exe")
                If ff <> "" Then
                    FindFFmpeg = ff
                    Exit Function
                End If
            End If
        Next
    End If
End Function

Function SearchFile(dirPath, fileName)
    SearchFile = ""
    Dim f
    On Error Resume Next
    For Each f In fso.GetFolder(dirPath).Files
        If LCase(f.Name) = LCase(fileName) Then
            SearchFile = f.Path
            Exit Function
        End If
    Next
    For Each f In fso.GetFolder(dirPath).SubFolders
        Dim result
        result = SearchFile(f.Path, fileName)
        If result <> "" Then
            SearchFile = result
            Exit Function
        End If
    Next
    On Error GoTo 0
End Function

Sub DownloadFFmpeg()
    On Error Resume Next
    ' Use winget if available
    shell.Run "winget install --id Gyan.FFmpeg --accept-package-agreements --accept-source-agreements", 1, True
    If Err.Number <> 0 Then
        ' Fallback: open download page
        shell.Run "https://www.gyan.dev/ffmpeg/builds/", 1, False
        MsgBox "Descarga FFmpeg manualmente y colocalo en:" & vbCrLf & appDir, vbInformation, "eSE"
    End If
    On Error GoTo 0
End Sub

Function IsProcessRunning(processName)
    Dim objWMI, colProcesses
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colProcesses = objWMI.ExecQuery("SELECT * FROM Win32_Process WHERE Name='" & processName & "'")
    IsProcessRunning = (colProcesses.Count > 0)
End Function

Sub KillProcess(processName)
    On Error Resume Next
    Dim objWMI, colProcesses, proc
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colProcesses = objWMI.ExecQuery("SELECT * FROM Win32_Process WHERE Name='" & processName & "' AND CommandLine LIKE '%server.js%'")
    For Each proc In colProcesses
        proc.Terminate
    Next
    On Error GoTo 0
End Sub
