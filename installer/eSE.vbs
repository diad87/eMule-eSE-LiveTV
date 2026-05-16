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
    shell.Run """" & emulePath & """ -AutoStart", 0, False
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
