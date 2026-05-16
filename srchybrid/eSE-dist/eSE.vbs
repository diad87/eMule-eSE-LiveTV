' eSE Launcher — eMule Streaming Engine
' Double-click to start eMule + eSE in background
' No console window, no taskbar clutter

Dim fso, shell, appDir, nodePath, ffmpegPath
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

appDir = fso.GetParentFolderName(WScript.ScriptFullName)

' --- Find node.exe ---
nodePath = appDir & "\node\node.exe"
If Not fso.FileExists(nodePath) Then
    ' Try system PATH
    nodePath = "node"
End If

' --- Find ffmpeg.exe ---
ffmpegPath = appDir & "\ffmpeg\ffmpeg.exe"
If Not fso.FileExists(ffmpegPath) Then
    ffmpegPath = appDir & "\ffmpeg.exe"
    If Not fso.FileExists(ffmpegPath) Then
        ' Add eSE dir to PATH so emule can find it later
        ffmpegPath = ""
    End If
End If

' --- Add ffmpeg dir to PATH if found ---
If ffmpegPath <> "" Then
    Dim ffmpegDir
    ffmpegDir = fso.GetParentFolderName(ffmpegPath)
    shell.Environment("Process")("PATH") = ffmpegDir & ";" & shell.Environment("Process")("PATH")
End If

' --- Configure eMule WebServer if not already set ---
Dim prefsFile, prefsContent
prefsFile = appDir & "\config\preferences.ini"
If fso.FileExists(prefsFile) Then
    ' Read current prefs
    Dim ts
    Set ts = fso.OpenTextFile(prefsFile, 1)
    prefsContent = ts.ReadAll
    ts.Close
    
    ' Enable WebServer if not set
    If InStr(prefsContent, "WebServerEnabled=") = 0 Then
        Set ts = fso.OpenTextFile(prefsFile, 8) ' Append
        ts.WriteLine ""
        ts.WriteLine "[WebServer]"
        ts.WriteLine "WebServerEnabled=1"
        ts.WriteLine "WebServerPort=4711"
        ts.WriteLine "Password=eSE"
        ts.Close
    End If
End If

' --- Start eMule minimized to tray ---
Dim emulePath
emulePath = appDir & "\emule.exe"
If fso.FileExists(emulePath) Then
    shell.Run """" & emulePath & """ -tray", 0, False
    WScript.Sleep 2000 ' Wait for eMule to start
End If

' --- Start eSE Node server ---
Dim serverJs
serverJs = appDir & "\eSE\server.js"
If fso.FileExists(serverJs) And fso.FileExists(nodePath) Then
    shell.Run """" & nodePath & """ """ & serverJs & """", 0, False
    WScript.Sleep 1000
End If

' --- Open browser to eSE ---
shell.Run "http://localhost:8080", 1, False

Set shell = Nothing
Set fso = Nothing
