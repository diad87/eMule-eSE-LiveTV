//this file is part of eMule — eSE RTMP Ingest (FFmpeg-based)
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "RTMPIngest.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CRTMPIngest::CRTMPIngest()
	: m_hFFmpegProcess(NULL)
	, m_hWatcherThread(NULL)
	, m_bRunning(false)
	, m_bStopWatcher(false)
	, m_nPort(1935)
	, m_nSegments(0)
{
}

CRTMPIngest::~CRTMPIngest()
{
	Stop();
}

CString CRTMPIngest::FindFFmpeg()
{
	// 1. Check eMule's own directory
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	CString exeDir(szPath);
	int pos = exeDir.ReverseFind(_T('\\'));
	if (pos > 0) {
		exeDir = exeDir.Left(pos + 1);
		CString ffPath = exeDir + _T("ffmpeg.exe");
		if (GetFileAttributes(ffPath) != INVALID_FILE_ATTRIBUTES)
			return ffPath;
	}

	// 2. Check common install paths
	static const LPCTSTR paths[] = {
		_T("C:\\ffmpeg\\bin\\ffmpeg.exe"),
		_T("C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe"),
		_T("C:\\Program Files (x86)\\ffmpeg\\bin\\ffmpeg.exe"),
	};
	for (auto& p : paths) {
		if (GetFileAttributes(p) != INVALID_FILE_ATTRIBUTES)
			return CString(p);
	}

	// 3. Try PATH (CreateProcess will resolve it)
	return _T("ffmpeg.exe");
}

CString CRTMPIngest::GetRTMPUrl() const
{
	CString url;
	url.Format(_T("rtmp://localhost:%u/live/stream"), m_nPort);
	return url;
}

bool CRTMPIngest::Start(UINT rtmpPort, UINT bitrate, const CString& outputDir, ChunkCallback cb)
{
	if (m_bRunning)
		return false;

	m_nPort = rtmpPort;
	m_strOutputDir = outputDir;
	m_callback = cb;
	m_nSegments = 0;

	// Ensure output directory exists
	CreateDirectory(outputDir, NULL);

	// Clean any leftover .ts files
	CString pattern = outputDir + _T("\\*.ts");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(pattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			DeleteFile(outputDir + _T("\\") + fd.cFileName);
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	// Clean m3u8
	DeleteFile(outputDir + _T("\\stream.m3u8"));

	// Build FFmpeg command line
	// FFmpeg listens on RTMP port and outputs HLS segments
	CString ffmpegExe = FindFFmpeg();
	CString cmdLine;
	cmdLine.Format(
		_T("\"%s\" -loglevel warning -listen 1 -i rtmp://0.0.0.0:%u/live/stream ")
		_T("-c:v copy -c:a copy ")
		_T("-f hls -hls_time 2 -hls_list_size 10 ")
		_T("-hls_flags delete_segments+append_list ")
		_T("-hls_segment_filename \"%s\\seg_%%05d.ts\" ")
		_T("\"%s\\stream.m3u8\""),
		(LPCTSTR)ffmpegExe, rtmpPort,
		(LPCTSTR)outputDir, (LPCTSTR)outputDir
	);

	// Launch FFmpeg process
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE; // Hidden window

	PROCESS_INFORMATION pi = {};
	BOOL ok = CreateProcess(
		NULL,
		cmdLine.GetBuffer(),
		NULL, NULL, FALSE,
		CREATE_NO_WINDOW,
		NULL,
		outputDir,
		&si,
		&pi
	);
	cmdLine.ReleaseBuffer();

	if (!ok) {
		DWORD err = GetLastError();
		CString msg;
		msg.Format(_T("Failed to start FFmpeg (error %u). Make sure ffmpeg.exe is in PATH or eMule directory."), err);
		AddLogLine(true, _T("eSE RTMP: %s"), (LPCTSTR)msg);
		return false;
	}

	CloseHandle(pi.hThread);
	m_hFFmpegProcess = pi.hProcess;
	m_bRunning = true;
	m_bStopWatcher = false;

	m_strRTMPUrl = GetRTMPUrl();

	AddLogLine(false, _T("eSE RTMP: Listening on %s (FFmpeg PID %u)"),
		(LPCTSTR)m_strRTMPUrl, pi.dwProcessId);

	// Start watcher thread
	m_hWatcherThread = CreateThread(NULL, 0, WatcherThread, this, 0, NULL);

	return true;
}

bool CRTMPIngest::StartScreenCapture(UINT bitrate, const CString& outputDir, ChunkCallback cb)
{
	if (m_bRunning)
		return false;

	m_strOutputDir = outputDir;
	m_callback = cb;
	m_nSegments = 0;
	m_nPort = 0;

	// Ensure output directory exists
	CreateDirectory(outputDir, NULL);

	// Clean leftovers
	CString pattern = outputDir + _T("\\*.ts");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(pattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			DeleteFile(outputDir + _T("\\") + fd.cFileName);
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	DeleteFile(outputDir + _T("\\stream.m3u8"));

	// For screen capture: use CRF (constant quality) at native resolution
	// CRF 20 = high quality, 23 = default, lower = better quality
	UINT crf = 23;
	if (bitrate >= 8000) crf = 18;      // 4K setting -> near-lossless
	else if (bitrate >= 5000) crf = 20;  // FHD -> high quality
	else if (bitrate >= 3000) crf = 23;  // HD -> good quality
	else crf = 28;                       // SD -> decent quality

	// Build FFmpeg command: capture desktop via gdigrab (native resolution, CRF quality)
	CString ffmpegExe = FindFFmpeg();
	CString cmdLine;
	cmdLine.Format(
		_T("\"%s\" -loglevel warning ")
		_T("-f gdigrab -framerate 30 -i desktop ")
		_T("-c:v libx264 -preset ultrafast -tune zerolatency -g 120 ")
		_T("-crf %u -maxrate %uk -bufsize %uk ")
		_T("-an ")
		_T("-f hls -hls_time 4 -hls_list_size 8 ")
		_T("-hls_flags delete_segments ")
		_T("-hls_segment_filename \"%s\\seg_%%05d.ts\" ")
		_T("\"%s\\stream.m3u8\""),
		(LPCTSTR)ffmpegExe,
		crf, bitrate * 2, bitrate * 4,
		(LPCTSTR)outputDir, (LPCTSTR)outputDir
	);

	// Launch FFmpeg process (hidden)
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION pi = {};
	BOOL created = CreateProcess(NULL, cmdLine.GetBuffer(), NULL, NULL,
		FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	cmdLine.ReleaseBuffer();

	if (!created) {
		AddLogLine(true, _T("eSE Screen: Failed to start FFmpeg for screen capture."));
		return false;
	}

	CloseHandle(pi.hThread);
	m_hFFmpegProcess = pi.hProcess;
	m_bRunning = true;
	m_bStopWatcher = false;

	// Start watcher thread
	m_hWatcherThread = CreateThread(NULL, 0, WatcherThread, this, 0, NULL);

	AddLogLine(false, _T("eSE Screen: Capturing desktop at native resolution, CRF %u"), crf);
	return true;
}

bool CRTMPIngest::StartMediaFile(const CString& filePath, UINT bitrate, const CString& outputDir, ChunkCallback cb)
{
	if (m_bRunning)
		return false;

	m_strOutputDir = outputDir;
	m_callback = cb;
	m_nSegments = 0;
	m_nPort = 0;

	// Verify file exists
	if (GetFileAttributes(filePath) == INVALID_FILE_ATTRIBUTES) {
		AddLogLine(true, _T("eSE Media: File not found: %s"), (LPCTSTR)filePath);
		return false;
	}

	// Ensure output directory exists
	CreateDirectory(outputDir, NULL);

	// Clean leftovers (all HLS files)
	CString patternTs = outputDir + _T("\\*.ts");
	CString patternM3u8 = outputDir + _T("\\*.m3u8");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(patternTs, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do { DeleteFile(outputDir + _T("\\") + fd.cFileName); } while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	hFind = FindFirstFile(patternM3u8, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do { DeleteFile(outputDir + _T("\\") + fd.cFileName); } while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}

	// Probe audio tracks: use temp file redirect (pipes unreliable on Windows)
	CString ffmpegExe = FindFFmpeg();
	CString probeFile = outputDir + _T("\\probe_out.txt");
	DeleteFile(probeFile);

	// Build: ffmpeg -i "file" -hide_banner 2>"probe_out.txt"
	// Use cmd /c to get stderr redirect
	CString probeCmd;
	probeCmd.Format(_T("cmd /c \"\"%s\" -i \"%s\" -hide_banner 2>\"%s\"\""),
		(LPCTSTR)ffmpegExe, (LPCTSTR)filePath, (LPCTSTR)probeFile);

	STARTUPINFO siProbe = {};
	siProbe.cb = sizeof(siProbe);
	siProbe.dwFlags = STARTF_USESHOWWINDOW;
	siProbe.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION piProbe = {};
	CreateProcess(NULL, probeCmd.GetBuffer(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &siProbe, &piProbe);
	probeCmd.ReleaseBuffer();
	WaitForSingleObject(piProbe.hProcess, 10000);
	CloseHandle(piProbe.hProcess);
	CloseHandle(piProbe.hThread);

	// Read probe output from file
	char probeBuf[8192] = {};
	HANDLE hProbeFile = CreateFile(probeFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hProbeFile != INVALID_HANDLE_VALUE) {
		DWORD probeRead = 0;
		ReadFile(hProbeFile, probeBuf, sizeof(probeBuf) - 1, &probeRead, NULL);
		CloseHandle(hProbeFile);
	}
	DeleteFile(probeFile);

	// Parse audio streams: look for "Stream #0:N(lang): Audio:"
	CStringA probeOutput(probeBuf);
	int nAudioTracks = 0;
	CStringA audioLangs[8]; // max 8 audio tracks
	int pos = 0;
	while ((pos = probeOutput.Find("Audio:", pos)) != -1) {
		// Extract language from "Stream #0:N(lang):"
		int streamPos = probeOutput.ReverseFind('(');  // find nearest ( before pos
		// Search backwards from pos for "(xxx)"
		int p = pos;
		CStringA lang = "und";
		while (p > 0 && probeOutput[p] != '\n') p--;
		int langStart = probeOutput.Find('(', p);
		int langEnd = probeOutput.Find(')', langStart);
		if (langStart > 0 && langEnd > langStart && langEnd < pos) {
			lang = probeOutput.Mid(langStart + 1, langEnd - langStart - 1);
		}
		if (nAudioTracks < 8) {
			audioLangs[nAudioTracks] = lang;
			nAudioTracks++;
		}
		pos++;
	}

	AddLogLine(false, _T("eSE Media: Found %d audio track(s)"), nAudioTracks);

	// Build FFmpeg command with proper stream mapping
	CString cmdLine;
	if (nAudioTracks >= 2) {
		// Multi-audio: use -var_stream_map to generate master playlist with audio renditions
		CString mapArgs;
		CString varMap;
		for (int i = 0; i < nAudioTracks && i < 8; i++) {
			CString m; m.Format(_T("-map 0:a:%d "), i);
			mapArgs += m;
		}
		// Build var_stream_map: "v:0,agroup:audio a:0,agroup:audio,language:eng,name:eng a:1,agroup:audio,language:spa,name:spa"
		varMap = _T("v:0,agroup:audio");
		for (int i = 0; i < nAudioTracks && i < 8; i++) {
			CString entry;
			entry.Format(_T(" a:%d,agroup:audio,language:%s,name:%s"), i,
				(LPCTSTR)CString(audioLangs[i]), (LPCTSTR)CString(audioLangs[i]));
			varMap += entry;
		}

		cmdLine.Format(
			_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
			_T("-i \"%s\" ")
			_T("-map 0:v:0 %s-sn ")
			_T("-c:v libx264 -preset ultrafast -tune zerolatency -g 120 ")
			_T("-b:v %uk -maxrate %uk -bufsize %uk ")
			_T("-c:a aac -ac 2 -ar 44100 -b:a 128k ")
			_T("-var_stream_map \"%s\" ")
			_T("-master_pl_name stream.m3u8 ")
			_T("-f hls -hls_time 4 -hls_list_size 8 ")
			_T("-hls_flags delete_segments ")
			_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
			_T("\"%s\\stream_%%v.m3u8\""),
			(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
			(LPCTSTR)mapArgs,
			bitrate, bitrate * 2, bitrate * 4,
			(LPCTSTR)varMap,
			(LPCTSTR)outputDir, (LPCTSTR)outputDir
		);
	} else {
		// Single audio or no audio: simple HLS
		cmdLine.Format(
			_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
			_T("-i \"%s\" ")
			_T("-map 0:v:0 -map 0:a? -sn ")
			_T("-c:v libx264 -preset ultrafast -tune zerolatency -g 120 ")
			_T("-b:v %uk -maxrate %uk -bufsize %uk ")
			_T("-c:a aac -ac 2 -ar 44100 -b:a 128k ")
			_T("-f hls -hls_time 4 -hls_list_size 8 ")
			_T("-hls_flags delete_segments ")
			_T("-hls_segment_filename \"%s\\seg_%%05d.ts\" ")
			_T("\"%s\\stream.m3u8\""),
			(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
			bitrate, bitrate * 2, bitrate * 4,
			(LPCTSTR)outputDir, (LPCTSTR)outputDir
		);
	}

	// Launch FFmpeg process (hidden)
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION pi = {};
	BOOL created = CreateProcess(NULL, cmdLine.GetBuffer(), NULL, NULL,
		FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	cmdLine.ReleaseBuffer();

	if (!created) {
		AddLogLine(true, _T("eSE Media: Failed to start FFmpeg for file broadcast."));
		return false;
	}

	CloseHandle(pi.hThread);
	m_hFFmpegProcess = pi.hProcess;
	m_bRunning = true;
	m_bStopWatcher = false;

	// Start watcher thread
	m_hWatcherThread = CreateThread(NULL, 0, WatcherThread, this, 0, NULL);

	AddLogLine(false, _T("eSE Media: Broadcasting file at %uk: %s"), bitrate, (LPCTSTR)filePath);
	return true;
}

bool CRTMPIngest::StartTestPattern(UINT bitrate, const CString& outputDir, ChunkCallback cb)
{
	if (m_bRunning)
		return false;

	m_strOutputDir = outputDir;
	m_callback = cb;
	m_nSegments = 0;
	m_nPort = 0; // No RTMP port for test pattern

	// Ensure output directory exists
	CreateDirectory(outputDir, NULL);

	// Clean leftovers
	CString pattern = outputDir + _T("\\*.ts");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(pattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			DeleteFile(outputDir + _T("\\") + fd.cFileName);
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	DeleteFile(outputDir + _T("\\stream.m3u8"));

	// Choose resolution based on bitrate
	LPCTSTR resolution = _T("1280x720");
	if (bitrate <= 1500) resolution = _T("854x480");
	else if (bitrate <= 3000) resolution = _T("1280x720");
	else if (bitrate <= 5000) resolution = _T("1920x1080");
	else resolution = _T("2560x1440");

	// Build FFmpeg command: generate test pattern with color bars + timestamp
	CString ffmpegExe = FindFFmpeg();
	CString cmdLine;
	cmdLine.Format(
		_T("\"%s\" -loglevel warning -re ")
		_T("-f lavfi -i testsrc2=size=%s:rate=30 ")
		_T("-f lavfi -i sine=frequency=440:sample_rate=44100 ")
		_T("-c:v libx264 -preset ultrafast -tune zerolatency -g 120 ")
		_T("-b:v %uk -maxrate %uk -bufsize %uk ")
		_T("-c:a aac -b:a 128k ")
		_T("-f hls -hls_time 4 -hls_list_size 8 ")
		_T("-hls_flags delete_segments ")
		_T("-hls_segment_filename \"%s\\seg_%%05d.ts\" ")
		_T("\"%s\\stream.m3u8\""),
		(LPCTSTR)ffmpegExe, resolution,
		bitrate, bitrate * 2, bitrate * 4,
		(LPCTSTR)outputDir, (LPCTSTR)outputDir
	);

	// Launch FFmpeg process (hidden)
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION pi = {};
	BOOL ok = CreateProcess(
		NULL, cmdLine.GetBuffer(),
		NULL, NULL, FALSE,
		CREATE_NO_WINDOW,
		NULL, outputDir, &si, &pi
	);
	cmdLine.ReleaseBuffer();

	if (!ok) {
		DWORD err = GetLastError();
		AddLogLine(true, _T("eSE TestPattern: Failed to start FFmpeg (error %u)"), err);
		return false;
	}

	CloseHandle(pi.hThread);
	m_hFFmpegProcess = pi.hProcess;
	m_bRunning = true;
	m_bStopWatcher = false;

	AddLogLine(false, _T("eSE TestPattern: Generating %s @ %u kbps (FFmpeg PID %u)"),
		resolution, bitrate, pi.dwProcessId);

	// Start watcher thread (same as RTMP — watches for .ts segments)
	m_hWatcherThread = CreateThread(NULL, 0, WatcherThread, this, 0, NULL);

	return true;
}

void CRTMPIngest::Stop()
{
	if (!m_bRunning)
		return;

	m_bStopWatcher = true;

	// Terminate FFmpeg process
	if (m_hFFmpegProcess) {
		TerminateProcess(m_hFFmpegProcess, 0);
		WaitForSingleObject(m_hFFmpegProcess, 3000);
		CloseHandle(m_hFFmpegProcess);
		m_hFFmpegProcess = NULL;
	}

	// Wait for watcher thread
	if (m_hWatcherThread) {
		WaitForSingleObject(m_hWatcherThread, 5000);
		CloseHandle(m_hWatcherThread);
		m_hWatcherThread = NULL;
	}

	m_bRunning = false;
	AddLogLine(false, _T("eSE RTMP: Stopped."));
}

DWORD WINAPI CRTMPIngest::WatcherThread(LPVOID param)
{
	CRTMPIngest* pThis = reinterpret_cast<CRTMPIngest*>(param);
	pThis->WatcherLoop();
	return 0;
}

void CRTMPIngest::WatcherLoop()
{
	// Watch the output directory for new .ts segment files.
	// When a new segment appears, read it and pass to the callback.

	// Wait for FFmpeg to start producing segments
	Sleep(2000);

	// Find the NEWEST segment (skip old backlog to avoid catch-up storm)
	UINT lastSeg = 0;
	int waitCount = 0;

	// Scan directory for highest existing segment number
	WIN32_FIND_DATA fd;
	CString searchPattern;
	searchPattern.Format(_T("%s\\seg_*.ts"), (LPCTSTR)m_strOutputDir);
	HANDLE hFind = FindFirstFile(searchPattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		UINT maxSeg = 0;
		do {
			// Parse segment number from filename: seg_NNNNN.ts
			CString name(fd.cFileName);
			int uscore = name.Find(_T('_'));
			int dot = name.Find(_T('.'));
			if (uscore >= 0 && dot > uscore) {
				UINT segNum = (UINT)_ttoi(name.Mid(uscore + 1, dot - uscore - 1));
				if (segNum > maxSeg)
					maxSeg = segNum;
			}
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
		lastSeg = maxSeg; // Start from the newest, not oldest
	}

	UINT bufferSeq = 0; // Our own counter starting at 0 for the LiveChunkBuffer
	AddLogLine(false, _T("eSE Watcher: Starting at FFmpeg segment %u"), lastSeg);

	while (!m_bStopWatcher) {
		// Check if FFmpeg is still alive
		if (WaitForSingleObject(m_hFFmpegProcess, 0) == WAIT_OBJECT_0) {
			// FFmpeg exited — could be OBS disconnected or an error
			if (!m_bStopWatcher) {
				AddLogLine(true, _T("eSE RTMP: FFmpeg process exited unexpectedly."));
			}
			break;
		}

		// Look for the next expected segment file
		CString segFile;
		segFile.Format(_T("%s\\seg_%05u.ts"), (LPCTSTR)m_strOutputDir, lastSeg);

		DWORD attr = GetFileAttributes(segFile);
		if (attr != INVALID_FILE_ATTRIBUTES) {
			// Wait a tiny bit for FFmpeg to finish writing
			Sleep(200);

			// Read the segment
			HANDLE hFile = CreateFile(segFile, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, 0, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				DWORD fileSize = GetFileSize(hFile, NULL);
				if (fileSize > 0 && fileSize < 10 * 1024 * 1024) { // Max 10 MB per segment
					BYTE* buffer = new BYTE[fileSize];
					DWORD bytesRead = 0;
					if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) && bytesRead == fileSize) {
						m_nSegments++;
						if (m_callback) {
							// Use bufferSeq (0-based) not lastSeg (FFmpeg's raw number)
							m_callback(buffer, fileSize, bufferSeq);
						}
						AddLogLine(false, _T("eSE Watcher: Fed seg %u (ffmpeg %u, %u KB)"),
							bufferSeq, lastSeg, fileSize / 1024);
						bufferSeq++;
					}
					delete[] buffer;
				}
				CloseHandle(hFile);
			}

			lastSeg++;
			waitCount = 0;
		}
		else {
			// No new segment yet — poll every 200ms
			Sleep(200);
			waitCount++;
			// If stuck for 10+ seconds, re-scan directory for new segments
			// (FFmpeg delete_segments may have skipped past our counter)
			if (waitCount > 50) {
				waitCount = 0;
				hFind = FindFirstFile(searchPattern, &fd);
				if (hFind != INVALID_HANDLE_VALUE) {
					UINT maxSeg = 0;
					do {
						CString name(fd.cFileName);
						int uscore = name.Find(_T('_'));
						int dot = name.Find(_T('.'));
						if (uscore >= 0 && dot > uscore) {
							UINT segNum = (UINT)_ttoi(name.Mid(uscore + 1, dot - uscore - 1));
							if (segNum > maxSeg)
								maxSeg = segNum;
						}
					} while (FindNextFile(hFind, &fd));
					FindClose(hFind);
					if (maxSeg > lastSeg) {
						AddLogLine(false, _T("eSE Watcher: Skipping to segment %u (was at %u)"),
							maxSeg, lastSeg);
						lastSeg = maxSeg;
					}
				}
			}
		}
	}
}
