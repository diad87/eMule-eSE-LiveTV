//this file is part of eMule — eSE RTMP Ingest (FFmpeg-based)
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveDebugLog.h"
#include "RTMPIngest.h"
#include "Log.h"
#include <string>
#include <ws2tcpip.h>

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
	, m_nLastSourceMode(UINT_MAX)
	, m_nLastBitrate(0)
	, m_nRestarts(0)
	, m_dwLastRestartTick(0)
	, m_nPreferredVariant(2)  // v7.1.6: default = 720p, matches pre-7.1.6 behavior
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

CRTMPIngest::HwEncoder CRTMPIngest::DetectHwEncoder()
{
	// Cached on first call; subsequent calls return without re-probing.
	static HwEncoder s_cached = HWENC_UNKNOWN;
	if (s_cached != HWENC_UNKNOWN) return s_cached;

	CString ffmpegExe = FindFFmpeg();
	CString cmdLine; cmdLine.Format(_T("\"%s\" -hide_banner -encoders"), (LPCTSTR)ffmpegExe);

	// Pipe stdout+stderr to a single anonymous pipe.
	HANDLE hRead = NULL, hWrite = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		s_cached = HWENC_CPU_X264;
		return s_cached;
	}
	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = hWrite;
	si.hStdError  = hWrite;
	PROCESS_INFORMATION pi = {};

	BOOL ok = CreateProcess(NULL, cmdLine.GetBuffer(), NULL, NULL, TRUE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	cmdLine.ReleaseBuffer();
	CloseHandle(hWrite);
	if (!ok) {
		CloseHandle(hRead);
		s_cached = HWENC_CPU_X264;
		LIVE_LOG("HWENC", "Probe failed (CreateProcess) — falling back to libx264");
		return s_cached;
	}

	// Read all output (it's a few KB — fits easily in the pipe).
	std::string output;
	char buf[4096];
	DWORD got = 0;
	while (ReadFile(hRead, buf, sizeof(buf), &got, NULL) && got > 0)
		output.append(buf, got);
	CloseHandle(hRead);
	WaitForSingleObject(pi.hProcess, 5000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Priority: NVENC > QSV > AMF > x264. NVENC tends to give the best
	// quality + most concurrent sessions per chip.
	HwEncoder result = HWENC_CPU_X264;
	const char* tag = "libx264";
	if (output.find("h264_nvenc") != std::string::npos) {
		result = HWENC_NVENC; tag = "h264_nvenc (NVIDIA)";
	} else if (output.find("h264_qsv") != std::string::npos) {
		result = HWENC_QSV;   tag = "h264_qsv (Intel)";
	} else if (output.find("h264_amf") != std::string::npos) {
		result = HWENC_AMF;   tag = "h264_amf (AMD)";
	}
	s_cached = result;
	LIVE_LOG("HWENC", "Detected: %s", tag);
	return result;
}

CString CRTMPIngest::GetRTMPUrl() const
{
	CString url;
	url.Format(_T("rtmp://localhost:%u/live/stream"), m_nPort);
	return url;
}

// Probe whether the given TCP port can be bound on 0.0.0.0. Returns 0 on
// success or a Winsock error code on failure. We use this *before* asking
// FFmpeg to act as an RTMP server so we can tell the user up-front "the
// port is taken" instead of letting FFmpeg fail with a cryptic message.
static int RTMPProbePort(uint16 port)
{
	WSADATA ws;
	WSAStartup(MAKEWORD(2, 2), &ws);
	SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return WSAGetLastError();

	BOOL one = TRUE;
	setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof(one));

	sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port        = htons(port);

	int rv = bind(s, (sockaddr*)&sa, sizeof(sa));
	int err = (rv == SOCKET_ERROR) ? WSAGetLastError() : 0;
	closesocket(s);
	return err;
}

// Aggressive cleanup of an HLS output directory: kill orphan ffmpeg
// processes that might still be writing into it, then delete every .ts
// + .m3u8. Prevents the watcher from picking up stale segments left by
// a previous run as if they were fresh — that's the bug that made the
// log show ACCEPT seq=0 fed by ffmpeg=489 on what was supposed to be
// a brand-new broadcast.
static int RTMPCleanOutputDir(const CString& outputDir)
{
	int deleted = 0;
	CString pattern = outputDir + _T("\\*.ts");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(pattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			CString full = outputDir + _T("\\") + fd.cFileName;
			if (DeleteFile(full)) deleted++;
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	DeleteFile(outputDir + _T("\\stream.m3u8"));
	return deleted;
}

// Kill any ffmpeg.exe whose command line contains the given marker
// (we use the output dir path). Used to clean orphan FFmpegs left
// over from a previous emule.exe that was killed without graceful
// Stop() — those orphans hold port 1935 and write into our temp dir.
//
// WMI via wmic.exe is the simplest way to enumerate command lines from
// C++ without dragging in COM. Output is parsed for the PID.
static int RTMPKillOrphanFFmpegs(const CString& marker)
{
	int killed = 0;

	HANDLE hRead = NULL, hWrite = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return 0;
	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow= SW_HIDE;
	si.hStdOutput = hWrite;
	si.hStdError  = hWrite;
	si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

	PROCESS_INFORMATION pi = {};
	CString cmd = _T("wmic process where \"name='ffmpeg.exe'\" get ProcessId,CommandLine /format:csv");
	BOOL ok = CreateProcess(NULL, cmd.GetBuffer(), NULL, NULL, TRUE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	cmd.ReleaseBuffer();
	CloseHandle(hWrite);
	if (!ok) { CloseHandle(hRead); return 0; }

	std::string out;
	char buf[2048];
	DWORD got = 0;
	while (ReadFile(hRead, buf, sizeof(buf) - 1, &got, NULL) && got > 0) {
		buf[got] = 0;
		out += buf;
	}
	CloseHandle(hRead);
	WaitForSingleObject(pi.hProcess, 5000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Parse CSV: each non-header line has Node,CommandLine,ProcessId
	CStringA markerA = (LPCSTR)CT2A(marker);
	std::string::size_type pos = 0;
	while (pos < out.size()) {
		std::string::size_type nl = out.find('\n', pos);
		std::string line = out.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
		pos = (nl == std::string::npos) ? out.size() : nl + 1;
		if (line.find("CommandLine") != std::string::npos) continue; // header
		if (line.find((LPCSTR)markerA) == std::string::npos) continue;
		// PID is after the LAST comma
		std::string::size_type lastComma = line.rfind(',');
		if (lastComma == std::string::npos) continue;
		std::string pidStr = line.substr(lastComma + 1);
		while (!pidStr.empty() && (pidStr.back() == '\r' || pidStr.back() == ' '))
			pidStr.pop_back();
		DWORD orphanPid = (DWORD)atoi(pidStr.c_str());
		if (orphanPid == 0 || orphanPid == GetCurrentProcessId()) continue;

		HANDLE hP = OpenProcess(PROCESS_TERMINATE, FALSE, orphanPid);
		if (hP) {
			if (TerminateProcess(hP, 1)) {
				CLiveDebugLog::Get().Append("RTMP",
					"Killed orphan ffmpeg.exe PID=%u (was using our temp dir)", orphanPid);
				killed++;
			}
			CloseHandle(hP);
		}
	}
	return killed;
}

// Background reader for the child's stderr pipe. Each newline-terminated
// chunk is forwarded to CLiveDebugLog with the [FFMPEG] tag — that's what
// finally tells the user *why* the RTMP server failed (codec, port, etc).
struct FFmpegStderrCtx { HANDLE hPipe; };
static DWORD WINAPI RTMPStderrPump(LPVOID p)
{
	FFmpegStderrCtx* ctx = (FFmpegStderrCtx*)p;
	char buf[1024];
	std::string carry;
	for (;;) {
		DWORD got = 0;
		if (!ReadFile(ctx->hPipe, buf, sizeof(buf) - 1, &got, NULL) || got == 0)
			break;
		buf[got] = 0;
		carry += buf;
		size_t nl;
		while ((nl = carry.find('\n')) != std::string::npos) {
			std::string line = carry.substr(0, nl);
			while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
				line.pop_back();
			if (!line.empty())
				CLiveDebugLog::Get().Append("FFMPEG", "%s", line.c_str());
			carry.erase(0, nl + 1);
		}
	}
	if (!carry.empty())
		CLiveDebugLog::Get().Append("FFMPEG", "%s", carry.c_str());
	CloseHandle(ctx->hPipe);
	delete ctx;
	return 0;
}

bool CRTMPIngest::Start(UINT rtmpPort, UINT bitrate, const CString& outputDir, ChunkCallback cb)
{
	if (m_bRunning)
		return false;

	m_nPort = rtmpPort;
	m_strOutputDir = outputDir;
	m_callback = cb;
	m_nSegments = 0;
	// Sprint 2 E.3: remember the launch profile so watchdog can re-spawn.
	m_nLastSourceMode = 0;
	m_nLastBitrate    = bitrate;
	m_strLastFile.Empty();

	// Reap orphan ffmpeg.exes that survived a hard kill of the previous
	// emule.exe. They hold port 1935 and keep writing to our temp dir.
	// "marker" = output dir path; that's enough to identify ours since
	// every spawn includes it on the command line via -hls_segment_filename.
	int orphans = RTMPKillOrphanFFmpegs(outputDir);
	if (orphans > 0) {
		LIVE_LOG("RTMP", "Reaped %d orphan ffmpeg.exe processes", orphans);
		Sleep(500); // give the OS a beat to release the port
	}
	// Also reap any orphan from a previous run that didn't carry our dir
	// in its cmdline — those are usually a leftover of testpattern/etc.
	// We match the literal token "eMule_RTMP" which is the only tail dir
	// name ever used by this code.
	int taggedOrphans = RTMPKillOrphanFFmpegs(_T("eMule_RTMP"));
	if (taggedOrphans > 0) {
		LIVE_LOG("RTMP", "Reaped %d additional eMule_RTMP-tagged ffmpegs", taggedOrphans);
		Sleep(500);
	}

	// Pre-flight: confirm we can actually bind 1935 before launching
	// FFmpeg. Without this, FFmpeg dies with a generic "Address already in
	// use" buried in its stderr and the user just sees "no se pudo iniciar".
	int probe = RTMPProbePort((uint16)rtmpPort);
	if (probe != 0) {
		LIVE_LOG("RTMP", "PORT %u BUSY (winsock=%d) — kill the offender: Get-Process ffmpeg | Stop-Process -Force",
			rtmpPort, probe);
		AddLogLine(true, _T("eSE RTMP: Port %u is busy (Winsock %d). ")
			_T("Run: Get-Process ffmpeg | Stop-Process -Force"),
			rtmpPort, probe);
		return false;
	}

	// Ensure output directory exists
	CreateDirectory(outputDir, NULL);

	// Clean leftover .ts/.m3u8 from any previous run. If we don't, the
	// watcher's "find newest segment" scan picks up stale files written by
	// an earlier broadcast (or even a different ffmpeg from someone else
	// using the same dir) and feeds them as if they were live — visible in
	// the log as baseSeg=489 / 12002 etc when the broadcast was supposed
	// to start at 0.
	int cleaned = RTMPCleanOutputDir(outputDir);
	if (cleaned > 0)
		LIVE_LOG("RTMP", "Cleaned %d leftover .ts files from %S", cleaned, (LPCWSTR)outputDir);

	// Build FFmpeg command line
	// FFmpeg listens on RTMP port and outputs HLS segments. The "?listen=1"
	// query string is the canonical way to make FFmpeg's librtmp act as a
	// server (the bare "-listen 1" flag is for HTTP). Bumped log level to
	// "info" so the stderr pump can show what FFmpeg is actually doing.
	CString ffmpegExe = FindFFmpeg();
	if (GetFileAttributes(ffmpegExe) == INVALID_FILE_ATTRIBUTES) {
		LIVE_LOG("RTMP", "ffmpeg.exe NOT FOUND — looked at \"%S\"", (LPCWSTR)ffmpegExe);
		AddLogLine(true, _T("eSE RTMP: ffmpeg.exe not found near eMule.exe"));
		return false;
	}
	LIVE_LOG("RTMP", "Using ffmpeg=\"%S\"  port=%u  out=\"%S\"",
		(LPCWSTR)ffmpegExe, rtmpPort, (LPCWSTR)outputDir);

	// FFmpeg's RTMP listener: per-protocol "-listen 1" flag MUST appear as an
	// input option (between any input flag and the -i URL). The "?listen=1"
	// query-string form does NOT work for RTMP — FFmpeg parses it as a normal
	// query and then tries to *connect* to 0.0.0.0:1935, which times out with
	// "Connection to tcp://0.0.0.0:1935 failed: Error number -138" (ETIMEDOUT).
	// "-timeout 0" tells the listener to wait forever for OBS to push.
	// "-rw_timeout 0" disables the read-watchdog after the connection is up.
	CString cmdLine;
	cmdLine.Format(
		_T("\"%s\" -hide_banner -loglevel info ")
		_T("-listen 1 -timeout 0 -rw_timeout 0 ")
		_T("-i rtmp://0.0.0.0:%u/live/stream ")
		_T("-c:v copy -c:a copy ")
		_T("-f hls -hls_time 2 -hls_list_size 10 ")
		_T("-hls_flags delete_segments+append_list ")
		_T("-hls_segment_filename \"%s\\seg_%%05d.ts\" ")
		_T("\"%s\\stream.m3u8\""),
		(LPCTSTR)ffmpegExe, rtmpPort,
		(LPCTSTR)outputDir, (LPCTSTR)outputDir
	);
	LIVE_LOG("RTMP", "cmd: %S", (LPCWSTR)cmdLine);

	// Pipe for capturing FFmpeg's stderr. Inheritable on the write end so
	// the child gets it; non-inheritable handle for our reader thread.
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	HANDLE hStderrRead = NULL, hStderrWrite = NULL;
	if (!CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
		LIVE_LOG("RTMP", "CreatePipe failed (err=%u) — running without stderr capture",
			GetLastError());
	}
	if (hStderrRead)
		SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFO si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError   = hStderrWrite ? hStderrWrite : GetStdHandle(STD_ERROR_HANDLE);
	si.hStdOutput  = hStderrWrite ? hStderrWrite : GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

	PROCESS_INFORMATION pi = {};
	BOOL ok = CreateProcess(
		NULL,
		cmdLine.GetBuffer(),
		NULL, NULL,
		hStderrWrite ? TRUE : FALSE,   // bInheritHandles
		CREATE_NO_WINDOW,
		NULL,
		outputDir,
		&si,
		&pi
	);
	cmdLine.ReleaseBuffer();

	// Close our copy of the write end immediately — only the child needs it.
	// Without this, ReadFile on the read end never returns 0 (EOF) when
	// FFmpeg dies, leaving the pump thread blocked forever.
	if (hStderrWrite) CloseHandle(hStderrWrite);

	if (!ok) {
		DWORD err = GetLastError();
		LIVE_LOG("RTMP", "CreateProcess FAILED (err=%u) — ffmpeg path bad?", err);
		if (hStderrRead) CloseHandle(hStderrRead);
		CString msg;
		msg.Format(_T("Failed to start FFmpeg (error %u). Make sure ffmpeg.exe is in PATH or eMule directory."), err);
		AddLogLine(true, _T("eSE RTMP: %s"), (LPCTSTR)msg);
		return false;
	}

	// Spawn the stderr pump now that the child owns the write end.
	if (hStderrRead) {
		FFmpegStderrCtx* ctx = new FFmpegStderrCtx{ hStderrRead };
		HANDLE hPump = CreateThread(NULL, 0, RTMPStderrPump, ctx, 0, NULL);
		if (hPump) CloseHandle(hPump);
	}

	CloseHandle(pi.hThread);
	m_hFFmpegProcess = pi.hProcess;
	m_bRunning = true;
	m_bStopWatcher = false;

	m_strRTMPUrl = GetRTMPUrl();

	AddLogLine(false, _T("eSE RTMP: Listening on %s (FFmpeg PID %u)"),
		(LPCTSTR)m_strRTMPUrl, pi.dwProcessId);
	LIVE_LOG("RTMP", "FFmpeg PID=%u listening on rtmp://localhost:%u/live/stream",
		(unsigned)pi.dwProcessId, rtmpPort);

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
	// Sprint 2 E.3 — remember launch profile
	m_nLastSourceMode = 2;
	m_nLastBitrate    = bitrate;
	m_strLastFile.Empty();

	// v7.1.5 STREAM-MIX FIX: kill ANY ffmpeg leftover from a prior emule
	// session that crashed/was force-killed. Without this, the orphan keeps
	// writing seg_*.ts into %TEMP%\eMule_RTMP\ in parallel with the new
	// ffmpeg we're about to spawn, the WatcherThread reads whichever bytes
	// landed last, and viewers see the wrong content (e.g. test pattern
	// instead of the movie they joined). Only Start() did this — the other
	// 3 modes inherited orphans and silently bled them into the buffer.
	int orphans = RTMPKillOrphanFFmpegs(_T("eMule_RTMP"));
	if (orphans > 0) {
		LIVE_LOG("RTMP", "Screen: reaped %d orphan ffmpeg.exe(s) from prior session", orphans);
		Sleep(500);
	}

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
		_T("-f hls -hls_time 2 -hls_list_size 12 ")
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
	// Sprint 2 E.3 — remember launch profile
	m_nLastSourceMode = 3;
	m_nLastBitrate    = bitrate;
	m_strLastFile     = filePath;

	// v7.1.6 — Map the requested bitrate to which ABR variant feeds the P2P
	// chunk buffer. ffmpeg still encodes all 4 variants (hardcoded ladder
	// 800/1600/2800/4500 kbps below); this only changes WHICH variant the
	// watcher picks up. <=1000 -> 360p (~800k), <=2000 -> 540p (~1.6M),
	// <=3500 -> 720p (~2.8M, prior behavior), otherwise 1080p (~4.5M).
	if      (bitrate <= 1000) m_nPreferredVariant = 0;
	else if (bitrate <= 2000) m_nPreferredVariant = 1;
	else if (bitrate <= 3500) m_nPreferredVariant = 2;
	else                      m_nPreferredVariant = 3;
	LIVE_LOG("RTMP", "Media: bitrate=%u -> P2P variant %u (360p|540p|720p|1080p)",
		bitrate, m_nPreferredVariant);

	// Verify file exists
	if (GetFileAttributes(filePath) == INVALID_FILE_ATTRIBUTES) {
		AddLogLine(true, _T("eSE Media: File not found: %s"), (LPCTSTR)filePath);
		return false;
	}

	// v7.1.5 STREAM-MIX FIX: see StartScreenCapture comment. An orphan
	// ffmpeg from a previously-crashed emule keeps writing test-pattern
	// (or screen, or prior-file) seg_*.ts into the same dir, racing this
	// new spawn — viewers end up with mixed/wrong bytes that pass the
	// streamKey filter and render as the wrong content.
	int orphans = RTMPKillOrphanFFmpegs(_T("eMule_RTMP"));
	if (orphans > 0) {
		LIVE_LOG("RTMP", "Media: reaped %d orphan ffmpeg.exe(s) from prior session", orphans);
		Sleep(500);
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

	// Sprint 2 L.3 — detect problematic source codecs that often lack a hardware
	// decoder in stock FFmpeg builds. Warn the user; FFmpeg may still try, but
	// it will fall back to libx264 transcoding which can be very slow.
	if (probeOutput.Find("Video: hevc") >= 0 || probeOutput.Find("Video: H.265") >= 0) {
		AddLogLine(true, _T("eSE Media: WARNING source codec is HEVC/H.265 — may need NVDEC or QSV decoder. ")
			_T("If broadcast lags or fails, re-encode source to H.264 first."));
	}
	if (probeOutput.Find("Video: av1") >= 0 || probeOutput.Find("Video: AV1") >= 0) {
		AddLogLine(true, _T("eSE Media: WARNING source codec is AV1 — software decode is very slow. ")
			_T("Strongly recommend re-encoding to H.264 before broadcasting."));
	}
	if (probeOutput.Find("Video: vp9") >= 0 || probeOutput.Find("Video: VP9") >= 0) {
		AddLogLine(true, _T("eSE Media: WARNING source codec is VP9 — re-encoding overhead expected. ")
			_T("Consider H.264 source if broadcast struggles."));
	}

	// Build FFmpeg command with proper stream mapping.
	// V2-S07+ playback fix: multi-audio HLS variants confuse VLC (the audio
	// rendition's segment counter diverges from the video's, and VLC drops
	// audio after the first cross-boundary fetch). Force single-audio output
	// (first track only) which uses the simple path with audio muxed INTO
	// the video segment — proven to play in VLC reliably. Multi-language
	// selection becomes opt-in (TODO: ?audio=eng query param).
	CString cmdLine;
	if (false /* multi-audio disabled, see comment above */ && nAudioTracks >= 2) {
		// Multi-audio: use -var_stream_map to generate master playlist with audio renditions
		CString mapArgs;
		CString varMap;
		for (int i = 0; i < nAudioTracks && i < 8; i++) {
			CString m; m.Format(_T("-map 0:a:%d "), i);
			mapArgs += m;
		}
		// Build var_stream_map. Audio variant 0 is marked as the default
		// (DEFAULT=YES) — VLC needs a SINGLE default to lock onto, having
		// multiple DEFAULT=YES audio tracks confused some HLS players and
		// caused audio drop after first segment.
		varMap = _T("v:0,agroup:audio");
		for (int i = 0; i < nAudioTracks && i < 8; i++) {
			CString entry;
			// "default:yes" only for the first audio track; others omit it.
			if (i == 0) {
				entry.Format(_T(" a:%d,agroup:audio,language:%s,name:%s,default:yes"),
					i, (LPCTSTR)CString(audioLangs[i]), (LPCTSTR)CString(audioLangs[i]));
			} else {
				entry.Format(_T(" a:%d,agroup:audio,language:%s,name:%s"),
					i, (LPCTSTR)CString(audioLangs[i]), (LPCTSTR)CString(audioLangs[i]));
			}
			varMap += entry;
		}

		// Critical: -g 48 (= 24fps * 2s) forces a keyframe every 2 seconds
		// so video segments split at 2s boundaries (matching audio segments).
		// Without this, libx264 with -g 120 puts keyframes every 5s -> video
		// segments are 5s, audio segments are 2s -> VLC desyncs and drops
		// audio after the first track switch.
		cmdLine.Format(
			_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
			_T("-i \"%s\" ")
			_T("-map 0:v:0 %s-sn ")
			_T("-c:v libx264 -preset ultrafast -tune zerolatency ")
			_T("-g 48 -keyint_min 48 -sc_threshold 0 ")
			_T("-b:v %uk -maxrate %uk -bufsize %uk ")
			_T("-c:a aac -ac 2 -ar 44100 -b:a 128k ")
			_T("-var_stream_map \"%s\" ")
			_T("-master_pl_name stream.m3u8 ")
			_T("-f hls -hls_time 4 -hls_list_size 20 ")
			_T("-hls_init_time 2 -hls_allow_cache 0 ")
			_T("-hls_flags delete_segments+independent_segments+program_date_time ")
			_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
			_T("\"%s\\stream_%%v.m3u8\""),
			(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
			(LPCTSTR)mapArgs,
			bitrate, bitrate * 2, bitrate * 4,
			(LPCTSTR)varMap,
			(LPCTSTR)outputDir, (LPCTSTR)outputDir
		);
	} else {
		// V2-S07+ ABR HLS — hardware-adaptive variant ladder.
		//
		// We probe the FFmpeg encoder list once and pick the heaviest ladder
		// the machine can actually sustain in real time:
		//
		//   NVENC  (NVIDIA)      -> 4 variants 360/540/720/1080  — GPU, zero CPU
		//   QSV    (Intel iGPU)  -> 3 variants 480/720/1080      — iGPU
		//   AMF    (AMD GPU)     -> 3 variants 480/720/1080      — GPU
		//   libx264 (CPU only)   -> 2 variants 540/720           — fits 4-core laptops
		//
		// libx264 CAPS at 720p deliberately: 4 simultaneous 1080p libx264
		// encodes saturate even an 8-core CPU and cause the stuttering the
		// user reported. Capping at 720p keeps the experience smooth on
		// modest hardware — which is the universal target (Netflix users
		// open YouTube on low-end laptops every day).
		HwEncoder hwenc = DetectHwEncoder();
		// All hardware branches share the same fragmented structure so the
		// var_stream_map / segment naming is identical regardless of which
		// codec was chosen.
		//
		// Per HLS spec, the master playlist lists all variants ordered from
		// LOWEST to HIGHEST bandwidth. VLC (and any compliant HLS player)
		// starts on the first variant for instant playback, then upgrades to
		// the highest variant its measured bandwidth + decoder can sustain.
		// This is the textbook adaptive-streaming flow used by Netflix /
		// Twitch / YouTube Live.
		//
		// Variants chosen for smooth ABR ladder. 4 steps with tighter spacing
		// so VLC's quality bumps are subtle, not jarring.
		//   v0  640x360   @  800 kbps  (instant first frame)
		//   v1  960x540   @ 1600 kbps  (intermediate, smooth jump from v0)
		//   v2  1280x720  @ 2800 kbps  (typical HD)
		//   v3  1920x1080 @ 4500 kbps  (full quality)
		//
		// CRITICAL: uses h264_nvenc (NVIDIA GPU encoder) instead of libx264.
		// 4 simultaneous 1080p libx264 encodes saturate even an 8-core CPU
		// and cause stuttering at the top tier. NVENC offloads everything to
		// the GPU's dedicated encoder block, freeing the CPU entirely and
		// supporting dozens of concurrent sessions on modern (Turing+) GPUs.
		// Quality at the same bitrate is comparable to libx264 -preset
		// veryfast — sometimes better at <2 Mbps.
		//
		// Preset p4 (medium) gives the right speed/quality balance for live;
		// p1 would be max speed but less efficient, p7 best quality but
		// slower. -rc vbr lets the encoder distribute bits intelligently
		// inside the bufsize window.
		// Audio is muxed INTO each variant (v:N,a:N pairing — no agroup),
		// avoiding the audio-rendition desync that VLC choked on with the
		// previous attempt.
		//
		// CPU note: 3 concurrent libx264 encodes at preset veryfast/ultrafast
		// is heavy. The lowest variant uses ultrafast (it's already small and
		// quality doesn't matter as much for fallback); the upper two use
		// veryfast so they look good at their bandwidth tier.
		//
		// Master playlist is written as stream.m3u8 (same filename as the
		// previous single-stream broadcasts so the /hls/stream.m3u8 URL still
		// works for clients).
		if (hwenc == HWENC_NVENC) {
			// 4 variants on NVENC — GPU eats it without breaking a sweat.
			cmdLine.Format(
				_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
				_T("-i \"%s\" ")
				_T("-map 0:v:0 -map 0:v:0 -map 0:v:0 -map 0:v:0 ")
				_T("-map 0:a:0? -map 0:a:0? -map 0:a:0? -map 0:a:0? ")
				_T("-c:v h264_nvenc -preset p4 -profile:v high -pix_fmt yuv420p ")
				_T("-rc vbr -g 48 -bf 2 ")
				_T("-s:v:0 640x360   -b:v:0  800k -maxrate:v:0  1200k -bufsize:v:0 1600k ")
				_T("-s:v:1 960x540   -b:v:1 1600k -maxrate:v:1  2200k -bufsize:v:1 3200k ")
				_T("-s:v:2 1280x720  -b:v:2 2800k -maxrate:v:2  3600k -bufsize:v:2 5600k ")
				_T("-s:v:3 1920x1080 -b:v:3 4500k -maxrate:v:3  5800k -bufsize:v:3 9000k ")
				_T("-c:a aac -ac 2 -ar 48000 ")
				_T("-b:a:0  96k -b:a:1 128k -b:a:2 160k -b:a:3 192k ")
				_T("-var_stream_map \"v:0,a:0 v:1,a:1 v:2,a:2 v:3,a:3\" ")
				_T("-master_pl_name stream.m3u8 ")
				_T("-f hls -hls_time 4 -hls_list_size 20 ")
				_T("-hls_init_time 2 -hls_allow_cache 0 ")
				_T("-hls_flags delete_segments+independent_segments+program_date_time ")
				_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
				_T("\"%s\\stream_%%v.m3u8\""),
				(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
				(LPCTSTR)outputDir, (LPCTSTR)outputDir
			);
		} else if (hwenc == HWENC_QSV) {
			// 3 variants on Intel Quick Sync.
			cmdLine.Format(
				_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
				_T("-i \"%s\" ")
				_T("-map 0:v:0 -map 0:v:0 -map 0:v:0 ")
				_T("-map 0:a:0? -map 0:a:0? -map 0:a:0? ")
				_T("-c:v h264_qsv -preset medium -profile:v high -pix_fmt nv12 ")
				_T("-g 48 -bf 2 ")
				_T("-s:v:0 854x480   -b:v:0 1000k -maxrate:v:0 1400k -bufsize:v:0 2000k ")
				_T("-s:v:1 1280x720  -b:v:1 2500k -maxrate:v:1 3200k -bufsize:v:1 5000k ")
				_T("-s:v:2 1920x1080 -b:v:2 4500k -maxrate:v:2 5800k -bufsize:v:2 9000k ")
				_T("-c:a aac -ac 2 -ar 48000 ")
				_T("-b:a:0 128k -b:a:1 160k -b:a:2 192k ")
				_T("-var_stream_map \"v:0,a:0 v:1,a:1 v:2,a:2\" ")
				_T("-master_pl_name stream.m3u8 ")
				_T("-f hls -hls_time 4 -hls_list_size 20 ")
				_T("-hls_init_time 2 -hls_allow_cache 0 ")
				_T("-hls_flags delete_segments+independent_segments+program_date_time ")
				_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
				_T("\"%s\\stream_%%v.m3u8\""),
				(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
				(LPCTSTR)outputDir, (LPCTSTR)outputDir
			);
		} else if (hwenc == HWENC_AMF) {
			// 3 variants on AMD AMF (VCE/VCN).
			cmdLine.Format(
				_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
				_T("-i \"%s\" ")
				_T("-map 0:v:0 -map 0:v:0 -map 0:v:0 ")
				_T("-map 0:a:0? -map 0:a:0? -map 0:a:0? ")
				_T("-c:v h264_amf -quality balanced -profile:v high -pix_fmt yuv420p ")
				_T("-g 48 ")
				_T("-s:v:0 854x480   -b:v:0 1000k -maxrate:v:0 1400k -bufsize:v:0 2000k ")
				_T("-s:v:1 1280x720  -b:v:1 2500k -maxrate:v:1 3200k -bufsize:v:1 5000k ")
				_T("-s:v:2 1920x1080 -b:v:2 4500k -maxrate:v:2 5800k -bufsize:v:2 9000k ")
				_T("-c:a aac -ac 2 -ar 48000 ")
				_T("-b:a:0 128k -b:a:1 160k -b:a:2 192k ")
				_T("-var_stream_map \"v:0,a:0 v:1,a:1 v:2,a:2\" ")
				_T("-master_pl_name stream.m3u8 ")
				_T("-f hls -hls_time 4 -hls_list_size 20 ")
				_T("-hls_init_time 2 -hls_allow_cache 0 ")
				_T("-hls_flags delete_segments+independent_segments+program_date_time ")
				_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
				_T("\"%s\\stream_%%v.m3u8\""),
				(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
				(LPCTSTR)outputDir, (LPCTSTR)outputDir
			);
		} else {
			// libx264 fallback — only 2 variants, capped at 720p. This is the
			// "weak laptop" path: 4-core CPUs at ultrafast can typically
			// sustain 720p + 540p simultaneously without falling behind
			// real-time. 1080p libx264 simply doesn't fit alongside another
			// variant on modest hardware.
			cmdLine.Format(
				_T("\"%s\" -loglevel warning -re -stream_loop -1 ")
				_T("-i \"%s\" ")
				_T("-map 0:v:0 -map 0:v:0 ")
				_T("-map 0:a:0? -map 0:a:0? ")
				_T("-c:v libx264 -preset ultrafast -profile:v high -pix_fmt yuv420p ")
				_T("-g 48 -keyint_min 48 -sc_threshold 0 ")
				_T("-s:v:0 960x540   -b:v:0 1500k -maxrate:v:0 2000k -bufsize:v:0 3000k ")
				_T("-s:v:1 1280x720  -b:v:1 2500k -maxrate:v:1 3200k -bufsize:v:1 5000k ")
				_T("-c:a aac -ac 2 -ar 48000 ")
				_T("-b:a:0 128k -b:a:1 160k ")
				_T("-var_stream_map \"v:0,a:0 v:1,a:1\" ")
				_T("-master_pl_name stream.m3u8 ")
				_T("-f hls -hls_time 4 -hls_list_size 20 ")
				_T("-hls_init_time 2 -hls_allow_cache 0 ")
				_T("-hls_flags delete_segments+independent_segments+program_date_time ")
				_T("-hls_segment_filename \"%s\\seg_%%v_%%05d.ts\" ")
				_T("\"%s\\stream_%%v.m3u8\""),
				(LPCTSTR)ffmpegExe, (LPCTSTR)filePath,
				(LPCTSTR)outputDir, (LPCTSTR)outputDir
			);
		}
		// bitrate param ignored — ladder is fixed per encoder tier.
		(void)bitrate;
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
	// Sprint 2 E.3 — remember launch profile
	m_nLastSourceMode = 1;
	m_nLastBitrate    = bitrate;
	m_strLastFile.Empty();

	// v7.1.5 STREAM-MIX FIX: see StartScreenCapture comment. Symmetric
	// orphan reap for test-pattern mode (same crash-then-restart hazard).
	int orphans = RTMPKillOrphanFFmpegs(_T("eMule_RTMP"));
	if (orphans > 0) {
		LIVE_LOG("RTMP", "TestPattern: reaped %d orphan ffmpeg.exe(s) from prior session", orphans);
		Sleep(500);
	}

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
		_T("-f hls -hls_time 2 -hls_list_size 12 ")
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

// Sprint 2 E.3 — Watchdog: re-spawn FFmpeg if it died unexpectedly.
// Limited to 5 restarts in any 5-minute window to avoid crash loops.
// Called from WatcherLoop when WaitForSingleObject sees FFmpeg gone.
// NOTE: this runs on the watcher thread; the watcher will exit normally
// after this call. Stop() will then close handles cleanly. The new spawn
// inside the relaunch creates a *new* watcher thread.
void CRTMPIngest::TryWatchdogRestart()
{
	// Reset counter if last restart was > 5 min ago
	DWORD now = GetTickCount();
	if (now - m_dwLastRestartTick > 5 * 60 * 1000)
		m_nRestarts = 0;

	// Don't auto-restart for RTMP listen mode (mode 0). FFmpeg in -listen 1
	// dies as soon as the (non-existent) OBS connection drops. Restarting
	// just spams the log and produces nothing useful — the user has to
	// connect OBS first, then press START. They can retry manually.
	if (m_nLastSourceMode == 0) {
		LIVE_LOG("RTMP",
			"FFmpeg died in RTMP-listen mode — NOT restarting. "
			"Connect OBS to rtmp://localhost:%u/live/stream then press START again.",
			m_nPort);
		AddLogLine(true, _T("eSE Watchdog: RTMP listen — waiting for user (no auto-restart)"));
		m_bRunning = false;
		return;
	}

	if (m_nRestarts >= 5) {
		AddLogLine(true, _T("eSE Watchdog: too many restarts (%u in 5 min), giving up"),
			m_nRestarts);
		m_bRunning = false;
		return;
	}

	if (m_nLastSourceMode == UINT_MAX) {
		AddLogLine(false, _T("eSE Watchdog: no remembered source mode, can't restart"));
		m_bRunning = false;
		return;
	}

	m_nRestarts++;
	m_dwLastRestartTick = now;

	AddLogLine(true, _T("eSE Watchdog: restarting FFmpeg (#%u, mode=%u)"),
		m_nRestarts, m_nLastSourceMode);

	// Capture the current state — Stop() will reset some of it
	UINT mode    = m_nLastSourceMode;
	UINT bitrate = m_nLastBitrate;
	UINT port    = m_nPort;
	CString outDir = m_strOutputDir;
	CString file   = m_strLastFile;
	ChunkCallback cb = m_callback;

	// Close the dead process handle BEFORE spawning a new one.
	// Don't call our own Stop() — it'd try to TerminateProcess on already-dead handle
	// and recursively join *us* (this thread).
	if (m_hFFmpegProcess) {
		CloseHandle(m_hFFmpegProcess);
		m_hFFmpegProcess = NULL;
	}
	m_bRunning = false;

	// Brief pause to avoid immediate respawn churn (e.g. port still bound)
	Sleep(1500);

	// Re-launch with same parameters. These re-set m_nLastSourceMode etc.
	switch (mode) {
		case 0: Start(port, bitrate, outDir, cb);                  break;
		case 1: StartTestPattern(bitrate, outDir, cb);             break;
		case 2: StartScreenCapture(bitrate, outDir, cb);           break;
		case 3: StartMediaFile(file, bitrate, outDir, cb);         break;
		default: m_bRunning = false;                                break;
	}
}

void CRTMPIngest::WatcherLoop()
{
	// Watch the output directory for new .ts segment files.
	// When a new segment appears, read it and pass to the callback.
	//
	// Files written by an unrelated FFmpeg sharing the same temp dir would
	// otherwise be served as if they were ours. Capture launch time and
	// reject any segment whose mtime predates it.
	FILETIME ftLaunch;
	GetSystemTimeAsFileTime(&ftLaunch);

	// Wait for FFmpeg to start producing segments
	Sleep(2000);

	// Find the NEWEST segment (skip old backlog to avoid catch-up storm)
	UINT lastSeg = 0;
	int waitCount = 0;

	// Lambda: parse the trailing segment number from "seg_NNNNN.ts" or
	// "seg_K_NNNNN.ts" (FFmpeg's multi-audio output uses the second form
	// with stream-index prefix). ReverseFind on '_' picks the LAST chunk.
	//
	// IMPORTANT: REJECT audio-variant outputs like seg_eng_NNNN.ts,
	// seg_ita_NNNN.ts, seg_spa_NNNN.ts. FFmpeg HLS gives those a sliding
	// numbering window that easily reaches ~13000+, while the video
	// variant (seg_0_NNNN.ts) starts at 0 — so mixing them confuses the
	// watcher into expecting seg_13697.ts that will never exist.
	auto parseSegNum = [](const CString& fname) -> int {
		// Strip "seg_" prefix.
		if (fname.GetLength() < 6 || _tcsncmp(fname, _T("seg_"), 4) != 0) return -1;
		// After "seg_", the next char must be a digit. If it's a letter
		// (e.g. "seg_eng_..."), this is an audio variant — reject.
		TCHAR c = fname[4];
		if (c < _T('0') || c > _T('9')) return -1;
		int uscore = fname.ReverseFind(_T('_'));
		int dot    = fname.ReverseFind(_T('.'));
		if (uscore < 0 || dot <= uscore) return -1;
		return _ttoi(fname.Mid(uscore + 1, dot - uscore - 1));
	};

	// Scan directory for highest existing segment number — video variants only.
	WIN32_FIND_DATA fd;
	CString searchPattern;
	searchPattern.Format(_T("%s\\seg_*.ts"), (LPCTSTR)m_strOutputDir);
	HANDLE hFind = FindFirstFile(searchPattern, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		UINT maxSeg = 0;
		do {
			CString name(fd.cFileName);
			int segNum = parseSegNum(name);
			if (segNum >= 0 && (UINT)segNum > maxSeg)
				maxSeg = (UINT)segNum;
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
		lastSeg = maxSeg; // Start from the newest, not oldest
	}

	UINT bufferSeq = 0; // Our own counter starting at 0 for the LiveChunkBuffer
	AddLogLine(false, _T("eSE Watcher: Starting at FFmpeg segment %u"), lastSeg);
	LIVE_LOG("RTMP", "Watcher started; out=%S, baseSeg=%u",
		(LPCWSTR)m_strOutputDir, lastSeg);

	while (!m_bStopWatcher) {
		// Check if FFmpeg is still alive
		if (WaitForSingleObject(m_hFFmpegProcess, 0) == WAIT_OBJECT_0) {
			// FFmpeg exited — could be OBS disconnected or an error
			if (!m_bStopWatcher) {
				AddLogLine(true, _T("eSE RTMP: FFmpeg process exited unexpectedly."));
				LIVE_LOG("RTMP", "FFmpeg DIED after %u segments — watchdog will restart", m_nSegments);
				// Sprint 2 E.3: try to auto-restart instead of giving up.
				TryWatchdogRestart();
			}
			break;
		}

		// Look for the next expected segment file. Always try the single-stream
		// name first (testpattern/screen/RTMP produce these). For file mode,
		// fall through to ABR variants in an order driven by m_nPreferredVariant
		// (v7.1.6: prefer the variant matching the broadcaster's bitrate hint,
		// then walk outward — closest variants next, farthest last).
		//
		// Example: preferred=0 (360p) -> try seg_, seg_0_, seg_1_, seg_2_, seg_3_
		// Example: preferred=2 (720p, pre-v7.1.6 default) -> try seg_, seg_2_, seg_1_, seg_3_, seg_0_
		// The fallback order matters when the preferred variant lags behind
		// (NVENC sometimes finishes higher variants before lower ones).
		CString segFile;
		DWORD attr = INVALID_FILE_ATTRIBUTES;
		// Build the per-variant suffix order once (cheap).
		int variantOrder[4];
		{
			int n = 0;
			variantOrder[n++] = (int)m_nPreferredVariant;
			for (int dist = 1; n < 4; ++dist) {
				int up   = (int)m_nPreferredVariant + dist;
				int down = (int)m_nPreferredVariant - dist;
				if (down >= 0 && down <= 3 && n < 4) variantOrder[n++] = down;
				if (up   >= 0 && up   <= 3 && n < 4) variantOrder[n++] = up;
			}
		}
		// Single-stream pattern is tried first (always present for non-ABR modes).
		{
			CString candidate;
			candidate.Format(_T("%s\\seg_%05u.ts"), (LPCTSTR)m_strOutputDir, lastSeg);
			DWORD a = GetFileAttributes(candidate);
			if (a != INVALID_FILE_ATTRIBUTES) {
				segFile = candidate;
				attr    = a;
			}
		}
		if (attr == INVALID_FILE_ATTRIBUTES) {
			for (int i = 0; i < 4 && attr == INVALID_FILE_ATTRIBUTES; ++i) {
				CString candidate;
				candidate.Format(_T("%s\\seg_%d_%05u.ts"), (LPCTSTR)m_strOutputDir,
					variantOrder[i], lastSeg);
				DWORD a = GetFileAttributes(candidate);
				if (a != INVALID_FILE_ATTRIBUTES) {
					segFile = candidate;
					attr    = a;
				}
			}
		}
		if (attr != INVALID_FILE_ATTRIBUTES) {
			// Wait a tiny bit for FFmpeg to finish writing
			Sleep(200);

			// Read the segment
			HANDLE hFile = CreateFile(segFile, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, 0, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				// Reject segments older than our launch — they belong to an
				// orphan FFmpeg process from a previous run. Compare the file's
				// last-write time against ftLaunch.
				FILETIME ftWrite;
				if (GetFileTime(hFile, NULL, NULL, &ftWrite)
					&& CompareFileTime(&ftWrite, &ftLaunch) < 0)
				{
					LIVE_LOG("RTMP", "SKIP stale seg_%05u.ts (older than launch)", lastSeg);
					CloseHandle(hFile);
					DeleteFile(segFile);
					lastSeg++;
					continue;
				}
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
						LIVE_LOG("RTMP", "FED seg=%u (ffmpeg=%u, %u KB) total=%u",
							bufferSeq, lastSeg, fileSize / 1024, m_nSegments);
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
						int segNum = parseSegNum(name);
						if (segNum >= 0 && (UINT)segNum > maxSeg)
							maxSeg = (UINT)segNum;
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
