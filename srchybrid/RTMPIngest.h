//this file is part of eMule — eSE RTMP Ingest (FFmpeg-based)
//Copyright (C)2024 eSE Team
#pragma once

#include <windows.h>
#include <functional>

// Manages an FFmpeg process that acts as an RTMP server on localhost.
// OBS (or any RTMP client) pushes video to rtmp://localhost:PORT/live/stream
// FFmpeg converts to HLS segments (.ts) in a temp directory.
// A watcher thread picks up new segments and forwards them via callback.

class CRTMPIngest
{
public:
	CRTMPIngest();
	~CRTMPIngest();

	// Callback invoked on the watcher thread when a new .ts chunk is ready.
	// Parameters: chunk data pointer, chunk size in bytes, chunk sequence number.
	typedef std::function<void(const BYTE* data, DWORD size, UINT seq)> ChunkCallback;

	// Start the FFmpeg RTMP listener.
	// Returns true if the process launched successfully.
	bool Start(UINT rtmpPort, UINT bitrate, const CString& outputDir, ChunkCallback cb);

	// Start with a built-in test pattern (color bars + timestamp).
	// No OBS or external source needed — great for testing.
	bool StartTestPattern(UINT bitrate, const CString& outputDir, ChunkCallback cb);

	// Start screen capture (desktop) via FFmpeg gdigrab.
	bool StartScreenCapture(UINT bitrate, const CString& outputDir, ChunkCallback cb);

	// Start broadcasting a media file (movie, video) as a 24/7 channel.
	// Uses -re for real-time playback, -stream_loop -1 for infinite looping.
	bool StartMediaFile(const CString& filePath, UINT bitrate, const CString& outputDir, ChunkCallback cb);

	// Stop the FFmpeg process and watcher thread.
	void Stop();

	// Is the ingest running?
	bool IsRunning() const { return m_bRunning; }

	// Get the RTMP URL that OBS should connect to.
	CString GetRTMPUrl() const;

	// Get the port.
	UINT GetPort() const { return m_nPort; }

	// Get count of segments received so far.
	UINT GetSegmentCount() const { return m_nSegments; }

	// Phase 5.1: locate ffmpeg.exe (PATH / install dirs / next to emule.exe).
	// Public so the WebServer pre-flight endpoint can probe availability
	// without instantiating the ingest pipeline.
	static CString FindFFmpeg();

	// V2-S07+ ABR: detect which hardware H.264 encoder this machine offers.
	// Probes FFmpeg's -encoders output once and caches the result. The chosen
	// encoder drives both quality strategy and how many concurrent variants
	// we generate, so weak laptops get a light 2-variant ladder while
	// machines with NVENC/QSV/AMF get the full 4-variant ladder.
	enum HwEncoder {
		HWENC_UNKNOWN = -1,
		HWENC_CPU_X264 = 0,   // libx264 fallback (always available)
		HWENC_NVENC    = 1,   // NVIDIA
		HWENC_QSV      = 2,   // Intel Quick Sync
		HWENC_AMF      = 3,   // AMD VCE/VCN
	};
	static HwEncoder DetectHwEncoder();

	// Sprint 2 E.3: watchdog/auto-restart counters
	UINT GetRestartCount() const { return m_nRestarts; }

private:
	HANDLE			m_hFFmpegProcess;
	HANDLE			m_hWatcherThread;
	volatile bool	m_bRunning;
	volatile bool	m_bStopWatcher;
	UINT			m_nPort;
	UINT			m_nSegments;
	CString			m_strOutputDir;
	CString			m_strRTMPUrl;
	ChunkCallback	m_callback;

	// Sprint 2 E.3 — Watchdog state
	// Remember the last source so we can re-spawn FFmpeg if it dies.
	// 0=Start(rtmp listen), 1=StartTestPattern, 2=StartScreenCapture, 3=StartMediaFile
	UINT			m_nLastSourceMode;
	UINT			m_nLastBitrate;
	CString			m_strLastFile;
	UINT			m_nRestarts;
	DWORD			m_dwLastRestartTick;
	void			TryWatchdogRestart();  // called from WatcherLoop on FFmpeg death

	// v7.1.6 — ABR variant preference for the P2P chunk feed (file mode only).
	// File broadcasts encode 4 simultaneous variants (0=360p, 1=540p, 2=720p,
	// 3=1080p) but only ONE of them goes through the P2P chunk buffer. Before
	// v7.1.6 this was hardcoded to variant 2 (720p, ~3 Mbps) — too heavy for
	// viewers on 4G/CGN or other constrained links. Now driven by the bitrate
	// parameter passed to StartMediaFile: <=1000 picks 0, <=2000 picks 1,
	// <=3500 picks 2, otherwise 3. Other variants are still encoded (no
	// ffmpeg-side change) so the watcher can fall back if the requested
	// variant isn't produced yet for a given segment number.
	UINT			m_nPreferredVariant;  // 0..3, default 2 (720p)

	// Static thread proc for the segment watcher.
	static DWORD WINAPI WatcherThread(LPVOID param);
	void WatcherLoop();

	// (FindFFmpeg moved to public above for pre-flight access.)
};
