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

	// Static thread proc for the segment watcher.
	static DWORD WINAPI WatcherThread(LPVOID param);
	void WatcherLoop();

	// Find FFmpeg in known locations or PATH.
	static CString FindFFmpeg();
};
