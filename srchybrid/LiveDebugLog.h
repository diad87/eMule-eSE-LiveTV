//this file is part of eMule  eSE Live Debug Log
//Copyright (C)2026 eSE Team
//
// In-process ring buffer of recent live-stream events. Lets the broadcaster
// see WHY a stream isn't reaching viewers without attaching a debugger or
// digging through the eMule classic log. Captured from the same call sites
// that previously only emitted AddLogLine() text.
//
// Visible in two places:
//   1) MFC: bottom EDIT control of the Live Stream tab (auto-scrolls)
//   2) Web: GET /api/live/log -> JSON {"items":["..."]}
//
// Designed to be cheap (single CCriticalSection, deque<CStringA>, capacity
// 500). Safe to call from any thread (FFmpeg watcher, mesh socket, Kad).
#pragma once

#include <deque>

class CLiveDebugLog
{
public:
	static CLiveDebugLog& Get();

	// Append a formatted line. Thread-safe.
	// Tag is a short uppercase prefix shown like "[TAG] message...".
	void Append(LPCSTR tag, LPCSTR fmt, ...);
	void AppendW(LPCSTR tag, LPCWSTR fmt, ...);

	// Snapshot of the last N entries (oldest first).
	// Each entry is "HH:MM:SS [TAG] message".
	void GetRecent(int maxItems, std::deque<CStringA>& out) const;

	// Drop everything.
	void Clear();

	int  GetCount() const;

private:
	CLiveDebugLog() = default;
	void AppendLineLocked(const CStringA& line);

	mutable CCriticalSection m_lock;
	std::deque<CStringA>     m_lines;     // capacity 500
	static const int         kMaxLines = 500;
};

// Convenience macros — match the call-site style of the rest of eMule.
#define LIVE_LOG(TAG, FMT, ...)  CLiveDebugLog::Get().Append(TAG, FMT, ##__VA_ARGS__)
#define LIVE_LOGW(TAG, FMT, ...) CLiveDebugLog::Get().AppendW(TAG, FMT, ##__VA_ARGS__)


// V2-S05 — Latency histogram with p50/p95/p99 percentiles.
// Bounded ring buffer (1000 samples) of chunk-arrival latencies in ms.
// Computed on demand; no per-sample sort. Thread-safe via CCriticalSection.
// Used by /api/live/metrics to expose esmule_chunk_latency_ms{quantile="..."}.
class LatencyHistogram {
public:
    LatencyHistogram();
    void  Record(DWORD latency_ms);
    void  Percentiles(DWORD& p50, DWORD& p95, DWORD& p99) const;
    DWORD Mean() const;
    int   SampleCount() const;
    void  Reset();

private:
    static const size_t kMaxSamples = 1000;
    std::deque<DWORD>     m_samples;   // FIFO ring
    mutable CCriticalSection m_lock;
};
