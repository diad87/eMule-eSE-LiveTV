//this file is part of eMule  eSE Live Debug Log (impl)
//Copyright (C)2026 eSE Team
#include "stdafx.h"
#include "LiveDebugLog.h"
#include <stdarg.h>
#include <time.h>
#include <algorithm>
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CLiveDebugLog& CLiveDebugLog::Get()
{
	static CLiveDebugLog instance;
	return instance;
}

void CLiveDebugLog::AppendLineLocked(const CStringA& line)
{
	m_lines.push_back(line);
	while ((int)m_lines.size() > kMaxLines)
		m_lines.pop_front();
}

void CLiveDebugLog::Append(LPCSTR tag, LPCSTR fmt, ...)
{
	char body[512];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(body, _countof(body), _TRUNCATE, fmt, ap);
	va_end(ap);

	time_t now = time(nullptr);
	struct tm tmv;
	localtime_s(&tmv, &now);

	CStringA line;
	line.Format("%02d:%02d:%02d [%s] %s",
		tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
		(tag && *tag) ? tag : "LIVE", body);

	CSingleLock guard(&m_lock, TRUE);
	AppendLineLocked(line);
}

void CLiveDebugLog::AppendW(LPCSTR tag, LPCWSTR fmt, ...)
{
	wchar_t body[512];
	va_list ap;
	va_start(ap, fmt);
	_vsnwprintf_s(body, _countof(body), _TRUNCATE, fmt, ap);
	va_end(ap);

	// Convert wide -> UTF-8 for storage so the JSON endpoint emits valid UTF-8.
	int bytes = WideCharToMultiByte(CP_UTF8, 0, body, -1, NULL, 0, NULL, NULL);
	if (bytes <= 0) return;
	CStringA bodyA;
	WideCharToMultiByte(CP_UTF8, 0, body, -1, bodyA.GetBuffer(bytes), bytes, NULL, NULL);
	bodyA.ReleaseBuffer();

	time_t now = time(nullptr);
	struct tm tmv;
	localtime_s(&tmv, &now);

	CStringA line;
	line.Format("%02d:%02d:%02d [%s] %s",
		tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
		(tag && *tag) ? tag : "LIVE", (LPCSTR)bodyA);

	CSingleLock guard(&m_lock, TRUE);
	AppendLineLocked(line);
}

void CLiveDebugLog::GetRecent(int maxItems, std::deque<CStringA>& out) const
{
	out.clear();
	CSingleLock guard(&m_lock, TRUE);
	int n = (int)m_lines.size();
	int start = (maxItems > 0 && maxItems < n) ? n - maxItems : 0;
	for (int i = start; i < n; ++i)
		out.push_back(m_lines[i]);
}

void CLiveDebugLog::Clear()
{
	CSingleLock guard(&m_lock, TRUE);
	m_lines.clear();
}

int CLiveDebugLog::GetCount() const
{
	CSingleLock guard(&m_lock, TRUE);
	return (int)m_lines.size();
}


// V2-S05 — LatencyHistogram implementation
LatencyHistogram::LatencyHistogram() {}

void LatencyHistogram::Record(DWORD latency_ms)
{
	CSingleLock guard(&m_lock, TRUE);
	m_samples.push_back(latency_ms);
	while (m_samples.size() > kMaxSamples) m_samples.pop_front();
}

void LatencyHistogram::Percentiles(DWORD& p50, DWORD& p95, DWORD& p99) const
{
	CSingleLock guard(&m_lock, TRUE);
	const size_t n = m_samples.size();
	if (n == 0) { p50 = p95 = p99 = 0; return; }
	std::vector<DWORD> sorted(m_samples.begin(), m_samples.end());
	std::sort(sorted.begin(), sorted.end());
	// Standard percentile indexing: floor(n * q / 100), clamped to [0, n-1].
	auto idx = [&](size_t q) -> size_t {
		size_t i = (n * q) / 100;
		return (i >= n) ? n - 1 : i;
	};
	p50 = sorted[idx(50)];
	p95 = sorted[idx(95)];
	p99 = sorted[idx(99)];
}

DWORD LatencyHistogram::Mean() const
{
	CSingleLock guard(&m_lock, TRUE);
	if (m_samples.empty()) return 0;
	uint64 sum = 0;
	for (DWORD v : m_samples) sum += v;
	return (DWORD)(sum / m_samples.size());
}

int LatencyHistogram::SampleCount() const
{
	CSingleLock guard(&m_lock, TRUE);
	return (int)m_samples.size();
}

void LatencyHistogram::Reset()
{
	CSingleLock guard(&m_lock, TRUE);
	m_samples.clear();
}
