//this file is part of eMule  eSE Live Debug Log (impl)
//Copyright (C)2026 eSE Team
#include "stdafx.h"
#include "LiveDebugLog.h"
#include <stdarg.h>
#include <time.h>
#include <algorithm>
#include <new>
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

void CLiveDebugLog::TryAppendShutdownStage(LiveShutdownStage stage) noexcept
{
	TryAppendShutdownStageImpl(stage, false);
}

void CLiveDebugLog::TryAppendShutdownStageImpl(LiveShutdownStage stage,
	bool simulateAllocationFailure) noexcept
{
	static const char* const names[] = {
		"ENTRY", "CAN_CLOSE_REJECTED", "CAN_CLOSE_PASS",
		"KAD_STOP_BEGIN", "KAD_STOPPED",
		"DISK_THREADS_STOP_BEGIN", "DISK_THREADS_STOPPED",
		"SAVES_BEGIN", "SAVES_COMPLETE",
		"STOP_UPNP_BEGIN", "STOP_UPNP_COMPLETE",
		"MAPPED_CLEANUP_BEGIN", "MAPPED_CLEANUP_COMPLETE",
		"PREFS_SAVE_BEGIN", "PREFS_SAVED",
		"NETWORK_THREADS_DELETE_BEGIN", "NETWORK_THREADS_DELETED",
		"WEBSERVER_DELETE_IMMINENT",
		"WEB_CLOSE_POST_DUPLICATE", "WEB_CLOSE_POST_FAILED",
		"WEB_CLOSE_POSTED"
	};
	const unsigned index = static_cast<unsigned>(stage);
	if (index >= _countof(names) ||
		!::TryEnterCriticalSection(&m_lock.m_sect))
		return;
	try {
		time_t now = time(NULL);
		struct tm tmv = {};
		localtime_s(&tmv, &now);
		char lineBuffer[96] = {};
		_snprintf_s(lineBuffer, _countof(lineBuffer), _TRUNCATE,
			"%02d:%02d:%02d [SHUTDOWN] stage=%s",
			tmv.tm_hour, tmv.tm_min, tmv.tm_sec, names[index]);
		if (simulateAllocationFailure)
			throw std::bad_alloc();
		AppendLineLocked(CStringA(lineBuffer));
	}
	catch (...) {
		// Diagnostic loss is preferable to delaying or failing shutdown.
	}
	::LeaveCriticalSection(&m_lock.m_sect);
}

struct CLiveDebugLog::ShutdownStageLockTestContext
{
	CLiveDebugLog* log;
	HANDLE entered;
	HANDLE release;
	DWORD exitDelayMilliseconds;
};

DWORD WINAPI CLiveDebugLog::ShutdownStageLockTestProc(LPVOID raw) noexcept
{
	ShutdownStageLockTestContext* context =
		static_cast<ShutdownStageLockTestContext*>(raw);
	context->log->m_lock.Lock();
	::SetEvent(context->entered);
	::WaitForSingleObject(context->release, 2000);
	context->log->m_lock.Unlock();
	if (context->exitDelayMilliseconds != 0)
		::Sleep(context->exitDelayMilliseconds);
	return 0;
}

bool CLiveDebugLog::RunShutdownStageSelfTest() noexcept
{
	const int beforeLockedAttempt = GetCount();
	HANDLE entered = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	HANDLE release = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (entered == NULL || release == NULL) {
		if (entered != NULL) ::CloseHandle(entered);
		if (release != NULL) ::CloseHandle(release);
		return false;
	}
	ShutdownStageLockTestContext* context = new (std::nothrow)
		ShutdownStageLockTestContext{ this, entered, release, 0 };
	if (context == NULL) {
		::CloseHandle(release);
		::CloseHandle(entered);
		return false;
	}
	HANDLE thread = ::CreateThread(NULL, 0, ShutdownStageLockTestProc,
		context, 0, NULL);
	if (thread == NULL) {
		delete context;
		::CloseHandle(release);
		::CloseHandle(entered);
		return false;
	}
	bool passed = ::WaitForSingleObject(entered, 1000) == WAIT_OBJECT_0;
	if (passed) {
		const DWORD started = ::GetTickCount();
		TryAppendShutdownStage(LiveShutdownStage::Entry);
		passed = ::GetTickCount() - started < 100;
	}
	::SetEvent(release);
	const bool joined = ::WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0;
	passed = joined && passed;
	if (!joined) {
		// Context and handles remain owned by the live helper. Never close/free
		// objects it can still address; this test failure is a bounded safe leak.
		return false;
	}
	::CloseHandle(thread);
	::CloseHandle(release);
	::CloseHandle(entered);
	delete context;
	if (!passed || GetCount() != beforeLockedAttempt)
		return false;

	// Exercise the timeout ownership rule with a helper which deliberately
	// outlives the first join. The later join is test-only and outside shutdown.
	ShutdownStageLockTestContext* delayed = new (std::nothrow)
		ShutdownStageLockTestContext{ this,
			::CreateEvent(NULL, TRUE, FALSE, NULL),
			::CreateEvent(NULL, TRUE, FALSE, NULL), 1250 };
	if (delayed == NULL || delayed->entered == NULL || delayed->release == NULL) {
		if (delayed != NULL) {
			if (delayed->entered != NULL) ::CloseHandle(delayed->entered);
			if (delayed->release != NULL) ::CloseHandle(delayed->release);
			delete delayed;
		}
		return false;
	}
	HANDLE delayedThread = ::CreateThread(NULL, 0, ShutdownStageLockTestProc,
		delayed, 0, NULL);
	if (delayedThread == NULL) {
		::CloseHandle(delayed->release);
		::CloseHandle(delayed->entered);
		delete delayed;
		return false;
	}
	if (::WaitForSingleObject(delayed->entered, 1000) != WAIT_OBJECT_0) {
		::SetEvent(delayed->release);
		return false; // live helper retains its heap context and handles
	}
	::SetEvent(delayed->release);
	if (::WaitForSingleObject(delayedThread, 25) != WAIT_TIMEOUT)
		passed = false;
	if (::WaitForSingleObject(delayedThread, 2000) != WAIT_OBJECT_0)
		return false; // live helper retains its heap context and handles
	::CloseHandle(delayedThread);
	::CloseHandle(delayed->release);
	::CloseHandle(delayed->entered);
	delete delayed;
	if (!passed)
		return false;

	const int before = GetCount();
	TryAppendShutdownStageImpl(LiveShutdownStage::Entry, true);
	if (GetCount() != before)
		return false;
	TryAppendShutdownStage(LiveShutdownStage::Entry);
	try {
		std::deque<CStringA> recent;
		GetRecent(1, recent);
		return !recent.empty() && recent.back().Find(
			"[SHUTDOWN] stage=ENTRY") >= 0;
	}
	catch (...) {
		return false;
	}
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
