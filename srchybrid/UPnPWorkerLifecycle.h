#pragma once

#include <Windows.h>
#include <atomic>

enum class UPnPWorkerStopResult {
	NotRunning = 0,
	Stopped = 1,
	TimedOut = 2,
	WaitFailed = 3
};

// UI patience bound only. It deliberately makes no claim that third-party
// DNS/HTTP stacks or journal I/O have a provable completion time.
constexpr DWORD kUPnPWorkerStopBoundMilliseconds = 15000;

template <typename FenceCallback>
UPnPWorkerStopResult RequestCooperativeUPnPWorkerStop(
	HANDLE worker, std::atomic_bool& cancelled, DWORD timeoutMilliseconds,
	FenceCallback fenceCallback)
{
	// Publication is fenced before cancellation becomes observable. This is
	// the linearization point after which the worker cannot post a callback.
	fenceCallback();
	if (worker == NULL)
		return UPnPWorkerStopResult::NotRunning;
	cancelled.store(true, std::memory_order_release);
	const DWORD wait = ::WaitForSingleObject(worker, timeoutMilliseconds);
	if (wait == WAIT_OBJECT_0)
		return UPnPWorkerStopResult::Stopped;
	if (wait == WAIT_TIMEOUT)
		return UPnPWorkerStopResult::TimedOut;
	return UPnPWorkerStopResult::WaitFailed;
}
