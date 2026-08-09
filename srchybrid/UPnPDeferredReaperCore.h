#pragma once

#include <Windows.h>
#include <array>
#include <cstddef>

inline BOOL WINAPI InitializeUPnPReaperLock(
	LPCRITICAL_SECTION lock, DWORD, DWORD) noexcept
{
#if defined(_MSC_VER)
	__try {
		return ::InitializeCriticalSectionAndSpinCount(lock, 0);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
#else
	return ::InitializeCriticalSectionAndSpinCount(lock, 0);
#endif
}

template <std::size_t Capacity>
class UPnPDeferredReaperCore
{
public:
	typedef void (*DestroyFn)(void*);
	typedef BOOL (WINAPI *InitializeLockFn)(
		LPCRITICAL_SECTION, DWORD, DWORD);
	explicit UPnPDeferredReaperCore(
		InitializeLockFn initializeLock = InitializeUPnPReaperLock) noexcept
		: m_initialized(initializeLock != NULL
			&& initializeLock(&m_lock, 0, 0) != FALSE)
	{
	}
	~UPnPDeferredReaperCore() noexcept
	{
		if (m_initialized)
			::DeleteCriticalSection(&m_lock);
	}

	bool Adopt(void* object, HANDLE worker, DestroyFn destroy)
	{
		if (!m_initialized || object == NULL || worker == NULL || destroy == NULL)
			return false;
		::EnterCriticalSection(&m_lock);
		for (Entry& entry : m_entries) {
			if (entry.object == object) {
				::LeaveCriticalSection(&m_lock);
				return true;
			}
		}
		for (Entry& entry : m_entries) {
			if (entry.object == NULL) {
				entry = Entry{object, worker, destroy};
				::LeaveCriticalSection(&m_lock);
				return true;
			}
		}
		::LeaveCriticalSection(&m_lock);
		return false;
	}

	std::size_t PollOnce()
	{
		if (!m_initialized)
			return 0;
		std::size_t destroyed = 0;
		for (Entry& entry : m_entries) {
			Entry ready{};
			::EnterCriticalSection(&m_lock);
			if (entry.object != NULL
					&& ::WaitForSingleObject(entry.worker, 0)
						== WAIT_OBJECT_0) {
				ready = entry;
				entry = Entry{};
			}
			::LeaveCriticalSection(&m_lock);
			if (ready.object != NULL) {
				ready.destroy(ready.object);
				++destroyed;
			}
		}
		return destroyed;
	}

	std::size_t size() const
	{
		if (!m_initialized)
			return 0;
		std::size_t count = 0;
		::EnterCriticalSection(&m_lock);
		for (const Entry& entry : m_entries)
			if (entry.object != NULL)
				++count;
		::LeaveCriticalSection(&m_lock);
		return count;
	}

private:
	struct Entry {
		void* object = NULL;
		HANDLE worker = NULL;
		DestroyFn destroy = NULL;
	};
	mutable CRITICAL_SECTION m_lock;
	bool m_initialized;
	std::array<Entry, Capacity> m_entries{};
};

typedef HANDLE (WINAPI *UPnPCreateEventFn)(
	LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef HANDLE (WINAPI *UPnPCreateThreadFn)(
	LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
	DWORD, LPDWORD);

inline bool StartUPnPDeferredReaperThread(HANDLE& wake, HANDLE& thread,
	LPTHREAD_START_ROUTINE procedure, void* context,
	UPnPCreateEventFn createEvent = ::CreateEventW,
	UPnPCreateThreadFn createThread = ::CreateThread)
{
	wake = createEvent(NULL, FALSE, FALSE, NULL);
	if (wake == NULL)
		return false;
	thread = createThread(NULL, 0, procedure, context, 0, NULL);
	if (thread != NULL)
		return true;
	::CloseHandle(wake);
	wake = NULL;
	return false;
}

template <typename Implementation>
inline void ReleaseUPnPOwnedImplementation(Implementation* implementation)
{
	if (implementation != NULL
			&& !implementation->DeferDestructionIfWorkerActive())
		delete implementation;
}
