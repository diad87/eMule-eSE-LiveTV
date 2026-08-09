#include "../UPnPWorkerLifecycle.h"
#include "../UPnPDeferredReaperCore.h"

#include <atomic>
#include <cstdio>

namespace {
int checks = 0;
int failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #x); } } while (0)

struct WorkerContext {
    std::atomic_bool* cancelled;
    std::atomic_bool* callbackEnabled;
    std::atomic_int* posts;
    DWORD blockingMilliseconds;
};

DWORD WINAPI SimulatedNetworkWorker(void* raw) {
    WorkerContext* context = static_cast<WorkerContext*>(raw);
    ::Sleep(context->blockingMilliseconds);
    if (context->cancelled->load(std::memory_order_acquire))
        return 0;
    if (context->callbackEnabled->load(std::memory_order_acquire))
        context->posts->fetch_add(1, std::memory_order_relaxed);
    return 0;
}

void TestCancellationDuringBoundedIo(DWORD phaseDelay) {
    std::atomic_bool cancelled{false};
    std::atomic_bool callbackEnabled{true};
    std::atomic_int posts{0};
    WorkerContext context{&cancelled, &callbackEnabled, &posts, phaseDelay};
    HANDLE worker = ::CreateThread(NULL, 0, SimulatedNetworkWorker,
        &context, 0, NULL);
    CHECK(worker != NULL);
    const UPnPWorkerStopResult result = RequestCooperativeUPnPWorkerStop(
        worker, cancelled, 1000,
        [&callbackEnabled]() {
            callbackEnabled.store(false, std::memory_order_release);
        });
    CHECK(result == UPnPWorkerStopResult::Stopped);
    CHECK(cancelled.load(std::memory_order_acquire));
    CHECK(posts.load(std::memory_order_acquire) == 0);
    CHECK(::CloseHandle(worker) != FALSE);
}

void TestTimeoutAndRepeatedStop() {
    std::atomic_bool cancelled{false};
    std::atomic_bool callbackEnabled{true};
    std::atomic_int posts{0};
    WorkerContext context{&cancelled, &callbackEnabled, &posts, 120};
    HANDLE worker = ::CreateThread(NULL, 0, SimulatedNetworkWorker,
        &context, 0, NULL);
    CHECK(worker != NULL);
    const auto fence = [&callbackEnabled]() {
        callbackEnabled.store(false, std::memory_order_release);
    };
    CHECK(RequestCooperativeUPnPWorkerStop(worker, cancelled, 1, fence) ==
        UPnPWorkerStopResult::TimedOut);
    CHECK(cancelled.load(std::memory_order_acquire));
    CHECK(RequestCooperativeUPnPWorkerStop(worker, cancelled, 1000, fence) ==
        UPnPWorkerStopResult::Stopped);
    CHECK(posts.load(std::memory_order_acquire) == 0);
    CHECK(::CloseHandle(worker) != FALSE);
}

void TestStartupFailureAndRepeatedEmptyStop() {
    std::atomic_bool cancelled{false};
    int fences = 0;
    CHECK(RequestCooperativeUPnPWorkerStop(NULL, cancelled, 1,
        [&fences]() { ++fences; }) == UPnPWorkerStopResult::NotRunning);
    CHECK(!cancelled.load(std::memory_order_acquire));
    CHECK(RequestCooperativeUPnPWorkerStop(NULL, cancelled, 1,
        [&fences]() { ++fences; }) == UPnPWorkerStopResult::NotRunning);
    CHECK(fences == 2);
}

struct MutationContext {
    std::atomic_bool* cancelled;
    std::atomic_int* phases;
};

DWORD WINAPI SimulatedPostAddRollback(void* raw) {
    MutationContext* context = static_cast<MutationContext*>(raw);
    context->phases->fetch_add(1); // Add completed.
    while (!context->cancelled->load(std::memory_order_acquire))
        ::Sleep(1);
    context->phases->fetch_add(1); // exact Get
    ::Sleep(10);
    context->phases->fetch_add(1); // exact Delete
    ::Sleep(10);
    context->phases->fetch_add(1); // absence Get
    return 0;
}

void TestCancellationCompensatesCompletedMutation() {
    std::atomic_bool cancelled{false};
    std::atomic_bool callbackEnabled{true};
    std::atomic_int phases{0};
    MutationContext context{&cancelled, &phases};
    HANDLE worker = ::CreateThread(NULL, 0, SimulatedPostAddRollback,
        &context, 0, NULL);
    CHECK(worker != NULL);
    while (phases.load(std::memory_order_acquire) == 0)
        ::Sleep(1);
    const UPnPWorkerStopResult result = RequestCooperativeUPnPWorkerStop(
        worker, cancelled, 1000, [&callbackEnabled]() {
            callbackEnabled.store(false, std::memory_order_release);
        });
    CHECK(result == UPnPWorkerStopResult::Stopped);
    CHECK(phases.load(std::memory_order_acquire) == 4);
    CHECK(!callbackEnabled.load(std::memory_order_acquire));
    CHECK(::CloseHandle(worker) != FALSE);
}

struct DeferredProbe {
    HANDLE release;
    HANDLE worker;
    std::atomic_int* deletes;
};

DWORD WINAPI UnboundedUntilReleased(void* raw) {
    DeferredProbe* probe = static_cast<DeferredProbe*>(raw);
    ::WaitForSingleObject(probe->release, INFINITE);
    return 0;
}

void TestDeferredOwnershipKeepsUiBoundedAndDeletesOnce() {
    std::atomic_int deletes{0};
    DeferredProbe* probe = new DeferredProbe{
        ::CreateEvent(NULL, TRUE, FALSE, NULL), NULL, &deletes};
    probe->worker = ::CreateThread(NULL, 0, UnboundedUntilReleased,
        probe, 0, NULL);
    CHECK(probe->release != NULL && probe->worker != NULL);
    std::atomic_bool cancelled{false};
    const ULONGLONG before = ::GetTickCount64();
    CHECK(RequestCooperativeUPnPWorkerStop(probe->worker, cancelled, 1,
        []() {}) == UPnPWorkerStopResult::TimedOut);
    CHECK(::GetTickCount64() - before < 1000); // UI continued.
    DeferredProbe* holder = probe; // transfer; no destructor/delete here.
    CHECK(holder == probe);
    CHECK(::SetEvent(holder->release) != FALSE);
    CHECK(::WaitForSingleObject(holder->worker, 1000) == WAIT_OBJECT_0);
    ::CloseHandle(holder->worker);
    ::CloseHandle(holder->release);
    holder->deletes->fetch_add(1);
    delete holder;
    CHECK(deletes.load() == 1);
}

struct ReaperProbe {
    HANDLE worker;
    std::atomic_int* deleted;
    std::atomic_bool* globalsUnavailable;
    bool requireUnavailable;
};

void DestroyReaperProbe(void* raw) {
    ReaperProbe* probe = static_cast<ReaperProbe*>(raw);
    if (!probe->requireUnavailable || probe->globalsUnavailable->load())
        probe->deleted->fetch_add(1);
    delete probe;
}

HANDLE WINAPI FailCreateEvent(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR) {
    ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
}

HANDLE WINAPI FailCreateThread(LPSECURITY_ATTRIBUTES, SIZE_T,
    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) {
    ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
}

BOOL WINAPI FailInitializeLock(LPCRITICAL_SECTION, DWORD, DWORD) {
    ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
}

DWORD WINAPI NoopThread(void*) { return 0; }

void TestProductionReaperCoreAndFailureSeams() {
    std::atomic_int deleted{0};
    std::atomic_bool globalsUnavailable{false};
    HANDLE pending = ::CreateEvent(NULL, TRUE, FALSE, NULL);
    HANDLE done = ::CreateEvent(NULL, TRUE, TRUE, NULL);
    CHECK(pending != NULL && done != NULL);
    UPnPDeferredReaperCore<2> core;
    ReaperProbe* delayed = new ReaperProbe{
        pending, &deleted, &globalsUnavailable, true};
    ReaperProbe* immediate = new ReaperProbe{
        done, &deleted, &globalsUnavailable, false};
    ReaperProbe* overflow = new ReaperProbe{
        done, &deleted, &globalsUnavailable, false};
    CHECK(core.Adopt(delayed, pending, DestroyReaperProbe));
    CHECK(core.Adopt(delayed, pending, DestroyReaperProbe)); // idempotent.
    CHECK(core.Adopt(immediate, done, DestroyReaperProbe));
    CHECK(!core.Adopt(overflow, done, DestroyReaperProbe));
    CHECK(deleted.load() == 0); // overflow never destroys an active object.
    delete overflow; // test-owned instrumentation cleanup, outside contract.
    CHECK(core.PollOnce() == 1);
    CHECK(deleted.load() == 1);
    globalsUnavailable.store(true);
    CHECK(::SetEvent(pending) != FALSE);
    CHECK(core.PollOnce() == 1);
    CHECK(deleted.load() == 2);
    CHECK(core.PollOnce() == 0);
    ::CloseHandle(pending);
    ::CloseHandle(done);

    HANDLE wake = NULL;
    HANDLE thread = NULL;
    CHECK(!StartUPnPDeferredReaperThread(wake, thread, NoopThread, NULL,
        FailCreateEvent, ::CreateThread));
    CHECK(wake == NULL && thread == NULL);
    CHECK(!StartUPnPDeferredReaperThread(wake, thread, NoopThread, NULL,
        ::CreateEventW, FailCreateThread));
    CHECK(wake == NULL && thread == NULL);

    UPnPDeferredReaperCore<1> unavailable(FailInitializeLock);
    ReaperProbe* lockFailure = new ReaperProbe{
        done, &deleted, &globalsUnavailable, false};
    CHECK(!unavailable.Adopt(lockFailure, done, DestroyReaperProbe));
    CHECK(unavailable.PollOnce() == 0);
    CHECK(deleted.load() == 2); // no destructor ran on lock-init failure.
    delete lockFailure; // test-only tracker cleanup after assertion.
}

struct OwnedFake {
    static int deletes;
    bool defer;
    explicit OwnedFake(bool value) : defer(value) {}
    bool DeferDestructionIfWorkerActive() { return defer; }
    ~OwnedFake() { ++deletes; }
};
int OwnedFake::deletes = 0;

void TestWrapperOwnershipSeam() {
    OwnedFake::deletes = 0;
    ReleaseUPnPOwnedImplementation(new OwnedFake(false));
    CHECK(OwnedFake::deletes == 1);
    OwnedFake* deferred = new OwnedFake(true);
    ReleaseUPnPOwnedImplementation(deferred);
    CHECK(OwnedFake::deletes == 1);
    delete deferred;
    CHECK(OwnedFake::deletes == 2);
}
} // namespace

int main() {
    TestCancellationDuringBoundedIo(40);  // SSDP/discovery phase.
    TestCancellationDuringBoundedIo(80);  // SOAP phase.
    TestTimeoutAndRepeatedStop();          // Post-before-unlock race.
    TestStartupFailureAndRepeatedEmptyStop();
    TestCancellationCompensatesCompletedMutation();
    TestDeferredOwnershipKeepsUiBoundedAndDeletesOnce();
    TestProductionReaperCoreAndFailureSeams();
    TestWrapperOwnershipSeam();
    std::printf("UPnP cooperative worker lifecycle: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
