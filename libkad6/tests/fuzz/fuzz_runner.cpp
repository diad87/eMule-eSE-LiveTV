// SPDX-License-Identifier: MIT
#include "fuzz_common.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>

#pragma comment(lib, "psapi.lib")

namespace {

struct MemorySample {
    std::size_t rss = 0;
    std::size_t peak_rss = 0;
    std::size_t private_bytes = 0;
};

MemorySample SampleMemory() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    MemorySample result;
    if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
        result.rss = counters.WorkingSetSize;
        result.peak_rss = counters.PeakWorkingSetSize;
        result.private_bytes = counters.PrivateUsage;
    }
    return result;
}

std::size_t ParseSize(const char* text, bool& ok) {
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 0);
    ok = errno == 0 && end && *end == '\0' && value > 0;
    return ok ? static_cast<std::size_t>(value) : 0;
}

} // namespace

int main(int argc, char** argv) {
    kad6_fuzz::Config config;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            bool ok = false;
            config.iterations = ParseSize(argv[++i], ok);
            if (!ok) { std::printf("invalid --iterations\n"); return 2; }
        } else if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            bool ok = false;
            config.seed = ParseSize(argv[++i], ok);
            if (!ok) { std::printf("invalid --seed\n"); return 2; }
        } else {
            std::printf("usage: fuzz_runner [--iterations N] [--seed N]\n");
            return 2;
        }
    }
    if (config.iterations < 100000) {
        std::printf("K6-0 gate requires at least 100000 iterations per target\n");
        return 2;
    }

    using Target = bool (*)(const kad6_fuzz::Config&, kad6_fuzz::Report&);
    const Target targets[] = {
        &kad6_fuzz::FuzzAddress, &kad6_fuzz::FuzzAsn,
        &kad6_fuzz::FuzzBootstrap, &kad6_fuzz::FuzzFrame,
        &kad6_fuzz::FuzzGateway,
        &kad6_fuzz::FuzzLease, &kad6_fuzz::FuzzPath,
        &kad6_fuzz::FuzzPublish,
        &kad6_fuzz::FuzzStore,
        &kad6_fuzz::FuzzTags, &kad6_fuzz::FuzzTicket,
        &kad6_fuzz::FuzzRecords, &kad6_fuzz::FuzzRouting,
        &kad6_fuzz::FuzzShaped
    };
#if defined(KAD6_FUZZ_ASAN)
    // MSVC ASan deliberately quarantines freed blocks. Keep a finite guard so
    // pathological growth still fails, but use the Release run for the strict
    // 64 MiB leak/RSS gate. ASan's job here is OOB/UAF detection.
    constexpr std::size_t kMemoryGrowthLimit = 768u * 1024u * 1024u;
    constexpr const char* kMemoryGrowthLabel = "768 MiB ASan quarantine guard";
#else
    constexpr std::size_t kMemoryGrowthLimit = 64u * 1024u * 1024u;
    constexpr const char* kMemoryGrowthLabel = "64 MiB Release RSS guard";
#endif
    const MemorySample processStart = SampleMemory();
    std::size_t totalIterations = 0;
    std::size_t totalFailures = 0;

    for (Target target : targets) {
        const MemorySample before = SampleMemory();
        kad6_fuzz::Report report;
        try {
            (void)target(config, report);
        } catch (const std::bad_alloc&) {
            ++report.failures;
            std::printf("  FAIL: unbounded/failed allocation in fuzz target\n");
        } catch (const std::exception& e) {
            ++report.failures;
            std::printf("  FAIL: exception in fuzz target: %s\n", e.what());
        } catch (...) {
            ++report.failures;
            std::printf("  FAIL: unknown exception in fuzz target\n");
        }
        const MemorySample after = SampleMemory();
        const std::size_t rssGrowth = after.rss > before.rss ? after.rss - before.rss : 0;
        const std::size_t privateGrowth = after.private_bytes > before.private_bytes
            ? after.private_bytes - before.private_bytes : 0;
        if (rssGrowth > kMemoryGrowthLimit || privateGrowth > kMemoryGrowthLimit) {
            ++report.failures;
            std::printf("  FAIL[%s]: memory growth exceeded %s\n",
                        report.target, kMemoryGrowthLabel);
        }
        std::printf("fuzz_%-7s: %zu iterations, %zu checks, max-in=%zu, max-out=%zu, "
                    "rss=%zu KiB (delta=%zu), private=%zu KiB (delta=%zu)\n",
                    report.target, report.iterations, report.checks,
                    report.max_input, report.max_output,
                    after.rss / 1024, rssGrowth / 1024,
                    after.private_bytes / 1024, privateGrowth / 1024);
        totalIterations += report.iterations;
        totalFailures += report.failures;
    }

    const MemorySample processEnd = SampleMemory();
    std::printf("fuzz_runner: %zu total iterations, %zu failures, peak RSS=%zu KiB, "
                "final RSS delta=%zu KiB\n",
                totalIterations, totalFailures, processEnd.peak_rss / 1024,
                (processEnd.rss > processStart.rss ? processEnd.rss - processStart.rss : 0) / 1024);
    return totalFailures == 0 ? 0 : 1;
}
