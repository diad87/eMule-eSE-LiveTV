#pragma once

#include <cstdint>
#include <cstring>

// Coherent identity of the Broadcast-first HLS source selected for a key.
// CLiveStreamManager copies and revalidates every field under its lock.
struct LiveHlsSourceSnapshot {
    std::uint8_t streamKey[16];
    std::uint64_t generation;
    bool broadcast;

    LiveHlsSourceSnapshot()
        : generation(0), broadcast(false)
        { std::memset(streamKey, 0, sizeof streamKey); }
};

// Only a successful response with a body may refresh the Viewer watchdog.
enum class LiveHlsReadPreparation {
    Failed = 0,
    PreparedWithoutBody,
    PreparedWithBody
};

enum class LiveHlsReadExecution {
    Stale = 0,
    Failed,
    Prepared
};

typedef LiveHlsReadPreparation (*LiveHlsReadPrepareCallback)(void* context);
