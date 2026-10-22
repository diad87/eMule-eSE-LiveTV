#pragma once
#include <cstdint>

// Windows types are supplied by the caller's Windows/MFC header. Only integers
// cross the message queue; result storage remains owned by the mailbox.
namespace natmap {
inline std::uint64_t DecodeMapperOperation(WPARAM low, LPARAM high) {
    return static_cast<std::uint32_t>(low)
        | (static_cast<std::uint64_t>(static_cast<std::uint32_t>(high)) << 32);
}
inline bool PostMapperOperation(HWND target, UINT message, std::uint64_t operation) {
    if (!target || !message || !operation) return false;
    return ::PostMessage(target,message,
        static_cast<WPARAM>(static_cast<std::uint32_t>(operation)),
        static_cast<LPARAM>(static_cast<std::uint32_t>(operation >> 32))) != FALSE;
}
}
