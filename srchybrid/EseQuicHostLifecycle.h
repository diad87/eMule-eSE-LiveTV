#pragma once
#include <cstddef>
#include <cstdint>
namespace ese {
// Main-thread lifecycle only; transport factory/activation is separate.
class QuicHostLifecycle {
public:
    virtual ~QuicHostLifecycle() = default;
    virtual void Stop() = 0;
    virtual void Poll(std::uint64_t now) = 0;
    virtual std::size_t RetireClosed() = 0;
    virtual bool Empty() const noexcept = 0;
};
}
