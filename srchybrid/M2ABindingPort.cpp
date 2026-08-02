// this file is part of eMule eSE - M2A composition-boundary self-test
#include "M2ABindingPort.h"

#include <mutex>

namespace eSELive {
namespace {

struct DestructionProbe final {
    explicit DestructionProbe(bool& destroyed) noexcept
        : destroyed(destroyed)
    {
    }

    ~DestructionProbe()
    {
        destroyed = true;
    }

    bool& destroyed;
};

bool CharacterizeMoveOnlyOwnership()
{
    bool destroyed = false;
    M2AModuleHandle first =
        MakeM2AModuleHandle(new DestructionProbe(destroyed));
    if (!first || destroyed)
        return false;

    M2AModuleHandle second = std::move(first);
    if (first || !second || destroyed)
        return false;
    second.Reset();
    return destroyed && !second;
}

bool CharacterizeCallbackAfterUnlock()
{
    std::mutex mutex;
    int snapshot = 0;
    const auto callback = [&mutex](int value) {
        if (!mutex.try_lock())
            return false;
        mutex.unlock();
        return value == 41;
    };

    {
        std::lock_guard<std::mutex> lock(mutex);
        snapshot = 41;
    }
    return callback(snapshot);
}

} // namespace

bool RunM2ABindingPortCharacterizationSelfTest()
{
    bool replaced = false, current = false, rejected = false;
    M2AModuleHandle binding =
        MakeM2AModuleHandle(new DestructionProbe(replaced));
    binding = MakeM2AModuleHandle(new DestructionProbe(current));
    M2AModuleHandle retained(M2AAssignmentPolicy::RetainExisting);
    retained = MakeM2AModuleHandle(new DestructionProbe(rejected));
    void* const first_binding = retained.Get();
    retained = MakeM2AModuleHandle(new DestructionProbe(rejected));
    return CharacterizeMoveOnlyOwnership() && replaced && !current &&
        retained.Get() == first_binding && rejected &&
        CharacterizeCallbackAfterUnlock();
}

} // namespace eSELive
