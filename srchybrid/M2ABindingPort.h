// this file is part of eMule eSE - type-erased M2A composition boundary
#pragma once

#include <utility>

namespace eSELive {

struct M2AParentPort final {
    void* const context = nullptr;

    explicit operator bool() const noexcept
    {
        return context != nullptr;
    }
};

enum class M2AAssignmentPolicy {
    Replace,
    RetainExisting,
};

class M2AModuleHandle final {
public:
    using Destroy = void (*)(void*);

    M2AModuleHandle() noexcept = default;
    explicit M2AModuleHandle(M2AAssignmentPolicy policy) noexcept
        : m_assignment_policy(policy)
    {
    }

    M2AModuleHandle(void* instance, Destroy destroy) noexcept
        : m_instance(instance),
          m_destroy(destroy)
    {
    }

    M2AModuleHandle(const M2AModuleHandle&) = delete;
    M2AModuleHandle& operator=(const M2AModuleHandle&) = delete;

    M2AModuleHandle(M2AModuleHandle&& other) noexcept
        : m_instance(other.m_instance),
          m_destroy(other.m_destroy),
          m_assignment_policy(other.m_assignment_policy)
    {
        other.m_instance = nullptr;
        other.m_destroy = nullptr;
    }

    M2AModuleHandle& operator=(M2AModuleHandle&& other) noexcept
    {
        if (this == &other)
            return *this;
        if (m_assignment_policy == M2AAssignmentPolicy::RetainExisting &&
            m_instance != nullptr)
            return *this;
        Reset();
        m_instance = other.m_instance;
        m_destroy = other.m_destroy;
        other.m_instance = nullptr;
        other.m_destroy = nullptr;
        return *this;
    }

    ~M2AModuleHandle()
    {
        Reset();
    }

    explicit operator bool() const noexcept
    {
        return m_instance != nullptr;
    }

    void* Get() noexcept { return m_instance; }
    const void* Get() const noexcept { return m_instance; }

    void Reset() noexcept
    {
        if (m_instance != nullptr && m_destroy != nullptr)
            m_destroy(m_instance);
        m_instance = nullptr;
        m_destroy = nullptr;
    }

private:
    void* m_instance = nullptr;
    Destroy m_destroy = nullptr;
    M2AAssignmentPolicy m_assignment_policy = M2AAssignmentPolicy::Replace;
};

template <typename Module>
M2AModuleHandle MakeM2AModuleHandle(Module* instance) noexcept
{
    return M2AModuleHandle(
        instance,
        [](void* raw) { delete static_cast<Module*>(raw); });
}

bool RunM2ABindingPortCharacterizationSelfTest();

} // namespace eSELive
