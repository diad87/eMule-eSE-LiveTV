// this file is part of eMule eSE - portable Kad6 release state owner
#include "LiveTunnelReleaseGate.h"
#include <atomic>
#include <limits>
#include <thread>
#include <utility>
namespace eSELive {
LiveTunnelReleaseGate::LiveTunnelReleaseGate(const M2AParentPort& parent)
{ (void)parent; }
void LiveTunnelReleaseGate::Configure(
    const LiveTunnelReleaseStorePort& port) noexcept
{
    std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
    m_k6ExitNoticeServer = port;
}
bool LiveTunnelReleaseGate::LoadEvidence()
{
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
      if (m_k6ReleaseEvidenceLoaded) return m_k6ReleaseEvidencePresent;
      port = m_k6ExitNoticeServer; }
    std::vector<std::uint8_t> wire;
    std::uint32_t status = 0;
    const bool present = port.load && port.load(port.context, wire, status);
    std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
    if (!m_k6ReleaseEvidenceLoaded) {
        m_k6ReleaseEvidenceLoaded = true; m_k6ReleaseStatus = status;
        m_k6ReleaseEvidencePresent = present;
        if (present) m_k6ReleaseEvidence = std::move(wire);
    }
    return m_k6ReleaseEvidencePresent;
}
bool LiveTunnelReleaseGate::SaveEvidence(
    const std::vector<std::uint8_t>& wire)
{
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
      port = m_k6ExitNoticeServer; }
    if (!port.save || !port.save(port.context, wire)) return false;
    std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
    m_k6ReleaseEvidence = wire;
    m_k6ReleaseEvidenceLoaded = m_k6ReleaseEvidencePresent = true;
    return true;
}
LiveTunnelReleaseSnapshot LiveTunnelReleaseGate::Snapshot() const
{
    std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
    return {m_k6ReleaseEvidencePresent, m_k6ReleaseRuntimeHealthy,
        m_k6PublicStableEnabled,
        m_k6PublicBetaEnabled, m_k6ReleaseStatus, m_k6ReleaseEvidence};
}
void LiveTunnelReleaseGate::ApplyEvaluation(
    bool optIn, bool betaOptIn, bool healthy, std::uint32_t evidence,
    std::uint32_t ok, std::uint32_t optOut, std::uint32_t unhealthy,
    std::uint32_t drain)
{
    const bool beta = betaOptIn && healthy;
    const std::uint32_t stable = !optIn ? optOut :
        evidence != ok ? evidence : !healthy ? unhealthy : ok;
    const bool enable = stable == ok || beta; bool previous;
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
      m_k6ReleaseRuntimeHealthy = healthy; m_k6PublicBetaEnabled = beta;
      m_k6ReleaseStatus = beta ? ok : stable;
      previous = m_k6PublicStableEnabled; port = m_k6ExitNoticeServer;
      if (enable != previous) m_k6PublicStableEnabled = enable; }
    if (enable == previous || !port.services) return;
    if (port.services(port.services_context, enable, enable ? 0 : drain))
        return;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
      m_k6PublicStableEnabled = m_k6PublicBetaEnabled = false;
      m_k6ReleaseStatus = unhealthy; }
    (void)port.services(port.services_context, false, 0);
}
bool LiveTunnelReleaseGate::IsEnabled() const noexcept
{ std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
  return m_k6PublicStableEnabled; }
bool LiveTunnelReleaseGate::GetChallenge(
    std::string& text, std::uint64_t now)
{
    std::array<std::uint8_t, 32> value{}; LiveTunnelReleaseStorePort port;
    bool generate;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
      generate = !m_k6ReleaseChallengeReady ||
          m_k6ReleaseChallengeExpires <= now;
      if (!generate) value = m_k6ReleaseChallenge;
      port = m_k6ExitNoticeServer; }
    if (generate) {
        if (now > (std::numeric_limits<std::uint64_t>::max)() - 60 ||
            !port.random || !port.random(port.context, value.data(), value.size())) {
            std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
            ClearChallengeLocked(); return false;
        }
        std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
        if (!m_k6ReleaseChallengeReady || m_k6ReleaseChallengeExpires <= now) {
            m_k6ReleaseChallenge = value; m_k6ReleaseChallengeExpires = now + 60;
            m_k6ReleaseChallengeReady = true;
        } else value = m_k6ReleaseChallenge;
    }
    static const char hex[] = "0123456789abcdef";
    text.resize(value.size() * 2);
    for (std::size_t i = 0; i < value.size(); ++i) {
        text[i * 2] = hex[value[i] >> 4];
        text[i * 2 + 1] = hex[value[i] & 15];
    }
    return true;
}
bool LiveTunnelReleaseGate::ConsumeChallenge(
    const std::string& text, std::uint64_t now) noexcept
{
    std::array<std::uint8_t, 32> decoded{};
    if (!DecodeHex(text, decoded)) return false;
    std::lock_guard<std::mutex> guard(m_k6ReleaseLock);
    std::uint8_t different = 0;
    for (std::size_t i = 0; i < decoded.size(); ++i)
        different |= decoded[i] ^ m_k6ReleaseChallenge[i];
    const bool valid = m_k6ReleaseChallengeReady &&
        m_k6ReleaseChallengeExpires > now && different == 0;
    if (valid) ClearChallengeLocked();
    return valid;
}
bool LiveTunnelReleaseGate::StartNotice(
    std::uint16_t number, const std::string& notice)
{
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock); port = m_k6ExitNoticeServer; }
    return port.notice_start &&
        port.notice_start(port.context, number, notice);
}
void LiveTunnelReleaseGate::StopNotice() noexcept
{
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock); port = m_k6ExitNoticeServer; }
    if (port.notice_stop) port.notice_stop(port.context);
}
LiveTunnelReleaseNoticeSnapshot
LiveTunnelReleaseGate::NoticeSnapshot() const noexcept
{
    LiveTunnelReleaseStorePort port;
    { std::lock_guard<std::mutex> guard(m_k6ReleaseLock); port = m_k6ExitNoticeServer; }
    return port.notice_snapshot ? port.notice_snapshot(port.context)
                                : LiveTunnelReleaseNoticeSnapshot{};
}
bool LiveTunnelReleaseGate::DecodeHex(
    const std::string& text, std::array<std::uint8_t, 32>& out) noexcept
{
    if (text.size() != out.size() * 2) return false;
    const auto nibble = [](char c) noexcept {
        return c >= '0' && c <= '9' ? c - '0' :
            c >= 'a' && c <= 'f' ? c - 'a' + 10 :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int high = nibble(text[i * 2]), low = nibble(text[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}
void LiveTunnelReleaseGate::ClearChallengeLocked() noexcept
{
    m_k6ReleaseChallenge.fill(0); m_k6ReleaseChallengeExpires = 0;
    m_k6ReleaseChallengeReady = false;
}
M2AModuleHandle M2A_BIND_LT1_BAB3CE64A0(const M2AParentPort& parent)
{ return MakeM2AModuleHandle(new LiveTunnelReleaseGate(parent)); }
LiveTunnelReleaseGate* ResolveLiveTunnelReleaseGate(
    M2AModuleHandle& handle) noexcept
{ return static_cast<LiveTunnelReleaseGate*>(handle.Get()); }
const LiveTunnelReleaseGate* ResolveLiveTunnelReleaseGate(
    const M2AModuleHandle& handle) noexcept
{ return static_cast<const LiveTunnelReleaseGate*>(handle.Get()); }
namespace {
struct TestContext { LiveTunnelReleaseGate* gate; bool unlocked = false; };
bool TestRandom(void* raw, std::uint8_t* bytes, std::size_t size)
{
    TestContext& context = *static_cast<TestContext*>(raw);
    for (std::size_t i = 0; i < size; ++i) bytes[i] = std::uint8_t(i + 1);
    context.unlocked = !context.gate->IsEnabled(); return true;
}
} // namespace
bool RunLiveTunnelReleaseGateCharacterizationSelfTest()
{
    int parent = 0; LiveTunnelReleaseGate gate(M2AParentPort{&parent});
    TestContext context{&gate}; LiveTunnelReleaseStorePort port;
    port.context = &context; port.random = TestRandom; gate.Configure(port);
    std::string challenge;
    if (!gate.GetChallenge(challenge, 100) || !context.unlocked ||
        !gate.ConsumeChallenge(challenge, 101) ||
        gate.ConsumeChallenge(challenge, 101) || gate.GetChallenge(challenge,
            (std::numeric_limits<std::uint64_t>::max)() - 30)) return false;
    gate.ApplyEvaluation(true, false, true, 0, 0, 1, 3, 30);
    std::atomic_bool coherent{true};
    std::thread reader([&] { if (!gate.Snapshot().public_enabled)
        coherent = false; });
    reader.join(); return gate.IsEnabled() && coherent && context.unlocked;
}
} // namespace eSELive
