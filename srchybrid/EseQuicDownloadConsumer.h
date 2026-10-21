#pragma once
#include "EseDirectBatchConsumer.h"
#include "reach/direct_route_dispatch.h"
#include "reach/direct_coordinator.h"
#include "EseNativeQuicRuntime.h"
#include "EseEd2kFramer.h"
#include "EseQuicEd2kWriter.h"
#include <functional>
#include <thread>
class CDirectReachabilityManager;
class CClientReqSocket;
class CUpDownClient;
class CPartFile;
class CNativeDirectSelfTestAccess;
namespace ese {
// Explicit opt-in consumer; no capability advertisement or automatic enabling.
// Route contexts must be registered before delivering their Start actions.
class QuicDownloadConsumer final : public DirectBatchConsumer {
    friend class ::CNativeDirectSelfTestAccess;
    friend class ::CDirectReachabilityManager;
public:
    using TerminalSink=std::function<void(std::uint64_t,reach::DirectReason)>;
    QuicDownloadConsumer(CDirectReachabilityManager&,TerminalSink);
    ~QuicDownloadConsumer() override;
    bool Register(reach::DirectHandle,const reach::DirectSessionRoute&,
        const NativeQuicConfig&,const QuicPeerConfig&);
    // Explicit ownership handoff of an already authorized legacy socket.
    // Caller has executed Start/registration, but has not connected it yet.
    // An isolated pre-auth client transfers ownership to this consumer. The
    // original transfer lifetime is separately fenced by the socket binding.
    bool RegisterPreparedLegacy(reach::DirectHandle,const reach::DirectSessionRoute&,CClientReqSocket&,std::uint64_t epoch);
    bool RegisterLegacy(reach::DirectHandle,const reach::DirectSessionRoute&);
    bool Schedule(reach::DirectHandle,const std::vector<reach::DirectSessionRoute>&,std::uint64_t now);
    bool PreparedServerRoute(reach::DirectHandle,std::uint32_t,
        const std::array<std::uint8_t,32>&,const udp::Endpoint&,const reach::DirectAttemptId&,std::uint64_t now);
    // Main-thread user close; does not cancel the DCO ahead of transport drain.
    // Faults/destruction still use immediate Close. No implicit TCP fallback.
    bool RequestClose(reach::DirectHandle,std::uint32_t route,std::uint16_t wireReason);
    void Accept(std::vector<reach::DirectCoordinatorBatch>&&) noexcept override;
    void Poll() noexcept override;
    // Called only after the event/action pump has returned, never reentrantly.
    void PumpOwnedRecovery() noexcept;
    enum class TcpStartResult { Unavailable, Scheduled, Failed };
    TcpStartResult BeginObservedTcp(reach::DirectHandle) noexcept;
private:
    static bool CanResumeFileStatus(unsigned status,bool stopped) noexcept;
    static bool CanResumeFile(const CPartFile*) noexcept;
    struct Entry {
        bool occupied=false,closing=false;
        reach::DirectHandle handle;
        reach::DirectSessionRoute route;
        NativeQuicConfig native;
        QuicPeerConfig peer;
        std::uint64_t owner=0,epoch=0;
        std::uint64_t clientLifetime=0;
        std::uint64_t transferClientLifetime=0;
        CUpDownClient* ownedRouteClient=nullptr;
        std::optional<std::array<std::uint8_t,16>> legacyExpectedHash;
        std::array<std::uint8_t,80> legacyExpectedKey{};
        std::uint8_t legacyExpectedKeySize=0;
        CUpDownClient* client=nullptr; // always revalidated against host registries
        CClientReqSocket* socket=nullptr;
        std::unique_ptr<Ed2kFramer> reader;
        std::shared_ptr<QuicEd2kWriter> writer;
    };
    Entry* Find(reach::DirectHandle,std::uint32_t);
    bool Live(const Entry&) const;
    bool Attach(Entry&,std::uint64_t);
    bool StartLegacy(Entry&,std::uint64_t);
    void StopOutput(Entry&) noexcept;
    void Close(Entry&,reach::DirectReason) noexcept;
    void Batch(const reach::DirectCoordinatorBatch&);
    void Fail(reach::DirectHandle,reach::DirectReason);
    const std::thread::id thread_;
    CDirectReachabilityManager& manager_;
    TerminalSink terminal_;
    reach::DirectRouteDispatch dispatch_;
    std::array<Entry,256> entries_{};
    std::array<reach::DirectHandle,256> retiring_{}; // one terminal generation per DCO slot
    struct RecoveryIntent {
        reach::DirectHandle handle; std::uint64_t epoch=0,nextQuicProbeMs=0;
        std::optional<QuicPeerConfig> pinnedPeer; // prepared before polling, scoped to this wire attempt
    };
    std::array<RecoveryIntent,256> recovery_{}; // value-only, bounded by DCO slots
};
}
