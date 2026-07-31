// this file is part of eMule eSE - explicit Kad2/Kad6 tunnel adapter boundary
#include "stdafx.h"
#include "LiveTunnelKadBridge.h"
#include "LiveTunnelGatewayStorePort.h"

#include <memory>
#include <thread>
#include <utility>

namespace eSELive {
M2AModuleHandle M2A_BIND_LT3_876B98A826(const M2AParentPort&);
M2AModuleHandle M2A_BIND_LT6_8E07B736A1(const M2AParentPort&);bool RunLiveTunnelOriginServiceCharacterizationSelfTest();
bool M2A_LT6_OperateBridge(
    const M2AModuleHandle&, LiveTunnelOriginOperation,
    void*, void*, void*, void*, void*, void*);
void M2A_LT3_InitializeBridge(
    M2AModuleHandle&, void*, void (*)(void*), void*, void (*)(void*),
    void*, void (*)(void*), void*, void (*)(void*));
bool M2A_LT3_LoadEpochsBridge(
    M2AModuleHandle&, const std::vector<std::uint8_t>&, bool);
bool M2A_LT3_EpochStoreHealthyBridge(const M2AModuleHandle&) noexcept;
bool M2A_LT3_EpochStoreInitializedBridge(const M2AModuleHandle&) noexcept;
bool M2A_LT3_EpochStoreFailedBridge(const M2AModuleHandle&) noexcept;
bool M2A_LT3_CanAcceptEpochBridge(
    const M2AModuleHandle&, const std::uint8_t*, std::size_t,
    std::uint64_t) noexcept;
bool M2A_LT3_PrepareEpochUpdateBridge(
    M2AModuleHandle&, const std::uint8_t*, std::size_t, std::uint64_t,
    std::uint64_t&, std::vector<std::uint8_t>&);
bool M2A_LT3_CommitEpochUpdateBridge(M2AModuleHandle&, std::uint64_t) noexcept;
void M2A_LT3_RollbackEpochUpdateBridge(M2AModuleHandle&, std::uint64_t) noexcept;
bool M2A_LT3_PlanGatewayFrameBridge(const M2AModuleHandle&, const std::uint8_t*, std::size_t, std::uint32_t, bool, void*);
bool M2A_LT3_OperateStoresBridge(
    const M2AModuleHandle&, LiveTunnelGatewayStoreOperation,
    void*, void*, void*, void*, void*, void*);

namespace {

template <typename T>
void DestroyLT3Store(void* value) {
    delete static_cast<T*>(value);
}
bool OperateLT3(const M2AModuleHandle& handle, LiveTunnelGatewayStoreOperation operation, void* a=nullptr, void* b=nullptr, void* c=nullptr, void* d=nullptr, void* e=nullptr, void* f=nullptr) { return M2A_LT3_OperateStoresBridge(handle, operation, a, b, c, d, e, f); }

} // namespace

LiveTunnelKadBridge::LiveTunnelKadBridge(LiveTunnelKadPorts ports)
    : m_ports(std::move(ports)),
      m_m2a_binding_876b98a826(M2AAssignmentPolicy::RetainExisting),
      m_m2a_binding_8e07b736a1(M2AAssignmentPolicy::RetainExisting)
{
    m_m2a_binding_876b98a826 = M2A_BIND_LT3_876B98A826(M2AParentPort{this});
    m_m2a_binding_8e07b736a1 =
        M2A_BIND_LT6_8E07B736A1(M2AParentPort{this});
    std::unique_ptr<kad6::K6SourceLeaseTable> leases(
        new kad6::K6SourceLeaseTable());
    std::unique_ptr<kad6::K6CohortScheduler> cohorts(
        new kad6::K6CohortScheduler());
    std::unique_ptr<kad6::K6PublishBudget> budget(
        new kad6::K6PublishBudget());
    std::unique_ptr<kad6::K6PublishCoalescer> coalescer(
        new kad6::K6PublishCoalescer());
    M2A_LT3_InitializeBridge(
        m_m2a_binding_876b98a826,
        leases.get(),
        &DestroyLT3Store<kad6::K6SourceLeaseTable>,
        cohorts.get(),
        &DestroyLT3Store<kad6::K6CohortScheduler>,
        budget.get(),
        &DestroyLT3Store<kad6::K6PublishBudget>,
        coalescer.get(),
        &DestroyLT3Store<kad6::K6PublishCoalescer>);
    leases.release();
    cohorts.release();
    budget.release();
    coalescer.release();
}

bool LiveTunnelKadBridge::LT3LoadSourceEpochs(
    const std::vector<std::uint8_t>& wire, bool filePresent) {
    return M2A_LT3_LoadEpochsBridge(
        m_m2a_binding_876b98a826, wire, filePresent);
}

bool LiveTunnelKadBridge::LT3SourceEpochStoreHealthy() const noexcept {
    return M2A_LT3_EpochStoreHealthyBridge(m_m2a_binding_876b98a826);
}

bool LiveTunnelKadBridge::LT3SourceEpochStoreInitialized() const noexcept {
    return M2A_LT3_EpochStoreInitializedBridge(m_m2a_binding_876b98a826);
}

bool LiveTunnelKadBridge::LT3SourceEpochStoreFailed() const noexcept {
    return M2A_LT3_EpochStoreFailedBridge(m_m2a_binding_876b98a826);
}

bool LiveTunnelKadBridge::LT3CanAcceptSourceEpoch(
    const std::array<std::uint8_t, 32>& identity,
    std::uint64_t epoch) const noexcept {
    return M2A_LT3_CanAcceptEpochBridge(
        m_m2a_binding_876b98a826, identity.data(), identity.size(), epoch);
}

bool LiveTunnelKadBridge::LT3PrepareSourceEpochUpdate(
    const std::array<std::uint8_t, 32>& identity, std::uint64_t epoch,
    std::uint64_t& token,
    std::vector<std::uint8_t>& encoded) {
    return M2A_LT3_PrepareEpochUpdateBridge(
        m_m2a_binding_876b98a826, identity.data(), identity.size(), epoch,
        token, encoded);
}
bool LiveTunnelKadBridge::LT3CommitSourceEpochUpdate(std::uint64_t token) noexcept { return M2A_LT3_CommitEpochUpdateBridge(m_m2a_binding_876b98a826, token); }
void LiveTunnelKadBridge::LT3RollbackSourceEpochUpdate(std::uint64_t token) noexcept { M2A_LT3_RollbackEpochUpdateBridge(m_m2a_binding_876b98a826, token); }
bool LiveTunnelKadBridge::LT3PlanSearchReply(std::uint32_t requestId, const std::vector<std::uint8_t>& wire, kad6::K6Frame& frame) const { return M2A_LT3_PlanGatewayFrameBridge(m_m2a_binding_876b98a826, wire.data(), wire.size(), requestId, true, &frame); }
bool LiveTunnelKadBridge::LT3PlanExitGateway(std::uint32_t requestId, const std::uint8_t* wire, std::size_t length, kad6::K6Frame& frame) const { return M2A_LT3_PlanGatewayFrameBridge(m_m2a_binding_876b98a826, wire, length, requestId, false, &frame); }

std::map<std::uint64_t, kad6::K6SourceLease> LiveTunnelKadBridge::LT3SourceLeaseEntries() const { std::map<std::uint64_t, kad6::K6SourceLease> value; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Entries, &value); return value; }
LT3SourceLeaseValue LiveTunnelKadBridge::LT3FindSourceLease(std::uint64_t leaseId) const { LT3SourceLeaseValue value; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Find, &leaseId, &value.value, &value.found); return value; }
std::size_t LiveTunnelKadBridge::LT3SourceLeaseActiveSize() { std::size_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::ActiveSize, &value); return value; }
bool LiveTunnelKadBridge::LT3SourceLeaseCanPublish(std::uint64_t leaseId) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CanPublish, &leaseId, &value); return value; }
bool LiveTunnelKadBridge::LT3SourceLeaseCanAccept(std::uint64_t leaseId) const { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CanAccept, &leaseId, &value); return value; }
kad6::Kad6Status LiveTunnelKadBridge::LT3AddBound(std::uint32_t circuitId, const kad6::Hash16& pseudonym, const kad6::K6SourceBind& bind, const kad6::K6SourceBound& bound, std::uint64_t now) { auto value=kad6::Kad6Status::BadValue; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::AddBound, &circuitId, const_cast<kad6::Hash16*>(&pseudonym), const_cast<kad6::K6SourceBind*>(&bind), const_cast<kad6::K6SourceBound*>(&bound), &now, &value); return value; }
kad6::Kad6Status LiveTunnelKadBridge::LT3MarkPublished(std::uint64_t leaseId) { auto value=kad6::Kad6Status::BadValue; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::MarkPublished, &leaseId, &value); return value; }
kad6::Kad6Status LiveTunnelKadBridge::LT3MarkServing(std::uint64_t leaseId) { auto value=kad6::Kad6Status::BadValue; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::MarkServing, &leaseId, &value); return value; }
kad6::Kad6Status LiveTunnelKadBridge::LT3BeginDrain(std::uint64_t leaseId) { auto value=kad6::Kad6Status::BadValue; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::BeginDrain, &leaseId, &value); return value; }
bool LiveTunnelKadBridge::LT3CloseSourceLease(std::uint64_t leaseId) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Close, &leaseId, &value); return value; }
std::size_t LiveTunnelKadBridge::LT3EraseClosedSourceLeases(std::size_t maximum) { std::size_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::EraseClosed, &maximum, &value); return value; }
void LiveTunnelKadBridge::LT3QueueCircuitTeardown(std::uint32_t circuitId) { OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::QueueCircuitTeardown, &circuitId); }
std::size_t LiveTunnelKadBridge::LT3DrainQueuedCircuits(std::size_t maximum, std::vector<std::uint64_t>* transitioned) { std::size_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::DrainQueuedCircuits, &maximum, transitioned, &value); return value; }
std::size_t LiveTunnelKadBridge::LT3ExpireSourceLeases(std::uint64_t now, std::size_t maximum, std::vector<std::uint64_t>* transitioned) { std::size_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Expire, &now, &maximum, transitioned, &value); return value; }
bool LiveTunnelKadBridge::LT3CohortRegister(const kad6::K6CohortBackend& backend) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CohortRegister, const_cast<kad6::K6CohortBackend*>(&backend), &value); return value; }
bool LiveTunnelKadBridge::LT3CohortSetServing(std::uint64_t leaseId, bool serving) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CohortSetServing, &leaseId, &serving, &value); return value; }
bool LiveTunnelKadBridge::LT3CohortSelect(const kad6::Hash16& fileHash, const kad6::Hash16& cohortId, std::uint64_t streamId, kad6::K6CohortBackend& selected) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CohortSelect, const_cast<kad6::Hash16*>(&fileHash), const_cast<kad6::Hash16*>(&cohortId), &streamId, &selected, &value); return value; }
bool LiveTunnelKadBridge::LT3CohortReleaseStream(std::uint64_t streamId) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::CohortReleaseStream, &streamId, &value); return value; }
std::uint32_t LiveTunnelKadBridge::LT3PublishAdmissionPermille(std::uint64_t now) { std::uint32_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::AdmissionPermille, &now, &value); return value; }
bool LiveTunnelKadBridge::LT3PublishAdmit(const kad6::K6PublishBudgetKey& key, std::uint64_t now) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Admit, const_cast<kad6::K6PublishBudgetKey*>(&key), &now, &value); return value; }
void LiveTunnelKadBridge::LT3PublishNoteOverload(std::uint64_t now) { OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::NoteOverload, &now); }
bool LiveTunnelKadBridge::LT3PublishEnqueue(const kad6::K6PublishSchedule& schedule, std::uint32_t jitter, std::uint64_t& effectiveLeaseId) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Enqueue, const_cast<kad6::K6PublishSchedule*>(&schedule), &jitter, &effectiveLeaseId, &value); return value; }
std::vector<kad6::K6PublishSchedule> LiveTunnelKadBridge::LT3PublishTakeDue(std::uint64_t now, std::size_t maximum) { std::vector<kad6::K6PublishSchedule> value; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::TakeDue, &now, &maximum, &value); return value; }
bool LiveTunnelKadBridge::LT3PublishRemove(std::uint64_t leaseId) { bool value=false; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::Remove, &leaseId, &value); return value; }
std::size_t LiveTunnelKadBridge::LT3PublishExpire(std::uint64_t now) { std::size_t value=0; OperateLT3(m_m2a_binding_876b98a826, LiveTunnelGatewayStoreOperation::PublishExpire, &now, &value); return value; }

namespace {
bool OperateLT6(
    const M2AModuleHandle& handle, LiveTunnelOriginOperation operation,
    void* a=nullptr, void* b=nullptr, void* c=nullptr, void* d=nullptr,
    void* e=nullptr, void* f=nullptr) {
    return M2A_LT6_OperateBridge(handle, operation, a, b, c, d, e, f);
}
}

bool LiveTunnelKadBridge::LT6AddSourceLookup(std::uint32_t requestId,const LiveTunnelOriginSourceLookup& value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddSourceLookup,&requestId,const_cast<LiveTunnelOriginSourceLookup*>(&value));}
bool LiveTunnelKadBridge::LT6BindSourceLookup(std::uint32_t requestId,std::uint32_t circuitId,LiveTunnelOriginSourceLookup& value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::BindSourceLookup,&requestId,&circuitId,&value);}
bool LiveTunnelKadBridge::LT6NoteSourceLookupResult(std::uint32_t requestId){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::NoteSourceLookupResult,&requestId);}
bool LiveTunnelKadBridge::LT6TakeSourceLookup(std::uint32_t requestId,std::uint32_t circuitId,LiveTunnelOriginSourceLookup& value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::TakeSourceLookup,&requestId,&circuitId,&value);}
bool LiveTunnelKadBridge::LT6AddDownloadActivation(std::uint32_t requestId,const LiveTunnelOriginDownloadActivation& value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddDownloadActivation,&requestId,const_cast<LiveTunnelOriginDownloadActivation*>(&value));}
bool LiveTunnelKadBridge::LT6TakeDownloadActivation(std::uint32_t requestId,std::uint32_t circuitId,LiveTunnelOriginDownloadActivation& value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::TakeDownloadActivation,&requestId,&circuitId,&value);}
bool LiveTunnelKadBridge::LT6RemoveDownloadActivation(std::uint32_t requestId,LiveTunnelOriginDownloadActivation* value){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::RemoveDownloadActivation,&requestId,value);}
void LiveTunnelKadBridge::LT6RemoveDownloadActivationsByClient(std::uintptr_t token){OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::RemoveDownloadActivationsByClient,&token);}
void LiveTunnelKadBridge::LT6AddSourceRoute(std::uint64_t leaseId,std::uint32_t circuitId){OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddSourceRoute,&leaseId,&circuitId);}
bool LiveTunnelKadBridge::LT6FindSourceRoute(std::uint64_t leaseId,std::uint32_t& circuitId) const{return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::FindSourceRoute,&leaseId,&circuitId);}
bool LiveTunnelKadBridge::LT6TakeSourceRoute(std::uint64_t leaseId,std::uint32_t& circuitId){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::TakeSourceRoute,&leaseId,&circuitId);}
void LiveTunnelKadBridge::LT6AddPublishRoute(std::uint64_t leaseId,std::uint32_t circuitId){OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddPublishRoute,&leaseId,&circuitId);}
bool LiveTunnelKadBridge::LT6TakePublishRoute(std::uint64_t leaseId,std::uint32_t& circuitId){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::TakePublishRoute,&leaseId,&circuitId);}
LiveTunnelOriginAdvertiseReservation LiveTunnelKadBridge::LT6ReserveAdvertise(const std::string& key,std::uint64_t now,std::uint64_t minimumEpoch){LiveTunnelOriginAdvertiseReservation value;OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::ReserveAdvertise,const_cast<std::string*>(&key),&now,&minimumEpoch,&value);return value;}
bool LiveTunnelKadBridge::LT6FinishAdvertise(const std::string& key,std::uint64_t generation,const LiveTunnelOriginAdvertiseCompletion& completion){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::FinishAdvertise,const_cast<std::string*>(&key),&generation,const_cast<LiveTunnelOriginAdvertiseCompletion*>(&completion));}
bool LiveTunnelKadBridge::LT6SubmitAdvertise(std::uint64_t generation,LiveTunnelOriginWorkerTask task){return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::SubmitAdvertise,&generation,&task);}
void LiveTunnelKadBridge::LT6AddTargetRoute(const std::string& key,const LiveTunnelOriginTargetRoute& value){OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddTargetRoute,const_cast<std::string*>(&key),const_cast<LiveTunnelOriginTargetRoute*>(&value));}
bool LiveTunnelKadBridge::LT6FindTargetRoute(const std::string& key,std::uint64_t now,LiveTunnelOriginTargetRoute& value) const{return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::FindTargetRoute,const_cast<std::string*>(&key),&now,&value);}
void LiveTunnelKadBridge::LT6AddLiveRoute(const std::string& key,const LiveTunnelOriginTargetRoute& value){OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::AddLiveRoute,const_cast<std::string*>(&key),const_cast<LiveTunnelOriginTargetRoute*>(&value));}
bool LiveTunnelKadBridge::LT6FindLiveRoute(const std::string& key,std::uint64_t now,LiveTunnelOriginTargetRoute& value) const{return OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::FindLiveRoute,const_cast<std::string*>(&key),&now,&value);}
LiveTunnelOriginSweepResult LiveTunnelKadBridge::LT6Sweep(std::uint64_t nowSeconds,std::uint32_t nowTick,const std::set<std::uint32_t>& activeCircuits){LiveTunnelOriginSweepResult value;OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::Sweep,&nowSeconds,&nowTick,const_cast<std::set<std::uint32_t>*>(&activeCircuits),&value);return value;}
void LiveTunnelKadBridge::LT6CancelWorker() noexcept{OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::Cancel);}
void LiveTunnelKadBridge::LT6JoinWorker() noexcept{OperateLT6(m_m2a_binding_8e07b736a1,LiveTunnelOriginOperation::Join);}

bool LiveTunnelKadBridge::ShouldRouteThroughTunnel(
    const wchar_t* keyword, std::uint8_t operation_class) const
{
    return m_ports.should_route &&
           m_ports.should_route(keyword, operation_class);
}

bool LiveTunnelKadBridge::SearchStreams(
    const wchar_t* keyword, std::vector<std::uint32_t>* search_ids,
    bool force_direct) const
{
    return m_ports.search_streams && keyword &&
           m_ports.search_streams(keyword, search_ids, force_direct);
}

void LiveTunnelKadBridge::StopSearches(
    const std::vector<std::uint32_t>& search_ids) const noexcept
{
    if (!m_ports.stop_search)
        return;
    for (std::uint32_t search_id : search_ids) {
        try {
            m_ports.stop_search(search_id);
        } catch (...) {
        }
    }
}

std::uint8_t LiveTunnelKadBridge::SelectedNetworkMask(
    std::uint8_t kad2_mask, std::uint8_t kad6_mask) const
{
    const std::uint8_t selected = m_ports.selected_networks
        ? m_ports.selected_networks() : 0;
    return BuildNetworkMask((selected & kSelectedKad2) != 0,
                            (selected & kSelectedKad6) != 0,
                            kad2_mask, kad6_mask);
}

std::uint8_t LiveTunnelKadBridge::BuildNetworkMask(
    bool kad2_selected, bool kad6_selected, std::uint8_t kad2_mask,
    std::uint8_t kad6_mask) noexcept
{
    std::uint8_t mask = 0;
    if (kad2_selected)
        mask |= kad2_mask;
    if (kad6_selected)
        mask |= kad6_mask;
    return mask;
}

std::uint8_t LiveTunnelKadBridge::BuildSearchFlags(
    std::uint8_t network_mask, std::uint8_t kad2_mask,
    std::uint8_t kad6_mask, std::uint8_t kad2_flag,
    std::uint8_t kad6_flag) noexcept
{
    return static_cast<std::uint8_t>(
        ((network_mask & kad2_mask) ? kad2_flag : 0) |
        ((network_mask & kad6_mask) ? kad6_flag : 0));
}

std::size_t LiveTunnelKadBridge::NetworkIndex(
    std::uint8_t network_origin, std::uint8_t kad6_origin) noexcept
{
    return network_origin == kad6_origin ? 1u : 0u;
}

bool RunLiveTunnelKadBridgeCharacterizationSelfTest()
{
    std::vector<std::uint32_t> stopped;
    LiveTunnelKadPorts ports;
    ports.should_route = [](const wchar_t* keyword, std::uint8_t operation) {
        return keyword != nullptr && operation == 7;
    };
    ports.search_streams =
        [](const wchar_t* keyword, std::vector<std::uint32_t>* ids, bool force) {
            if (!keyword || !ids || !force)
                return false;
            ids->push_back(42);
            return true;
        };
    ports.stop_search = [&stopped](std::uint32_t id) {
        if (id == 2)
            throw id;
        stopped.push_back(id);
    };
    ports.selected_networks = [] {
        return static_cast<std::uint8_t>(
            LiveTunnelKadBridge::kSelectedKad2 |
            LiveTunnelKadBridge::kSelectedKad6);
    };

    LiveTunnelKadBridge bridge(std::move(ports));
    std::vector<std::uint32_t> ids;
    if (!bridge.ShouldRouteThroughTunnel(L"live", 7) ||
        !bridge.SearchStreams(L"live", &ids, true) ||
        ids != std::vector<std::uint32_t>{42})
        return false;
    bridge.StopSearches({1, 2, 3});
    if (stopped != std::vector<std::uint32_t>({1, 3}) ||
        bridge.SelectedNetworkMask(0x10, 0x20) != 0x30)
        return false;
    if (LiveTunnelKadBridge::BuildSearchFlags(
            0x20, 0x10, 0x20, 0x01, 0x02) != 0x02)
        return false;
    if (!bridge.LT3LoadSourceEpochs({}, false) || !bridge.LT3SourceEpochStoreHealthy()) return false;
    std::array<std::uint8_t, 32> identity{}, other{}; identity[0] = 1; other[0] = 2; std::uint64_t tokenA = 0, tokenB = 0; std::vector<std::uint8_t> wireA, wireB; bool preparedA = false, preparedB = false;
    std::thread first([&] { preparedA = bridge.LT3PrepareSourceEpochUpdate(identity, 1, tokenA, wireA); }); std::thread second([&] { preparedB = bridge.LT3PrepareSourceEpochUpdate(other, 1, tokenB, wireB); }); first.join(); second.join();
    if (preparedA == preparedB || bridge.LT3CanAcceptSourceEpoch(identity, 2) || bridge.LT3CanAcceptSourceEpoch(other, 2)) return false;
    bridge.LT3RollbackSourceEpochUpdate(preparedA ? tokenA : tokenB);
    if (!bridge.LT3CanAcceptSourceEpoch(identity, 1) || !bridge.LT3PrepareSourceEpochUpdate(identity, 1, tokenA, wireA) || wireA.empty() || !bridge.LT3CommitSourceEpochUpdate(tokenA) || bridge.LT3CanAcceptSourceEpoch(identity, 1)) return false;
    kad6::Hash16 pseudonym{}; pseudonym[0]=1; kad6::K6SourceBind bind{}; bind.transport_mask=kad6::kK6TransportTcp; bind.requested_lifetime_s=3600; bind.desired_family=4; bind.requested_mode=kad6::K6BindingMode::DedicatedVep; bind.bind_nonce[0]=1; kad6::K6SourceBound bound{}; bound.status=kad6::K6SourceBoundStatus::Ok; bound.transport_mask=bind.transport_mask; bound.binding_mode=kad6::K6BindingMode::DedicatedVep; bound.identity_mode=kad6::K6IdentityMode::OriginatorVep; bound.endpoint_slot=1; bound.source_lease_id=1; bound.lifetime_s=3600; bound.refresh_after_s=1800; bound.virtual_endpoint.addr.family=kad6::Kad6Address::Family::IPv4; bound.virtual_endpoint.addr.addr[0]=1; bound.virtual_endpoint.tcp_port=1; bound.virtual_endpoint.transport_flags=kad6::kK6EpTcpEd2k; bound.virtual_endpoint.valid_until=3600; bound.exit_apparent_ip=bound.virtual_endpoint.addr; bound.bind_nonce=bind.bind_nonce; std::vector<std::uint64_t> stoppedLeases; if (!bridge.LT3SourceEpochStoreHealthy() || bridge.LT3AddBound(7,pseudonym,bind,bound,0)!=kad6::Kad6Status::Ok || bridge.LT3AddBound(7,pseudonym,bind,bound,0)!=kad6::Kad6Status::BadValue || (bridge.LT3QueueCircuitTeardown(7),bridge.LT3DrainQueuedCircuits(1,&stoppedLeases))!=1 || stoppedLeases!=std::vector<std::uint64_t>{1}) return false; const LT3SourceLeaseValue stoppedLease=bridge.LT3FindSourceLease(1); if (!stoppedLease || stoppedLease->state!=kad6::K6SourceLeaseState::Closed || bridge.LT3EraseClosedSourceLeases(1)!=1 || bridge.LT3FindSourceLease(1)) return false;
    LiveTunnelKadBridge corrupt(LiveTunnelKadPorts{});
    if (bridge.LT3CanAcceptSourceEpoch(identity, 1) || corrupt.LT3LoadSourceEpochs(std::vector<std::uint8_t>{1}, true) || !corrupt.LT3SourceEpochStoreFailed()) return false;
    return LiveTunnelKadBridge::NetworkIndex(2,2)==1&&LiveTunnelKadBridge::NetworkIndex(1,2)==0&&
        RunLiveTunnelOriginServiceCharacterizationSelfTest();
}

} // namespace eSELive
