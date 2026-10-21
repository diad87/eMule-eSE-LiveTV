#include "stdafx.h"
#include "EseQuicDownloadConsumer.h"
#include "DirectReachabilityManager.h"
#include "emule.h"
#include "ClientList.h"
#include "UpDownClient.h"
#include "ListenSocket.h"
#include "UploadBandwidthThrottler.h"
#include "ClientCredits.h"
#include "UploadQueue.h"
#include "Preferences.h"
#include "PartFile.h"
#include <chrono>
namespace ese {
namespace { bool Same(reach::DirectHandle a,reach::DirectHandle b) { return a.slot==b.slot && a.generation==b.generation; } }
QuicDownloadConsumer::QuicDownloadConsumer(CDirectReachabilityManager& manager,TerminalSink terminal)
    :thread_(std::this_thread::get_id()),manager_(manager),terminal_(std::move(terminal)) {}
QuicDownloadConsumer::~QuicDownloadConsumer() {
    if(std::this_thread::get_id()!=thread_) std::terminate();
    for(auto& e:entries_) if(e.occupied) Close(e,reach::DirectReason::Disabled);
    // Manager drains terminal events and retires owners after this destructor.
}
QuicDownloadConsumer::Entry* QuicDownloadConsumer::Find(reach::DirectHandle handle,std::uint32_t route) {
    for(auto& e:entries_) if(e.occupied && Same(e.handle,handle) && e.route.id==route) return &e;
    return nullptr;
}
bool QuicDownloadConsumer::Register(reach::DirectHandle handle,const reach::DirectSessionRoute& route,
    const NativeQuicConfig& native,const QuicPeerConfig& peer) {
    if(std::this_thread::get_id()!=thread_ || route.transport!=reach::DirectQuic ||
        !route.id || Find(handle,route.id) || !terminal_) return false;
    const auto snapshot=manager_.DirectConnections().Snapshot(handle);
    if(!snapshot || snapshot->peer.domain!=reach::DirectPeerDomain::NodePublicKey ||
        snapshot->peer.identity!=peer.expectedNode || snapshot->attempt_id!=peer.local.attempt ||
        !HasQuicPeerTrustPolicy(peer)) return false;
    for(auto& e:entries_) if(!e.occupied) {
        if(!dispatch_.Register(handle,route.id,route.transport)) return false;
        e.occupied=true; e.handle=handle; e.route=route; e.native=native; e.peer=peer; return true;
    }
    return false;
}
bool QuicDownloadConsumer::Schedule(reach::DirectHandle handle,
    const std::vector<reach::DirectSessionRoute>& routes,std::uint64_t now) {
    if(std::this_thread::get_id()!=thread_ || routes.size()>reach::kDirectMaxRoutes) return false;
    const auto snapshot=manager_.DirectConnections().Snapshot(handle);
    if(!snapshot || (snapshot->state!=reach::DirectSessionState::Gathering && snapshot->state!=reach::DirectSessionState::Recovering)) return false;
    for(const auto& route:routes) {
        const auto* entry=Find(handle,route.id);
        if(!entry || entry->closing || route.transport!=entry->route.transport) return false;
        const auto& a=route.candidate; const auto& b=entry->route.candidate;
        if(a.id!=b.id || a.kind!=b.kind || a.family!=b.family || a.address!=b.address ||
            a.port!=b.port || a.transport_mask!=b.transport_mask || a.evidence!=b.evidence ||
            a.scope!=b.scope || a.topology_generation!=b.topology_generation ||
            a.expires_monotonic_ms!=b.expires_monotonic_ms || a.interface_id!=b.interface_id || a.rtt_ms!=b.rtt_ms) return false;
    }
    // Own actions immediately; no caller can drop the first Start batch.
    Batch(manager_.DirectConnections().SetRoutes(handle,routes,now));
    return true;
}

bool QuicDownloadConsumer::RegisterPreparedLegacy(reach::DirectHandle handle,
    const reach::DirectSessionRoute& route,CClientReqSocket& socket,std::uint64_t epoch) {
    if(std::this_thread::get_id()!=thread_ || !terminal_ || Find(handle,route.id) ||
        (route.transport!=reach::DirectTcp && route.transport!=reach::DirectUtp) ||
        !theApp.clientlist || !theApp.listensocket || !theApp.listensocket->IsValidSocket(&socket) ||
        !socket.client || !theApp.clientlist->IsValidClient(socket.client) || socket.client->socket!=&socket ||
        !socket.OwnsLegacyDirectRoute(handle,route.id,epoch) ||
        !manager_.DirectConnections().AuthorizesStart(handle,route,epoch)) return false;
    const auto lifetime=manager_.DirectTransferClientLifetime(handle);
    if(!lifetime || *lifetime!=socket.LegacyDirectTransferLifetime() ||
        (*lifetime!=socket.client->GetDirectClientLifetime() && !socket.client->HasIsolatedDirectRouteCredits()) ||
        !manager_.HasDirectTransferSubscription(*lifetime,handle)) return false;
    for(auto& e:entries_) if(!e.occupied) {
        if(!dispatch_.Register(handle,route.id,route.transport)) return false;
        e.occupied=true; e.handle=handle; e.route=route; e.epoch=epoch;
        e.client=socket.client; e.socket=&socket; e.clientLifetime=socket.client->GetDirectClientLifetime();
        e.transferClientLifetime=*lifetime;
        if(e.clientLifetime!=*lifetime) e.ownedRouteClient=socket.client;
        return true;
    }
    return false;
}

bool QuicDownloadConsumer::RegisterLegacy(reach::DirectHandle handle,const reach::DirectSessionRoute& route) {
    if(std::this_thread::get_id()!=thread_ || !thePrefs.IsEseNetLabActive() || !terminal_ ||
        !route.id || Find(handle,route.id) || (route.transport!=reach::DirectTcp && route.transport!=reach::DirectUtp) ||
        (route.candidate.family!=4 && route.candidate.family!=6) || !route.candidate.port ||
        !(route.candidate.transport_mask&route.transport) || !theApp.clientlist || !theApp.clientcredits) return false;
    const auto state=manager_.DirectConnections().Snapshot(handle);
    const auto lifetime=manager_.DirectTransferClientLifetime(handle);
    if(!state || !lifetime || (state->state!=reach::DirectSessionState::Gathering && state->state!=reach::DirectSessionState::Recovering) ||
        state->topology_generation!=manager_.GetTopologyGeneration() || route.candidate.topology_generation!=state->topology_generation ||
        route.candidate.expires_monotonic_ms<=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) || !manager_.HasDirectTransferSubscription(*lifetime,handle)) return false;
    auto* original=theApp.clientlist->FindClientByLifetime(*lifetime);
    if(!original || original->HasIsolatedDirectRouteCredits()) return false;
    const auto expected=original->NativeDirectCandidates(state->topology_generation,route.candidate.expires_monotonic_ms).peer.expected_user_hash;
    if(!expected) return false;
    auto* credits=original->Credits(); if(!credits) credits=theApp.clientcredits->FindCredit(expected->data());
    if(credits && (memcmp(credits->GetKey(),expected->data(),16) || credits->GetSecIDKeyLen()>80)) return false;
    for(auto& e:entries_) if(!e.occupied) {
        if(!dispatch_.Register(handle,route.id,route.transport)) return false;
        e.occupied=true; e.handle=handle; e.route=route; e.transferClientLifetime=*lifetime; e.legacyExpectedHash=expected;
        if(credits) { e.legacyExpectedKeySize=credits->GetSecIDKeyLen();
            memcpy(e.legacyExpectedKey.data(),credits->GetSecureIdent(),e.legacyExpectedKeySize); }
        return true;
    }
    return false;
}

bool QuicDownloadConsumer::StartLegacy(Entry& e,std::uint64_t epoch) {
    if(e.closing || !thePrefs.IsEseNetLabActive() || !theApp.clientlist || !theApp.listensocket ||
        !manager_.DirectConnections().AuthorizesStart(e.handle,e.route,epoch)) return false;
    if(e.socket) return e.socket->OwnsLegacyDirectRoute(e.handle,e.route.id,epoch);
    auto* original=theApp.clientlist->FindClientByLifetime(e.transferClientLifetime);
    if(!original || !e.legacyExpectedHash || !manager_.HasDirectTransferSubscription(e.transferClientLifetime,e.handle)) return false;
    const auto expected=original->NativeDirectCandidates(e.route.candidate.topology_generation,e.route.candidate.expires_monotonic_ms).peer.expected_user_hash;
    if(expected!=e.legacyExpectedHash) return false;
    auto* pinned=original->Credits(); if(!pinned) pinned=theApp.clientcredits->FindCredit(expected->data());
    if((pinned ? pinned->GetSecIDKeyLen() : 0)!=e.legacyExpectedKeySize ||
        (e.legacyExpectedKeySize && memcmp(pinned->GetSecureIdent(),e.legacyExpectedKey.data(),e.legacyExpectedKeySize))) return false;
    uint32 ipv4=0; if(e.route.candidate.family==4) memcpy(&ipv4,e.route.candidate.address.data(),4);
    // ed2kID=false consumes a host-order hybrid ID; route bytes are network-order.
    auto temporary=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),e.route.candidate.port,ntohl(ipv4),0,0,false);
    if(!temporary->EnableDirectRouteCreditIsolation(*expected,pinned)) return false;
    if(e.route.candidate.family==6) temporary->SetIPv6Address(CAddress::FromIPv6Bytes(e.route.candidate.address.data()));
    theApp.clientlist->AddClient(temporary.get());
    if(!theApp.clientlist->IsValidClient(temporary.get())) return false;
    e.client=temporary.get(); e.clientLifetime=e.client->GetDirectClientLifetime(); e.ownedRouteClient=temporary.release(); e.epoch=epoch;
    e.socket=new CClientReqSocket(e.client); e.client->socket=e.socket;
    if(e.route.transport==reach::DirectUtp && !e.socket->InitUtpSupport()) return false;
    if(!e.socket->RegisterLegacyDirectRoute(e.handle,e.route,epoch,e.transferClientLifetime) ||
        !e.socket->Create(e.route.candidate.family==6 ? AF_INET6 : AF_INET)) return false;
    const bool encrypted=original->HasValidHash() && original->SupportsCryptLayer() && thePrefs.IsCryptLayerEnabled() &&
        (original->RequestsCryptLayer() || thePrefs.IsCryptLayerPreferred());
    e.socket->SetConnectionEncryption(encrypted,encrypted ? expected->data() : nullptr,false);
    SOCKADDR_STORAGE address{}; int size=0;
    if(e.route.candidate.family==4) {
        auto& a=*reinterpret_cast<sockaddr_in*>(&address); a.sin_family=AF_INET; a.sin_port=htons(e.route.candidate.port);
        memcpy(&a.sin_addr,e.route.candidate.address.data(),4); size=sizeof a;
    } else {
        auto& a=*reinterpret_cast<sockaddr_in6*>(&address); a.sin6_family=AF_INET6; a.sin6_port=htons(e.route.candidate.port);
        memcpy(&a.sin6_addr,e.route.candidate.address.data(),16);
        if(e.route.candidate.scope==reach::DirectScope::SameLan) {
            if(e.route.candidate.interface_id>UINT32_MAX) return false;
            a.sin6_scope_id=static_cast<uint32>(e.route.candidate.interface_id);
        }
        size=sizeof a;
    }
    e.socket->WaitForOnConnect();
    if(!e.socket->Connect(reinterpret_cast<sockaddr*>(&address),size) && WSAGetLastError()!=WSAEWOULDBLOCK) return false;
    e.client->SendHelloPacket();
    return true;
}

bool QuicDownloadConsumer::Live(const Entry& e) const {
    return e.socket && e.client && theApp.clientlist && theApp.listensocket &&
        theApp.clientlist->IsValidClient(e.client) && theApp.listensocket->IsValidSocket(e.socket) &&
        e.clientLifetime && e.client->GetDirectClientLifetime()==e.clientLifetime &&
        manager_.HasDirectTransferSubscription(e.transferClientLifetime ? e.transferClientLifetime : e.clientLifetime,e.handle) &&
        (!e.transferClientLifetime || theApp.clientlist->FindClientByLifetime(e.transferClientLifetime)) &&
        e.client->socket==e.socket && e.socket->client==e.client &&
        (e.route.transport!=reach::DirectQuic || e.client->NativeDirectExpectedNode()==e.peer.expectedNode);
}
bool QuicDownloadConsumer::PreparedServerRoute(reach::DirectHandle handle,std::uint32_t route,
    const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,const reach::DirectAttemptId& attempt,std::uint64_t now) {
    if(std::this_thread::get_id()!=thread_ || endpoint.scope) return false;
    const auto* entry=Find(handle,route);
    if(!entry || entry->closing || !entry->owner || !entry->native.server || entry->peer.local.role!=1 ||
        entry->peer.expectedNode!=peer || entry->peer.local.attempt!=attempt ||
        entry->route.transport!=reach::DirectQuic || entry->route.candidate.address!=endpoint.address ||
        entry->route.candidate.port!=endpoint.port || entry->route.candidate.family!=(endpoint.ipv6 ? 6 : 4)) return false;
    const auto snapshot=manager_.DirectConnections().Snapshot(handle);
    const auto lifetime=manager_.DirectTransferClientLifetime(handle);
    if(!snapshot || snapshot->attempt_id!=attempt || snapshot->peer.domain!=reach::DirectPeerDomain::NodePublicKey ||
        snapshot->state==reach::DirectSessionState::Failed || snapshot->state==reach::DirectSessionState::Cancelled ||
        snapshot->peer.identity!=peer || !lifetime || !theApp.clientlist ||
        !theApp.clientlist->FindClientByLifetime(*lifetime) || !manager_.HasDirectTransferSubscription(*lifetime,handle) ||
        entry->route.candidate.topology_generation!=manager_.GetTopologyGeneration() ||
        entry->route.candidate.expires_monotonic_ms<=now) return false;
    const auto* client=theApp.clientlist->FindClientByLifetime(*lifetime);
    if(!client || client->NativeDirectExpectedNode()!=peer) return false;
    const auto* transport=manager_.FindNativeQuicLab(entry->owner);
    if(!transport) return false;
    const auto state=transport->Snapshot();
    return state.started && !state.closed;
}
bool QuicDownloadConsumer::Attach(Entry& e,std::uint64_t epoch) {
    if(e.route.transport!=reach::DirectQuic) {
        if(e.closing || !Live(e) || !e.socket->AdoptLegacyDirectRoute(e.handle,e.route.id,epoch)) return false;
        e.client=e.socket->client; e.clientLifetime=e.client->GetDirectClientLifetime();
        if(e.ownedRouteClient) { delete e.ownedRouteClient; e.ownedRouteClient=nullptr; }
        e.epoch=epoch; return true;
    }
    if(e.closing || !e.owner || e.socket || !theApp.clientlist || !theApp.listensocket) return false;
    const auto* bound=manager_.ValidateNativeQuicDelivery(e.owner,e.handle,e.route.id,epoch);
    auto* transport=manager_.FindNativeQuicLab(e.owner);
    if(!bound || !transport) return false;
    const auto lifetime=manager_.DirectTransferClientLifetime(e.handle);
    if(!lifetime) return false;
    auto* client=theApp.clientlist->FindClientByLifetime(*lifetime);
    if(!client || client->socket ||
        !manager_.HasDirectTransferSubscription(client->GetDirectClientLifetime(),e.handle) ||
        !client->MatchesNativeDirectBoundIdentity(bound->node,bound->userHash)) return false;
    e.reader=std::make_unique<Ed2kFramer>(transport->RxPool());
    e.writer=std::make_shared<QuicEd2kWriter>(transport->TxPool());
    e.client=client; e.socket=new CClientReqSocket(client); e.epoch=epoch;
    e.clientLifetime=client->GetDirectClientLifetime();
    if(!e.socket->AttachDirectWriter(e.owner,e.handle,e.route.id,epoch,e.writer)) return false;
    if(epoch>1) {
        // Reservations/inflaters and buffered upload work belong to the old
        // stream. Accepted PartFile ranges, identity and accounting survive.
        if(client->GetRequestFile()) {
            client->ClearDownloadBlockRequests(); client->SetDownloadState(DS_CONNECTING);
        }
        if(theApp.uploadqueue && !theApp.uploadqueue->ResetDirectUploadStream(client,epoch)) return false;
        if(theApp.uploadqueue && theApp.uploadqueue->IsDownloading(client) && theApp.uploadBandwidthThrottler) {
            if(!client->GetSlotNumber()) return false;
            theApp.uploadBandwidthThrottler->AddToStandardList(client->GetSlotNumber()-1,e.socket);
        }
    }
    if(!e.native.server) client->SendHelloPacket(); // existing HELLO parser drives ConnectionEstablished
    return true;
}
void QuicDownloadConsumer::StopOutput(Entry& e) noexcept {
    e.closing=true;
    if(e.socket && theApp.listensocket && theApp.listensocket->IsValidSocket(e.socket)) {
        if(e.client && theApp.clientlist && theApp.clientlist->IsValidClient(e.client) &&
            e.client->Credits() && theApp.uploadqueue && theApp.uploadqueue->IsDownloading(e.client)) {
            e.client->UpdateUploadingStatisticsData();
            if(theApp.uploadBandwidthThrottler) theApp.uploadBandwidthThrottler->RemoveFromStandardList(e.socket);
        }
        e.socket->StopDirectOutput();
        e.socket->Safe_Delete();
    }
    e.socket=nullptr; e.client=nullptr;
    if(e.ownedRouteClient && theApp.clientlist && theApp.clientlist->IsValidClient(e.ownedRouteClient)) delete e.ownedRouteClient;
    e.ownedRouteClient=nullptr;
    if(e.writer) e.writer->Stop();
    e.writer.reset(); e.reader.reset(); // before owner/pool retirement
}
bool QuicDownloadConsumer::RequestClose(reach::DirectHandle handle,std::uint32_t route,std::uint16_t code) {
    if(std::this_thread::get_id()!=thread_) return false;
    auto* e=Find(handle,route);
    if(!e || !e->owner) return false;
    auto* transport=manager_.FindNativeQuicLab(e->owner);
    if(!transport || (!e->closing && (!Live(*e) ||
        !manager_.ValidateNativeQuicDelivery(e->owner,handle,route,e->epoch)))) return false;
    if(!transport->RequestClose(code)) return false;
    StopOutput(*e);
    return true;
}
void QuicDownloadConsumer::Close(Entry& e,reach::DirectReason reason) noexcept {
    StopOutput(e);
    if(auto* transport=manager_.FindNativeQuicLab(e.owner)) transport->Close(reason);
}
void QuicDownloadConsumer::Fail(reach::DirectHandle handle,reach::DirectReason reason) {
    Batch(manager_.DirectConnections().Cancel(handle,reason));
}
void QuicDownloadConsumer::Batch(const reach::DirectCoordinatorBatch& batch) {
    if(!manager_.DirectConnections().Snapshot(batch.handle) || dispatch_.HasTerminal(batch.handle)) return;
    const auto recoveryState=manager_.DirectConnections().Snapshot(batch.handle);
    if(recoveryState && recoveryState->state==reach::DirectSessionState::Recovering &&
        batch.handle.slot<recovery_.size()) {
        auto& intent=recovery_[batch.handle.slot];
        if(!Same(intent.handle,batch.handle) || intent.epoch!=recoveryState->epoch) {
            intent={}; intent.handle=batch.handle; intent.epoch=recoveryState->epoch;
            for(const auto& entry:entries_) if(entry.occupied && Same(entry.handle,batch.handle) &&
                entry.route.transport==reach::DirectQuic && entry.epoch==recoveryState->epoch &&
                entry.peer.persistent && entry.peer.hasPin && !entry.peer.allowFirstUse && !entry.peer.trustCommitter) {
                intent.pinnedPeer=entry.peer; break;
            }
        }
    }
    const auto split=dispatch_.Split(batch);
    if(!split) {
        // Fail before executing any unvalidated route action. Cancellation's
        // Close list may contain that same unknown route; never recurse through
        // it. Close only owned contexts and deliver its central terminal.
        auto cancelled=manager_.DirectConnections().Cancel(batch.handle,reach::DirectReason::NoRoute);
        for(auto& entry:entries_) if(entry.occupied && Same(entry.handle,batch.handle)) Close(entry,reach::DirectReason::NoRoute);
        reach::DirectCoordinatorBatch terminalOnly{batch.handle,{},std::move(cancelled.terminal_subscribers)};
        for(const auto& action:cancelled.actions)
            if(action.type==reach::DirectActionType::Terminal) terminalOnly.actions.push_back(action);
        if(!terminalOnly.actions.empty()) Batch(terminalOnly);
        return;
    }
    for(const auto step:split->order) {
        const auto& action=split->transports[step.transport].actions[step.action];
        if(action.type==reach::DirectActionType::Terminal) continue; // central below, including no-route attempts
        auto* e=Find(batch.handle,action.route_id);
        switch(action.type) {
        case reach::DirectActionType::Start:
            if(!e) { Fail(batch.handle,reach::DirectReason::NoRoute); return; }
            if(e->route.transport!=reach::DirectQuic) {
                if(!StartLegacy(*e,action.session_epoch)) {
                    const auto state=manager_.DirectConnections().Snapshot(e->handle);
                    if(!state || manager_.DirectEvents().TryPush({e->handle,state->topology_generation,e->route.id,1,
                        action.session_epoch,reach::DirectEventType::Closed,0,reach::DirectReason::DirectUnreachable})!=reach::DirectEnqueueStatus::Accepted)
                        Fail(batch.handle,reach::DirectReason::ResourceLimit);
                }
                break;
            }
            if(!e->owner) {
                e->peer.sessionEpoch=action.session_epoch;
                e->owner=manager_.BeginNativeQuicLab(e->native,e->peer,e->handle,e->route);
                if(!e->owner) { Fail(batch.handle,reach::DirectReason::DirectUnreachable); return; }
            }
            break;
        case reach::DirectActionType::Attach:
            if(!e || !Attach(*e,action.session_epoch)) { Fail(batch.handle,reach::DirectReason::DirectUnreachable); return; }
            break;
        case reach::DirectActionType::Close:
            if(e && action.session_epoch>=e->epoch) Close(*e,action.reason);
            break;
        case reach::DirectActionType::Terminal:
            break;
        }
    }
    for(const auto& action:batch.actions) if(action.type==reach::DirectActionType::Terminal) {
        if(!dispatch_.MarkTerminal(batch.handle)) return;
        if(batch.handle.slot<retiring_.size()) retiring_[batch.handle.slot]=batch.handle;
        for(auto& entry:entries_) if(entry.occupied && Same(entry.handle,batch.handle)) Close(entry,action.reason);
        for(const auto subscriber:split->terminal_subscribers) terminal_(subscriber,action.reason);
    }
}
void QuicDownloadConsumer::Accept(std::vector<reach::DirectCoordinatorBatch>&& batches) noexcept {
    if(std::this_thread::get_id()!=thread_) std::terminate();
    try { for(const auto& batch:batches) Batch(batch); }
    catch(...) { for(auto& e:entries_) if(e.occupied) { Close(e,reach::DirectReason::ResourceLimit); } }
}
bool QuicDownloadConsumer::CanResumeFileStatus(unsigned status,bool stopped) noexcept {
    // Fail closed for completion, pause, errors and initial hashing states.
    return !stopped && (status==PS_READY || status==PS_EMPTY);
}
bool QuicDownloadConsumer::CanResumeFile(const CPartFile* file) noexcept {
    return file && CanResumeFileStatus(file->GetStatus(),file->IsStopped());
}
void QuicDownloadConsumer::PumpOwnedRecovery() noexcept {
    if(std::this_thread::get_id()!=thread_) std::terminate();
    for(auto& intent:recovery_) if(intent.handle.generation) {
        const auto recoveryHandle=intent.handle;
        try {
            const auto state=manager_.DirectConnections().Snapshot(intent.handle);
            const auto lifetime=manager_.DirectTransferClientLifetime(intent.handle);
            auto* client=lifetime && theApp.clientlist ? theApp.clientlist->FindClientByLifetime(*lifetime) : nullptr;
            if(!state || state->state!=reach::DirectSessionState::Recovering || state->epoch!=intent.epoch ||
                !client || !CanResumeFile(client->GetRequestFile()) ||
                !manager_.HasDirectTransferSubscription(*lifetime,intent.handle)) { intent={}; continue; }
            if(client->socket) continue; // old output must detach before preparing another adapter
            auto pending=intent; intent={}; // single use before any Start/callback
            const auto result=BeginObservedTcp(pending.handle);
            if(result==TcpStartResult::Unavailable) {
                const auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
                if(pending.pinnedPeer && now>=pending.nextQuicProbeMs) {
                    pending.nextQuicProbeMs=now+1500; // bounded retries; never hot-loop profile IO or PROBE
                    manager_.BeginOwnedDirectQuicRecovery(pending.handle,*pending.pinnedPeer);
                }
                // No Start was emitted. Retain the wait only for this still-live recovery.
                const auto current=manager_.DirectConnections().Snapshot(pending.handle);
                if(!intent.handle.generation && current && current->state==reach::DirectSessionState::Recovering &&
                    current->epoch==pending.epoch) intent=pending;
            }
        } catch(...) {
            intent={};
            Fail(recoveryHandle,reach::DirectReason::ResourceLimit);
        }
    }
}
QuicDownloadConsumer::TcpStartResult QuicDownloadConsumer::BeginObservedTcp(reach::DirectHandle handle) noexcept {
    if(std::this_thread::get_id()!=thread_) std::terminate();
    try {
        const auto state=manager_.DirectConnections().Snapshot(handle);
        const auto lifetime=manager_.DirectTransferClientLifetime(handle);
        auto* client=lifetime && theApp.clientlist ? theApp.clientlist->FindClientByLifetime(*lifetime) : nullptr;
        if(!state || (state->state!=reach::DirectSessionState::Gathering && state->state!=reach::DirectSessionState::Recovering) ||
            !client || client->socket || !CanResumeFile(client->GetRequestFile()) ||
            !manager_.HasDirectTransferSubscription(*lifetime,handle)) return TcpStartResult::Unavailable;
        reach::NativeDirectTransportPolicy policy; policy.enabled_transports=reach::DirectTcp;
        const auto selected=manager_.SelectDirectDownloadRoutes(handle,policy);
        if(selected.routes.empty()) return TcpStartResult::Unavailable;
        // Reserve every context before any Start. Terminal Batch retires partial reservations.
        for(const auto& route:selected.routes) if(!RegisterLegacy(handle,route)) {
            Fail(handle,reach::DirectReason::NoRoute); return TcpStartResult::Failed;
        }
        if(!Schedule(handle,selected.routes,static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()))) {
            Fail(handle,reach::DirectReason::NoRoute); return TcpStartResult::Failed;
        }
        client->SetDownloadState(DS_CONNECTING);
        return TcpStartResult::Scheduled;
    } catch(...) { Fail(handle,reach::DirectReason::ResourceLimit); return TcpStartResult::Failed; }
}
void QuicDownloadConsumer::Poll() noexcept {
    if(std::this_thread::get_id()!=thread_) std::terminate();
    for(auto& e:entries_) if(e.occupied) {
        try {
            if(e.socket && !e.closing) {
                if(!Live(e))
                    Fail(e.handle,reach::DirectReason::PeerGone);
                else if(e.route.transport!=reach::DirectQuic) {
                    // Legacy RX/TX belongs to the existing OS/uTP callbacks
                    // and throttler, never to QUIC framing/pools. Batch owns
                    // adoption/close/terminal and the common dispatch drain.
                }
                else if(!e.socket->PumpDirectStream(e.owner,e.handle,e.route.id,e.epoch,*e.reader)) {
                    // A parser/binding failure may already have emitted its
                    // typed Closed event. Do not mask it with PeerGone.
                    auto* source=manager_.FindNativeQuicLab(e.owner);
                    if(source && source->Snapshot().closed) StopOutput(e);
                    else Fail(e.handle,reach::DirectReason::DirectUnreachable);
                }
                else {
                    const auto result=e.socket->FlushDirectStream(e.owner,e.handle,e.route.id,e.epoch,*e.writer);
                    if(result.status!=reach::DirectIoStatus::Accepted && result.status!=reach::DirectIoStatus::WouldBlock)
                        Fail(e.handle,reach::DirectReason::DirectUnreachable);
                    else if(result.accepted && e.writer->Remaining()==0 && e.socket->HasQueues()
                        && theApp.uploadBandwidthThrottler) {
                        // Native WouldBlock has no TCP FD_WRITE. Re-arm the
                        // existing throttler only after actual writer progress
                        // drains a segment; do not spin/requeue on empty polls
                        // or send around its bandwidth policy.
                        theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(e.socket,true);
                    }
                }
            }
            if(e.closing && (!e.owner || manager_.ReleaseNativeQuicLab(e.owner))) {
                if(!dispatch_.MarkDrained(e.handle,e.route.id,e.route.transport)) std::terminate();
                e=Entry{};
            }
        } catch(...) { Close(e,reach::DirectReason::ResourceLimit); }
    }
    for(auto& handle:retiring_) if(handle.generation) {
        bool ownsContext=false;
        for(const auto& e:entries_) if(e.occupied && Same(e.handle,handle)) { ownsContext=true; break; }
        if(!ownsContext && manager_.ReleaseDirectAttempt(handle,dispatch_)) handle={};
    }
}
}
