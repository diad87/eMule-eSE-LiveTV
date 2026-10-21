#include "stdafx.h"
#include "Log.h"
#include "EseQuicAttemptRetirement.h"
#include "EseDirectAttemptRetirement.h"
#include "EseQuicDownloadConsumer.h"
#include "DirectReachabilityManager.h"

#include <chrono>
#include <exception>
#include <ctime>
#include "emule.h"
#include "Preferences.h"
#include "DownloadQueue.h"
#include "ClientList.h"
#include "updownclient.h"
#include "ClientUDPSocket.h"
#include "ListenSocket.h"
#include "PartFile.h"
#include "LocalNetworkSignature.h"
#include "NodeIdentity.h"
#include "EseQuicHostStart.h"
#include "EseQuicDcoActions.h"
#include "EseKad6ContactCacheFile.h"
#include "EseKad6ContactRefreshReplies.h"
#include "Kad6CryptoHost.h"
#include "EseControlInitiatorHost.h"
#include "EseKad6ResolutionHost.h"
#include "EseKad6FindContacts.h"
#include "EseKad6ServiceCapabilities.h"
#include "EseKad6IndexService.h"
#include "EseKad6IndexBootstrap.h"
#include "EseKad6PublicationSerial.h"
#include "EseKad6PublicationAttempt.h"
#include "EseKad6PublicationDescriptor.h"
#include "EseKad6NearestContacts.h"
#include "KnownFile.h"
#include "EsePeerTrustStore.h"
#include "UploadQueue.h"
#include "SharedFileList.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Prefs.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kademlia/kademlia/UDPFirewallTester.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace {
std::wstring PeerTrustDirectory()
{
	std::wstring path(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR));
	if(path.empty()) return {};
	if(path.back()!=L'\\' && path.back()!=L'/') path+=L'\\';
	return path+L"peer_trust";
}
std::wstring PeerTrustPath(const std::wstring& directory,const std::array<std::uint8_t,32>& node)
{
	if(directory.empty() || !reach::NonzeroIdentity(node)) return {};
	std::wstring path=directory+L"\\";
	for(const auto byte:node) { path+=L"0123456789abcdef"[byte>>4]; path+=L"0123456789abcdef"[byte&15]; }
	return path+L".trust"; // Node-only; never IP/user_hash or endpoint-derived trust.
}
bool SameResolutionSource(const ese::discovery::DirectSource& a,const ese::discovery::DirectSource& b) noexcept
{
	return a.node==b.node && a.digest==b.digest && a.generation==b.generation && a.serial==b.serial &&
		a.file==b.file && a.fileSize==b.fileSize;
}
}

ese::trust::LoadResult CDirectReachabilityManager::LoadDirectQuicPeerTrust(
	const std::array<std::uint8_t,32>& node,ese::trust::Record& output) const
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !reach::NonzeroIdentity(node)) return ese::trust::LoadResult::Invalid;
	try {
		const auto directory=PeerTrustDirectory();
		if(directory.empty()) return ese::trust::LoadResult::Invalid;
		const auto attributes=GetFileAttributesW(directory.c_str());
		if(attributes==INVALID_FILE_ATTRIBUTES) {
			const auto error=GetLastError();
			return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND ? ese::trust::LoadResult::Missing : ese::trust::LoadResult::IoError;
		}
		if(!(attributes&FILE_ATTRIBUTE_DIRECTORY) || (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) return ese::trust::LoadResult::Invalid;
		ese::trust::Record record;
		const auto result=ese::trust::LoadRecord(PeerTrustPath(directory,node).c_str(),record);
		if(result!=ese::trust::LoadResult::Loaded) return result;
		if(record.node!=node) return ese::trust::LoadResult::Invalid;
		output=record; return result;
	} catch(...) { return ese::trust::LoadResult::IoError; }
}

bool CDirectReachabilityManager::ConfigureDirectQuicPeerTrust(ese::QuicPeerConfig& peer,bool allowFirstUse)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!peer.persistent || !reach::NonzeroIdentity(peer.expectedNode)) return false;
	try {
		ese::trust::Record known;
		const auto result=LoadDirectQuicPeerTrust(peer.expectedNode,known);
		if(result==ese::trust::LoadResult::Loaded) {
			peer.pin=known.node; peer.hasPin=true; peer.allowFirstUse=false; peer.trustCommitter.reset(); return true;
		}
		if(result!=ese::trust::LoadResult::Missing || !allowFirstUse) return false;
		const auto directory=PeerTrustDirectory();
		if(directory.empty()) return false;
		if(!CreateDirectoryW(directory.c_str(),nullptr) && GetLastError()!=ERROR_ALREADY_EXISTS) return false;
		const auto attributes=GetFileAttributesW(directory.c_str());
		if(attributes==INVALID_FILE_ATTRIBUTES || !(attributes&FILE_ATTRIBUTE_DIRECTORY) || (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) return false;
		std::array<std::uint8_t,16> nonce{};
		const auto crypto=MakeKad6HostCryptoHooks();
		if(!crypto.random_bytes || !crypto.random_bytes(nonce.data(),nonce.size()) || !reach::NonzeroIdentity(nonce)) return false;
		const auto path=PeerTrustPath(directory,peer.expectedNode);
		auto temporary=path+L".";
		for(const auto byte:nonce) { temporary+=L"0123456789abcdef"[byte>>4]; temporary+=L"0123456789abcdef"[byte&15]; }
		temporary+=L".new";
		auto committer=std::make_shared<ese::trust::FileCommitter>(path,temporary);
		peer.pin={}; peer.hasPin=false; peer.allowFirstUse=true; peer.trustCommitter=std::move(committer); return true;
	} catch(...) { return false; }
}

uint64 CDirectReachabilityManager::MonotonicMilliseconds()
{
	return static_cast<uint64>(std::chrono::duration_cast<
		std::chrono::milliseconds>(std::chrono::steady_clock::now()
			.time_since_epoch()).count());
}

CDirectReachabilityManager::CDirectReachabilityManager()
	: m_dwOwnerThreadId(::GetCurrentThreadId())
	, m_bEnabled(false)
	, m_nLocalTcpPort(0)
	, m_nLocalUdpPort(0)
	, m_nAdvertisedTcpPort(0)
	, m_nAdvertisedUdpPort(0)
{
	m_mapperResults=std::make_shared<natmap::MapperResultMailbox>();
	m_directSubscribers=std::make_unique<reach::DirectSubscribers>();
	m_directPartContributions=std::make_unique<reach::DirectPartContributions>();
	m_pendingDirectVerifications=std::make_unique<PendingDirectVerifications>();
	m_directControlSessions=std::make_unique<ese::control::Sessions>();
	m_directContactRefreshReplies=std::make_unique<ese::discovery::ContactRefreshReplies>();
}

natmap::Endpoint CDirectReachabilityManager::MakeAnyV4(uint16 nPort)
{
	return natmap::Endpoint{
		natmap::IpAddress::V4(0, 0, 0, 0), nPort,
		natmap::EndpointSource::LocalInterface};
}
bool CDirectReachabilityManager::LoadDirectKad6Contacts(const wchar_t* path)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId || m_kad6DirectContacts) return false;
	try {
		auto cache=std::make_unique<ese::discovery::Kad6ContactCache>();
		if (!ese::discovery::LoadContactCache(*cache,path,MakeKad6HostCryptoHooks())) return false;
		m_kad6DirectContacts=std::move(cache); return true;
	} catch (...) { return false; }
}
bool CDirectReachabilityManager::SaveDirectKad6Contacts(const wchar_t* path,const wchar_t* temporary)
{
	AssertMainThread();
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && m_kad6DirectContacts &&
		ese::discovery::SaveContactCache(*m_kad6DirectContacts,path,temporary);
}
bool CDirectReachabilityManager::ImportDirectKad6Contact(const std::array<std::uint8_t,32>& expected,
	const std::uint8_t* bytes,std::size_t size)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
	try {
		if (!m_kad6DirectContacts) m_kad6DirectContacts=std::make_unique<ese::discovery::Kad6ContactCache>();
		if (!m_kad6DirectContacts->Import(expected,bytes,size,MakeKad6HostCryptoHooks())) return false;
		m_kad6DirectContactsChanged=true; return true;
	} catch (...) { return false; }
}

bool CDirectReachabilityManager::SaveChangedDirectKad6Contacts(const wchar_t* path)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
	if (!m_kad6DirectContactsChanged) return true;
	if (!path || !*path) return false;
	try {
		GUID id{}; wchar_t suffix[40]{};
		if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id,suffix,_countof(suffix))) return false;
		const std::wstring temporary=std::wstring(path)+L"."+suffix+L".tmp";
		if (!SaveDirectKad6Contacts(path,temporary.c_str())) return false;
		m_kad6DirectContactsChanged=false; return true;
	} catch (...) { return false; }
}

CDirectReachabilityManager::~CDirectReachabilityManager()
{
	ShutdownDirectHost();
}

bool CDirectReachabilityManager::FreshDirectKad6Contact(const std::array<std::uint8_t,32>& node,
	kad6::K6RouterRecord& out)
{
	AssertMainThread(); out={};
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_kad6DirectContacts) return false;
	const auto utc=std::time(nullptr);
	return utc>0 && m_kad6DirectContacts->Fresh(node,MakeKad6HostCryptoHooks(),static_cast<std::uint64_t>(utc),out);
}

bool CDirectReachabilityManager::BeginDirectKad6ContactRefresh(const std::array<std::uint8_t,32>& node,
	std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize>& bytes,std::size_t& size)
{
	AssertMainThread(); bytes={}; size=0;
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && m_kad6DirectContacts &&
		m_kad6DirectContacts->BeginRefresh(node,MonotonicMilliseconds(),bytes,size);
}

bool CDirectReachabilityManager::ApplyDirectKad6ContactRefresh(ese::control::ContactRefreshRequest& pending,
	const ese::control::Sessions& sessions,const ese::udp::Endpoint& endpoint,
	const std::uint8_t* bytes,std::size_t size)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_kad6DirectContacts) return false;
	const auto utc=std::time(nullptr); if(utc<=0) return false;
	kad6::K6RouterRecord record;
	if (!ese::discovery::ImportRefreshedContact(*m_kad6DirectContacts,pending,sessions,endpoint,
		bytes,size,MonotonicMilliseconds(),MakeKad6HostCryptoHooks(),static_cast<std::uint64_t>(utc),record)) return false;
	m_kad6DirectContactsChanged=true; return true;
}

bool CDirectReachabilityManager::AdoptDirectConsumer(std::unique_ptr<ese::DirectBatchConsumer>& consumer)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !consumer || m_directConsumer
		|| m_directPump.Busy() || m_directConnections.Size() || m_quicHost) return false;
	m_directConsumer = std::move(consumer);
	return true;
}

bool CDirectReachabilityManager::InstallQuicDownloadConsumer()
{
	AssertMainThread();
	if(m_builtinQuicConsumer) return true;
	if(m_directConsumer || m_directPump.Busy() || m_directConnections.Size() || m_quicHost) return false;
	auto owned=std::make_unique<ese::QuicDownloadConsumer>(*this,
		[this](uint64 token,reach::DirectReason reason) { m_directSubscribers->Complete(token,reason); });
	auto* borrowed=owned.get();
	std::unique_ptr<ese::DirectBatchConsumer> consumer=std::move(owned);
	if(!AdoptDirectConsumer(consumer)) return false;
	m_builtinQuicConsumer=borrowed;
	return true;
}

bool CDirectReachabilityManager::RegisterDirectQuicRoute(reach::DirectHandle handle,
	const reach::DirectSessionRoute& route,const ese::NativeQuicConfig& native,const ese::QuicPeerConfig& peer)
{
	AssertMainThread();
	return m_builtinQuicConsumer && !m_directPump.Busy() && m_builtinQuicConsumer->Register(handle,route,native,peer);
}

bool CDirectReachabilityManager::RegisterPreparedDirectLegacyRoute(reach::DirectHandle handle,
	const reach::DirectSessionRoute& route,CClientReqSocket& socket,uint64 epoch)
{
	AssertMainThread();
	return m_builtinQuicConsumer && !m_directPump.Busy() &&
		m_builtinQuicConsumer->RegisterPreparedLegacy(handle,route,socket,epoch);
}

bool CDirectReachabilityManager::ScheduleDirectQuicRoutes(reach::DirectHandle handle,
	const std::vector<reach::DirectSessionRoute>& routes)
{
	AssertMainThread();
	if(!m_builtinQuicConsumer || m_directPump.Busy()) return false;
	return m_builtinQuicConsumer->Schedule(handle,routes,MonotonicMilliseconds());
}

bool CDirectReachabilityManager::RegisterDirectLegacyRoute(reach::DirectHandle handle,const reach::DirectSessionRoute& route)
{
	AssertMainThread();
	return m_builtinQuicConsumer && !m_directPump.Busy() && m_builtinQuicConsumer->RegisterLegacy(handle,route);
}

reach::NativeDirectRoutes CDirectReachabilityManager::SelectDirectQuicDownloadRoutes(reach::DirectHandle handle,
	const reach::NativeDirectTransportPolicy& transport)
{
	AssertMainThread();
	if(!m_quicHost || transport.enabled_transports!=reach::DirectQuic) return {};
	return SelectDirectDownloadRoutes(handle,transport);
}

bool CDirectReachabilityManager::RecordDirectTcpObservation(CClientReqSocket& socket)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() || !theApp.listensocket || !theApp.clientlist ||
		!theApp.listensocket->IsValidSocket(&socket) || !socket.client || !theApp.clientlist->IsValidClient(socket.client)) return false;
	const auto observed=socket.ObservedLegacyTcpCandidate();
	const auto now=MonotonicMilliseconds();
	if(!observed || observed->topology_generation!=GetTopologyGeneration() || observed->expires_monotonic_ms<=now) return false;
	const auto lifetime=socket.client->GetDirectClientLifetime();
	DirectTcpObservation* vacant=nullptr;
	for(auto& entry:m_directTcpObservations) {
		if(!entry.lifetime || entry.candidate.expires_monotonic_ms<=now || entry.candidate.topology_generation!=GetTopologyGeneration()) {
			if(!vacant) vacant=&entry;
		} else if(entry.lifetime==lifetime && entry.candidate.family==observed->family && entry.candidate.address==observed->address &&
			entry.candidate.port==observed->port && entry.candidate.interface_id==observed->interface_id) { vacant=&entry; break; }
	}
	if(!vacant) return false;
	*vacant={}; vacant->lifetime=lifetime; vacant->candidate=*observed;
	vacant->candidate.expires_monotonic_ms=(std::min)(observed->expires_monotonic_ms,now+15000);
	std::copy(socket.client->GetUserHash(),socket.client->GetUserHash()+16,vacant->userHash.begin());
	return true;
}

bool CDirectReachabilityManager::QueueAuthenticatedProvisionalPeer(CClientReqSocket& socket)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !theApp.listensocket || !theApp.clientlist ||
        !theApp.listensocket->IsValidSocket(&socket) || !socket.client ||
        !theApp.clientlist->IsValidClient(socket.client) || socket.client->socket!=&socket ||
        !socket.m_legacyDirectRoute || socket.m_legacyDirectClosed || !socket.m_legacyDirectConnected ||
        !socket.m_legacyHelloAccepted || !socket.m_legacyExpectedHash ||
        !socket.client->HasPassedSecureIdent(false) ||
        std::memcmp(socket.client->GetUserHash(),socket.m_legacyExpectedHash->data(),16) ||
        !socket.HasDirectTransferAuthority(socket.m_legacyDirectHandle)) return false;
    const auto state=m_directConnections.Snapshot(socket.m_legacyDirectHandle);
    if(!state || state->epoch!=socket.m_legacyDirectEpoch || state->topology_generation!=GetTopologyGeneration()) return false;
    if(state->peer.domain!=reach::DirectPeerDomain::Provisional) return true;
    for(std::size_t i=0;i<m_authenticatedProvisionalPeerCount;++i) {
        const auto& pending=m_authenticatedProvisionalPeers[i];
        if(pending.handle.slot==socket.m_legacyDirectHandle.slot && pending.handle.generation==socket.m_legacyDirectHandle.generation &&
            pending.route==socket.m_legacyDirectRoute && pending.epoch==socket.m_legacyDirectEpoch) return true;
    }
    if(m_authenticatedProvisionalPeerCount==m_authenticatedProvisionalPeers.size()) return false;
    auto& pending=m_authenticatedProvisionalPeers[m_authenticatedProvisionalPeerCount++];
    pending={}; pending.handle=socket.m_legacyDirectHandle; pending.route=socket.m_legacyDirectRoute;
    pending.epoch=socket.m_legacyDirectEpoch; pending.peer.domain=reach::DirectPeerDomain::UserHash;
    std::copy(socket.m_legacyExpectedHash->begin(),socket.m_legacyExpectedHash->end(),pending.peer.identity.begin());
    return true; // no callbacks, adoption or socket destruction on this stack
}

void CDirectReachabilityManager::ApplyDirectTcpObservations(reach::NativeDirectCandidateSnapshotV1& snapshot,uint64 lifetime,uint64 now) const
{
	if(!snapshot.peer.expected_user_hash || snapshot.count>snapshot.candidates.size()) return;
	for(std::size_t i=0;i<snapshot.count;++i) {
		auto& candidate=snapshot.candidates[i].route;
		// A scalar evidence field cannot certify UDP by a TCP connection.
		if(candidate.transport_mask!=reach::DirectTcp || candidate.evidence!=reach::DirectEvidence::Advertised) continue;
		for(const auto& entry:m_directTcpObservations) {
			const auto& proof=entry.candidate;
			if(entry.lifetime!=lifetime || entry.userHash!=*snapshot.peer.expected_user_hash || proof.expires_monotonic_ms<=now ||
				proof.topology_generation!=snapshot.local_generation || proof.kind!=candidate.kind || proof.family!=candidate.family ||
				proof.address!=candidate.address || proof.port!=candidate.port || proof.scope!=candidate.scope || proof.interface_id!=candidate.interface_id) continue;
			candidate.evidence=reach::DirectEvidence::Observed;
			candidate.expires_monotonic_ms=(std::min)(candidate.expires_monotonic_ms,proof.expires_monotonic_ms);
			break;
		}
	}
}

bool CDirectReachabilityManager::GatherDirectTcpObservations(reach::NativeDirectCandidateSnapshotV1& snapshot,uint64 lifetime,uint64 now) const
{
	if(!lifetime || !snapshot.peer.expected_user_hash || snapshot.count>snapshot.candidates.size() ||
		snapshot.local_generation!=GetTopologyGeneration()) return false;
	ApplyDirectTcpObservations(snapshot,lifetime,now);
	for(const auto& entry:m_directTcpObservations) {
		const auto& proof=entry.candidate;
		if(entry.lifetime!=lifetime || entry.userHash!=*snapshot.peer.expected_user_hash ||
			proof.topology_generation!=snapshot.local_generation || proof.expires_monotonic_ms<=now ||
			proof.transport_mask!=reach::DirectTcp || proof.evidence!=reach::DirectEvidence::Observed) continue;
		bool present=false; uint64 greatestId=0;
		for(std::size_t i=0;i<snapshot.count;++i) {
			const auto& candidate=snapshot.candidates[i].route;
			greatestId=(std::max)(greatestId,candidate.id);
			if(candidate.transport_mask==reach::DirectTcp && candidate.kind==proof.kind &&
				candidate.family==proof.family && candidate.address==proof.address && candidate.port==proof.port &&
				candidate.scope==proof.scope && candidate.interface_id==proof.interface_id) present=true;
		}
		if(present) continue;
		if(snapshot.count==snapshot.candidates.size() || greatestId==(std::numeric_limits<uint64>::max)()) return false;
		auto& candidate=snapshot.candidates[snapshot.count++]; candidate={};
		candidate.route=proof; candidate.route.id=greatestId+1;
		candidate.source=reach::DirectCandidateSource::Observed;
	}
	return true;
}

reach::NativeDirectRoutes CDirectReachabilityManager::SelectDirectDownloadRoutes(reach::DirectHandle handle,
	const reach::NativeDirectTransportPolicy& transport,uint32 firstRouteId)
{
	AssertMainThread();
	reach::NativeDirectRoutes rejected;
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!m_builtinQuicConsumer || m_directPump.Busy() || !theApp.clientlist || !firstRouteId ||
		!transport.enabled_transports || (transport.enabled_transports & ~(reach::DirectTcp|reach::DirectUtp|reach::DirectQuic)) ||
		((transport.enabled_transports&reach::DirectQuic) && !m_quicHost)) return rejected;
	const auto attempt=m_directConnections.Snapshot(handle);
	const auto lifetime=DirectTransferClientLifetime(handle);
	if(!attempt || !lifetime || (attempt->state!=reach::DirectSessionState::Gathering &&
		attempt->state!=reach::DirectSessionState::Recovering)) return rejected;
	firstRouteId=attempt->NextRouteId(firstRouteId);
	if(!firstRouteId) return rejected; // exhausted ID space cannot wrap into an old route
	auto* client=theApp.clientlist->FindClientByLifetime(*lifetime);
	if(!client || !HasDirectTransferSubscription(*lifetime,handle)) return rejected;
	const auto now=MonotonicMilliseconds();
	const auto generation=GetTopologyGeneration();
	auto snapshot=client->NativeDirectCandidates(generation,now+15000);
	const auto key=reach::NativeDirectPeerKey(snapshot.peer,0,0);
	if(attempt->topology_generation!=generation || !key || key->domain!=attempt->peer.domain ||
		key->identity!=attempt->peer.identity) return rejected;
	if(transport.enabled_transports&reach::DirectTcp) {
		// Preserve UDP discovery offers and gather separately owned TCP evidence.
		if(snapshot.peer.expected_user_hash && !GatherDirectTcpObservations(snapshot,*lifetime,now)) return rejected;
	}
	reach::DirectPolicy policy;
	if(snapshot.peer.expected_node_pub && IsIsolatedLanQuicPeer(*snapshot.peer.expected_node_pub,m_isolatedLanQuicEndpoint)) policy=*m_isolatedLanQuicPolicy;
	policy.topology_generation=generation; policy.now_monotonic_ms=now;
	return reach::BuildNativeDirectRoutes(snapshot,policy,transport,firstRouteId);
}

std::optional<reach::DirectReason> CDirectReachabilityManager::TakeDirectTerminal(uint64 token,uint64 lifetime)
{
	AssertMainThread();
	const auto record=m_directSubscribers->Resolve(token);
	return record && record->client_lifetime==lifetime ? m_directSubscribers->TakeTerminal(token) : std::nullopt;
}

bool CDirectReachabilityManager::RetainDirectControlDownload(reach::DirectHandle handle,
	const std::array<std::uint8_t,32>& peer,const ese::udp::Endpoint& endpoint,
	const ese::control::Header& context,uint64 now)
{
	AssertMainThread();
	PruneDirectControlDownloads();
	const auto state=m_directConnections.Snapshot(handle);
	const auto lifetime=DirectTransferClientLifetime(handle);
	if(!state || !lifetime || state->state==reach::DirectSessionState::Failed ||
		state->state==reach::DirectSessionState::Cancelled || state->attempt_id!=context.attempt ||
		state->peer.domain!=reach::DirectPeerDomain::NodePublicKey || state->peer.identity!=peer ||
		!context.generation || state->topology_generation!=GetTopologyGeneration()) return false;
	for(auto& entry:m_retainedControlDownloads) if(entry.owner && entry.handle.slot==handle.slot &&
		entry.handle.generation==handle.generation)
		return m_directControlSessions->RetainDownload(peer,endpoint,context,entry.owner,now);
	if(m_nextControlRetentionOwner==(std::numeric_limits<uint64>::max)()) return false;
	for(auto& entry:m_retainedControlDownloads) if(!entry.owner) {
		const auto owner=++m_nextControlRetentionOwner;
		if(!m_directControlSessions->RetainDownload(peer,endpoint,context,owner,now)) return false;
		// Control generation belongs to its initiator; retention lifecycle is
		// fenced by this host's independent local topology generation.
		entry={handle,owner,state->topology_generation,*lifetime}; return true;
	}
	return false;
}

void CDirectReachabilityManager::PruneDirectControlDownloads()
{
	AssertMainThread();
	for(auto& entry:m_retainedControlDownloads) if(entry.owner) {
		const auto state=m_directConnections.Snapshot(entry.handle);
		if(!state || state->state==reach::DirectSessionState::Failed || state->state==reach::DirectSessionState::Cancelled ||
			entry.topology!=GetTopologyGeneration() || !HasDirectTransferSubscription(entry.lifetime,entry.handle)) {
			m_directControlSessions->ReleaseDownload(entry.owner); entry={};
		}
	}
}

void CDirectReachabilityManager::TickDirectConnections()
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId) return;
	SynchronizeLocalSocketBindings();
	m_mapperResults->Expire(MonotonicMilliseconds());
	if(m_localNetworkTracker.SampleDue(MonotonicMilliseconds()))
		ObserveLocalNetworkSignature(natmap::ReadLocalNetworkSignature());
	if(natmap::MappingLeasesRequireInvalidation(m_tcpLease,m_udpLease,MonotonicMilliseconds())) {
		Initialize(GetLocalTcpPort(),GetLocalUdpPort());
		m_snapshot.ed2k_tcp_v4.state=natmap::ReachabilityState::Degraded;
		m_snapshot.ed2k_tcp_v4.reason=natmap::ReasonCode::LeaseExpired;
		m_snapshot.kad_udp_v4.state=natmap::ReachabilityState::Degraded;
		m_snapshot.kad_udp_v4.reason=natmap::ReasonCode::LeaseExpired;
	}
	PruneDirectControlDownloads();
    const auto callbackNow=MonotonicMilliseconds();
    if(!theApp.m_bReachBindingSelfTest && callbackNow>=m_nextClassicCallbackRecheck &&
        CurrentClassicCallbackEndpoint(callbackNow).generation && Kademlia::CKademlia::IsConnected()) {
        if(callbackNow<=(std::numeric_limits<uint64>::max)()-50000) {
            m_nextClassicCallbackRecheck=callbackNow+50000;
            // Reuse the standard firewall check, including legacy opcodes.
            // Never restart a check already in progress or claim HighID.
            if(!Kademlia::CKademlia::GetPrefs()->GetRecheckIP())
                Kademlia::CKademlia::GetPrefs()->SetRecheckIP();
        }
    }
	PumpDirectUploadAuthorizations();
    if(!theApp.m_bReachBindingSelfTest && callbackNow>=m_nextKad6PublicContactRecheck &&
        CurrentKad6PublicContact(callbackNow).generation && Kademlia::CKademlia::IsKad2Running() &&
        !Kademlia::CUDPFirewallTester::IsFWCheckUDPRunning() && callbackNow<=(std::numeric_limits<uint64>::max)()-50000) {
        m_nextKad6PublicContactRecheck=callbackNow+50000;
        Kademlia::CUDPFirewallTester::ReCheckFirewallUDP(true);
    }
	PumpDirectControlReplies();
	PumpDirectPartVerifications();
	m_directPump.Tick(m_directConsumer.get(), [this] { return PumpDirectEvents(); });
	if(m_builtinQuicConsumer && !m_directPump.Busy()) m_builtinQuicConsumer->PumpOwnedRecovery();
    PublishDirectDiagnostics();
}

std::string CDirectReachabilityManager::GetDirectStatusJson() const
{
    std::lock_guard<std::mutex> lock(m_diagnosticMutex); return m_diagnosticJson;
}
std::string CDirectReachabilityManager::GetDirectStatusLabel() const
{
    std::lock_guard<std::mutex> lock(m_diagnosticMutex); return m_diagnosticLabel;
}
void CDirectReachabilityManager::PublishDirectDiagnostics()
{
    AssertMainThread();
    const auto now=MonotonicMilliseconds();
    std::array<bool,reach::kDirectMaxAttempts> seen{};
    std::string body="[",label;
    for(const auto handle:m_directConnections.ActiveHandles()) {
        const auto snapshot=m_directConnections.Snapshot(handle);
        const auto routes=m_directConnections.RoutesSnapshot(handle);
        if(!snapshot || !routes) continue;
        auto& entry=m_diagnosticSlots[handle.slot]; seen[handle.slot]=true; entry.lastSeen=now;
        if(!entry.publisher || entry.generation!=handle.generation) {
            if(m_diagnosticId==(std::numeric_limits<uint64>::max)()) continue;
            entry.publisher=std::make_unique<reach::DirectDiagnosticPublisher>();
            entry.generation=handle.generation; entry.opaqueId=++m_diagnosticId;
        }
        auto projection=reach::ProjectDirectDiagnostic(*snapshot,*routes);
        if(projection.authenticated) {
            const auto lifetime=DirectTransferClientLifetime(handle);
            auto* client=lifetime && theApp.clientlist ? theApp.clientlist->FindClientByLifetime(*lifetime) : nullptr;
            if(client) {
                const auto* file=client->GetRequestFile();
                if(file && (file->IsStopped() || file->GetStatus()==PS_PAUSED))
                    projection.progress_blocker=reach::DirectProgressBlocker::LocalPause;
                else if(client->GetDownloadState()==DS_ONQUEUE)
                    projection.progress_blocker=reach::DirectProgressBlocker::RemoteQueue;
            }
        }
        projection.session_id=entry.opaqueId;
        entry.publisher->Publish(projection,now);
        const auto published=entry.publisher->Read();
        if(!published) continue;
        if(body.size()>1) body+=",";
        body+=reach::DirectDiagnosticJson(*published);
        // GUI label derives from exactly the same published state as API.
        if(label.empty()) label=reach::DirectDiagnosticState(published->state);
    }
    // Keep retired terminal diagnostics briefly, without retaining a client,
    // transport or DCO attempt. New slot generation receives a different ID.
    for(std::size_t i=0;i<seen.size();++i) if(!seen[i] && m_diagnosticSlots[i].publisher) {
        auto& entry=m_diagnosticSlots[i];
        if(now<entry.lastSeen || now-entry.lastSeen>=30000) {entry={}; continue;}
        const auto previous=entry.publisher->Read();
        if(!previous) { entry={}; continue; }
        auto retired=*previous;
        if(retired.state!=reach::DirectSessionState::Failed && retired.state!=reach::DirectSessionState::Cancelled) {
            retired.state=reach::DirectSessionState::Cancelled; retired.terminal_reason=reach::DirectReason::PeerGone;
            retired.progress_blocker=reach::DirectProgressBlocker::Terminal;
            retired.authenticated=false; retired.route_kind=0; retired.transport=0;
            entry.publisher->Publish(retired,now);
        }
        const auto published=entry.publisher->Read();
        if(body.size()>1) body+=",";
        body+=reach::DirectDiagnosticJson(*published);
        if(label.empty()) label=reach::DirectDiagnosticState(published->state);
    }
    body+="]";
    const auto discoveryState=ese::discovery::DiscoveryOutcomeName(m_kad6DiscoveryStatus.State());
    const auto callbackState=ese::classic::CallbackAvailabilityName(GetClassicCallbackAvailability());
    const std::string controlStatus=std::string("{\"kad6_discovery\":\"")+discoveryState+
        "\",\"classic_callback\":\""+callbackState+"\"}";
    if(label.empty() && thePrefs.IsEseNetLabActive())
        label=m_kad6DiscoveryStatus.State()!=ese::discovery::DiscoveryOutcome::Idle ? discoveryState : callbackState;
    const auto fingerprint=body+controlStatus+label;
    std::lock_guard<std::mutex> lock(m_diagnosticMutex);
    if(fingerprint==m_diagnosticBody || m_diagnosticSequence==(std::numeric_limits<uint64>::max)()) return;
    const auto sequence=m_diagnosticSequence+1;
    auto json="{\"schema_version\":2,\"snapshot_sequence\":\""+std::to_string(sequence)+
        "\",\"available\":true,\"sessions\":"+body+",\"control\":"+controlStatus+"}";
    m_diagnosticJson=std::move(json); m_diagnosticBody=fingerprint;
    m_diagnosticLabel=std::move(label); m_diagnosticSequence=sequence;
}

void CDirectReachabilityManager::ShutdownDirectHost()
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || m_directPump.Busy()) std::terminate();
	m_mapperResults->DiscardAll();
	if (m_quicHost) m_quicHost->Stop();
	*m_directContactRefreshReplies=ese::discovery::ContactRefreshReplies{};
	*m_directControlSessions=ese::control::Sessions{};
	m_directConsumer.reset(); // release framers before their session RX pools
	m_builtinQuicConsumer=nullptr;
	ShutdownQuicHost();
}

ese::control::Sessions& CDirectReachabilityManager::DirectControlSessions()
{
	AssertMainThread(); return *m_directControlSessions;
}

uint64 CDirectReachabilityManager::BeginDirectControlBootstrap(const std::array<std::uint8_t,32>& expectedPeer,
	const ese::udp::Endpoint& endpoint,uint64 deadline)
{
	return BeginDirectBootstrap(expectedPeer,endpoint,deadline,nullptr,0);
}

uint64 CDirectReachabilityManager::BeginDirectQuicDownloadBootstrap(reach::DirectHandle handle,
	const ese::udp::Endpoint& endpoint,uint64 deadline)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || endpoint.scope) return 0;
	const auto attempt=m_directConnections.Snapshot(handle);
	const auto lifetime=DirectTransferClientLifetime(handle);
	if(!attempt || !lifetime || attempt->peer.domain!=reach::DirectPeerDomain::NodePublicKey) return 0;
	// Preflight only: this temporary path checks the exact owned advertised
	// endpoint against address/topology/lease policy. It is never stored as a
	// return proof and cannot schedule data before a signed selected4 ACK.
	reach::NativeDirectTransportPolicy policy; policy.enabled_transports=reach::DirectQuic;
	policy.udp_path_validated=true; policy.quic_binding_available=true; policy.validated_udp_count=1;
	auto& path=policy.validated_udp_paths[0]; path.node=attempt->peer.identity;
	path.address=endpoint.address; path.family=endpoint.ipv6 ? 6 : 4; path.port=endpoint.port;
	path.topology_generation=GetTopologyGeneration(); path.expires_monotonic_ms=deadline;
	if(IsIsolatedLanQuicPeer(attempt->peer.identity,endpoint)) { path.scope=reach::DirectScope::SameLan; path.interface_id=m_isolatedLanQuicPolicy->required_interface_id; }
	const auto preflight=SelectDirectQuicDownloadRoutes(handle,policy);
	if(preflight.routes.empty()) {
		if(theApp.m_bReachBindingSelfTest) Log(_T("ACK_START_SELFTEST reject: preflight routes0 status=%u snapshot=%u busy=%u"),
			unsigned(preflight.status),unsigned(preflight.snapshot_status),unsigned(m_directPump.Busy()));
		return 0;
	}
	const auto owner=BeginDirectBootstrap(attempt->peer.identity,endpoint,deadline,&attempt->attempt_id,4,
		attempt->state==reach::DirectSessionState::Recovering);
	if(owner) { m_directBootstrapDownload=handle; m_directBootstrapDownloadLifetime=*lifetime; }
	if(theApp.m_bReachBindingSelfTest) {
		const auto observedNow=MonotonicMilliseconds();
		Log(_T("ACK_START_SELFTEST bootstrap: owner=%I64u deadlineRemaining=%I64u"),
			static_cast<ULONGLONG>(owner),static_cast<ULONGLONG>(deadline>observedNow?deadline-observedNow:0));
	}
	return owner;
}

reach::NativeDirectRoutes CDirectReachabilityManager::SelectOwnedDirectQuicDownloadRoutes(reach::DirectHandle handle)
{
	return SelectOwnedDirectDownloadRoutes(handle,reach::DirectQuic);
}

reach::NativeDirectRoutes CDirectReachabilityManager::SelectOwnedDirectDownloadRoutes(reach::DirectHandle handle,uint8 enabledTransports)
{
	AssertMainThread();
	reach::NativeDirectRoutes rejected;
	if(!enabledTransports || (enabledTransports & ~(reach::DirectTcp|reach::DirectQuic)) ||
		::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directBootstrap ||
		!DirectControlBootstrapReady(m_directBootstrapOwner) || m_directBootstrap->Selected()!=4 ||
		(handle.slot!=m_directBootstrapDownload.slot || handle.generation!=m_directBootstrapDownload.generation) ||
		!m_directBootstrapDownloadLifetime ||
		!HasDirectTransferSubscription(m_directBootstrapDownloadLifetime,handle) ||
		m_directBootstrapDataUntil<=MonotonicMilliseconds()) return rejected;
	const auto attempt=m_directConnections.Snapshot(handle);
	if(!attempt || attempt->attempt_id!=m_directBootstrapContext.attempt ||
		attempt->peer.identity!=m_directBootstrapPeer) return rejected;
	// The selected4 ACK certifies only this UDP path. TCP eligibility still
	// requires its own endpoint/lifetime/hash/topology observation in the selector.
	reach::NativeDirectTransportPolicy policy; policy.enabled_transports=enabledTransports;
	policy.udp_path_validated=true; policy.quic_binding_available=true; policy.validated_udp_count=1;
	auto& path=policy.validated_udp_paths[0]; path.node=m_directBootstrapPeer;
	path.address=m_directBootstrapEndpoint.address; path.family=m_directBootstrapEndpoint.ipv6 ? 6 : 4;
	path.port=m_directBootstrapEndpoint.port; path.topology_generation=m_directBootstrapContext.generation;
	path.expires_monotonic_ms=m_directBootstrapDataUntil;
	if(IsIsolatedLanQuicPeer(m_directBootstrapPeer,m_directBootstrapEndpoint)) { path.scope=reach::DirectScope::SameLan; path.interface_id=m_isolatedLanQuicPolicy->required_interface_id; }
	return SelectDirectDownloadRoutes(handle,policy);
}

bool CDirectReachabilityManager::EnableDirectQuicDownloadHandoff(reach::DirectHandle handle,bool allowFirstUse)
{
	return EnableDirectQuicDownloadHandoffWithTrust(handle,allowFirstUse,nullptr);
}

bool CDirectReachabilityManager::EnableDirectQuicDownloadHandoffWithTrust(reach::DirectHandle handle,bool allowFirstUse,
	const ese::QuicPeerConfig* prepared)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || m_directPump.Busy() || !m_builtinQuicConsumer ||
		!m_directBootstrap || m_directBootstrapDownloadPolicy || !m_directBootstrapDownloadLifetime ||
		handle.slot!=m_directBootstrapDownload.slot || handle.generation!=m_directBootstrapDownload.generation ||
		!HasDirectTransferSubscription(m_directBootstrapDownloadLifetime,handle) ||
		!theApp.clientlist || !theApp.clientlist->FindClientByLifetime(m_directBootstrapDownloadLifetime) ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub()) return false;
	const auto attempt=m_directConnections.Snapshot(handle);
	if(!attempt || (attempt->state!=reach::DirectSessionState::Gathering && attempt->state!=reach::DirectSessionState::Recovering) ||
		attempt->attempt_id!=m_directBootstrapContext.attempt || attempt->peer.identity!=m_directBootstrapPeer ||
		m_directBootstrapContext.generation!=GetTopologyGeneration()) return false;
    auto peer=PrepareDirectQuicDownloadPolicy(handle,allowFirstUse,prepared);
    if(!peer) return false;
    if(!m_directBootstrapReady && MonotonicMilliseconds()>=m_directBootstrapDeadline) {
        CancelDirectControlBootstrap(); return false;
    }
    m_directBootstrapDownloadPolicy=std::move(*peer); return true;
}

std::optional<ese::QuicPeerConfig> CDirectReachabilityManager::PrepareDirectQuicDownloadPolicy(
    reach::DirectHandle handle,bool allowFirstUse,const ese::QuicPeerConfig* prepared)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId || m_directPump.Busy() || !DirectQuicDownloadAvailable() ||
        !theApp.clientlist) return std::nullopt;
    const auto lifetime=DirectTransferClientLifetime(handle);
    const auto attempt=m_directConnections.Snapshot(handle);
    if(!lifetime || !HasDirectTransferSubscription(*lifetime,handle) || !theApp.clientlist->FindClientByLifetime(*lifetime) ||
        !attempt || attempt->peer.domain!=reach::DirectPeerDomain::NodePublicKey ||
        (attempt->state!=reach::DirectSessionState::Gathering && attempt->state!=reach::DirectSessionState::Recovering) ||
        attempt->topology_generation!=GetTopologyGeneration()) return std::nullopt;
	ese::QuicPeerConfig peer; peer.persistent=true; peer.expectedNode=attempt->peer.identity;
	peer.local.role=0; peer.local.caps=1; peer.local.attempt=attempt->attempt_id;
	peer.local.topologyGeneration=GetTopologyGeneration(); peer.sessionEpoch=attempt->epoch;
	std::copy(eSELive::NodeIdentityPub(),eSELive::NodeIdentityPub()+32,peer.local.node.begin());
	std::copy(thePrefs.GetUserHash(),thePrefs.GetUserHash()+16,peer.local.userHash.begin());
	const auto crypto=MakeKad6HostCryptoHooks();
	if(!crypto.random_bytes || !crypto.random_bytes(peer.local.nonce.data(),peer.local.nonce.size()) ||
		!reach::NonzeroIdentity(peer.local.nonce)) return std::nullopt;
	if(prepared) {
		if(allowFirstUse || !prepared->persistent || !prepared->hasPin || prepared->allowFirstUse ||
			prepared->trustCommitter || prepared->pin!=peer.expectedNode || prepared->expectedNode!=peer.expectedNode ||
			prepared->local.attempt!=attempt->attempt_id || prepared->local.topologyGeneration!=GetTopologyGeneration()) return std::nullopt;
		peer.pin=prepared->pin; peer.hasPin=true; // exact attempt's preloaded pin, never a new trust decision
	} else if(!ConfigureDirectQuicPeerTrust(peer,allowFirstUse)) return std::nullopt;
    if(theApp.m_bReachBindingSelfTest && m_directPolicyPreparationSelfTestDelayMs) {
        const auto delay=m_directPolicyPreparationSelfTestDelayMs;
        m_directPolicyPreparationSelfTestDelayMs=0;
        if(delay>2000) return std::nullopt;
        ::Sleep(delay); // models slow blocking profile/nonce preparation, never changes a clock or network deadline
    }
    return peer;
}

uint64 CDirectReachabilityManager::BeginOwnedDirectQuicDownload(reach::DirectHandle handle,bool allowFirstUse)
{
	return BeginOwnedDirectQuicDownloadWithTrust(handle,allowFirstUse,nullptr);
}

uint64 CDirectReachabilityManager::BeginOwnedDirectQuicRecovery(reach::DirectHandle handle,const ese::QuicPeerConfig& prepared)
{
	AssertMainThread();
	if(!DirectQuicDownloadAvailable()) return 0;
	const auto state=m_directConnections.Snapshot(handle);
	if(!state || state->state!=reach::DirectSessionState::Recovering ||
		state->peer.domain!=reach::DirectPeerDomain::NodePublicKey || !prepared.persistent || !prepared.hasPin ||
		prepared.allowFirstUse || prepared.trustCommitter || prepared.pin!=state->peer.identity ||
		prepared.expectedNode!=state->peer.identity || prepared.local.attempt!=state->attempt_id ||
		prepared.local.topologyGeneration!=state->topology_generation || state->topology_generation!=GetTopologyGeneration()) return 0;
	if(m_directBootstrap) {
		// A recovery cannot steal another peer's outstanding control negotiation.
		if(m_directBootstrapDownload.slot==handle.slot && m_directBootstrapDownload.generation==handle.generation &&
			m_directBootstrapDownloadPolicy && m_directBootstrapContext.attempt==state->attempt_id)
			return m_directBootstrapOwner;
		if(m_directBootstrap->State()==ese::control::InitiatorState::Probe ||
			m_directBootstrap->State()==ese::control::InitiatorState::Prove) return 0;
	}
	return BeginOwnedDirectQuicDownloadWithTrust(handle,false,&prepared);
}

uint64 CDirectReachabilityManager::BeginOwnedDirectQuicDownloadWithTrust(reach::DirectHandle handle,bool allowFirstUse,
	const ese::QuicPeerConfig* prepared)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_quicHost || !m_builtinQuicConsumer ||
		m_directPump.Busy() || !theApp.clientlist) {
		if(theApp.m_bReachBindingSelfTest) Log(_T("ACK_START_SELFTEST reject: owner gate thread=%u host=%u consumer=%u busy=%u list=%u"),
			unsigned(::GetCurrentThreadId()==m_dwOwnerThreadId),unsigned(bool(m_quicHost)),unsigned(m_builtinQuicConsumer!=nullptr),
			unsigned(m_directPump.Busy()),unsigned(theApp.clientlist!=nullptr));
		return 0;
	}
	const auto lifetime=DirectTransferClientLifetime(handle);
	if(!lifetime || !HasDirectTransferSubscription(*lifetime,handle)) return 0;
	auto* client=theApp.clientlist->FindClientByLifetime(*lifetime);
	if(!client) return 0;
	const auto now=MonotonicMilliseconds();
	const auto candidates=client->NativeDirectCandidates(GetTopologyGeneration(),now+15000);
	for(std::size_t i=0;i<candidates.count;++i) {
		const auto& route=candidates.candidates[i].route;
		if(!(route.transport_mask&reach::DirectQuic) || (route.scope!=reach::DirectScope::Global &&
			!IsIsolatedLanQuicPeer(candidates.peer.expected_node_pub.value_or(std::array<std::uint8_t,32>{}),m_isolatedLanQuicEndpoint)) ||
			(route.family!=4 && route.family!=6) || route.expires_monotonic_ms<=now) continue;
		ese::udp::Endpoint endpoint; endpoint.address=route.address; endpoint.port=route.port; endpoint.ipv6=route.family==6;
        // Blocking profile/entropy preparation is not network negotiation.
        // The existing Core deadline is unchanged; endpoint preflight below
        // rechecks current identity, topology and lease after preparation.
        auto peer=PrepareDirectQuicDownloadPolicy(handle,allowFirstUse,prepared);
        if(!peer) return 0;
        const auto preparedNow=MonotonicMilliseconds();
        if(preparedNow>(std::numeric_limits<uint64>::max)()-1500) return 0;
		const auto owner=BeginDirectQuicDownloadBootstrap(handle,endpoint,preparedNow+1500);
		if(!owner) continue;
        if(m_directBootstrapDownload.slot==handle.slot && m_directBootstrapDownload.generation==handle.generation &&
            peer->local.attempt==m_directBootstrapContext.attempt && peer->expectedNode==m_directBootstrapPeer &&
            peer->local.topologyGeneration==GetTopologyGeneration() && MonotonicMilliseconds()<m_directBootstrapDeadline) {
            m_directBootstrapDownloadPolicy=std::move(*peer);
			if(theApp.m_bReachBindingSelfTest) Log(_T("ACK_START_SELFTEST handoff enabled: owner=%I64u"),static_cast<ULONGLONG>(owner));
			return owner;
		}
		if(theApp.m_bReachBindingSelfTest) Log(_T("ACK_START_SELFTEST reject: handoff enable failed"));
		CancelDirectControlBootstrap(); return 0;
	}
	return 0;
}

CDirectReachabilityManager::DirectTcpStartResult CDirectReachabilityManager::BeginOwnedObservedTcpDownload(reach::DirectHandle handle)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!m_builtinQuicConsumer || m_directPump.Busy()) return DirectTcpStartResult::Unavailable;
	switch(m_builtinQuicConsumer->BeginObservedTcp(handle)) {
	case ese::QuicDownloadConsumer::TcpStartResult::Scheduled: return DirectTcpStartResult::Scheduled;
	case ese::QuicDownloadConsumer::TcpStartResult::Failed: return DirectTcpStartResult::Failed;
	default: return DirectTcpStartResult::Unavailable;
	}
}

bool CDirectReachabilityManager::DirectQuicDownloadAvailable() const noexcept
{
	return DirectDownloadAvailable() && m_quicHost &&
		eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub();
}

bool CDirectReachabilityManager::FailOwnedDirectDownload(reach::DirectHandle handle,reach::DirectReason reason)
{
	AssertMainThread();
	if(!DirectDownloadAvailable() || reason==reach::DirectReason::None) return false;
	const auto state=m_directConnections.Snapshot(handle);
	const auto lifetime=DirectTransferClientLifetime(handle);
	if(!state || state->state!=reach::DirectSessionState::Gathering || !lifetime || !HasDirectTransferSubscription(*lifetime,handle)) return false;
	m_builtinQuicConsumer->Fail(handle,reason); return true;
}

bool CDirectReachabilityManager::DirectDownloadAvailable() const noexcept
{
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && thePrefs.IsEseNetLabActive() &&
		m_builtinQuicConsumer && !m_directPump.Busy();
}

void CDirectReachabilityManager::PumpDirectQuicDownloadHandoff()
{
	if(!m_directBootstrapDownloadPolicy || !DirectControlBootstrapReady(m_directBootstrapOwner) ||
		!m_directBootstrap || m_directBootstrap->Selected()!=4 || m_directPump.Busy()) return;
	const auto handle=m_directBootstrapDownload;
	const auto routes=SelectOwnedDirectDownloadRoutes(handle);
	const auto peer=*m_directBootstrapDownloadPolicy;
	m_directBootstrapDownloadPolicy.reset(); // Single-use, before invoking host/consumer.
	ese::NativeQuicConfig native; native.server=false; native.local.port=GetLocalUdpPort();
	bool registered=!routes.routes.empty();
	for(const auto& route:routes.routes) {
		const bool accepted=route.transport==reach::DirectQuic
			? RegisterDirectQuicRoute(handle,route,native,peer)
			: route.transport==reach::DirectTcp && RegisterDirectLegacyRoute(handle,route);
		if(!accepted) { registered=false; break; }
	}
	// Reserve every eligible adapter before SetRoutes can emit Start. The DCO
	// owns ordering, fallback, authentication and loser cancellation, not ACK.
	if(!registered || !ScheduleDirectQuicRoutes(handle,routes.routes)) {
		m_directPump.Tick(m_builtinQuicConsumer,[&] {
			return std::vector<reach::DirectCoordinatorBatch>{m_directConnections.Cancel(handle,reach::DirectReason::NoRoute)};
		});
		CancelDirectControlBootstrap();
	} else {
		const auto state=m_directConnections.Snapshot(handle);
		const auto lifetime=DirectTransferClientLifetime(handle);
		auto* client=lifetime && theApp.clientlist ? theApp.clientlist->FindClientByLifetime(*lifetime) : nullptr;
		// Recovery retains the logical source, but HELLOANSWER must re-enter
		// its normal file request path instead of keeping the old DS_CONNECTED.
		if(state && (state->state==reach::DirectSessionState::Connecting || state->state==reach::DirectSessionState::Authenticating) &&
			client && !client->socket && ese::QuicDownloadConsumer::CanResumeFile(client->GetRequestFile()) &&
			HasDirectTransferSubscription(*lifetime,handle)) client->SetDownloadState(DS_CONNECTING);
	}
}

uint64 CDirectReachabilityManager::BeginDirectBootstrap(const std::array<std::uint8_t,32>& expectedPeer,
	const ese::udp::Endpoint& endpoint,uint64 deadline,const reach::DirectAttemptId* attempt,std::uint8_t mask,bool renewing)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_quicHost || !thePrefs.IsEseNetLabActive() ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
		m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return 0;
	if(m_directBootstrap && (m_directBootstrap->State()==ese::control::InitiatorState::Probe ||
		m_directBootstrap->State()==ese::control::InitiatorState::Prove)) {
		if(theApp.m_bReachBindingSelfTest) Log(_T("ACK_START_SELFTEST reject: existing bootstrap active state=%u"),unsigned(m_directBootstrap->State()));
		return 0;
	}
	const auto now=MonotonicMilliseconds();
	if(deadline<=now || deadline-now>2000 || !GetTopologyGeneration()) return 0;
	const auto crypto=MakeKad6HostCryptoHooks();
	ese::control::Header header; header.type=ese::wire::kEseWireUdpProbe;
	header.generation=GetTopologyGeneration(); header.sequence=1;
	ese::control::Probe probe; probe.peer=expectedPeer; probe.mask=mask;
	std::copy(eSELive::NodeIdentityPub(),eSELive::NodeIdentityPub()+32,probe.node.begin());
	if(attempt) header.attempt=*attempt;
	if(renewing) {
		const auto context=header;
		if(!attempt || (!m_directControlSessions->NextBootstrap(expectedPeer,endpoint,context,now,header) &&
			!m_directControlSessions->NextExpiredBootstrap(expectedPeer,endpoint,context,now,header))) return 0;
	}
	if(!crypto.random_bytes || (!attempt && !crypto.random_bytes(header.attempt.data(),header.attempt.size())) ||
		!crypto.random_bytes(probe.nonce.data(),probe.nonce.size())) return 0;
    const auto started=MonotonicMilliseconds();
    if(deadline<=started) return 0; // never return an already-expired owner after entropy preparation
	CancelDirectControlBootstrap();
	try {
		auto pending=std::make_unique<ese::control::InitiatorHost>(*m_quicHost);
		const auto owner=++m_nextDirectContactRefreshOwner;
		if(!pending->Start(owner,header,probe,endpoint,started,deadline)) return 0;
		m_directBootstrapContext=header; m_directBootstrapEndpoint=endpoint;
		m_directBootstrapPeer=expectedPeer; m_directBootstrapOwner=owner; m_directBootstrapIssued=started;
        m_directBootstrapDeadline=deadline;
		m_directBootstrap=std::move(pending); return owner;
	} catch(...) { return 0; }
}
bool CDirectReachabilityManager::DirectControlBootstrapReady(uint64 owner) const noexcept
{
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && thePrefs.IsEseNetLabActive() &&
		m_directBootstrapContext.generation==GetTopologyGeneration() &&
		owner && owner==m_directBootstrapOwner && m_directBootstrapReady &&
		m_directControlSessions->Current(m_directBootstrapPeer,m_directBootstrapEndpoint,
			m_directBootstrapContext,MonotonicMilliseconds());
}
void CDirectReachabilityManager::CancelDirectControlBootstrap()
{
	AssertMainThread(); m_directBootstrap.reset(); m_directBootstrapOwner=0; m_directBootstrapIssued=0;
    m_directBootstrapDeadline=0;
	m_directBootstrapReady=false; m_directBootstrapContext={}; m_directBootstrapPeer={}; m_directBootstrapEndpoint={};
	m_directBootstrapDownload={}; m_directBootstrapDownloadLifetime=0; m_directBootstrapDataUntil=0;
	m_directBootstrapDownloadPolicy.reset();
}

uint64 CDirectReachabilityManager::ExpectDirectControlBootstrap(const std::array<std::uint8_t,32>& expectedPeer,
	const ese::udp::Endpoint& endpoint,uint64 deadline)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_quicHost || !thePrefs.IsEseNetLabActive() ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
		m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return 0;
	const auto now=MonotonicMilliseconds();
	if(deadline<=now || deadline-now>2000 || !GetTopologyGeneration()) return 0;
	for(auto& entry:m_directResponders) if(!entry.owner) {
		try {
			if(!m_directCookieAuthority) {
				auto authority=std::make_unique<ese::control::CookieAuthority>();
				auto limit=std::make_unique<ese::control::ChallengeLimit>();
				if(!authority->Initialize()) return 0;
				m_directCookieAuthority=std::move(authority); m_directChallengeLimit=std::move(limit);
			}
			std::array<std::uint8_t,32> local{}; std::copy(eSELive::NodeIdentityPub(),eSELive::NodeIdentityPub()+32,local.begin());
			const auto owner=++m_nextDirectContactRefreshOwner;
			if(!m_quicHost->ExpectControlBootstrap(local,expectedPeer,endpoint,owner,deadline)) return 0;
			entry={expectedPeer,endpoint,owner,deadline,GetTopologyGeneration()}; return owner;
		} catch(...) { return 0; }
	}
	return 0;
}
void CDirectReachabilityManager::CancelDirectControlResponder(uint64 owner)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return;
	for(auto& entry:m_directResponders) if(owner && entry.owner==owner) {
		if(m_quicHost) m_quicHost->RemoveControlReplies(owner);
		entry={};
	}
}

bool CDirectReachabilityManager::AuthorizeDirectQuicControlResponder(uint64 owner,reach::DirectHandle handle,uint32 route)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!m_builtinQuicConsumer || m_directPump.Busy() || !owner || !route) return false;
	const auto attempt=m_directConnections.Snapshot(handle);
	if(!attempt) return false;
	const auto now=MonotonicMilliseconds();
	for(auto& entry:m_directResponders) if(entry.owner==owner && entry.deadline>now &&
		entry.topology==GetTopologyGeneration() && !entry.dataRoute && !entry.dataSubscriber && !entry.dataPreparationAttempted &&
		m_builtinQuicConsumer->PreparedServerRoute(handle,route,entry.peer,entry.endpoint,attempt->attempt_id,now)) {
		entry.dataAttempt=handle; entry.dataRoute=route; return true;
	}
	return false;
}

uint64 CDirectReachabilityManager::PrepareDirectKad6ContactRefresh(const std::array<std::uint8_t,32>& witness,
	const ese::udp::Endpoint& endpoint,const std::array<std::uint8_t,32>& requester,
	const ese::control::Datagram& get,uint64 deadline)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_quicHost || !m_kad6DirectContacts ||
		m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return 0;
	const auto now=MonotonicMilliseconds();
	if (now>(std::numeric_limits<uint64>::max)()-2000 || deadline<=now) return 0;
	const auto until=(std::min)(deadline,now+2000);
	const auto owner=++m_nextDirectContactRefreshOwner;
	if (!m_directContactRefreshReplies->Start(owner,witness,endpoint,requester,get,*m_directControlSessions,now,until)) return 0;
	ese::control::Header request;
	if (!ese::control::VerifyContactGet(requester,get.bytes.data(),get.size,request) ||
		!m_quicHost->ExpectControlReply(request,ese::wire::kEseWireUdpK6ContactResult,endpoint,owner,until)) {
		CancelDirectKad6ContactRefresh(owner); return 0;
	}
	std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize> cached{}; std::size_t size=0;
	if (!m_kad6DirectContacts->BeginRefresh(witness,now,cached,size)) {
		CancelDirectKad6ContactRefresh(owner); return 0;
	}
	return owner; // caller sends the already signed GET; failures retain cooldown
}

bool CDirectReachabilityManager::AuthorizeDirectQuicControlRequest(uint64 owner,uint64 subscriber,
	const std::array<std::uint8_t,32>& trustedPin)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!m_builtinQuicConsumer || m_directPump.Busy() || !theApp.clientlist) return false;
	const auto registration=m_directSubscribers->Resolve(subscriber);
	if(!registration || registration->terminal_reason ||
		(registration->consumer!=reach::DirectConsumerKind::Download && registration->consumer!=reach::DirectConsumerKind::Upload)) return false;
	auto* client=theApp.clientlist->FindClientByLifetime(registration->client_lifetime);
	if(!client || client->NativeDirectExpectedNode()!=trustedPin) return false;
	const auto now=MonotonicMilliseconds();
	for(auto& entry:m_directResponders) if(entry.owner==owner && owner && entry.peer==trustedPin &&
		entry.deadline>now && entry.topology==GetTopologyGeneration() &&
		!entry.dataRoute && !entry.dataSubscriber && !entry.dataPreparationAttempted) {
		entry.dataSubscriber=subscriber; return true;
	}
	return false;
}

bool CDirectReachabilityManager::PrepareConsentedDirectQuicResponder(ControlResponder& entry,
	const ese::control::Header& context,uint64 now)
{
	if(!entry.dataSubscriber || entry.dataPreparationAttempted || entry.dataRoute ||
		!m_builtinQuicConsumer || m_directPump.Busy() || entry.endpoint.scope) return false;
	entry.dataPreparationAttempted=true; // duplicates never allocate/restart/renew
	const auto generation=GetTopologyGeneration();
	reach::NativeValidatedUdpPath path{entry.peer,entry.endpoint.address,
		static_cast<std::uint8_t>(entry.endpoint.ipv6 ? 6 : 4),entry.endpoint.port,generation,now+15000};
	reach::DirectPolicy routePolicy;
	if(IsIsolatedLanQuicPeer(entry.peer,entry.endpoint)) { routePolicy=*m_isolatedLanQuicPolicy; path.scope=reach::DirectScope::SameLan; path.interface_id=routePolicy.required_interface_id; }
	auto routes=reach::BuildNativeQuicReturnRoutes(path,now,routePolicy);
	if(routes.routes.size()!=1) {
		if(m_rejectedQuicPreparationPolicies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedQuicPreparationPolicies;
		return false;
	}
	if(!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub()) return false;
	ese::QuicPeerConfig peer; peer.expectedNode=entry.peer; peer.pin=entry.peer; peer.hasPin=true; peer.persistent=true;
	std::copy(eSELive::NodeIdentityPub(),eSELive::NodeIdentityPub()+32,peer.local.node.begin());
	std::copy(thePrefs.GetUserHash(),thePrefs.GetUserHash()+16,peer.local.userHash.begin());
	peer.local.attempt=context.attempt; peer.local.topologyGeneration=generation; peer.local.role=1; peer.local.caps=1;
	const auto crypto=MakeKad6HostCryptoHooks();
	if(!crypto.random_bytes || !crypto.random_bytes(peer.local.nonce.data(),peer.local.nonce.size())) return false;
	const auto admission=RequestSharedDirectControlAttempt(entry.dataSubscriber,context,entry.endpoint);
	if(admission.request.status!=reach::DirectRequestStatus::Created && admission.request.status!=reach::DirectRequestStatus::Joined) return false;
	const auto handle=admission.request.handle;
	const auto state=m_directConnections.Snapshot(handle);
	if(!state || (state->state!=reach::DirectSessionState::Gathering && state->state!=reach::DirectSessionState::Recovering)) return false;
	const auto routeId=state->NextRouteId();
	if(!routeId) return false; // exhausted route high-water never wraps
	routes.routes[0].id=routeId; routes.routes[0].candidate.id=routeId;
	peer.sessionEpoch=state->epoch;
	ese::NativeQuicConfig native; native.server=true; native.local.port=GetLocalUdpPort();
	if(!RegisterDirectQuicRoute(handle,routes.routes[0],native,peer) || !ScheduleDirectQuicRoutes(handle,routes.routes)) {
		m_directPump.Tick(m_builtinQuicConsumer,[&] {
			return std::vector<reach::DirectCoordinatorBatch>{m_directConnections.Cancel(handle,reach::DirectReason::NoRoute)};
		});
		return false;
	}
	if(!m_builtinQuicConsumer->PreparedServerRoute(handle,routeId,entry.peer,entry.endpoint,context.attempt,now)) return false;
	entry.dataAttempt=handle; entry.dataRoute=routeId; return true;
}

void CDirectReachabilityManager::CancelDirectKad6ContactRefresh(uint64 owner)
{
	AssertMainThread(); if (::GetCurrentThreadId()!=m_dwOwnerThreadId) return;
	m_directContactRefreshReplies->Cancel(owner);
	if(m_quicHost) m_quicHost->RemoveControlReplies(owner);
}

ese::QuicUdpSendResult CDirectReachabilityManager::SendDirectKad6ContactRefresh(uint64 owner)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_quicHost) return {ese::QuicUdpSendStatus::Closed,0};
	ese::udp::Endpoint endpoint; ese::control::Datagram get;
	if(!m_directContactRefreshReplies->RequestInSession(owner,*m_directControlSessions,MonotonicMilliseconds(),endpoint,get)) {
		CancelDirectKad6ContactRefresh(owner); return {ese::QuicUdpSendStatus::Invalid,0};
	}
	const auto result=m_quicHost->SendControl(endpoint,{get.bytes.data(),get.size});
	if(result.status!=ese::QuicUdpSendStatus::Sent && result.status!=ese::QuicUdpSendStatus::WouldBlock)
		CancelDirectKad6ContactRefresh(owner);
	return result;
}

bool CDirectReachabilityManager::BeginDirectKad6Resolution(const std::array<std::uint8_t,16>& file,
	uint64 size,uint64 maximumSize)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || m_directResolution || !m_quicHost ||
		!thePrefs.IsEseNetLabActive() || !eSELive::NodeIdentityIsPersistent() || !GetTopologyGeneration()) return false;
	try {
		auto resolution=std::make_unique<ese::discovery::Kad6Resolution>();
        if(!resolution->Start(file,size,maximumSize,MonotonicMilliseconds(),GetTopologyGeneration())) return false;
		auto bridge=std::make_unique<ese::discovery::Kad6ResolutionHost>(*m_quicHost,*resolution);
		m_directResolutionTopology=GetTopologyGeneration();
		m_directResolution=std::move(resolution); m_directResolutionHost=std::move(bridge); return true;
	} catch(...) { return false; }
}
bool CDirectReachabilityManager::TryBeginQueuedKad6Resolution(const std::array<std::uint8_t,16>& file,uint64 size)
{
    AssertMainThread();
    // Ordinary queue processing must not steal an existing resolution or
    // bootstrap. Consent remains the existing opt-in, not a new default.
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId ||
        !thePrefs.IsEseNetLabActive() || m_directResolution || m_directBootstrapOwner || !m_quicHost ||
        !m_kad6DirectContacts || !eSELive::NodeIdentityIsPersistent() ||
        !GetTopologyGeneration() || !size || size>MAX_EMULE_FILE_SIZE) return false;
    if(!m_queuedKad6Cooldown.Claim(file,MonotonicMilliseconds())) return false;
    std::array<std::array<std::uint8_t,32>,64> hints{};
    const auto count=m_kad6DirectContacts->SnapshotHints(hints);
    std::array<std::uint8_t,16> target{};
    if(!ese::control::DirectIndexKey(file,size,MAX_EMULE_FILE_SIZE,target)) return false;
    ese::discovery::NearestContacts<16> nearest(target);
    std::array<LearnedWitness,64> options{};
    std::array<LearnedWitness,16> seeds{}; unsigned seedCount=0;
    for(unsigned i=0;i<count;++i) {
        kad6::K6RouterRecord record;
        const bool fresh=FreshDirectKad6Contact(hints[i],record);
        if((!fresh && !m_kad6DirectContacts->ReadHint(hints[i],record)) ||
            !(record.caps&ese::discovery::K6_CAP_DIRECT_INDEX_V1)) continue;
        // The current shared UDP host supports IPv4 only. A signed record is
        // probationary until bootstrap proves this exact endpoint's return.
        for(const auto& endpoint:record.endpoints) if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
            (endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port) {
            auto& seed=options[i]; seed.node=record.node_pub; seed.endpoint.port=endpoint.udp_port;
            std::copy(endpoint.addr.addr.begin(),endpoint.addr.addr.begin()+4,seed.endpoint.address.begin());
            seed.used=true; seed.needsRefresh=!fresh; nearest.Add(record.kad_id,record.node_pub,i); break;
        }
    }
    for(unsigned i=0;i<nearest.Count();++i) seeds[seedCount++]=options[nearest[i].ordinal];
    if(!seedCount) { m_kad6DiscoveryStatus.MissingBootstrap(); return false; }
    if(!BeginDirectKad6Resolution(file,size,MAX_EMULE_FILE_SIZE)) return false;
    m_kad6DiscoveryStatus.Started();
    m_resolutionLearned=seeds;
    m_resolutionDirectIndexBit=ese::discovery::K6_CAP_DIRECT_INDEX_V1;
    m_queuedKad6File=file; m_queuedKad6Size=size;
    m_resolutionLearnedBootstrap=true; m_resolutionAutomaticFinds=true; m_resolutionAutomaticGets=true;
    return true;
}
void CDirectReachabilityManager::RetireInactiveQueuedKad6Resolution(CDownloadQueue& queue)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_queuedKad6Size) return;
    auto* file=queue.GetFileByID(m_queuedKad6File.data());
    if(!file || file->GetFileSize()!=m_queuedKad6Size || file->IsStopped() ||
        (file->GetStatus()!=PS_READY && file->GetStatus()!=PS_EMPTY) || !thePrefs.IsEseNetLabActive())
        CancelDirectKad6Resolution();
}
void CDirectReachabilityManager::CancelDirectKad6Resolution()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return;
    m_kad6DiscoveryStatus.Cancelled();
	// Bridge retires registrations while both borrowed objects are still alive.
	m_directResolutionHost.reset();
	if(m_directResolution) m_directResolution->Cancel();
	m_directResolution.reset(); m_directResolutionTopology=0;
    m_queuedKad6File={}; m_queuedKad6Size=0; // cooldown survives cancellation
	m_directResolved={}; m_directResolvedCount=0;
	m_resolutionWitnesses={}; m_resolutionAutomaticGetSlots={}; m_resolutionAutomaticGets=false;
	m_resolutionAutomaticFinds=false;
	m_resolutionAutomaticGetsPrepared=0; m_resolutionAutomaticGetLastSend=ese::QuicUdpSendStatus::Invalid;
	m_resolutionAutomaticGetHistory={}; m_resolutionAutomaticGetHistoryCount=0;
	m_resolutionDirectIndexBit=0;
	for(const auto& learned:m_resolutionLearned) {
        if(learned.refreshOwner) CancelDirectKad6ContactRefresh(learned.refreshOwner);
		if(learned.owner && learned.owner==m_directBootstrapOwner) CancelDirectControlBootstrap();
    }
	m_resolutionLearned={}; m_resolutionLearnedBootstrap=false;
}
bool CDirectReachabilityManager::AddDirectKad6ResolutionWitness(const std::array<std::uint8_t,32>& witness,
	const ese::udp::Endpoint& endpoint,const ese::control::Header& session,uint64 directIndexBit)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolution || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration() || !directIndexBit || (directIndexBit&(directIndexBit-1))) return false;
	if(m_resolutionDirectIndexBit && m_resolutionDirectIndexBit!=directIndexBit) return false;
	for(const auto& seed:m_resolutionWitnesses) if(seed.used && seed.node==witness) return false;
	const auto now=MonotonicMilliseconds(); kad6::K6RouterRecord record;
	if(!FreshDirectKad6Contact(witness,record) || !(record.caps&directIndexBit) ||
		!m_directControlSessions->Current(witness,endpoint,session,now)) return false;
	ese::discovery::Kad6Lookup::Contact contact; contact.node=witness; contact.id=record.kad_id;
	if((!m_directResolution->Lookup().ContainsValidated(contact) && !m_directResolution->Lookup().AddValidatedRecord(contact,now)) ||
		!m_directResolution->Lookup().MarkReturnVerified(witness,now)) return false;
	for(auto& seed:m_resolutionWitnesses) if(!seed.used) { seed={witness,endpoint,session,true}; m_resolutionDirectIndexBit=directIndexBit; return true; }
	return false;
}
bool CDirectReachabilityManager::EnableDirectKad6LearnedBootstrap()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return false;
	m_resolutionLearnedBootstrap=true; return true;
}
void CDirectReachabilityManager::PumpDirectKad6LearnedBootstrap()
{
	if(!m_resolutionLearnedBootstrap || !m_directResolution || !m_directResolutionHost) return;
	for(auto& learned:m_resolutionLearned) if(learned.used && learned.owner) {
		if(DirectControlBootstrapReady(learned.owner)) {
            const auto now=MonotonicMilliseconds();
            const auto deadline=m_directResolution->Lookup().Deadline();
            if(learned.needsRefresh && now<deadline) {
                if(!learned.refreshOwner) {
                    ese::control::Header request;
                    std::array<std::uint8_t,32> requester{};
                    if(eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub())
                        memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
                    class PersistentSigner final : public ese::control::Signer {
                        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
                            return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
                        }
                    } signer;
                    ese::control::Datagram get;
                    if(m_directControlSessions->NextRequest(learned.node,learned.endpoint,m_directBootstrapContext,
                        ese::wire::kEseWireUdpK6ContactGet,now,request) &&
                        ese::control::BuildContactGet(request,requester,signer,get)) {
                        learned.refreshUntil=(std::min)(deadline,now+2000);
                        learned.refreshOwner=PrepareDirectKad6ContactRefresh(learned.node,learned.endpoint,requester,get,learned.refreshUntil);
                    }
                    if(learned.refreshOwner) SendDirectKad6ContactRefresh(learned.refreshOwner);
                    else { CancelDirectControlBootstrap(); learned.used=false; }
                } else if(now>=learned.refreshUntil) {
                    CancelDirectKad6ContactRefresh(learned.refreshOwner);
                    CancelDirectControlBootstrap(); learned.used=false;
                }
                // Keep the exact bootstrap owner while its refresh is live;
                // another seed must not replace this authenticated session.
                if(learned.used) return;
                continue; // Never FIND with expired signed bytes.
            }
			AddDirectKad6ResolutionWitness(learned.node,learned.endpoint,m_directBootstrapContext,m_resolutionDirectIndexBit);
			CancelDirectControlBootstrap(); learned.used=false;
		} else if(learned.owner!=m_directBootstrapOwner) learned.used=false;
	}
	if(m_directBootstrap && (m_directBootstrap->State()==ese::control::InitiatorState::Probe ||
		m_directBootstrap->State()==ese::control::InitiatorState::Prove)) return;
	for(auto& learned:m_resolutionLearned) if(learned.used && !learned.tried) {
		const auto now=MonotonicMilliseconds(); const auto deadline=m_directResolution->Lookup().Deadline();
		if(now>=deadline) return;
		kad6::K6RouterRecord record;
		learned.tried=true;
        const bool fresh=FreshDirectKad6Contact(learned.node,record);
		if((!fresh && (!learned.needsRefresh || !m_kad6DirectContacts->ReadHint(learned.node,record))) ||
            !(record.caps&m_resolutionDirectIndexBit)) { learned.used=false; continue; }
		bool endpointCurrent=false;
		for(const auto& endpoint:record.endpoints)
			if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
				(endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port==learned.endpoint.port &&
				std::equal(endpoint.addr.addr.begin(),endpoint.addr.addr.begin()+4,learned.endpoint.address.begin())) endpointCurrent=true;
		if(!endpointCurrent) { learned.used=false; continue; }
		const auto until=now+((deadline-now<2000)?deadline-now:2000);
		learned.owner=BeginDirectControlBootstrap(learned.node,learned.endpoint,until);
		if(learned.owner) return;
		learned.used=false;
	}
}
bool CDirectReachabilityManager::EnableDirectKad6AutomaticFinds()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return false;
	m_resolutionAutomaticFinds=true; return true;
}
void CDirectReachabilityManager::PumpDirectKad6AutomaticFinds()
{
	if(!m_resolutionAutomaticFinds || !m_directResolutionHost || !m_directResolution) return;
	m_directResolutionHost->PumpFindRetries(*m_directControlSessions,MonotonicMilliseconds());
	std::array<ese::discovery::Kad6Lookup::Contact,2> round{};
	const auto count=BeginDirectKad6FindRound(round);
	for(unsigned slot=0;slot<count;++slot) {
		bool started=false;
		for(const auto& seed:m_resolutionWitnesses) if(seed.used && seed.node==round[slot].node) {
			ese::control::Header assigned;
			const auto owner=PrepareDirectKad6NextFind(slot,seed.node,seed.endpoint,seed.session,assigned);
			if(owner) { SendDirectKad6Find(owner); started=true; }
			break;
		}
		// A missing/revoked session or failed preparation must not block the round.
		// Visited and transmission budgets are never restored on failure.
		if(!started) m_directResolution->Lookup().Complete(round[slot].node,MonotonicMilliseconds());
	}
}
bool CDirectReachabilityManager::EnableDirectKad6AutomaticGets()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return false;
	m_resolutionAutomaticGets=true; return true;
}
void CDirectReachabilityManager::PumpDirectKad6AutomaticGets()
{
	if(!m_resolutionAutomaticGets || !m_directResolutionHost || !m_directResolution) return;
	m_directResolutionHost->PumpGetRetries(*m_directControlSessions,MonotonicMilliseconds());
	for(auto& pending:m_resolutionAutomaticGetSlots)
		if(pending.used && !m_directResolutionHost->OwnsGet(pending.owner)) pending={};
	if(m_directResolvedCount==m_directResolved.size()) return;
	std::array<ese::discovery::Kad6Resolution::LocatedSource,32> sources;
	const auto count=SnapshotDirectKad6LocatedSources(sources);
	for(unsigned index=0;index<count;++index) {
		bool requested=false; unsigned slot=4;
		for(unsigned i=0;i<m_resolutionAutomaticGetHistoryCount;++i) {
			const auto& old=m_resolutionAutomaticGetHistory[i];
			if(SameResolutionSource(old.source,sources[index].source) &&
				(old.completed || old.witness==sources[index].witness)) requested=true;
		}
		for(unsigned i=0;i<4;++i) {
			const auto& pending=m_resolutionAutomaticGetSlots[i];
			if(!pending.used && slot==4) slot=i;
			if(pending.used && SameResolutionSource(pending.source,sources[index].source)) requested=true;
		}
		if(requested) continue; if(slot==4) return;
		if(m_resolutionAutomaticGetHistoryCount==m_resolutionAutomaticGetHistory.size()) return;
		for(const auto& seed:m_resolutionWitnesses) if(seed.used && seed.node==sources[index].witness &&
			seed.endpoint==sources[index].witnessEndpoint) {
			ese::control::Header assigned;
			const auto owner=PrepareDirectKad6NextLocatedGet(slot,index,seed.session,assigned);
			if(owner) {
				m_resolutionAutomaticGetSlots[slot]={sources[index].source,true,owner}; ++m_resolutionAutomaticGetsPrepared;
				m_resolutionAutomaticGetHistory[m_resolutionAutomaticGetHistoryCount++]={sources[index].source,sources[index].witness,false};
				m_resolutionAutomaticGetLastSend=SendDirectKad6DescriptorGet(owner).status;
			}
			break;
		}
	}
}
unsigned CDirectReachabilityManager::BeginDirectKad6FindRound(std::array<ese::discovery::Kad6Lookup::Contact,2>& out)
{
	AssertMainThread(); out={};
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolution || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return 0;
	return m_directResolution->Lookup().BeginRound(MonotonicMilliseconds(),out);
}
uint64 CDirectReachabilityManager::PrepareDirectKad6Find(unsigned slot,
	const std::array<std::uint8_t,32>& witness,const ese::udp::Endpoint& endpoint,const ese::control::Datagram& packet)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !m_directResolution ||
		!thePrefs.IsEseNetLabActive() || m_directResolutionTopology!=GetTopologyGeneration() ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
		m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return 0;
	const auto now=MonotonicMilliseconds();
	const auto until=m_directResolution->Lookup().FindAuthorization(witness,now); if(!until) return 0;
	std::array<std::uint8_t,32> requester{}; memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
	const auto owner=++m_nextDirectContactRefreshOwner;
	if(!m_directResolutionHost->StartFind(slot,owner,witness,endpoint,requester,packet,*m_directControlSessions,now,until)) return 0;
	ese::control::Envelope envelope;
	if(ese::control::ParseUntrusted(packet.bytes.data(),packet.size,envelope))
		m_directControlSessions->RememberOutgoing(witness,endpoint,envelope.header,now);
	return owner;
}
uint64 CDirectReachabilityManager::PrepareDirectKad6NextFind(unsigned slot,
	const std::array<std::uint8_t,32>& witness,const ese::udp::Endpoint& endpoint,
	const ese::control::Header& session,ese::control::Header& assigned)
{
	AssertMainThread(); assigned={};
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolution || !m_directResolutionHost ||
		!thePrefs.IsEseNetLabActive() || m_directResolutionTopology!=GetTopologyGeneration() ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub()) return 0;
	const auto now=MonotonicMilliseconds();
	if(!m_directResolution->Lookup().FindAuthorization(witness,now)) return 0;
	ese::discovery::DirectFind query; uint64 maximumSize=0;
	if(!m_directResolution->Query(query,maximumSize)) return 0;
	memcpy(query.requester.data(),eSELive::NodeIdentityPub(),32);
	ese::control::Header request;
	if(!m_directControlSessions->NextRequest(witness,endpoint,session,
		ese::wire::kEseWireUdpK6DirectFind,now,request)) return 0;
	class PersistentSigner final : public ese::control::Signer {
		bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
			return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
		}
	} signer;
	ese::control::Datagram packet;
	if(!ese::control::BuildDirectFind(request,query,maximumSize,signer,packet)) return 0;
	const auto owner=PrepareDirectKad6Find(slot,witness,endpoint,packet);
	if(owner) assigned=request;
	return owner;
}
ese::QuicUdpSendResult CDirectReachabilityManager::SendDirectKad6Find(uint64 owner)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return {ese::QuicUdpSendStatus::Invalid,0};
	return m_directResolutionHost->SendOwnedFind(owner,*m_directControlSessions,MonotonicMilliseconds());
}
uint64 CDirectReachabilityManager::PrepareDirectKad6DescriptorGet(unsigned slot,
	const std::array<std::uint8_t,32>& witness,const ese::udp::Endpoint& endpoint,
	const ese::discovery::Locator& locator,const ese::control::Datagram& packet)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !m_directResolution ||
		!thePrefs.IsEseNetLabActive() || m_directResolutionTopology!=GetTopologyGeneration() ||
		!eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
		m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return 0;
	const auto now=MonotonicMilliseconds();
	if(now>(std::numeric_limits<uint64>::max)()-2000) return 0;
	const auto until=(std::min)(now+2000,m_directResolution->Lookup().Deadline());
	std::array<std::uint8_t,32> requester{}; memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
	const auto owner=++m_nextDirectContactRefreshOwner;
	if(!m_directResolutionHost->StartGet(slot,owner,witness,endpoint,requester,locator,packet,
		*m_directControlSessions,now,until)) return 0;
	ese::control::Envelope envelope;
	if(ese::control::ParseUntrusted(packet.bytes.data(),packet.size,envelope))
		m_directControlSessions->RememberOutgoing(witness,endpoint,envelope.header,now);
	return owner;
}
uint64 CDirectReachabilityManager::PrepareDirectKad6NextLocatedGet(unsigned slot,unsigned sourceIndex,
	const ese::control::Header& session,ese::control::Header& assigned)
{
	AssertMainThread(); assigned={};
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return 0;
	std::array<ese::discovery::Kad6Resolution::LocatedSource,32> sources;
	if(sourceIndex>=SnapshotDirectKad6LocatedSources(sources)) return 0;
	const auto& source=sources[sourceIndex]; ese::control::Header request;
	if(!m_directControlSessions->NextRequest(source.witness,source.witnessEndpoint,session,
		ese::wire::kEseWireUdpDescriptorGet,MonotonicMilliseconds(),request)) return 0;
	const auto owner=PrepareDirectKad6LocatedGet(slot,sourceIndex,request);
	if(owner) assigned=request;
	return owner;
}
uint64 CDirectReachabilityManager::PrepareDirectKad6LocatedGet(unsigned slot,unsigned sourceIndex,
	const ese::control::Header& request)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
		request.type!=ese::wire::kEseWireUdpDescriptorGet) return 0;
	std::array<ese::discovery::Kad6Resolution::LocatedSource,32> sources;
	if(sourceIndex>=SnapshotDirectKad6LocatedSources(sources)) return 0;
	const auto& source=sources[sourceIndex];
	std::array<std::uint8_t,32> requester{}; memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
	class PersistentSigner final : public ese::control::Signer {
		bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
			return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
		}
	} signer;
	ese::control::Datagram packet;
	if(!ese::control::BuildDescriptorGet(request,source.source.file,source.locator,requester,signer,packet)) return 0;
	return PrepareDirectKad6DescriptorGet(slot,source.witness,source.witnessEndpoint,source.locator,packet);
}
ese::QuicUdpSendResult CDirectReachabilityManager::SendDirectKad6DescriptorGet(uint64 owner)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolutionHost || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return {ese::QuicUdpSendStatus::Invalid,0};
	return m_directResolutionHost->SendOwnedGet(owner,*m_directControlSessions,MonotonicMilliseconds());
}
unsigned CDirectReachabilityManager::SnapshotDirectKad6LocatedSources(
	std::array<ese::discovery::Kad6Resolution::LocatedSource,32>& out)
{
	AssertMainThread(); out={};
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_directResolution || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return 0;
	return m_directResolution->SnapshotLocatedSources(MonotonicMilliseconds(),out);
}
unsigned CDirectReachabilityManager::ConsumeDirectKad6DownloadSources(CDownloadQueue& queue)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return 0;
	const auto now=MonotonicMilliseconds(); unsigned consumed=0;
	for(unsigned i=0;i<m_directResolvedCount;) {
		const bool expired=m_directResolved[i].until<=now;
		const bool adopted=!expired && queue.AdoptDirectKad6Discovery(m_directResolved[i]);
		if(!expired && !adopted) { ++i; continue; } // Retain bounded pending evidence, not a fabricated source.
		if(adopted) ++consumed;
		for(unsigned j=i+1;j<m_directResolvedCount;++j) m_directResolved[j-1]=std::move(m_directResolved[j]);
		m_directResolved[--m_directResolvedCount]={};
	}
	return consumed;
}
bool CDirectReachabilityManager::PopDirectKad6Resolved(ese::discovery::Kad6Resolution::ResolvedCandidate& out)
{
	AssertMainThread(); out={};
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		m_directResolutionTopology!=GetTopologyGeneration()) return false;
	const auto now=MonotonicMilliseconds();
	while(m_directResolvedCount) {
		auto candidate=m_directResolved[0];
		for(unsigned i=1;i<m_directResolvedCount;++i) m_directResolved[i-1]=m_directResolved[i];
		m_directResolved[--m_directResolvedCount]={};
		if(candidate.until>now) { out=std::move(candidate); return true; }
	}
	return false;
}
bool CDirectReachabilityManager::ConfigureIsolatedLanQuicPeer(const std::array<std::uint8_t,32>& node,
	const ese::udp::Endpoint& endpoint,uint64 interfaceId,uint64 labDurationMs)
{
	AssertMainThread();
	if(theApp.m_strQuicPairSelfTestRole.IsEmpty() || !theApp.m_bReachBindingSelfTest || m_isolatedLanQuicPolicy ||
		labDurationMs<120000 || labDurationMs>1200000 ||
		endpoint.ipv6 || endpoint.scope || !endpoint.port || !interfaceId || !GetTopologyGeneration() ||
		!thePrefs.GetBindAddr() || !reach::NonzeroIdentity(node)) return false;
	const auto& a=endpoint.address;
	if(!(a[0]==10 || (a[0]==172 && a[1]>=16 && a[1]<=31) || (a[0]==192 && a[1]==168))) return false;
	const auto bind=inet_addr(CT2A(thePrefs.GetBindAddr()));
	if(bind==INADDR_NONE || std::memcmp(&bind,a.data(),4)) return false; // isolated same-host pair, exact /32
	ULONG bytes=0;
	if(GetAdaptersAddresses(AF_INET,0,nullptr,nullptr,&bytes)!=ERROR_BUFFER_OVERFLOW || bytes>1024*1024) return false;
	std::vector<BYTE> buffer(bytes); auto adapters=reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
	if(GetAdaptersAddresses(AF_INET,0,nullptr,adapters,&bytes)!=NO_ERROR) return false;
	bool assigned=false;
	for(auto adapter=adapters;adapter;adapter=adapter->Next) if(adapter->IfIndex==interfaceId && adapter->OperStatus==IfOperStatusUp)
		for(auto u=adapter->FirstUnicastAddress;u;u=u->Next) if(u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family==AF_INET &&
			!std::memcmp(&reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr)->sin_addr,a.data(),4)) assigned=true;
	ese::trust::Record trust;
	if(!assigned || LoadDirectQuicPeerTrust(node,trust)!=ese::trust::LoadResult::Loaded || trust.node!=node) return false;
	reach::DirectPolicy policy; policy.topology_generation=GetTopologyGeneration(); policy.allow_same_lan=true;
	policy.required_interface_id=interfaceId; policy.local_interface_family=4; policy.local_interface_address=a; policy.local_prefix_length=32;
	m_isolatedLanQuicPeer=node; m_isolatedLanQuicEndpoint=endpoint; m_isolatedLanQuicUntil=MonotonicMilliseconds()+labDurationMs;
	m_isolatedLanQuicPolicy=policy; return true;
}
bool CDirectReachabilityManager::IsIsolatedLanQuicPeer(const std::array<std::uint8_t,32>& node,const ese::udp::Endpoint& endpoint) const
{
	return !theApp.m_strQuicPairSelfTestRole.IsEmpty() && thePrefs.IsEseNetLabActive() && m_isolatedLanQuicPolicy &&
		m_isolatedLanQuicPolicy->topology_generation==GetTopologyGeneration() && m_isolatedLanQuicUntil>MonotonicMilliseconds() &&
		node==m_isolatedLanQuicPeer && endpoint==m_isolatedLanQuicEndpoint;
}
bool CDirectReachabilityManager::AppendIsolatedLanQuicCandidate(reach::NativeDirectCandidateSnapshotV1& snapshot) const
{
	if(!snapshot.peer.expected_node_pub || snapshot.local_generation!=GetTopologyGeneration() ||
		!IsIsolatedLanQuicPeer(*snapshot.peer.expected_node_pub,m_isolatedLanQuicEndpoint) || snapshot.count==snapshot.candidates.size()) return false;
	auto& candidate=snapshot.candidates[snapshot.count++]; candidate={}; candidate.route.id=3;
	auto& route=candidate.route; route.family=4; route.address=m_isolatedLanQuicEndpoint.address; route.port=m_isolatedLanQuicEndpoint.port;
	route.kind=reach::DirectKind::DirectV4; route.scope=reach::DirectScope::SameLan; route.interface_id=m_isolatedLanQuicPolicy->required_interface_id;
	route.transport_mask=reach::DirectQuic; route.evidence=reach::DirectEvidence::Advertised;
	route.topology_generation=GetTopologyGeneration(); route.expires_monotonic_ms=(std::min)(m_isolatedLanQuicUntil,MonotonicMilliseconds()+15000); return true;
}
bool CDirectReachabilityManager::HasPendingDirectUpload(uint64 lifetime) const
{
	for(const auto& grant:m_uploadControlGrants) if(grant.lifetime==lifetime && grant.topology==GetTopologyGeneration()) {
		const auto record=ResolveDirectSubscriber(grant.subscriber);
		if(!record || record->terminal_reason) continue;
		if(IsIsolatedLanQuicPeer(grant.peer,grant.endpoint)) return true;
		if(record->attempt && HasDirectTransferSubscription(lifetime,*record->attempt)) {
			const auto state=m_directConnections.Snapshot(*record->attempt);
			if(state && state->state!=reach::DirectSessionState::Failed && state->state!=reach::DirectSessionState::Cancelled) return true;
		}
	}
	return false;
}
void CDirectReachabilityManager::RetireDirectUploadAuthorization(UploadControlGrant& grant)
{
	if(grant.owner) CancelDirectControlResponder(grant.owner);
	if(grant.subscriber) {
		const auto batch=RetireDirectSubscriber(grant.subscriber);
		if(m_builtinQuicConsumer) m_builtinQuicConsumer->Batch(batch);
	}
	grant={};
}

void CDirectReachabilityManager::PumpDirectUploadAuthorizations()
{
	if(m_directPump.Busy()) return;
	const auto now=MonotonicMilliseconds();
	auto eligible=[&](CUpDownClient* client,ese::udp::Endpoint& endpoint) {
		if(!thePrefs.IsEseNetLabActive() || !m_quicHost || !m_builtinQuicConsumer ||
			!theApp.uploadqueue || !theApp.sharedfiles || !client || client->IsBanned() ||
			!client->SupportsEseNetLabV1() || !client->HasEseNodePub() || !client->GetUDPPort() ||
			(!theApp.uploadqueue->IsOnUploadQueue(client) && !theApp.uploadqueue->IsDownloading(client)) ||
			!theApp.sharedfiles->GetFileByID(client->GetUploadFileID())) return false;
		const auto address=client->IsIPv6OnlyEndpoint() ? client->GetIPv6Address() : CAddress::FromIPv4NetworkOrder(client->GetIP());
		endpoint={}; endpoint.ipv6=address.GetType()==CAddress::IPv6; endpoint.port=client->GetUDPPort();
		std::copy(address.Data(),address.Data()+address.GetSize(),endpoint.address.begin());
		if(!address.IsUsablePublic() && !IsIsolatedLanQuicPeer(client->NativeDirectExpectedNode().value_or(std::array<std::uint8_t,32>{}),endpoint)) return false;
		return true;
	};
	// Revoke before consuming a queued PROVE, including file changes and lost consent.
	for(auto& grant:m_uploadControlGrants) if(grant.lifetime) {
		auto* client=theApp.clientlist ? theApp.clientlist->FindClientByLifetime(grant.lifetime) : nullptr;
		ese::udp::Endpoint endpoint;
		const auto registration=ResolveDirectSubscriber(grant.subscriber);
		if(!eligible(client,endpoint) || !(endpoint==grant.endpoint) || grant.topology!=GetTopologyGeneration() ||
			client->NativeDirectExpectedNode()!=grant.peer || std::memcmp(client->GetUploadFileID(),grant.file.data(),16) ||
			!registration || registration->terminal_reason) {
			if(!theApp.m_strQuicPairSelfTestRole.IsEmpty()) Log(_T("QUIC_PAIR_REVOKE live=%u eligible=%u endpoint=%u topology=%u node=%u file=%u record=%u terminal=%u ip=%08x udp=%u lab=%u queue=%u slot=%u"),
				unsigned(client!=nullptr),unsigned(eligible(client,endpoint)),unsigned(endpoint==grant.endpoint),unsigned(grant.topology==GetTopologyGeneration()),
				unsigned(client && client->NativeDirectExpectedNode()==grant.peer),unsigned(client && !std::memcmp(client->GetUploadFileID(),grant.file.data(),16)),
				unsigned(registration.has_value()),registration && registration->terminal_reason ? unsigned(*registration->terminal_reason):0,
				client ? client->GetIP():0,client ? client->GetUDPPort():0,unsigned(client && client->SupportsEseNetLabV1()),
				unsigned(client && theApp.uploadqueue && theApp.uploadqueue->IsOnUploadQueue(client)),unsigned(client && theApp.uploadqueue && theApp.uploadqueue->IsDownloading(client)));
			RetireDirectUploadAuthorization(grant); continue;
		}
		bool pending=false;
		for(const auto& responder:m_directResponders)
			if(responder.owner==grant.owner && responder.deadline>now) pending=true;
		const auto uploadAttempt=registration->attempt ? m_directConnections.Snapshot(*registration->attempt) : std::nullopt;
		if(!pending && (!registration->attempt || (uploadAttempt &&
			uploadAttempt->state==reach::DirectSessionState::Recovering && !uploadAttempt->winner))) {
			if(grant.owner) CancelDirectControlResponder(grant.owner);
			grant.owner=ExpectDirectControlBootstrap(grant.peer,grant.endpoint,now+2000);
			if(grant.owner && !AuthorizeDirectQuicControlRequest(grant.owner,grant.subscriber,grant.peer))
				RetireDirectUploadAuthorization(grant);
		}
	}
	if(!theApp.uploadqueue || !theApp.clientlist || !m_quicHost || !thePrefs.IsEseNetLabActive()) return;
	if(now<m_nextUploadAuthorizationAdmission || std::none_of(m_uploadControlGrants.begin(),m_uploadControlGrants.end(),
		[](const UploadControlGrant& g) { return !g.lifetime; })) return;
	m_nextUploadAuthorizationAdmission=now+1000; // bounded trust IO, not on every 100ms queue tick
	auto admit=[&](CUpDownClient* client) {
		ese::udp::Endpoint endpoint;
		if(!eligible(client,endpoint) || client->socket) return; // never replace a live classic socket
		for(const auto& grant:m_uploadControlGrants) if(grant.lifetime==client->GetDirectClientLifetime()) return;
		auto free=std::find_if(m_uploadControlGrants.begin(),m_uploadControlGrants.end(),[](const UploadControlGrant& g) { return !g.lifetime; });
		if(free==m_uploadControlGrants.end()) return;
		const auto node=client->NativeDirectExpectedNode(); ese::trust::Record trust;
		// HELLO advertises identity; it never creates a trusted pin by itself.
		if(!node || LoadDirectQuicPeerTrust(*node,trust)!=ese::trust::LoadResult::Loaded || trust.node!=*node) return;
		const auto subscriber=AcquireDirectSubscriber(client->GetDirectClientLifetime(),reach::DirectConsumerKind::Upload);
		if(!subscriber) return;
		free->lifetime=client->GetDirectClientLifetime(); free->subscriber=subscriber;
		free->peer=*node; free->endpoint=endpoint; free->topology=GetTopologyGeneration();
		std::copy(client->GetUploadFileID(),client->GetUploadFileID()+16,free->file.begin());
		free->owner=ExpectDirectControlBootstrap(*node,endpoint,now+2000);
		if(!free->owner || !AuthorizeDirectQuicControlRequest(free->owner,subscriber,*node)) RetireDirectUploadAuthorization(*free);
	};
	std::size_t ordinal=0,scanned=0;
	auto scan=[&](CUpDownClient* client) { if(ordinal++>=m_uploadAuthorizationScanOffset) { admit(client); ++scanned; } };
	for(POSITION pos=theApp.uploadqueue->GetFirstFromWaitingList();pos && scanned<32;) scan(theApp.uploadqueue->GetNextFromWaitingList(pos));
	for(POSITION pos=theApp.uploadqueue->GetFirstFromUploadList();pos && scanned<32;) scan(theApp.uploadqueue->GetNextFromUploadList(pos));
	m_uploadAuthorizationScanOffset=scanned==32 ? m_uploadAuthorizationScanOffset+32 : 0;
}

void CDirectReachabilityManager::PumpDirectControlReplies()
{
	if(!m_quicHost) return;
    SynchronizeKad6IndexService();
	const auto now=MonotonicMilliseconds();
	if(m_kad6PublicationSize) {
		auto* owned=theApp.sharedfiles ? theApp.sharedfiles->GetFileByID(m_kad6PublicationFile.data()) : nullptr;
		if(!thePrefs.IsEseNetLabActive() || !Kademlia::CKademlia::IsKad6Running() || !owned ||
			owned->GetFileSize()!=m_kad6PublicationSize || m_kad6PublicationTopology!=GetTopologyGeneration() ||
			now>=m_kad6PublicationUntil) CancelKad6Publication();
	}
	if(m_directResolution) {
		if(!thePrefs.IsEseNetLabActive() || m_directResolutionTopology!=GetTopologyGeneration()) CancelDirectKad6Resolution();
        else if(!m_directResolution->Poll(now)) { m_kad6DiscoveryStatus.Expired(); CancelDirectKad6Resolution(); }
		else m_directResolutionHost->Poll(*m_directControlSessions,now);
	}
	if(m_directBootstrap) {
		bool downloadCurrent=true;
		if(m_directBootstrapDownloadLifetime) {
			const auto attempt=m_directConnections.Snapshot(m_directBootstrapDownload);
			downloadCurrent=attempt && attempt->attempt_id==m_directBootstrapContext.attempt &&
				attempt->peer.domain==reach::DirectPeerDomain::NodePublicKey &&
				attempt->peer.identity==m_directBootstrapPeer &&
				(attempt->state==reach::DirectSessionState::Gathering || attempt->state==reach::DirectSessionState::Recovering) &&
				HasDirectTransferSubscription(m_directBootstrapDownloadLifetime,m_directBootstrapDownload) &&
				theApp.clientlist && theApp.clientlist->FindClientByLifetime(m_directBootstrapDownloadLifetime) &&
				(!m_directBootstrapDataUntil || now<m_directBootstrapDataUntil);
		}
		// Revoke before Poll: a withdrawn download must not emit a delayed
		// PROBE/PROVE retry, even though its control deadline has not expired.
		if(!downloadCurrent || !thePrefs.IsEseNetLabActive() || m_directBootstrapContext.generation!=GetTopologyGeneration())
			CancelDirectControlBootstrap();
		else {
			m_directBootstrap->Poll(now);
			if(m_directBootstrap->State()==ese::control::InitiatorState::Failed) CancelDirectControlBootstrap();
		}
	}
	for(auto& entry:m_directResponders) if(entry.owner &&
		(now>=entry.deadline || entry.topology!=GetTopologyGeneration() || !thePrefs.IsEseNetLabActive()))
		CancelDirectControlResponder(entry.owner);
	m_directContactRefreshReplies->PollInSession(*m_directControlSessions,now,[this](uint64 owner) { m_quicHost->RemoveControlReplies(owner); });
	ese::QuicUdpRouter::PendingControl packet;
	const auto utc=std::time(nullptr);
	for(unsigned count=0;count<32 && m_quicHost->PopControlReply(packet);++count) {
        bool publicationReply=false;
        for(auto& witness:m_kad6PublicationWitnesses) if(witness.used && witness.replyOwner && witness.replyOwner==packet.owner) {
            publicationReply=true; std::uint8_t status=255;
            if(witness.attempt && packet.receivedMs<=now && witness.attempt->Receive(*m_directControlSessions,packet.peer,
                packet.bytes.data(),packet.size,now,status)) {
                m_quicHost->RemoveControlReplies(witness.replyOwner); witness.replyOwner=0;
                if(status==0 && m_kad6StoredPublications!=(std::numeric_limits<uint64>::max)()) ++m_kad6StoredPublications;
                if(witness.attempt->State()!=ese::discovery::PublicationState::Restage) witness.done=true;
            } else if(m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedDirectControlReplies;
            break;
        }
        if(publicationReply) continue;
        if(m_kad6IndexOwner && packet.owner==m_kad6IndexOwner) {
            if(!ReceiveKad6IndexService(packet,now) && m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)())
                ++m_rejectedDirectControlReplies;
            continue;
        }
		ControlResponder* responder=nullptr;
		for(auto& entry:m_directResponders) if(entry.owner && entry.owner==packet.owner) { responder=&entry; break; }
		if(responder) {
			ese::control::Envelope envelope; ese::control::Datagram response;
			std::array<std::uint8_t,32> local{}; bool valid=false;
			if(eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub() && packet.receivedMs<=now &&
				packet.peer==responder->endpoint && ese::control::ParseUntrusted(packet.bytes.data(),packet.size,envelope)) {
				std::copy(eSELive::NodeIdentityPub(),eSELive::NodeIdentityPub()+32,local.begin());
				if(envelope.header.type==ese::wire::kEseWireUdpProbe) {
					valid=ese::control::BuildChallenge(*m_directCookieAuthority,*m_directChallengeLimit,packet.peer,local,
						responder->peer,packet.bytes.data(),packet.size,now,response);
					if(valid) {
						ese::control::Probe probe; ese::control::Challenge challenge;
						ese::control::Envelope issued;
						valid=ese::control::Decode(envelope.payload,envelope.payloadSize,probe) &&
							ese::control::ParseUntrusted(response.bytes.data(),response.size,issued) &&
							ese::control::Decode(issued.payload,issued.payloadSize,challenge) &&
							responder->challenge.Remember(envelope.header,probe,challenge,now,responder->deadline);
					}
				} else if(envelope.header.type==ese::wire::kEseWireUdpProve) {
					ese::control::Prove proof;
					const bool correlated=ese::control::Decode(envelope.payload,envelope.payloadSize,proof) &&
						responder->challenge.Matches(envelope.header,proof,now);
					auto admission=correlated
						? ese::control::AdmitProve(*m_directCookieAuthority,*m_directControlSessions,packet.peer,
							local,responder->peer,packet.bytes.data(),packet.size,now,proof)
						: ese::control::Admission::Rejected;
					if(correlated && admission==ese::control::Admission::Rejected &&
						ese::control::VerifyProve(*m_directCookieAuthority,packet.peer,local,responder->peer,
							packet.bytes.data(),packet.size,now,proof)) {
						std::array<std::uint8_t,32> digest{}; const auto crypto=MakeKad6HostCryptoHooks();
						if(crypto.sha256 && crypto.sha256(packet.bytes.data(),packet.size,digest.data()))
							admission=m_directControlSessions->ReadmitFreshVerified(responder->peer,packet.peer,
								envelope.header,digest,responder->challenge.Issued(),now);
					}
					if(admission==ese::control::Admission::Accepted || admission==ese::control::Admission::Duplicate) {
						class PersistentSigner final : public ese::control::Signer {
							bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
								return eSELive::NodeIdentitySign(p,n,out.data());
							}
						} signer;
						std::uint8_t selected=0;
						if((proof.probe.mask&4) && responder->dataSubscriber && !responder->dataPreparationAttempted)
							PrepareConsentedDirectQuicResponder(*responder,envelope.header,now);
						const auto consent=responder->dataSubscriber ? m_directSubscribers->Resolve(responder->dataSubscriber) : std::nullopt;
						const bool consentCurrent=!responder->dataSubscriber || (consent && !consent->terminal_reason && consent->attempt &&
							consent->attempt->slot==responder->dataAttempt.slot && consent->attempt->generation==responder->dataAttempt.generation);
						if(consentCurrent && (proof.probe.mask&4) && responder->dataRoute && m_builtinQuicConsumer &&
							m_builtinQuicConsumer->PreparedServerRoute(responder->dataAttempt,responder->dataRoute,
								responder->peer,responder->endpoint,envelope.header.attempt,now)) selected=4;
						if(selected==4 && !RetainDirectControlDownload(responder->dataAttempt,responder->peer,
							responder->endpoint,envelope.header,now)) selected=0;
						valid=ese::control::BuildAck(proof,envelope.header,selected,local,signer,response);
					}
				}
			}
			if(valid) m_quicHost->SendControl(packet.peer,{response.bytes.data(),response.size});
			else if(m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedDirectControlReplies;
			continue; // never reinterpret a responder packet as a client reply
		}
		if(m_directBootstrap && packet.owner==m_directBootstrapOwner) {
			class PersistentSigner final : public ese::control::Signer {
				bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
					return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
				}
			} signer;
			const bool accepted=packet.receivedMs<=now && m_directBootstrap->Receive(packet.owner,packet.peer,packet.bytes.data(),packet.size,now,signer);
			if(!accepted && m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedDirectControlReplies;
			if(accepted &&
				m_directBootstrap->State()==ese::control::InitiatorState::Ready) {
				std::array<std::uint8_t,32> digest{}; const auto crypto=MakeKad6HostCryptoHooks();
				if(crypto.sha256 && crypto.sha256(packet.bytes.data(),packet.size,digest.data())) {
					const auto state=m_directConnections.Snapshot(m_directBootstrapDownload);
					auto result=state && state->state==reach::DirectSessionState::Recovering
						? m_directControlSessions->ReadmitVerified(m_directBootstrapPeer,m_directBootstrapEndpoint,m_directBootstrapContext,digest,now)
						: m_directControlSessions->AdmitVerified(m_directBootstrapPeer,m_directBootstrapEndpoint,m_directBootstrapContext,digest,now);
					if(state && state->state==reach::DirectSessionState::Recovering && result==ese::control::Admission::Rejected)
						result=m_directControlSessions->ReadmitFreshVerified(m_directBootstrapPeer,m_directBootstrapEndpoint,
							m_directBootstrapContext,digest,m_directBootstrapIssued,now);
					m_directBootstrapReady=result==ese::control::Admission::Accepted;
					if(m_directBootstrapReady && m_directBootstrapDownloadLifetime && m_directBootstrap->Selected()==4)
						m_directBootstrapReady=RetainDirectControlDownload(m_directBootstrapDownload,m_directBootstrapPeer,
							m_directBootstrapEndpoint,m_directBootstrapContext,now);
					if(m_directBootstrapReady && m_directBootstrapDownloadLifetime && m_directBootstrap->Selected()==4)
						m_directBootstrapDataUntil=now+15000;
				}
				if(!m_directBootstrapReady) CancelDirectControlBootstrap();
			}
			continue;
		}
		if(m_directResolutionHost && m_directResolutionHost->OwnsFind(packet.owner)) {
			ese::discovery::FindResultView result;
			ese::control::Kad6FindContacts contacts(MakeKad6HostCryptoHooks(),m_resolutionDirectIndexBit,
				utc>0 ? static_cast<std::uint64_t>(utc) : 0);
			const bool accepted=packet.receivedMs<=now && m_directResolutionHost->ReceiveFind(packet.owner,
				*m_directControlSessions,packet.peer,packet.bytes.data(),packet.size,now,result,&contacts);
			if(accepted && result.kind==1) for(unsigned i=0;i<result.count;++i) {
				kad6::K6RouterRecord record; std::size_t consumed=0;
				if(kad6::DecodeK6RouterRecord(result.entries[i].bytes,result.entries[i].size,record,&consumed)!=kad6::Kad6Status::Ok ||
					consumed!=result.entries[i].size) continue;
				ese::discovery::Kad6Lookup::Contact learned; learned.node=record.node_pub; learned.id=record.kad_id;
				if(m_directResolution->Lookup().ContainsValidated(learned)) continue;
				if(ImportDirectKad6Contact(record.node_pub,result.entries[i].bytes,result.entries[i].size) &&
					m_directResolution->Lookup().AddValidatedRecord(learned,now)) {
					// Current shared MFC port is IPv4; never fabricate IPv6 reachability.
					for(const auto& endpoint:record.endpoints) if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
						(endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port) {
						for(auto& pending:m_resolutionLearned) if(!pending.used && !pending.tried) {
							pending.node=record.node_pub; pending.endpoint.port=endpoint.udp_port;
							std::copy(endpoint.addr.addr.begin(),endpoint.addr.addr.begin()+4,pending.endpoint.address.begin());
							pending.used=true; break;
						}
						break;
					}
				}
				// Signed capability grants probation only, never return verification.
			}
			if(!accepted && m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedDirectControlReplies;
			continue;
		}
		if(m_directResolutionHost && m_directResolutionHost->OwnsGet(packet.owner)) {
			ese::discovery::Kad6Resolution::ResolvedCandidate candidate;
			const bool accepted=m_directResolvedCount<m_directResolved.size() && packet.receivedMs<=now &&
				m_directResolutionHost->ReceiveResolved(packet.owner,*m_directControlSessions,packet.peer,
					packet.bytes.data(),packet.size,now,candidate);
			if(accepted) {
				for(unsigned i=0;i<m_resolutionAutomaticGetHistoryCount;++i)
					if(SameResolutionSource(m_resolutionAutomaticGetHistory[i].source,candidate.source))
						m_resolutionAutomaticGetHistory[i].completed=true;
				m_directResolved[m_directResolvedCount++]=std::move(candidate);
                m_kad6DiscoveryStatus.Resolved();
			}
			else if(m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) ++m_rejectedDirectControlReplies;
			continue;
		}
		if(!m_kad6DirectContacts || utc<=0 || packet.receivedMs>now) continue;
		if(m_directContactRefreshReplies->Receive(packet.owner,*m_kad6DirectContacts,*m_directControlSessions,
			packet.peer,packet.bytes.data(),packet.size,now,MakeKad6HostCryptoHooks(),static_cast<std::uint64_t>(utc))) {
			m_kad6DirectContactsChanged=true; m_quicHost->RemoveControlReplies(packet.owner);
            for(auto& learned:m_resolutionLearned) if(learned.used && learned.refreshOwner==packet.owner) {
                // AddWitness still rechecks freshness, cap and the exact live
                // bootstrap session. A changed endpoint requires a new proof.
                kad6::K6RouterRecord refreshed;
                bool sameEndpoint=false;
                if(FreshDirectKad6Contact(learned.node,refreshed))
                    for(const auto& ep:refreshed.endpoints)
                        if(ep.addr.family==kad6::Kad6Address::Family::IPv4 && (ep.transport_flags&kad6::kK6EpUdpKad6) &&
                            ep.udp_port==learned.endpoint.port && std::equal(ep.addr.addr.begin(),ep.addr.addr.begin()+4,learned.endpoint.address.begin()))
                            sameEndpoint=true;
                learned.refreshOwner=0; learned.needsRefresh=false;
                if(!sameEndpoint || !(refreshed.caps&m_resolutionDirectIndexBit)) {
                    if(learned.owner==m_directBootstrapOwner) CancelDirectControlBootstrap();
                    learned.used=false;
                }
            }
		} else if(m_rejectedDirectControlReplies!=(std::numeric_limits<uint64>::max)()) {
			++m_rejectedDirectControlReplies;
		}
	}
	PumpDirectQuicDownloadHandoff();
	PumpDirectKad6AutomaticGets();
	PumpDirectKad6LearnedBootstrap();
	PumpDirectKad6AutomaticFinds();
    PumpKad6Publication();
}

bool CDirectReachabilityManager::AdoptQuicHost(std::unique_ptr<ese::QuicSessionHost>& host)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !host || m_quicHost)
		return false;
	m_quicHost = std::move(host);
	return true;
}

void CDirectReachabilityManager::ShutdownQuicHost()
{
	AssertMainThread();
	CancelDirectKad6Resolution();
	CancelDirectControlBootstrap();
	for(auto& grant:m_uploadControlGrants) RetireDirectUploadAuthorization(grant);
	m_isolatedLanQuicPolicy.reset(); m_isolatedLanQuicUntil=0;
	m_directResponders={}; // cookie secret/challenge budget persist across restart
	for(auto& entry:m_retainedControlDownloads) if(entry.owner) m_directControlSessions->ReleaseDownload(entry.owner);
	m_retainedControlDownloads={};
	if (!m_quicHost) return;
	if (::GetCurrentThreadId() != m_dwOwnerThreadId) std::terminate();
	*m_directContactRefreshReplies=ese::discovery::ContactRefreshReplies{};
	*m_directControlSessions=ese::control::Sessions{};
	m_quicHost->Stop();
	// Shutdown only: update coordinator state but do not execute network actions.
	// Draining global events makes room for at most 256*4 retained local events.
	PumpDirectEvents();
	m_quicHost->Poll(MonotonicMilliseconds());
	PumpDirectEvents();
	m_quicHost->RetireClosed();
	if (!m_quicHost->Empty()) std::terminate(); // never destroy pending owners
    RetireKad6IndexService();
    CancelKad6Publication();
	m_quicHost.reset();
	m_quicOwners = ese::QuicRouteOwners{};
	m_directPartContributions->Clear();
	for(auto& pending:*m_pendingDirectVerifications) pending={};
}

bool CDirectReachabilityManager::EnableNativeQuicLab()
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || m_quicHost
		|| !thePrefs.IsEseNetLabActive() || !eSELive::NodeIdentityIsPersistent()
		|| theApp.clientudp == NULL || theApp.clientudp->GetConnectedPort() == 0)
		return false;
	try {
		if(!m_directConsumer && !InstallQuicDownloadConsumer()) return false;
		auto host = ese::CreateQuicSessionHost(
			*theApp.clientudp, m_directBuffers, m_directEvents, m_directControlBudget);
		return AdoptQuicHost(host);
	} catch (...) {
		return false;
	}
}

uint64 CDirectReachabilityManager::BeginNativeQuicLab(const ese::NativeQuicConfig& native,
	const ese::QuicPeerConfig& peer, reach::DirectHandle handle,
	const reach::DirectSessionRoute& route)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !m_quicHost
		|| !thePrefs.IsEseNetLabActive() || theApp.clientudp == NULL) return 0;
	const auto attempt = m_directConnections.Snapshot(handle);
	const auto* node = eSELive::NodeIdentityPub();
	if (!attempt || !node) return 0;
	ese::QuicHostStartContext context;
	std::copy(node, node + context.localNode.size(), context.localNode.begin());
	context.persistent = eSELive::NodeIdentityIsPersistent();
	context.boundPort = theApp.clientudp->GetConnectedPort();
	context.topology = GetTopologyGeneration();
	context.now = MonotonicMilliseconds();
	if (!ese::ValidQuicHostStart(native, peer, route, *attempt, context)
		|| !m_directConnections.AuthorizesStart(handle, route, peer.sessionEpoch)) return 0;
	if (!m_quicOwners.Reserve(handle, route.id, peer.sessionEpoch)) return 0;
	uint64 owner = 0;
	try { owner = m_quicHost->Begin(native, peer, handle, route); }
	catch (...) { m_quicOwners.CancelReservation(handle, route.id); return 0; }
	if (!owner) { m_quicOwners.CancelReservation(handle, route.id); return 0; }
	if (!m_quicOwners.Bind(handle, route.id, owner)) std::terminate(); // broken owner identity contract
	if (auto* transport = m_quicHost->Find(owner)) transport->SetReceiveBudget(64 * 1024);
	return owner;
}

ese::QuicTransport* CDirectReachabilityManager::FindNativeQuicLab(uint64 owner)
{
	AssertMainThread();
	return ::GetCurrentThreadId() == m_dwOwnerThreadId && m_quicHost ? m_quicHost->Find(owner) : nullptr;
}

bool CDirectReachabilityManager::ReleaseNativeQuicLab(uint64 owner)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !m_quicHost || !m_quicHost->Release(owner)) return false;
	m_quicOwners.Erase(owner);
	return true;
}

// The route registry includes reservations and retained terminal owners.
// Event queue must be empty for this generation before allowing slot reuse.

bool CDirectReachabilityManager::ReleaseNativeQuicAttempt(reach::DirectHandle handle)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId) return false;
	if(!ese::ReleaseQuicAttempt(m_directConnections, m_quicOwners, m_directEvents, handle)) return false;
	m_directPartContributions->DiscardHandle(handle);
	for(auto& pending:*m_pendingDirectVerifications)
		if(pending.source.handle.slot==handle.slot && pending.source.handle.generation==handle.generation) pending={};
	return true;
}

bool CDirectReachabilityManager::ReleaseDirectAttempt(reach::DirectHandle handle,reach::DirectRouteDispatch& dispatch)
{
	AssertMainThread();
	if (::GetCurrentThreadId()!=m_dwOwnerThreadId || m_quicOwners.HasHandle(handle)) return false;
	if(!ese::ReleaseDirectAttempt(m_directConnections,dispatch,m_directEvents,handle)) return false;
	m_directPartContributions->DiscardHandle(handle);
	for(auto& pending:*m_pendingDirectVerifications)
		if(pending.source.handle.slot==handle.slot && pending.source.handle.generation==handle.generation) pending={};
	return true;
}

bool CDirectReachabilityManager::AdoptNativeQuicWinner(uint64 owner, reach::DirectHandle handle)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !m_quicHost) return false;
	const auto attempt = m_directConnections.Snapshot(handle);
	if (!attempt || attempt->state != reach::DirectSessionState::Ready || !attempt->winner)
		return false;
	const auto* node = eSELive::NodeIdentityPub();
	if (!thePrefs.IsEseNetLabActive() || !eSELive::NodeIdentityIsPersistent() || !node)
		return false;
	auto* transport = m_quicHost->Find(owner);
	const auto* binding = m_quicOwners.Find(handle, attempt->winner);
	if (!binding || binding->owner != owner || !transport) return false;
	if (!transport->AdoptWinner(handle, attempt->winner, attempt->epoch)) return false;
	if (!m_quicOwners.Adopt(owner, attempt->epoch)) std::terminate();
	return true;
}

natmap::Endpoint CDirectReachabilityManager::MakePublicV4(uint32 nNetworkOrderIP,
	uint16 nPort, natmap::EndpointSource source)
{
	const uint8* bytes = reinterpret_cast<const uint8*>(&nNetworkOrderIP);
	return natmap::Endpoint{
		natmap::IpAddress::V4(bytes[0], bytes[1], bytes[2], bytes[3]),
		nPort, source};
}

const ese::binding::Hello* CDirectReachabilityManager::ValidateNativeQuicDelivery(uint64 owner,
	reach::DirectHandle handle, uint32 route, uint64 epoch)
{
	AssertMainThread();
	if (::GetCurrentThreadId() != m_dwOwnerThreadId || !m_quicHost || !thePrefs.IsEseNetLabActive()) return nullptr;
	const auto attempt = m_directConnections.Snapshot(handle);
	const auto* binding = m_quicOwners.Find(handle, route);
	if (!attempt || !binding || binding->owner != owner || binding->epoch != epoch ||
		attempt->winner != route || attempt->epoch != epoch ||
		(attempt->state != reach::DirectSessionState::Ready && attempt->state != reach::DirectSessionState::Transferring)) return nullptr;
	auto* transport = m_quicHost->Find(owner);
	return transport && transport->AllowsDelivery(handle, route, epoch) ? transport->BoundPeer() : nullptr;
}

CClientReqSocket* CDirectReachabilityManager::ValidateLegacyDirectPartDelivery(const reach::DirectPartContributor& source)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		source.kind!=reach::DirectPartOwnerKind::Legacy || !source.owner ||
		source.topology!=GetTopologyGeneration() || !theApp.clientlist) return nullptr;
	const auto lifetime=DirectTransferClientLifetime(source.handle);
	if(!lifetime || *lifetime!=source.owner || !HasDirectTransferSubscription(source.owner,source.handle)) return nullptr;
	auto* original=theApp.clientlist->FindClientByLifetime(source.owner);
	if(!original || !original->socket) return nullptr;
	auto* socket=original->socket;
	const auto current=socket->LegacyDirectPartContributor();
	if(!current || current->owner!=source.owner || current->handle.slot!=source.handle.slot ||
		current->handle.generation!=source.handle.generation || current->route!=source.route ||
		current->epoch!=source.epoch || current->topology!=source.topology) return nullptr;
	return socket;
}

bool CDirectReachabilityManager::RecordDirectPartContribution(const reach::DirectFileKey& file,
	uint32 part,const reach::DirectPartContributor& source,uint64 bytes)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || source.topology!=GetTopologyGeneration()) return false;
	if(source.kind==reach::DirectPartOwnerKind::Legacy) {
		auto* socket=ValidateLegacyDirectPartDelivery(source);
		auto* requested=socket && socket->client ? socket->client->GetRequestFile() : nullptr;
		if(!requested) return false;
		const auto current=requested->NativeDirectFileKey();
		if(current.lifetime!=file.lifetime || current.hash!=file.hash) return false;
	} else if(source.kind!=reach::DirectPartOwnerKind::Quic ||
		!ValidateNativeQuicDelivery(source.owner,source.handle,source.route,source.epoch)) return false;
	std::size_t pendingCount=0;
	for(const auto& pending:*m_pendingDirectVerifications) if(pending.revision) ++pendingCount;
	if(!m_directPartContributions->Contains(file,part,source) &&
		m_directPartContributions->Size()+pendingCount>=reach::DirectPartContributions::Capacity) return false;
	return m_directPartContributions->Record(file,part,source,bytes);
}

std::vector<reach::DirectPartReceipt> CDirectReachabilityManager::SnapshotDirectPartContributions(
	const reach::DirectFileKey& file,uint32 part,uint64 hashGeneration) const
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return {};
	return m_directPartContributions->Snapshot(file,part,hashGeneration);
}

void CDirectReachabilityManager::DiscardDirectFileContributions(const reach::DirectFileKey& file) noexcept
{
	AssertMainThread();
	if(::GetCurrentThreadId()==m_dwOwnerThreadId) m_directPartContributions->DiscardFile(file);
	// Already checked, value-owned proofs describe a past event. Deleting the
	// file object does not undo that event; delivery still fences the session.
}

void CDirectReachabilityManager::InvalidateDirectPartRange(const reach::DirectFileKey& file,
	uint32 first,uint32 last,bool discard) noexcept
{
	AssertMainThread();
	if(::GetCurrentThreadId()==m_dwOwnerThreadId) m_directPartContributions->InvalidateRange(file,first,last,discard);
}

bool CDirectReachabilityManager::AcceptDirectPartVerification(const reach::DirectPartReceipt& receipt,
	uint64 hashGeneration,reach::PartVerification proof)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
	for(auto& pending:*m_pendingDirectVerifications) if(!pending.revision) {
		const auto accepted=m_directPartContributions->TakeVerified(receipt,hashGeneration,proof);
		if(!accepted) return false;
		pending=*accepted; return true; // retain owned proof until transport accepts it
	}
	return false; // full: do not consume provenance
}

void CDirectReachabilityManager::PumpDirectPartVerifications()
{
	for(auto& pending:*m_pendingDirectVerifications) if(pending.revision) {
		const auto& source=pending.source;
		if(source.kind==reach::DirectPartOwnerKind::Legacy) {
			auto* socket=ValidateLegacyDirectPartDelivery(source);
			if(!socket || socket->ReportLegacyVerifiedPart()) pending={};
			continue;
		}
		auto* transport=FindNativeQuicLab(source.owner);
		if(source.kind!=reach::DirectPartOwnerKind::Quic || source.topology!=GetTopologyGeneration() || !transport ||
			!ValidateNativeQuicDelivery(source.owner,source.handle,source.route,source.epoch)) {
			pending={}; continue;
		}
		if(transport->HasReportedVerifiedPart() || transport->ReportVerifiedPart(reach::PartVerification::Verified))
			pending={}; // first-part milestone is single-use per session
	}
}

bool CDirectReachabilityManager::BuildMappedPlane(natmap::PlaneSnapshot& plane,
	natmap::MapperKind mapper, natmap::Transport transport,
	const natmap::Endpoint& local, const natmap::Endpoint& external,
	uint32 nLifetimeSeconds, uint32 nMapperEpoch, uint64 nGeneration)
{
	plane.local = local;
	natmap::TransitionResult result = natmap::ApplyEvent(plane,
		natmap::StateEvent{natmap::EventType::BeginGeneration, nGeneration});
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;
	result = natmap::ApplyEvent(plane,
		natmap::StateEvent{natmap::EventType::MappingStarted, nGeneration});
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;

	natmap::StateEvent mapped;
	mapped.type = natmap::EventType::MappingSucceeded;
	mapped.generation = nGeneration;
	mapped.lease.mapper = mapper;
	mapped.lease.transport = transport;
	mapped.lease.local = local;
	mapped.lease.public_endpoint = external;
	mapped.lease.requested_external_port = local.port;
	mapped.lease.granted_external_port = external.port;
	mapped.lease.lifetime_seconds = nLifetimeSeconds;
	mapped.lease.mapper_epoch = nMapperEpoch;
	mapped.lease.generation = nGeneration;
	mapped.lease.owned_by_us = true;
	result = natmap::ApplyEvent(plane, mapped);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;
	return true;
}

void CDirectReachabilityManager::AssertMainThread() const
{
	ASSERT(m_dwOwnerThreadId == ::GetCurrentThreadId());
}

reach::DirectCoordinator& CDirectReachabilityManager::DirectConnections()
{
	AssertMainThread();
	return m_directConnections;
}

uint64 CDirectReachabilityManager::AcquireDirectSubscriber(uint64 lifetime,reach::DirectConsumerKind consumer)
{
	AssertMainThread();
	if(m_pendingSubscriberRetirementCount) return 0; // drain before admitting new lifetimes
	return m_directSubscribers->Acquire(lifetime,consumer);
}

std::optional<reach::DirectSubscriber> CDirectReachabilityManager::ResolveDirectSubscriber(uint64 token) const
{
	AssertMainThread();
	return m_directSubscribers->Resolve(token);
}

reach::DirectCoordinatorBatch CDirectReachabilityManager::RetireDirectSubscriber(uint64 token)
{
	AssertMainThread();
	const auto retired=m_directSubscribers->Remove(token);
	return retired && retired->attempt ? m_directConnections.Unsubscribe(*retired->attempt,token)
		: reach::DirectCoordinatorBatch{};
}

bool CDirectReachabilityManager::ResetConsumedDirectSubscriber(uint64 token,uint64 lifetime)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
	const auto record=m_directSubscribers->Resolve(token);
	if(!record || record->client_lifetime!=lifetime || !record->terminal_reason || !record->terminal_taken
		|| (record->attempt && m_directConnections.Snapshot(*record->attempt))) return false;
	// Released attempt has no adapter/action ownership left. Never unsubscribe
	// a live generation or silently discard an unread terminal notification.
	return m_directSubscribers->Remove(token).has_value();
}

bool CDirectReachabilityManager::HasDirectTransferSubscription(uint64 lifetime,reach::DirectHandle handle) const
{
	AssertMainThread();
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && m_directSubscribers->HasTransferBinding(lifetime,handle);
}

std::optional<uint64> CDirectReachabilityManager::DirectTransferClientLifetime(reach::DirectHandle handle) const
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return std::nullopt;
	return m_directSubscribers->TransferLifetime(handle);
}

void CDirectReachabilityManager::RetireDirectClient(uint64 lifetime) noexcept
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) std::terminate();
	for(auto& entry:m_directTcpObservations) if(entry.lifetime==lifetime) entry={};
	while(const auto record=m_directSubscribers->FindLifetime(lifetime)) {
		if(record->attempt) {
			// Acquire is fenced while any retirement is pending. Thus every
			// live record has a reserved slot, without destructor allocation.
			if(m_pendingSubscriberRetirementCount==m_pendingSubscriberRetirements.size()) std::terminate();
			m_pendingSubscriberRetirements[m_pendingSubscriberRetirementCount++]={record->token,*record->attempt};
		}
		m_directSubscribers->Remove(record->token);
	}
}

reach::NativeDirectRequestResult CDirectReachabilityManager::RequestDirectConnection(
	const reach::NativeDirectCandidateSnapshotV1& snapshot,uint64 sourceRecordId,
	uint64 sourceEpoch,uint64 subscriber)
{
	AssertMainThread();
	SynchronizeLocalSocketBindings();
	reach::NativeDirectRequestResult result;
	const uint64 generation=m_topologyGenerationExhausted ? 0 : m_snapshot.topology_generation;
	result.snapshot_status=reach::ValidateNativeSnapshot(snapshot,generation);
	if(result.snapshot_status!=reach::NativeSnapshotStatus::Ok) return result;
	const auto registration=m_directSubscribers->Resolve(subscriber);
	const auto peer=reach::NativeDirectPeerKey(snapshot.peer,sourceRecordId,sourceEpoch);
	if(!registration || !peer) return result;
	if(registration->attempt) {
		const auto existing=m_directConnections.Snapshot(*registration->attempt);
		if(!existing || existing->peer.domain!=peer->domain || existing->peer.identity!=peer->identity
			|| existing->peer.source_record_id!=peer->source_record_id || existing->peer.source_epoch!=peer->source_epoch)
			return result; // no mutation of a subscription bound to another peer
	}
	reach::DirectAttemptId attempt{};
	const auto crypto=MakeKad6HostCryptoHooks();
	if(!crypto.random_bytes || !crypto.random_bytes(attempt.data(),attempt.size())) return result;
	result=reach::RequestNativeDirect(m_directConnections,snapshot,generation,
		sourceRecordId,sourceEpoch,subscriber,attempt,MonotonicMilliseconds());
	if(result.request.status==reach::DirectRequestStatus::Created || result.request.status==reach::DirectRequestStatus::Joined) {
		const bool bound=m_directSubscribers->Bind(subscriber,result.request.handle);
		ASSERT(bound); // main-thread preflight above prevents a conflicting binding
	}
	return result;
}

reach::NativeDirectRequestResult CDirectReachabilityManager::RequestSharedDirectControlAttempt(
	uint64 subscriber,const ese::control::Header& context,const ese::udp::Endpoint& endpoint)
{
	AssertMainThread();
	reach::NativeDirectRequestResult rejected;
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() ||
		!m_quicHost || !theApp.clientlist || m_pendingSubscriberRetirementCount || m_directPump.Busy()) return rejected;
	const auto registration=m_directSubscribers->Resolve(subscriber);
	if(!registration || registration->terminal_reason ||
		(registration->consumer!=reach::DirectConsumerKind::Download && registration->consumer!=reach::DirectConsumerKind::Upload)) return rejected;
	auto* client=theApp.clientlist->FindClientByLifetime(registration->client_lifetime);
	if(!client) return rejected;
	const auto now=MonotonicMilliseconds();
	const auto generation=GetTopologyGeneration();
	const auto snapshot=client->NativeDirectCandidates(generation,now+15000);
	if(!snapshot.peer.expected_node_pub || !m_directControlSessions->Current(
		*snapshot.peer.expected_node_pub,endpoint,context,now)) return rejected;
	if(registration->attempt) {
		const auto existing=m_directConnections.Snapshot(*registration->attempt);
		if(!existing || existing->peer.domain!=reach::DirectPeerDomain::NodePublicKey ||
			existing->peer.identity!=*snapshot.peer.expected_node_pub || existing->attempt_id!=context.attempt) return rejected;
	}
	const auto result=reach::RequestNativeDirectShared(m_directConnections,snapshot,generation,
		subscriber,context.attempt,now);
	if(result.request.status==reach::DirectRequestStatus::Created || result.request.status==reach::DirectRequestStatus::Joined) {
		const bool bound=m_directSubscribers->Bind(subscriber,result.request.handle);
		ASSERT(bound);
	}
	return result;
}

std::vector<reach::DirectCoordinatorBatch> CDirectReachabilityManager::PumpDirectEvents()
{
	AssertMainThread();
	std::vector<reach::DirectCoordinatorBatch> retiredBatches;
	retiredBatches.reserve(m_pendingSubscriberRetirementCount);
	// No user callback is executed by client destruction. Queue owns only
	// scalar token/handle; process retirement before considering late events.
	while(m_pendingSubscriberRetirementCount) {
		const auto pending=m_pendingSubscriberRetirements[m_pendingSubscriberRetirementCount-1];
		auto batch=m_directConnections.Unsubscribe(pending.handle,pending.token);
		if(!batch.actions.empty()) retiredBatches.push_back(std::move(batch));
		m_pendingSubscriberRetirements[--m_pendingSubscriberRetirementCount]={};
	}
	// Drain releases the queue lock before the coordinator processes events.
	// Invalidate before processing queued events: an old delivery cannot win
	// against a topology change committed since the previous tick.
	auto batches = (m_snapshot.topology_generation || m_topologyGenerationExhausted)
		? m_directConnections.InvalidateTopology(m_topologyGenerationExhausted ? 0 : m_snapshot.topology_generation)
		: std::vector<reach::DirectCoordinatorBatch>{};
	const auto now=MonotonicMilliseconds();
    auto events=m_directEvents.Drain();
    if(m_authenticatedProvisionalPeerCount) {
        std::vector<reach::DirectSessionEvent> authentication;
        for(auto it=events.begin();it!=events.end();) {
            if(it->type==reach::DirectEventType::Authenticated) {
                authentication.push_back(*it); it=events.erase(it);
            } else ++it;
        }
        // Connected and terminal events establish/fence route state first.
        // Authentication stays deferred until redundant ownership is retired.
        auto before=m_directConnections.AdvanceAll(now,events);
        for(auto& batch:before) batches.push_back(std::move(batch));
        for(std::size_t i=0;i<m_authenticatedProvisionalPeerCount;++i) {
            const auto pending=m_authenticatedProvisionalPeers[i];
            m_authenticatedProvisionalPeers[i]={};
            const bool hasProof=std::any_of(authentication.begin(),authentication.end(),[&](const auto& event) {
                return event.handle.slot==pending.handle.slot && event.handle.generation==pending.handle.generation &&
                    event.route_id==pending.route && event.session_epoch==pending.epoch;
            });
            if(!hasProof) continue;
            const auto resolved=m_directConnections.ResolveAuthenticatedPeer(pending.handle,pending.route,pending.epoch,pending.peer);
            if(resolved.status==reach::DirectIdentityResolution::Merged) {
                if(!m_directSubscribers->RebindMerged(pending.handle,resolved.destination,resolved.moved_subscribers)) {
                    batches.push_back(m_directConnections.Cancel(resolved.destination,reach::DirectReason::ResourceLimit));
                    batches.push_back(resolved.retired); // destination terminal owns the moved notifications
                } else batches.push_back(resolved.retired);
            } else if(resolved.status==reach::DirectIdentityResolution::ResourceLimit ||
                resolved.status==reach::DirectIdentityResolution::Rejected) {
                batches.push_back(m_directConnections.Cancel(pending.handle,
                    resolved.status==reach::DirectIdentityResolution::ResourceLimit ? reach::DirectReason::ResourceLimit : reach::DirectReason::IdentityMismatch));
            }
        }
        m_authenticatedProvisionalPeerCount=0;
        events=std::move(authentication);
    }
	auto advanced=m_directConnections.AdvanceAll(now, events);
	for(auto& batch:retiredBatches) batches.push_back(std::move(batch));
	for(auto& batch:advanced) batches.push_back(std::move(batch));
	// Execute only registered QUIC lifecycle actions. Start still requires peer
	// configuration from the source/client adapter; other transports are untouched.
	if (m_quicHost) ese::ApplyQuicDcoActions(m_directConnections, m_quicOwners, batches,
		[this](uint64 owner) { return m_quicHost->Find(owner); },
		[this](uint64 owner, reach::DirectHandle handle) { return AdoptNativeQuicWinner(owner, handle); });
    // Capture terminal transitions before consumers release their DCO slots.
    PublishDirectDiagnostics();
	return batches;
}

void CDirectReachabilityManager::Initialize(uint16 nLocalTcpPort, uint16 nLocalUdpPort)
{
	AssertMainThread();
	m_classicCallbackProof.Reset();
    m_kad6PublicContactProof.Reset();
    m_nextKad6PublicContactRecheck=0;
	m_nextClassicCallbackRecheck=0;
	m_mapperResults->DiscardAll();
	uint64 generation=0;
	if(!natmap::NextTopologyGeneration(m_snapshot.topology_generation,generation)) {
		m_topologyGenerationExhausted=true;
		generation=m_snapshot.topology_generation; // exhausted: retain fence, stay disabled
	}
	m_directContactRefreshReplies->CancelAll([this](uint64 owner) {
		if(m_quicHost) m_quicHost->RemoveControlReplies(owner);
	});
	*m_directControlSessions=ese::control::Sessions{};
	m_bEnabled.store(false, std::memory_order_release);
	m_nLocalTcpPort.store(nLocalTcpPort, std::memory_order_release);
	m_nLocalUdpPort.store(nLocalUdpPort, std::memory_order_release);
	m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
	m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_snapshot = natmap::ReachabilitySnapshot{};
	m_snapshot.topology_generation = generation;

	m_snapshot.ed2k_tcp_v4.state = natmap::ReachabilityState::Disabled;
	m_snapshot.ed2k_tcp_v4.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.ed2k_tcp_v4.local = MakeAnyV4(nLocalTcpPort);
	m_snapshot.ed2k_tcp_v4.advertised = m_snapshot.ed2k_tcp_v4.local;
	m_snapshot.ed2k_tcp_v4.generation = generation;

	m_snapshot.kad_udp_v4.state = natmap::ReachabilityState::Disabled;
	m_snapshot.kad_udp_v4.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.kad_udp_v4.local = MakeAnyV4(nLocalUdpPort);
	m_snapshot.kad_udp_v4.advertised = m_snapshot.kad_udp_v4.local;
	m_snapshot.kad_udp_v4.generation = generation;

	m_snapshot.direct_v6.state = natmap::ReachabilityState::Disabled;
	m_snapshot.direct_v6.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.direct_v6.generation = generation;
}

uint16 CDirectReachabilityManager::GetLocalTcpPort() const
{
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetLocalUdpPort() const
{
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedTcpPort() const
{
	if (m_bEnabled.load(std::memory_order_acquire))
		return m_nAdvertisedTcpPort.load(std::memory_order_acquire);
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedUdpPort() const
{
	if (m_bEnabled.load(std::memory_order_acquire))
		return m_nAdvertisedUdpPort.load(std::memory_order_acquire);
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedV6TcpPort() const
{
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedV6UdpPort() const
{
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

const natmap::ReachabilitySnapshot& CDirectReachabilityManager::GetSnapshot() const
{
	AssertMainThread();
	return m_snapshot;
}

uint64 CDirectReachabilityManager::GetTopologyGeneration() const
{
	AssertMainThread();
	return m_snapshot.topology_generation;
}

natmap::UpstreamGatewayCandidates
CDirectReachabilityManager::GetUpstreamGatewayCandidates() const
{
	AssertMainThread();
	if (!m_tcpChain.NeedsUpstream())
		return natmap::UpstreamGatewayCandidates{};
	return natmap::BuildUpstreamGatewayCandidates(
		m_tcpChain.FinalEndpoint().address);
}

bool CDirectReachabilityManager::HasVerifiedEd2kReachability() const
{
	AssertMainThread();
	return m_snapshot.ed2k_tcp_v4.HasClassicHighIdEvidence();
}
ese::classic::CallbackTcpEndpoint CDirectReachabilityManager::CurrentClassicCallbackEndpoint(uint64 now) const
{
    ese::classic::CallbackTcpEndpoint endpoint;
    if(!IsEnabled() || !m_tcpChain.IsComplete() || !m_tcpLease.HasLease() || m_tcpLease.IsExpired(now) ||
        now<m_tcpLease.timing().acquired_monotonic_ms || now>(std::numeric_limits<uint64>::max)()-180000)
        return endpoint;
    const auto mapped=m_tcpChain.FinalEndpoint();
    if(mapped.address.family!=natmap::AddressFamily::IPv4 || !mapped.IsUsable() ||
        mapped.port!=GetAdvertisedTcpPort() || m_tcpChain.generation()!=GetTopologyGeneration()) return endpoint;
    std::copy(mapped.address.bytes.begin(),mapped.address.bytes.begin()+4,endpoint.address.begin());
    endpoint.localPort=GetLocalTcpPort(); endpoint.publicPort=mapped.port; endpoint.generation=GetTopologyGeneration();
    endpoint.until=m_tcpLease.lease().lifetime_seconds ? m_tcpLease.timing().expires_monotonic_ms : now+180000;
    return endpoint;
}
bool CDirectReachabilityManager::TryPublishQueuedKad6File(CKnownFile& file)
{
    AssertMainThread(); auto now=MonotonicMilliseconds();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !thePrefs.IsEseNetLabActive() || !Kademlia::CKademlia::IsKad6Running() ||
        !m_quicHost || m_kad6PublicationSize || m_directResolution || m_directBootstrapOwner || now<m_nextKad6Publication ||
        !m_kad6DirectContacts || !eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() ||
        !theApp.sharedfiles || theApp.sharedfiles->GetFileByID(file.GetFileHash())!=&file ||
        !file.GetFileSize() || file.GetFileSize()>MAX_EMULE_FILE_SIZE || now>(std::numeric_limits<uint64>::max)()-15000) return false;
    std::array<std::array<std::uint8_t,32>,64> hints{};
    const auto count=m_kad6DirectContacts->SnapshotHints(hints);
    std::array<std::uint8_t,16> fileHash{}, target{};
    memcpy(fileHash.data(),file.GetFileHash(),16);
    if(!ese::control::DirectIndexKey(fileHash,file.GetFileSize(),MAX_EMULE_FILE_SIZE,target)) return false;
    ese::discovery::NearestContacts<3> nearest(target);
    for(unsigned i=0;i<count;++i) {
        kad6::K6RouterRecord record;
        if(!FreshDirectKad6Contact(hints[i],record) || !(record.caps&ese::discovery::K6_CAP_DIRECT_INDEX_V1)) continue;
        for(const auto& endpoint:record.endpoints) if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
            (endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port) {
            nearest.Add(record.kad_id,record.node_pub,i); break;
        }
    }
    unsigned witnesses=0;
    for(unsigned position=0;position<nearest.Count();++position) {
        const unsigned i=nearest[position].ordinal;
        kad6::K6RouterRecord record;
        if(!FreshDirectKad6Contact(hints[i],record) || !(record.caps&ese::discovery::K6_CAP_DIRECT_INDEX_V1)) continue;
        for(const auto& endpoint:record.endpoints) if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
            (endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port) {
            auto& witness=m_kad6PublicationWitnesses[witnesses++]; witness.node=record.node_pub;
            witness.endpoint.port=endpoint.udp_port; witness.used=true;
            std::copy(endpoint.addr.addr.begin(),endpoint.addr.addr.begin()+4,witness.endpoint.address.begin()); break;
        }
    }
    if(!witnesses) return false;
    std::array<std::uint8_t,32> node{}; memcpy(node.data(),eSELive::NodeIdentityPub(),32);
    class PersistentSigner final : public ese::control::Signer {
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
        }
    } signer;
    uint64 serial=0;
    try {
        if(m_kad6PublicationSerialNode!=node) {
            m_kad6PublicationSerial.reset(); m_kad6PublicationSerialNode=node;
        }
        if(!m_kad6PublicationSerial) m_kad6PublicationSerial=std::make_unique<ese::discovery::PublicationSerial>();
        if(!m_kad6PublicationSerial->Ready()) {
            CString path=thePrefs.GetMuleDirectory(EMULE_CONFIGDIR); path+=_T("kad6-publication-");
            for(const auto byte:node) { CString hex; hex.Format(_T("%02x"),static_cast<unsigned>(byte)); path+=hex; }
            path+=_T(".seq");
            if(!m_kad6PublicationSerial->Initialize(path,node)) { CancelKad6Publication(); return false; }
        }
        if(!m_kad6PublicationSerial->Allocate(signer,serial)) { CancelKad6Publication(); return false; }
    } catch(...) { CancelKad6Publication(); return false; }
    // Durable allocation can block: lease bounds must use the time after the flush.
    now=MonotonicMilliseconds();
    if(now>(std::numeric_limits<uint64>::max)()-15000) { CancelKad6Publication(); return false; }
    std::array<ese::discovery::OwnedPublicationCandidate,2> candidates{}; unsigned routes=0;
    const auto tcp=CurrentClassicCallbackEndpoint(now);
    const auto tcpUntil=m_classicCallbackProof.VerifiedUntil(tcp,now);
    if(tcpUntil>now+1000) {
        auto& candidate=candidates[routes++]; candidate.endpoint.port=tcp.publicPort;
        std::copy(tcp.address.begin(),tcp.address.end(),candidate.endpoint.address.begin());
        candidate.transports=1; candidate.ttl=static_cast<std::uint32_t>((std::min)(uint64(30),(tcpUntil-now)/1000));
    }
    ese::discovery::PublicUdpContact udp;
    if(GetVerifiedKad6PublicContact(udp) && udp.until>now+1000) {
        auto& candidate=candidates[routes++]; candidate.endpoint.port=udp.publicPort;
        std::copy(udp.address.begin(),udp.address.end(),candidate.endpoint.address.begin());
        candidate.transports=4; candidate.ttl=static_cast<std::uint32_t>((std::min)(uint64(30),(udp.until-now)/1000));
    }
    std::array<std::uint8_t,16> userHash{},kadId{},hash{};
    memcpy(hash.data(),file.GetFileHash(),16); memcpy(userHash.data(),thePrefs.GetUserHash(),16);
    if(Kademlia::CKademlia::GetPrefs()) Kademlia::CKademlia::GetPrefs()->GetKadID().ToByteArray(kadId.data());
    if(!ese::discovery::BuildOwnedPublication(hash,file.GetFileSize(),GetTopologyGeneration(),serial,node,userHash,kadId,
        candidates,routes,30,signer,m_kad6PublicationDescriptor,m_kad6PublicationLength,m_kad6PublicationSource,MAX_EMULE_FILE_SIZE)) {
        CancelKad6Publication(); return false;
    }
    m_kad6PublicationFile=hash; m_kad6PublicationSize=file.GetFileSize();
    m_kad6PublicationTopology=GetTopologyGeneration(); m_kad6PublicationUntil=now+15000;
    m_nextKad6Publication=now+5000; return true;
}
void CDirectReachabilityManager::CancelKad6Publication()
{
    for(auto& witness:m_kad6PublicationWitnesses) {
        if(witness.replyOwner && m_quicHost) m_quicHost->RemoveControlReplies(witness.replyOwner);
        if(witness.bootstrapOwner && witness.bootstrapOwner==m_directBootstrapOwner) CancelDirectControlBootstrap();
        witness=PublicationWitness{};
    }
    m_kad6PublicationFile={}; m_kad6PublicationSize=0; m_kad6PublicationTopology=0; m_kad6PublicationUntil=0;
    m_kad6PublicationDescriptor={}; m_kad6PublicationSource={}; m_kad6PublicationLength=0;
}
void CDirectReachabilityManager::PumpKad6Publication()
{
    if(!m_kad6PublicationSize) return;
    const auto now=MonotonicMilliseconds();
    auto* file=theApp.sharedfiles ? theApp.sharedfiles->GetFileByID(m_kad6PublicationFile.data()) : nullptr;
    if(!thePrefs.IsEseNetLabActive() || !Kademlia::CKademlia::IsKad6Running() || !m_quicHost || !file ||
        file->GetFileSize()!=m_kad6PublicationSize || m_kad6PublicationTopology!=GetTopologyGeneration() ||
        now>=m_kad6PublicationUntil) { CancelKad6Publication(); return; }
    class PersistentSigner final : public ese::control::Signer {
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
        }
    } signer;
    bool allDone=true;
    for(auto& witness:m_kad6PublicationWitnesses) if(witness.used && !witness.done) {
        allDone=false;
        if(!witness.attempt) {
            if(!witness.bootstrapOwner) {
                if(m_directBootstrapOwner || m_directResolution) continue;
                kad6::K6RouterRecord fresh;
                bool sameEndpoint=false;
                if(FreshDirectKad6Contact(witness.node,fresh) && (fresh.caps&ese::discovery::K6_CAP_DIRECT_INDEX_V1))
                    for(const auto& endpoint:fresh.endpoints)
                        if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4 &&
                            (endpoint.transport_flags&kad6::kK6EpUdpKad6) && endpoint.udp_port==witness.endpoint.port &&
                            std::equal(endpoint.addr.addr.begin(),endpoint.addr.addr.begin()+4,witness.endpoint.address.begin()))
                            sameEndpoint=true;
                if(!sameEndpoint) { witness.done=true; continue; }
                witness.bootstrapOwner=BeginDirectControlBootstrap(witness.node,witness.endpoint,(std::min)(m_kad6PublicationUntil,now+2000));
                if(!witness.bootstrapOwner) witness.done=true;
                return;
            }
            if(witness.bootstrapOwner!=m_directBootstrapOwner) { witness.done=true; continue; }
            if(!DirectControlBootstrapReady(witness.bootstrapOwner)) continue;
            try { witness.attempt=std::make_unique<ese::discovery::PublicationAttempt>(); }
            catch(...) { witness.done=true; CancelDirectControlBootstrap(); continue; }
            if(!witness.attempt->Start(*m_directControlSessions,witness.node,witness.endpoint,m_directBootstrapContext,
                m_kad6PublicationDescriptor.data(),m_kad6PublicationLength,m_kad6PublicationSource,MAX_EMULE_FILE_SIZE,now,signer)) {
                witness.done=true; CancelDirectControlBootstrap(); continue;
            }
            CancelDirectControlBootstrap(); witness.bootstrapOwner=0;
        }
        if(!witness.attempt->Current(*m_directControlSessions,now)) { witness.done=true; continue; }
        if(witness.attempt->State()==ese::discovery::PublicationState::Restage) {
            if(!witness.attempt->Restage(*m_directControlSessions,now,signer)) continue;
            witness.descriptorSent=false; witness.nextSend=0; witness.sends=0;
        }
        if(!witness.replyOwner) {
            if(m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) { witness.done=true; continue; }
            witness.replyOwner=++m_nextDirectContactRefreshOwner;
            if(!m_quicHost->ExpectControlReply(witness.attempt->Request(),ese::wire::kEseWireUdpK6DirectPutResult,
                witness.endpoint,witness.replyOwner,witness.attempt->Deadline())) { witness.done=true; continue; }
        }
        if(!witness.descriptorSent) {
            const auto& desc=witness.attempt->DescriptorPacket();
            const auto result=m_quicHost->SendControl(witness.endpoint,{desc.bytes.data(),desc.size});
            if(result.status==ese::QuicUdpSendStatus::WouldBlock) continue;
            if(result.status!=ese::QuicUdpSendStatus::Sent) { witness.done=true; continue; }
            witness.descriptorSent=true;
        }
        if(now>=witness.nextSend && witness.sends<3) {
            const auto& source=witness.attempt->SourcePacket();
            const auto result=m_quicHost->SendControl(witness.endpoint,{source.bytes.data(),source.size});
            if(result.status==ese::QuicUdpSendStatus::WouldBlock) continue;
            if(result.status!=ese::QuicUdpSendStatus::Sent) { witness.done=true; continue; }
            ++witness.sends; witness.nextSend=now+500;
        }
    }
    if(allDone) CancelKad6Publication();
}
void CDirectReachabilityManager::RetireKad6IndexService()
{
    if(m_quicHost && m_kad6IndexOwner) m_quicHost->RetireControlService(m_kad6IndexOwner);
    m_kad6IndexOwner=0; m_kad6IndexTopology=0;
    m_kad6IndexBootstrap.reset(); m_kad6IndexReceiver.reset();
}
uint64 CDirectReachabilityManager::GetKad6ServiceCapabilities() const
{
    ese::discovery::PublicUdpContact contact;
    return m_kad6IndexOwner && m_kad6IndexTopology==GetTopologyGeneration() &&
        thePrefs.IsEseNetLabActive() && Kademlia::CKademlia::IsKad6Running() &&
        eSELive::NodeIdentityIsPersistent() && GetVerifiedKad6PublicContact(contact)
        ? ese::discovery::K6_CAP_DIRECT_INDEX_V1 : 0;
}
void CDirectReachabilityManager::SynchronizeKad6IndexService()
{
    ese::discovery::PublicUdpContact contact;
    if(!m_quicHost || !thePrefs.IsEseNetLabActive() || !Kademlia::CKademlia::IsKad6Running() ||
        !eSELive::NodeIdentityIsPersistent() || !eSELive::NodeIdentityPub() || !GetVerifiedKad6PublicContact(contact)) {
        RetireKad6IndexService(); return;
    }
    if(m_kad6IndexOwner && m_kad6IndexTopology==GetTopologyGeneration()) return;
    RetireKad6IndexService();
    if(m_nextDirectContactRefreshOwner==(std::numeric_limits<uint64>::max)()) return;
    try {
        auto bootstrap=std::make_unique<ese::discovery::Kad6IndexBootstrap>(m_directControlBudget);
        if(!bootstrap->Initialize()) return;
        auto receiver=std::make_unique<ese::discovery::Kad6IndexService<10000>>(m_directControlBudget);
        std::array<std::uint8_t,32> local{}; memcpy(local.data(),eSELive::NodeIdentityPub(),32);
        const auto owner=++m_nextDirectContactRefreshOwner;
        if(!m_quicHost->ActivateControlService(local,owner,GetTopologyGeneration())) return;
        m_kad6IndexBootstrap=std::move(bootstrap); m_kad6IndexReceiver=std::move(receiver);
        m_kad6IndexOwner=owner; m_kad6IndexTopology=GetTopologyGeneration();
    } catch(...) { RetireKad6IndexService(); }
}
bool CDirectReachabilityManager::ReceiveKad6IndexService(const ese::QuicUdpRouter::PendingControl& packet,uint64 now)
{
    if(!GetKad6ServiceCapabilities() || !m_kad6IndexBootstrap || !m_kad6IndexReceiver || packet.receivedMs>now)
        return false;
    ese::control::Envelope envelope;
    if(!ese::control::ParseUntrusted(packet.bytes.data(),packet.size,envelope)) return false;
    std::array<std::uint8_t,32> local{},peer{}; memcpy(local.data(),eSELive::NodeIdentityPub(),32);
    class PersistentSigner final : public ese::control::Signer {
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
        }
    } signer;
    ese::control::Datagram response;
    if(envelope.header.type==ese::wire::kEseWireUdpProbe || envelope.header.type==ese::wire::kEseWireUdpProve) {
        ese::control::Header context;
        const auto result=m_kad6IndexBootstrap->Receive(*m_directControlSessions,packet.peer,local,packet.bytes.data(),
            packet.size,now,signer,response,peer,context);
        if(result==ese::discovery::IndexBootstrapResult::Rejected) return false;
        if(result==ese::discovery::IndexBootstrapResult::Accepted &&
            !m_quicHost->RegisterControlServiceSession(peer,packet.peer,context,now,now+30000)) return false;
    } else {
        if(!m_quicHost->ResolveControlServicePeer(packet.peer,envelope.header,now,peer)) return false;
        std::vector<kad6::Byte> contact;
        if(envelope.header.type==ese::wire::kEseWireUdpK6ContactGet &&
            (!Kademlia::CKademlia::GetUDPListener() || !Kademlia::CKademlia::GetUDPListener()->GetKad6ServiceContact(contact))) return false;
        const auto crypto=MakeKad6HostCryptoHooks(); const auto utc=std::time(nullptr);
        class Neighbors final : public ese::discovery::IndexNeighbors {
        public:
            Neighbors(CDirectReachabilityManager& manager,const std::array<std::uint8_t,32>& local)
                : manager_(manager),local_(local) {}
            bool Find(const ese::discovery::DirectFind& query,std::array<ese::discovery::FindEntryView,4>& closer,
                std::uint8_t& closerCount) noexcept override {
              closer={}; closerCount=0;
              try {
                std::array<std::uint8_t,16> target{};
                if(!manager_.m_kad6DirectContacts ||
                    !ese::control::DirectIndexKey(query.file,query.fileSize,MAX_EMULE_FILE_SIZE,target)) return false;
                std::array<std::array<std::uint8_t,32>,64> hints{};
                const auto count=manager_.m_kad6DirectContacts->SnapshotHints(hints);
                ese::discovery::NearestContacts<2> nearest(target);
                for(unsigned i=0;i<count;++i) {
                    kad6::K6RouterRecord record;
                    if(hints[i]!=local_ && manager_.FreshDirectKad6Contact(hints[i],record) &&
                        (record.caps&ese::discovery::K6_CAP_DIRECT_INDEX_V1)) nearest.Add(record.kad_id,record.node_pub,i);
                }
                for(unsigned i=0;i<nearest.Count();++i) {
                    kad6::K6RouterRecord record;
                    if(manager_.FreshDirectKad6Contact(hints[nearest[i].ordinal],record) &&
                        kad6::EncodeK6RouterRecord(record,bytes_[closerCount])==kad6::Kad6Status::Ok) {
                        closer[closerCount]={bytes_[closerCount].data(),bytes_[closerCount].size(),0}; ++closerCount;
                    }
                }
                return true;
              } catch(...) { closer={}; closerCount=0; return false; }
            }
        private:
            CDirectReachabilityManager& manager_; std::array<std::uint8_t,32> local_{};
            std::array<std::vector<kad6::Byte>,2> bytes_;
        } neighbors(*this,local);
        const auto result=m_kad6IndexReceiver->Receive(*m_directControlSessions,peer,packet.peer,packet.bytes.data(),packet.size,
            MAX_EMULE_FILE_SIZE,now,local,signer,response,contact.data(),contact.size(),&crypto,utc>0?static_cast<uint64>(utc):0,
            &neighbors);
        if(result==ese::discovery::IndexDispatch::Rejected) return false;
        if(result==ese::discovery::IndexDispatch::Silent) return true;
    }
    const auto sent=m_quicHost->SendControl(packet.peer,{response.bytes.data(),response.size}).status==ese::QuicUdpSendStatus::Sent;
    ese::udp::Endpoint secondaryPeer; ese::control::Datagram secondary;
    while(m_kad6IndexReceiver->PopSecondary(*m_directControlSessions,now,secondaryPeer,secondary))
        m_quicHost->SendControl(secondaryPeer,{secondary.bytes.data(),secondary.size});
    return sent;
}
ese::discovery::PublicUdpContact CDirectReachabilityManager::CurrentKad6PublicContact(uint64 now) const
{
    ese::discovery::PublicUdpContact contact;
    if(!IsEnabled() || !thePrefs.IsEseNetLabActive() || !m_udpChain.IsComplete() || !m_udpLease.HasLease() ||
        m_udpLease.IsExpired(now) || now<m_udpLease.timing().acquired_monotonic_ms ||
        now>(std::numeric_limits<uint64>::max)()-180000) return contact;
    const auto mapped=m_udpChain.FinalEndpoint();
    if(mapped.address.family!=natmap::AddressFamily::IPv4 || !mapped.IsUsable() ||
        mapped.port!=GetAdvertisedUdpPort() || m_udpChain.generation()!=GetTopologyGeneration()) return contact;
    std::copy(mapped.address.bytes.begin(),mapped.address.bytes.begin()+4,contact.address.begin());
    contact.localPort=GetLocalUdpPort(); contact.publicPort=mapped.port; contact.generation=GetTopologyGeneration();
    contact.until=m_udpLease.lease().lifetime_seconds ? m_udpLease.timing().expires_monotonic_ms : now+180000;
    return contact;
}
bool CDirectReachabilityManager::BeginKad6PublicContactVerification(uint32 peerIp)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds();
    return m_kad6PublicContactProof.Begin(peerIp,CurrentKad6PublicContact(now),now);
}
bool CDirectReachabilityManager::ObserveKad6PublicContactVerification(uint32 peerIp,uint16 testedPublicPort,uint16 receivedLocalPort)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds();
    return m_kad6PublicContactProof.Receive(peerIp,testedPublicPort,receivedLocalPort,CurrentKad6PublicContact(now),now);
}
bool CDirectReachabilityManager::GetVerifiedKad6PublicContact(ese::discovery::PublicUdpContact& out) const
{
    out={}; if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds(); const auto contact=CurrentKad6PublicContact(now);
    if(!m_kad6PublicContactProof.Current(contact,now)) return false;
    out=contact; out.until=m_kad6PublicContactProof.VerifiedUntil(contact,now); return true;
}
bool CDirectReachabilityManager::BeginClassicCallbackVerification(uint32 peerIp)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds();
    return m_classicCallbackProof.Begin(peerIp,CurrentClassicCallbackEndpoint(now),now);
}
bool CDirectReachabilityManager::ObserveClassicCallbackAck(uint32 peerIp)
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds();
    return m_classicCallbackProof.AcceptRecorded(peerIp,CurrentClassicCallbackEndpoint(now),now);
}
bool CDirectReachabilityManager::HasVerifiedClassicCallbackReachability() const
{
    AssertMainThread();
    if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
    const auto now=MonotonicMilliseconds();
    return m_classicCallbackProof.Current(CurrentClassicCallbackEndpoint(now),now);
}
ese::classic::CallbackAvailability CDirectReachabilityManager::GetClassicCallbackAvailability() const
{
    AssertMainThread();
    const bool enabled=thePrefs.IsEseNetLabActive();
    return ese::classic::EvaluateCallback(enabled,HasVerifiedClassicCallbackReachability(),
        Kademlia::CKademlia::IsConnected() && (!enabled || Kademlia::CKademlia::IsKad2Running()),
        !Kademlia::CKademlia::IsFirewalled());
}

bool CDirectReachabilityManager::BeginEd2kVerification()
{
	AssertMainThread();
	if (!IsEnabled())
		return false;
	const natmap::ReachabilityState state = m_snapshot.ed2k_tcp_v4.state;
	if (state == natmap::ReachabilityState::Verifying)
		return true;
	natmap::StateEvent event;
	event.type = natmap::EventType::VerificationStarted;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::ObserveServerIdChange(bool bHighId,uint64 capturedGeneration)
{
	AssertMainThread();
	if (!IsEnabled() || !natmap::IsCurrentProofGeneration(capturedGeneration,
		m_snapshot.ed2k_tcp_v4.generation,m_snapshot.topology_generation))
		return false;
	if (m_snapshot.ed2k_tcp_v4.state != natmap::ReachabilityState::Verifying
		&& !BeginEd2kVerification())
		return false;

	natmap::StateEvent event;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	if (bHighId) {
		event.type = natmap::EventType::ServerEvidenceObserved;
		event.primary_evidence = natmap::Evidence{
			natmap::EvidenceKind::ServerHighId,
			m_snapshot.ed2k_tcp_v4.advertised, event.generation,
			MonotonicMilliseconds()};
	} else {
		event.type = natmap::EventType::VerificationFailed;
		event.reason = natmap::ReasonCode::ServerCallbackFailed;
	}
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::ObserveInboundTcpAccept(uint64 capturedGeneration,uint16 observedLocalPort,uint32 peerIp,uint64 acceptedAt)
{
	AssertMainThread();
	if (!IsEnabled() || !natmap::IsCurrentInboundProof(capturedGeneration,
		m_snapshot.ed2k_tcp_v4.generation,m_snapshot.topology_generation,
		observedLocalPort,m_snapshot.ed2k_tcp_v4.local.port))
		return false;
	if(peerIp && acceptedAt && acceptedAt<=MonotonicMilliseconds())
        m_classicCallbackProof.RememberInbound(peerIp,capturedGeneration,observedLocalPort,acceptedAt);
	natmap::StateEvent event;
	event.type = natmap::EventType::InboundEvidenceObserved;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	event.inbound_evidence = natmap::Evidence{
		natmap::EvidenceKind::InboundTcpAccept,
		m_snapshot.ed2k_tcp_v4.advertised, event.generation,
		MonotonicMilliseconds()};
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

uint64 CDirectReachabilityManager::BeginMapperOperation(natmap::MapperKind mapper,
	uint16 tcp,uint16 udp,bool refresh,uint64 timeoutMs)
{
	AssertMainThread();
	SynchronizeLocalSocketBindings();
	if(!natmap::MatchesLocalMappingPorts(GetLocalTcpPort(),GetLocalUdpPort(),tcp,udp)) return 0;
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || m_topologyGenerationExhausted ||
		!timeoutMs || timeoutMs>40000 || m_nextMapperOperation==(std::numeric_limits<uint64>::max)()) return 0;
	const auto now=MonotonicMilliseconds();
	if(now>(std::numeric_limits<uint64>::max)()-timeoutMs) return 0;
	natmap::MapperOperation operation;
	operation.id=++m_nextMapperOperation; operation.generation=m_snapshot.topology_generation;
	operation.started=now; operation.deadline=now+timeoutMs; operation.mapper=mapper;
	operation.tcp=tcp; operation.udp=udp; operation.refresh=refresh;
	return m_mapperResults->Begin(operation) ? operation.id : 0;
}

bool CDirectReachabilityManager::TakeMapperResult(uint64 operation,natmap::OwnedMapperResult& out)
{
	AssertMainThread(); out={};
	SynchronizeLocalSocketBindings();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId ||
		!m_mapperResults->Take(operation,m_snapshot.topology_generation,MonotonicMilliseconds(),out)) return false;
	if(!natmap::MatchesLocalMappingPorts(GetLocalTcpPort(),GetLocalUdpPort(),out.operation.tcp,out.operation.udp)) {
		out={}; return false;
	}
	if(out.operation.refresh && !out.result.success && thePrefs.IsEseNetLabActive())
		InvalidateLocalTopology(); // Withdraw current grant/proofs before rediscovery.
	return true;
}

void CDirectReachabilityManager::SynchronizeLocalSocketBindings()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return;
	const uint16 tcp = theApp.listensocket ? theApp.listensocket->GetConnectedPort() : 0;
	const uint16 udp = theApp.clientudp ? theApp.clientudp->GetConnectedPort() : 0;
	if(tcp!=GetLocalTcpPort() || udp!=GetLocalUdpPort()) Initialize(tcp,udp);
}

bool CDirectReachabilityManager::ObserveLocalNetworkSignature(uint64 signature)
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId || !m_localNetworkTracker.Observe(signature)) return false;
	InvalidateLocalTopology();
	return true;
}

void CDirectReachabilityManager::InvalidateLocalTopology()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return;
	Initialize(GetLocalTcpPort(),GetLocalUdpPort());
	m_mappingRediscoveryNeeded=true;
}

bool CDirectReachabilityManager::ConsumeMappingRediscovery()
{
	AssertMainThread();
	if(::GetCurrentThreadId()!=m_dwOwnerThreadId) return false;
	const bool pending=m_mappingRediscoveryNeeded;
	m_mappingRediscoveryNeeded=false;
	return pending;
}

bool CDirectReachabilityManager::MappingRediscoveryNeeded() const
{
	AssertMainThread();
	return ::GetCurrentThreadId()==m_dwOwnerThreadId && m_mappingRediscoveryNeeded;
}

bool CDirectReachabilityManager::ObserveMappedPorts(natmap::MapperKind mapper,
	uint32 nExternalIP, uint16 nLocalTcpPort, uint16 nExternalTcpPort,
	uint16 nLocalUdpPort, uint16 nExternalUdpPort,
	uint32 nLifetimeSeconds, uint32 nMapperEpoch, bool bRefresh)
{
	AssertMainThread();
	if (m_topologyGenerationExhausted || mapper == natmap::MapperKind::None || nExternalIP == 0 ||
		nLocalTcpPort == 0 || nExternalTcpPort == 0)
		return false;

	const natmap::EndpointSource source = mapper == natmap::MapperKind::Pcp
		? natmap::EndpointSource::PcpMap
		: mapper == natmap::MapperKind::NatPmp
			? natmap::EndpointSource::NatPmpPublicAddress
			: natmap::EndpointSource::UpnpExternalAddress;
	const natmap::Endpoint localTcp = MakeAnyV4(nLocalTcpPort);
	const natmap::Endpoint publicTcp = MakePublicV4(
		nExternalIP, nExternalTcpPort, source);
	const natmap::Endpoint localUdp = MakeAnyV4(nLocalUdpPort);
	const natmap::Endpoint publicUdp = MakePublicV4(
		nExternalIP, nExternalUdpPort, source);
	const uint64 now = MonotonicMilliseconds();

	if (bRefresh && m_tcpLease.HasLease()) {
		natmap::PortLease tcpRenewal = m_tcpLease.lease();
		tcpRenewal.mapper = mapper;
		tcpRenewal.local = localTcp;
		tcpRenewal.public_endpoint = publicTcp;
		tcpRenewal.granted_external_port = nExternalTcpPort;
		tcpRenewal.lifetime_seconds = nLifetimeSeconds;
		tcpRenewal.mapper_epoch = nMapperEpoch;
		natmap::LeaseController tcpLease = m_tcpLease;
		bool renewed = tcpLease.AcceptRenewal(tcpRenewal, now)
			&& !tcpLease.LastRenewalObservedEpochReset();
		natmap::LeaseController udpLease = m_udpLease;
		natmap::NatChainTransaction tcpChain = m_tcpChain;
		natmap::NatChainTransaction udpChain = m_udpChain;
		if (renewed)
			renewed = tcpChain.layer_count() != 0 && tcpChain.AcceptRenewal(
				tcpChain.layer_count() - 1, tcpRenewal, now);
		if (renewed && nLocalUdpPort != 0) {
			if (!udpLease.HasLease())
				renewed = false;
			else {
				natmap::PortLease udpRenewal = udpLease.lease();
				udpRenewal.mapper = mapper;
				udpRenewal.local = localUdp;
				udpRenewal.public_endpoint = publicUdp;
				udpRenewal.granted_external_port = nExternalUdpPort;
				udpRenewal.lifetime_seconds = nLifetimeSeconds;
				udpRenewal.mapper_epoch = nMapperEpoch;
				renewed = udpLease.AcceptRenewal(udpRenewal, now)
					&& !udpLease.LastRenewalObservedEpochReset();
				if (renewed)
					renewed = udpChain.layer_count() != 0 && udpChain.AcceptRenewal(
						udpChain.layer_count() - 1, udpRenewal, now);
			}
		}
		if (renewed) {
			m_tcpLease = tcpLease;
			m_tcpChain = tcpChain;
			m_snapshot.ed2k_tcp_v4.lease = tcpLease.lease();
			if (nLocalUdpPort != 0) {
				m_udpLease = udpLease;
				m_udpChain = udpChain;
				m_snapshot.kad_udp_v4.lease = udpLease.lease();
			}
			return true;
		}
		// A changed endpoint is a new topology generation, never a silent
		// renewal of the identity currently visible to servers and peers.
	}

	uint64 generation=0;
	if(!natmap::NextTopologyGeneration(m_snapshot.topology_generation,generation)) return false;
	natmap::PlaneSnapshot tcpPlane = m_snapshot.ed2k_tcp_v4;
	natmap::PlaneSnapshot udpPlane = m_snapshot.kad_udp_v4;
	const bool tcpOk = BuildMappedPlane(tcpPlane, mapper,
		natmap::Transport::Tcp, localTcp, publicTcp,
		nLifetimeSeconds, nMapperEpoch, generation);
	bool udpOk = true;
	if (nLocalUdpPort != 0) {
		udpOk = nExternalUdpPort != 0 && BuildMappedPlane(udpPlane,
			mapper, natmap::Transport::Udp, localUdp, publicUdp,
			nLifetimeSeconds, nMapperEpoch, generation);
	}
	if (!tcpOk || !udpOk)
		return false;

	natmap::LeaseController tcpLease;
	natmap::LeaseController udpLease;
	if (!tcpLease.Activate(tcpPlane.lease, now)
		|| (nLocalUdpPort != 0 && !udpLease.Activate(udpPlane.lease, now)))
		return false;
	natmap::NatChainTransaction tcpChain = m_tcpChain;
	natmap::NatChainTransaction udpChain = m_udpChain;
	if (!tcpChain.Begin(generation) || !tcpChain.AppendLease(tcpPlane.lease, now)
		|| (nLocalUdpPort != 0 && (!udpChain.Begin(generation)
			|| !udpChain.AppendLease(udpPlane.lease, now))))
		return false;
	// Mapping commits invalidate control exchange ownership as well as local
	// reachability evidence. Preserve the process send budget and cache hints.
	m_classicCallbackProof.Reset();
	m_nextClassicCallbackRecheck=0;
    m_kad6PublicContactProof.Reset();
	m_nextKad6PublicContactRecheck=0;
	m_mapperResults->DiscardAll();
	m_directContactRefreshReplies->CancelAll([this](uint64 owner) {
		if(m_quicHost) m_quicHost->RemoveControlReplies(owner);
	});
	*m_directControlSessions=ese::control::Sessions{};
	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcpPlane;
	m_snapshot.kad_udp_v4 = udpPlane;
	m_tcpLease = tcpLease;
	m_tcpChain = tcpChain;
	if (nLocalUdpPort != 0)
		m_udpLease = udpLease;
	if (nLocalUdpPort != 0)
		m_udpChain = udpChain;

	if (publicTcp.address.IsSharedCgnatV4()) {
		natmap::StateEvent blocked;
		blocked.type = natmap::EventType::CgnatDetected;
		blocked.generation = generation;
		blocked.reason = natmap::ReasonCode::CgnatWithoutLease;
		m_snapshot.ed2k_tcp_v4 = natmap::ApplyEvent(
			m_snapshot.ed2k_tcp_v4, blocked).snapshot;
		m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
		m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
		m_bEnabled.store(false, std::memory_order_release);
		return true;
	}
	if (publicTcp.address.IsRfc1918V4()) {
		m_snapshot.ed2k_tcp_v4.reason = natmap::ReasonCode::NoRoute;
		m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
		m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
		m_bEnabled.store(false, std::memory_order_release);
		return true;
	}
	m_nAdvertisedTcpPort.store(nExternalTcpPort, std::memory_order_release);
	if (nLocalUdpPort != 0)
		m_nAdvertisedUdpPort.store(nExternalUdpPort, std::memory_order_release);
	m_bEnabled.store(true, std::memory_order_release);

	// The candidate must be advertised in the next server login so the classic
	// callback can verify it. Green status still requires both evidence kinds.
	return true;
}
