#pragma once
// Explicit --reach-binding-selftest only; never called by normal activation.
// The eMule side uses its existing socket, MFC socket messages and persistent
// identity. Only the isolated loopback peer uses an ephemeral signer.
#include <afxpriv.h>
#include <chrono>
#include <stdexcept>
#include <string>
#include "ClientUDPSocket.h"
#include "EseQuicHostFactory.h"
#include "EseQuicSocketOwner.h"
#include "EsePeerTrustStore.h"
#include "EseQuicHeaderProbe.h"
#include "LiveCrypto.h"
#include "Log.h"
#include "NodeIdentity.h"
#include "KnownFile.h"
#include "PartFile.h"
#include "DownloadQueue.h"
#include "UploadQueue.h"
#include "SharedFileList.h"
#include "TransferDlg.h"
#include "PartHashThread.h"
#include "PartFileWriteThread.h"
#include "Preferences.h"
#include "ClientCredits.h"
#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "DirectReachabilityManager.h"
#include "EseKad6ServiceCapabilities.h"
#include "EseQuicDownloadConsumer.h"
#include "ClientList.h"
#include "IPFilter.h"
#include "zlib/zlib.h"
#include "ListenSocket.h"
#include "eMuleAI/UtpSocket.h"
#include "EseQuicEd2kPump.h"
#include "EseQuicEd2kWriter.h"
#include "EseControlCookieCrypto.h"
#include "EseControlInitiator.h"
#include "../tools/quic/SimulatedQuicPort.h"
#include "EseKad6ContactRefresh.h"
#include "EseKad6FindContacts.h"
#include "Kad6CryptoHost.h"
#include <ctime>
#include "SafeFile.h"
#include "Packets.h"
#include "reach/part_contributions.h"
#include "reach/direct_client_lifetime.h"
#include "reach/direct_coordinator.h"

// No production setter or global clock override: only this explicit lab can
// seed a per-file timestamp to exercise the normal periodic deadline branch.
class CNativeDirectSelfTestAccess {
public:
    static uint64 StoredKad6Publications(CDirectReachabilityManager& manager) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("publication diagnostic fixture gate");
        return manager.m_kad6StoredPublications;
    }
    static void TestDiagnosticWinner(CDirectReachabilityManager& manager,reach::DirectHandle handle) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("diagnostic fixture lab gate");
        const auto before=manager.DirectConnections().Snapshot(handle);
        if(!before || before->state!=reach::DirectSessionState::Ready) throw std::runtime_error("diagnostic ready fixture");
        manager.PublishDirectDiagnostics();
        const auto& slot=manager.m_diagnosticSlots[handle.slot];
        const auto projected=slot.publisher ? slot.publisher->Read() : nullptr;
        const auto json=manager.GetDirectStatusJson();
        const auto after=manager.DirectConnections().Snapshot(handle);
        if(!projected || !projected->authenticated || projected->session_epoch!=before->epoch ||
            !slot.opaqueId || projected->session_id!=slot.opaqueId ||
            json.find(reach::DirectDiagnosticJson(*projected))==std::string::npos ||
            json.find("\"endpoint\"")!=std::string::npos || json.find("\"node\"")!=std::string::npos ||
            !after || after->state!=before->state || after->epoch!=before->epoch || after->subscribers!=before->subscribers)
            throw std::runtime_error("diagnostic winner projection changed owner or leaked identity");
        Log(_T("REACH_SELFTEST V162 PASS: actual Ready DCO winner diagnostic opaque session decimal epoch published immutable cache no endpoint key or authority mutation; GUI and API share cache no HTTP wire assertion"));
    }
    static void TestDiagnosticRetirement(CDirectReachabilityManager& manager) {
        if(!theApp.m_bReachBindingSelfTest || manager.DirectConnections().Size()) throw std::runtime_error("diagnostic retirement scope");
        reach::DirectPeerKey peer; peer.source_record_id=0x163; peer.source_epoch=1;
        reach::DirectAttemptId id{}; id[0]=0x63;
        const auto request=manager.DirectConnections().Request(peer,0x163,id,manager.GetTopologyGeneration(),manager.MonotonicMilliseconds());
        if(request.status!=reach::DirectRequestStatus::Created) throw std::runtime_error("diagnostic retirement admission");
        manager.PublishDirectDiagnostics();
        manager.DirectConnections().Cancel(request.handle,reach::DirectReason::Disabled);
        manager.PublishDirectDiagnostics();
        const auto idBefore=manager.m_diagnosticSlots[request.handle.slot].opaqueId;
        if(!manager.DirectConnections().Release(request.handle)) throw std::runtime_error("diagnostic retirement release");
        manager.PublishDirectDiagnostics();
        const auto retained=manager.m_diagnosticSlots[request.handle.slot].publisher->Read();
        if(manager.DirectConnections().Size() || !retained || retained->session_id!=idBefore ||
            retained->state!=reach::DirectSessionState::Cancelled || retained->terminal_reason!=reach::DirectReason::Disabled ||
            manager.GetDirectStatusJson().find(reach::DirectDiagnosticJson(*retained))==std::string::npos)
            throw std::runtime_error("diagnostic terminal disappeared after owner retirement");
        Log(_T("REACH_SELFTEST V163 PASS: terminal Disabled diagnostic retained after actual DCO release zero owner resources opaque id stable no reason rewrite; explicit no route fixture"));
    }
    static void DelayNextQuicPolicy(CDirectReachabilityManager& manager,uint32 delay) {
        if(!theApp.m_bReachBindingSelfTest || !delay || delay>2000 || manager.m_directPolicyPreparationSelfTestDelayMs)
            throw std::runtime_error("invalid isolated slow preparation fixture");
        manager.m_directPolicyPreparationSelfTestDelayMs=delay;
    }
    static uint64 QuicPolicyIssued(CDirectReachabilityManager& manager) { return manager.m_directBootstrapIssued; }
    static void TestMixedSelector(CDirectReachabilityManager& manager,CUpDownClient& client,
        reach::DirectHandle handle,const reach::NativeDirectTransportPolicy& udpPolicy) {
        if(!theApp.m_bReachBindingSelfTest || client.socket || !udpPolicy.validated_udp_count)
            throw std::runtime_error("mixed selector outside isolated pre-adoption lab");
        const auto before=manager.DirectConnections().Snapshot(handle);
        const auto now=static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        const auto owned=client.NativeDirectCandidates(manager.GetTopologyGeneration(),now+15000);
        const auto oldRecord=manager.m_directTcpObservations[0];
        std::array<BYTE,16> oldHash{}; std::copy(client.GetUserHash(),client.GetUserHash()+16,oldHash.begin());
        struct Restore { std::function<void()> action; ~Restore() { action(); } } restore{
            [&]() { manager.m_directTcpObservations[0]=oldRecord; client.SetUserHash(oldHash.data()); }};
        auto hash=owned.peer.expected_user_hash.value_or(std::array<BYTE,16>{});
        if(!reach::NonzeroIdentity(hash)) { hash[0]=0x73; hash[15]=0x60; }
        client.SetUserHash(hash.data()); // expectation only; restored before any transport preparation
        auto& observation=manager.m_directTcpObservations[0]; observation={};
        observation.lifetime=client.GetDirectClientLifetime(); observation.userHash=hash;
        auto& route=observation.candidate; route.id=160; route.kind=reach::DirectKind::DirectV4;
        route.family=4; route.address={8,8,4,4}; route.port=4662; route.transport_mask=reach::DirectTcp;
        route.evidence=reach::DirectEvidence::Observed; route.topology_generation=manager.GetTopologyGeneration();
        route.expires_monotonic_ms=now+2000;
        const auto valid=observation;
        auto policy=udpPolicy; policy.enabled_transports=reach::DirectTcp|reach::DirectQuic;
        const auto selected=manager.SelectDirectDownloadRoutes(handle,policy,42);
        if(selected.routes.size()!=2 || selected.routes[0].transport!=reach::DirectTcp ||
            selected.routes[1].transport!=reach::DirectQuic || selected.routes[0].id!=42 || selected.routes[1].id!=43)
            throw std::runtime_error("mixed host selector did not retain separately evidenced TCP and QUIC");
        for(unsigned mismatch=0;mismatch<4;++mismatch) {
            observation=valid;
            if(mismatch==0) ++observation.lifetime;
            if(mismatch==1) observation.userHash[0]^=1;
            if(mismatch==2) ++observation.candidate.topology_generation;
            if(mismatch==3) observation.candidate.expires_monotonic_ms=0;
            const auto rejected=manager.SelectDirectDownloadRoutes(handle,policy,42);
            if(rejected.routes.size()!=1 || rejected.routes[0].transport!=reach::DirectQuic)
                throw std::runtime_error("mixed selector borrowed stale or unrelated TCP evidence");
        }
        observation=valid; ++policy.validated_udp_paths[0].node[0];
        const auto onlyTcp=manager.SelectDirectDownloadRoutes(handle,policy,42);
        const auto after=manager.DirectConnections().Snapshot(handle);
        if(onlyTcp.routes.size()!=1 || onlyTcp.routes[0].transport!=reach::DirectTcp || !before || !after || client.socket ||
            after->state!=before->state || after->epoch!=before->epoch || after->winner!=before->winner ||
            after->subscribers!=before->subscribers || after->highest_route_id!=before->highest_route_id || after->useful_bytes!=before->useful_bytes)
            throw std::runtime_error("mixed selection granted authority or mutated the attempt");
        Log(_T("REACH_SELFTEST V160 PASS: host selects separately evidenced TCP and QUIC rejects stale lifetime hash topology TTL and unrelated UDP pin no Start identity adoption or attempt mutation; seeded observation and UDP proof not physical TCP return-path evidence"));
    }
    static void TestWindowIsolation() {
        if(!theApp.m_bReachBindingSelfTest || !theApp.emuledlg) throw std::runtime_error("window isolation outside explicit lab");
        const auto window=theApp.emuledlg->m_hWnd;
        TCHAR text[]=_T("exit"); COPYDATASTRUCT command{};
        command.dwData=OP_CLCOMMAND; command.cbData=sizeof(text); command.lpData=text;
        if(SendMessage(window,RegisterWindowMessage(EMULE_GUID),0,0)!=0 ||
            SendMessage(window,WM_COPYDATA,0,reinterpret_cast<LPARAM>(&command))!=0 || theApp.IsClosing())
            throw std::runtime_error("isolated selftest accepted normal-instance discovery or external exit");
        Log(_T("REACH_SELFTEST window isolation PASS: not normal CLI recipient external exit refused"));
    }
    static void TracePair(CDirectReachabilityManager& manager,uint64 lifetime) {
        Log(_T("QUIC_PAIR_TRACE role=%s lifetime=%I64u bootstrap=%I64u ready=%u rejects=%I64u policies=%I64u"),
            (LPCTSTR)theApp.m_strQuicPairSelfTestRole,lifetime,manager.m_directBootstrapOwner,unsigned(manager.m_directBootstrapReady),
            manager.m_rejectedDirectControlReplies,manager.m_rejectedQuicPreparationPolicies);
        if(const auto record=manager.m_directSubscribers->FindLifetime(lifetime)) {
            const auto state=record->attempt ? manager.DirectConnections().Snapshot(*record->attempt) : std::nullopt;
            Log(_T("QUIC_PAIR_TRACE token=%I64u attempt=%u terminal=%u state=%u winner=%u useful=%I64u"),record->token,
                unsigned(record->attempt.has_value()),record->terminal_reason ? unsigned(*record->terminal_reason):0,
                state ? unsigned(state->state):999,state ? state->winner:0,state ? state->useful_bytes:0);
        }
        for(const auto& r:manager.m_directResponders) if(r.owner)
            Log(_T("QUIC_PAIR_TRACE responder=%I64u subscriber=%I64u prep=%u route=%u deadline=%I64u"),
                r.owner,r.dataSubscriber,unsigned(r.dataPreparationAttempted),r.dataRoute,r.deadline);
    }
    static void SeedPairClient(CUpDownClient& client,const std::array<BYTE,48>& identity,uint32 ip,uint16 udp) {
        if(theApp.m_strQuicPairSelfTestRole.IsEmpty()) throw std::runtime_error("pair enrollment outside explicit lab");
        memcpy(client.m_eseNodePub,identity.data(),32); client.m_bEseNodePubSet=true;
        client.SetUserHash(identity.data()+32); client.SetIP(ip); client.SetUDPPort(udp);
        client.m_uEseCapabilities|=0x10000000;
        client.SetUserName(_T("isolated QUIC pair enrollment"));
    }
    static void TestLargeOffsetPartFile() {
        Log(_T("LARGE_OFFSET_SELFTEST stage1: enter"));
        if(!theApp.m_bReachBindingSelfTest || !theApp.m_pPartFileWriteThread ||
            !theApp.m_pPartFileWriteThread->IsRunning()) throw std::runtime_error("large offset IOCP fixture guard");
        const bool sparse=thePrefs.GetSparsePartFiles(),allocate=thePrefs.GetAllocCompleteMode();
        struct PreferencesRestore {
            bool sparse,allocate;
            ~PreferencesRestore() { thePrefs.SetSparsePartFiles(sparse); thePrefs.SetAllocCompleteMode(allocate); }
        } preferencesRestore{sparse,allocate};
        thePrefs.SetSparsePartFiles(true); thePrefs.SetAllocCompleteMode(false);
        auto file=std::make_unique<CPartFile>(_T("ed2k://|file|large-offset-parser.bin|4294971393|ED93ED93ED93ED93ED93ED93ED93ED93|/"));
        Log(_T("LARGE_OFFSET_SELFTEST stage2: file created status=%u"),unsigned(file->GetStatus()));
        CUpDownClient client;
        struct Cleanup {
            CUpDownClient& client; std::unique_ptr<CPartFile>& file;
            ~Cleanup() {
                Log(_T("LARGE_OFFSET_SELFTEST stage8: cleanup writes=%d"),file->m_iWrites);
                // DS_DOWNLOADING exit removes the UI row through m_reqfile.
                // Keep that file alive/bound until its source is withdrawn.
                client.ClearDownloadBlockRequests(); client.SetDownloadState(DS_NONE); client.SetRequestFile(nullptr);
                theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(file.get());
                theApp.downloadqueue->RemoveFile(file.get());
                if(file->m_iWrites>0) file.release(); // worker ownership on failed deadline
            }
        } cleanup{client,file};
        if(file->GetStatus()!=PS_READY && file->GetStatus()!=PS_EMPTY) throw std::runtime_error("large offset file creation");
        if(!(GetFileAttributes(file->GetFilePath())&FILE_ATTRIBUTE_SPARSE_FILE))
            throw std::runtime_error("large offset fixture requires actual sparse file");
        theApp.downloadqueue->AddDownload(file.get(),false);
        client.SetRequestFile(file.get());
        constexpr uint64 start=4294967294ULL,end=4294967296ULL;
        auto block=std::make_unique<Requested_Block_Struct>();
        block->StartOffset=start; block->EndOffset=start+4096; block->transferred=0;
        memcpy(block->FileID,file->GetFileHash(),16);
        auto pending=std::make_unique<Pending_Block_Struct>(); pending->block=block.get();
        client.m_PendingBlocks_list.AddTail(pending.get()); block.release(); pending.release();
        client.SetDownloadState(DS_DOWNLOADING);
        CSafeMemFile packet(35); packet.WriteHash16(file->GetFileHash()); packet.WriteUInt64(start); packet.WriteUInt64(end+1);
        const BYTE expected[3]={254,255,0}; packet.Write(expected,3);
        const auto wire=packet.Detach();
        struct FreeWire { BYTE* bytes; ~FreeWire() { free(bytes); } } freeWire{wire};
        client.ProcessBlockPacket(wire,35,false,true);
        Log(_T("LARGE_OFFSET_SELFTEST stage3: parser returned completed=%I64u"),static_cast<ULONGLONG>(file->GetCompletedSize()));
        if(!file->IsComplete(start,end) || file->IsComplete(0,2) || file->GetCompletedSize()!=3)
            throw std::runtime_error("large offset accepted range truncated or inflated");
        file->FlushBuffer();
        Log(_T("LARGE_OFFSET_SELFTEST stage4: flush queued writes=%d"),file->m_iWrites);
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);
        while(file->m_iWrites>0 && std::chrono::steady_clock::now()<deadline) Sleep(1);
        if(file->m_iWrites) throw std::runtime_error("large offset IOCP write deadline");
        Log(_T("LARGE_OFFSET_SELFTEST stage5: writes drained"));
        file->FlushBuffer();
        Log(_T("LARGE_OFFSET_SELFTEST stage6: completed buffers consumed"));
        CFile disk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
        BYTE stored[3]={}; disk.Seek(start,CFile::begin);
        Log(_T("LARGE_OFFSET_SELFTEST stage7: disk seek succeeded"));
        if(disk.Read(stored,3)!=3 || memcmp(stored,expected,3) || !file->IsCompleteBD(start,end) || file->IsCompleteBD(0,2))
            throw std::runtime_error("large offset actual disk bytes or gap mismatch");
        Log(_T("REACH_SELFTEST V155 PASS: real I64 ProcessBlockPacket accepts offsets4294967294..4294967296 PartFile IOCP sparse disk2542550 exact3 no low range alias; seeded reservation direct parser no transport full F3 or integrity proof"));
    }
    static void TestMalformedBlockTimer(CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("block timer test guard");
        const auto savedTimer=client.m_dwLastBlockReceived;
        const auto savedState=client.GetDownloadState();
        struct Restore {
            CUpDownClient& client; DWORD timer; EDownloadState state;
            ~Restore() { client.SetDownloadState(state); client.m_dwLastBlockReceived=timer; }
        } restore{client,savedTimer,savedState};
        client.SetDownloadState(DS_DOWNLOADING);
        std::array<BYTE,40> bytes{};
        auto write=[&](unsigned at,uint64 value,unsigned width) {
            for(unsigned i=0;i<width;++i) bytes[at+i]=static_cast<BYTE>(value>>(i*8));
        };
        unsigned checks=0;
        for(bool packed:{false,true}) for(bool wide:{false,true}) {
            const unsigned width=wide?8:4,header=16+width+(packed?4:width);
            auto reject=[&](const BYTE* packet,uint32 size) {
                client.m_dwLastBlockReceived=0x13579BDF;
                bool rejected=false;
                try { client.ProcessBlockPacket(packet,size,packed,wide); }
                catch(const CString&) { rejected=true; }
                if(!rejected || client.m_dwLastBlockReceived!=0x13579BDF ||
                    client.GetDownloadState()!=DS_DOWNLOADING)
                    throw std::runtime_error("malformed block renews timer or mutates download state");
                ++checks;
            };
            for(unsigned size=0;size<=header;++size) reject(bytes.data(),size);
            reject(nullptr,header+1);
            if(!packed) {
                write(16,wide?4294967294ULL:100,width);
                write(16+width,wide?4294967296ULL:102,width);
                reject(bytes.data(),header+3); // declared2 vs payload3
                write(16+width,0,width); reject(bytes.data(),header+3);
            } else if(wide) {
                write(16,UINT64_MAX-1,8); reject(bytes.data(),header+3);
            }
        }
        if(checks!=121) throw std::runtime_error("block timer corpus coverage mismatch");
        Log(_T("REACH_SELFTEST V154 PASS: production block parser 121 malformed headers and bounds reject without timer renewal or download state mutation including I64 overflow; no valid large file write proof"));
    }
    static bool HasRetainedControl(CDirectReachabilityManager& manager,reach::DirectHandle handle) {
        for(const auto& entry:manager.m_retainedControlDownloads) if(entry.owner &&
            entry.handle.slot==handle.slot && entry.handle.generation==handle.generation) return true;
        return false;
    }
    static void TestRetiredControlLedger(CDirectReachabilityManager& manager,reach::DirectHandle handle,
        const std::array<std::uint8_t,32>& peer,const ese::udp::Endpoint& endpoint,
        const reach::DirectAttemptId& attempt,uint64 topology) {
        if(!theApp.m_bReachBindingSelfTest || HasRetainedControl(manager,handle))
            throw std::runtime_error("retired server control owner was not released");
        // A copy exercises normal tombstone reclamation without advancing the
        // live manager clock or authorizing any real traffic.
        auto ledger=std::make_unique<ese::control::Sessions>(manager.DirectControlSessions());
        ese::control::Header header; header.attempt=attempt; header.generation=topology; header.sequence=1;
        std::array<std::uint8_t,32> digest{}; digest.fill(92);
        const auto now=static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        if(ledger->AdmitVerified(peer,endpoint,header,digest,now+64000)!=ese::control::Admission::Accepted)
            throw std::runtime_error("retired server control ledger remains retained");
        Log(_T("REACH_SELFTEST V152 PASS: real server consent retained while live retirement removes manager owner and copied ledger reclaims after64s; no live clock advance or new wire permission"));
    }
    static void TestConsentedServerRecoveryPreparation(CDirectReachabilityManager& manager,
        CUpDownClient& client,reach::DirectHandle handle,const std::array<std::uint8_t,32>& peer,uint32 initialHighwater) {
        unsigned stage=0;
        auto check=[&](bool good) { ++stage; if(!good) throw std::runtime_error(
            std::string("consented server recovery preparation fence stage")+std::to_string(stage)); };
        check(theApp.m_bReachBindingSelfTest);
        const auto before=manager.DirectConnections().Snapshot(handle);
        Log(_T("SERVER_RECOVERY_SELFTEST state: present=%u state=%u epoch=%I64u highwater=%u token=%I64u"),
            unsigned(bool(before)),before?unsigned(before->state):255,
            static_cast<ULONGLONG>(before?before->epoch:0),before?before->highest_route_id:0,
            static_cast<ULONGLONG>(client.GetNativeDirectDownloadSubscriber()));
        check(before && before->state==reach::DirectSessionState::Recovering && before->epoch==1 &&
            initialHighwater && before->highest_route_id==initialHighwater);
        const auto nextRoute=before->NextRouteId(); check(nextRoute>initialHighwater);
        CDirectReachabilityManager::ControlResponder entry;
        entry.peer=peer; entry.endpoint.address[0]=8; entry.endpoint.address[1]=8;
        entry.endpoint.address[2]=8; entry.endpoint.address[3]=8; entry.endpoint.port=4665;
        entry.dataSubscriber=client.GetNativeDirectDownloadSubscriber();
        const auto now=static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        ese::control::Header context; context.attempt=before->attempt_id; context.generation=before->topology_generation+7; context.sequence=1;
        std::array<std::uint8_t,32> digest{}; digest.fill(91);
        // Isolate this trusted-ledger preparation fixture from the preceding
        // real loopback consent exchange. This is NOT endpoint rebinding proof.
        struct LedgerRestore {
            ese::control::Sessions& target; ese::control::Sessions saved;
            ~LedgerRestore() { target=saved; }
        } restore{manager.DirectControlSessions(),manager.DirectControlSessions()};
        manager.DirectControlSessions()=ese::control::Sessions{};
        check(manager.DirectControlSessions().AdmitVerified(peer,entry.endpoint,context,digest,now)==ese::control::Admission::Accepted);
        check(manager.PrepareConsentedDirectQuicResponder(entry,context,now));
        const auto after=manager.DirectConnections().Snapshot(handle);
        check(entry.dataRoute==nextRoute && entry.dataAttempt.slot==handle.slot && entry.dataAttempt.generation==handle.generation &&
            after && after->epoch==1 && after->attempt_id==before->attempt_id && after->highest_route_id==nextRoute);
        check(manager.m_builtinQuicConsumer->PreparedServerRoute(handle,nextRoute,peer,entry.endpoint,context.attempt,now));
        check(context.generation!=manager.GetTopologyGeneration() &&
            manager.RetainDirectControlDownload(handle,peer,entry.endpoint,context,now));
        check(HasRetainedControl(manager,handle));
        check(!manager.PrepareConsentedDirectQuicResponder(entry,context,now));
        Log(_T("REACH_SELFTEST V151 PASS: product server recovery preparation next route above original highwater same attempt epoch1 duplicate no restart; seeded trusted control ledger no wire proof second product or recovered handshake"));
        Log(_T("REACH_SELFTEST V153 PASS: product server control remote generation differs local topology retained exact remote ledger local lifecycle fence; seeded trusted context not wire peer generation interoperability"));
    }
    static bool ClassicTransportCaptured(const CClientReqSocket& socket) { return socket.m_classicDirectTcpCandidate.has_value(); }
    static uint64 ClassicParsedSignatures(const CClientReqSocket& socket) { return socket.m_classicLabParsedSignatures; }
    static void ChangeClassicChallengeForTest(CClientReqSocket& socket) {
        if(!theApp.m_bReachBindingSelfTest || !socket.m_classicDirectChallenge) throw std::runtime_error("classic challenge fixture guard");
        socket.m_classicDirectChallenge^=1;
    }
    static bool RecoveryFileEligible(const CPartFile* file) { return ese::QuicDownloadConsumer::CanResumeFile(file); }
    static void TestRecoveryFileStates() {
        auto check=[](bool value) { if(!value) throw std::runtime_error("owned recovery file state guard"); };
        check(!ese::QuicDownloadConsumer::CanResumeFile(nullptr));
        check(ese::QuicDownloadConsumer::CanResumeFileStatus(PS_READY,false));
        check(ese::QuicDownloadConsumer::CanResumeFileStatus(PS_EMPTY,false));
        check(!ese::QuicDownloadConsumer::CanResumeFileStatus(PS_READY,true));
        for(const auto status:{PS_COMPLETING,PS_COMPLETE,PS_PAUSED,PS_ERROR})
            check(!ese::QuicDownloadConsumer::CanResumeFileStatus(status,false));
        check(!ese::QuicDownloadConsumer::CanResumeFileStatus(0xFFFF,false));
    }
    static bool HasPendingOwnedRecovery(CDirectReachabilityManager& manager,reach::DirectHandle handle,uint64 epoch) {
        if(!manager.m_builtinQuicConsumer || handle.slot>=manager.m_builtinQuicConsumer->recovery_.size()) return false;
        const auto& intent=manager.m_builtinQuicConsumer->recovery_[handle.slot];
        return intent.handle.slot==handle.slot && intent.handle.generation==handle.generation && intent.epoch==epoch;
    }
    static void TestPinnedOwnedRecovery(CDirectReachabilityManager& manager,reach::DirectHandle handle) {
        auto check=[](bool good) { if(!good) throw std::runtime_error("pinned owned QUIC recovery policy fence"); };
        check(theApp.m_bReachBindingSelfTest && manager.m_builtinQuicConsumer &&
            handle.slot<manager.m_builtinQuicConsumer->recovery_.size());
        const auto& intent=manager.m_builtinQuicConsumer->recovery_[handle.slot];
        check(intent.pinnedPeer.has_value() && intent.nextQuicProbeMs!=0);
        const auto state=manager.DirectConnections().Snapshot(handle);
        check(state && state->state==reach::DirectSessionState::Recovering);
        const auto policy=*intent.pinnedPeer;
        check(policy.hasPin && policy.persistent && !policy.allowFirstUse && !policy.trustCommitter &&
            policy.pin==state->peer.identity && policy.local.attempt==state->attempt_id);
        for(unsigned variant=0;variant<6;++variant) {
            auto bad=policy;
            switch(variant) {
            case 0: bad.pin[0]^=1; break;
            case 1: bad.expectedNode[0]^=1; break;
            case 2: bad.local.attempt[0]^=1; break;
            case 3: ++bad.local.topologyGeneration; break;
            case 4: bad.allowFirstUse=true; break;
            case 5: bad.persistent=false; break;
            }
            check(manager.BeginOwnedDirectQuicRecovery(handle,bad)==0);
        }
        auto stale=handle; ++stale.generation;
        check(manager.BeginOwnedDirectQuicRecovery(stale,policy)==0);
        const auto after=manager.DirectConnections().Snapshot(handle);
        check(after && after->state==state->state && after->epoch==state->epoch &&
            after->highest_route_id==state->highest_route_id && after->useful_bytes==state->useful_bytes);
    }
    static void TestTcpObservation(CDirectReachabilityManager& manager,CUpDownClient& client,const reach::DirectSessionRoute& route) {
        auto check=[](bool good) { if(!good) throw std::runtime_error("actual authenticated TCP observation exact binding"); };
        const auto now=static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        reach::NativeDirectCandidateSnapshotV1 source; source.local_generation=manager.GetTopologyGeneration(); source.count=1;
        std::array<uint8,16> hash{}; memcpy(hash.data(),client.GetUserHash(),16); source.peer.expected_user_hash=hash;
        source.candidates[0].route=route.candidate; source.candidates[0].route.evidence=reach::DirectEvidence::Advertised;
        source.candidates[0].route.expires_monotonic_ms=now+15000;
        auto apply=[&](auto snapshot,uint64 lifetime,uint64 when) { manager.ApplyDirectTcpObservations(snapshot,lifetime,when); return snapshot; };
        const auto observed=apply(source,client.GetDirectClientLifetime(),now);
        check(observed.candidates[0].route.evidence==reach::DirectEvidence::Observed &&
            observed.candidates[0].route.expires_monotonic_ms<=route.candidate.expires_monotonic_ms);
        auto different=source; ++different.candidates[0].route.port;
        check(apply(different,client.GetDirectClientLifetime(),now).candidates[0].route.evidence==reach::DirectEvidence::Advertised);
        different=source; (*different.peer.expected_user_hash)[0]^=1;
        check(apply(different,client.GetDirectClientLifetime(),now).candidates[0].route.evidence==reach::DirectEvidence::Advertised);
        different=source; ++different.local_generation;
        check(apply(different,client.GetDirectClientLifetime(),now).candidates[0].route.evidence==reach::DirectEvidence::Advertised);
        different=source; different.candidates[0].route.transport_mask=reach::DirectTcp|reach::DirectQuic;
        check(apply(different,client.GetDirectClientLifetime(),now).candidates[0].route.evidence==reach::DirectEvidence::Advertised);
        check(apply(source,client.GetDirectClientLifetime()+1,now).candidates[0].route.evidence==reach::DirectEvidence::Advertised &&
            apply(source,client.GetDirectClientLifetime(),now+15001).candidates[0].route.evidence==reach::DirectEvidence::Advertised);
		auto udpOnly=source; udpOnly.candidates[0].route.transport_mask=reach::DirectQuic;
		check(manager.GatherDirectTcpObservations(udpOnly,client.GetDirectClientLifetime(),now) && udpOnly.count==2 &&
			udpOnly.candidates[0].route.evidence==reach::DirectEvidence::Advertised &&
			udpOnly.candidates[0].route.transport_mask==reach::DirectQuic &&
			udpOnly.candidates[1].route.transport_mask==reach::DirectTcp &&
			udpOnly.candidates[1].route.evidence==reach::DirectEvidence::Observed &&
			udpOnly.candidates[1].route.id!=udpOnly.candidates[0].route.id &&
			udpOnly.candidates[1].source==reach::DirectCandidateSource::Observed);
		check(manager.GatherDirectTcpObservations(udpOnly,client.GetDirectClientLifetime(),now) && udpOnly.count==2);
		auto expired=source; expired.count=0;
		check(manager.GatherDirectTcpObservations(expired,client.GetDirectClientLifetime(),now+15001) && expired.count==0);
		expired=source; expired.count=0; (*expired.peer.expected_user_hash)[0]^=1;
		check(manager.GatherDirectTcpObservations(expired,client.GetDirectClientLifetime(),now) && expired.count==0);
    }
    static CClientReqSocket* LegacyConsumerSocket(CDirectReachabilityManager& manager,reach::DirectHandle handle,uint32 route) {
        if(!manager.m_builtinQuicConsumer) return nullptr;
        const auto* entry=manager.m_builtinQuicConsumer->Find(handle,route);
        return entry ? entry->socket : nullptr;
    }
    static bool HasLegacyReservation(CDirectReachabilityManager& manager,reach::DirectHandle handle,uint32 route) {
        return manager.m_builtinQuicConsumer && manager.m_builtinQuicConsumer->Find(handle,route)!=nullptr;
    }
    static void FailLegacyReservationsForTest(CDirectReachabilityManager& manager,reach::DirectHandle handle) {
        if(!theApp.m_bReachBindingSelfTest || !manager.m_builtinQuicConsumer) throw std::runtime_error("legacy reservation failure fixture guard");
        manager.m_builtinQuicConsumer->Fail(handle,reach::DirectReason::NoRoute);
    }
    static void SeedLegacyPendingRange(CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest || !client.m_PendingBlocks_list.IsEmpty())
            throw std::runtime_error("isolated pending range fixture");
        auto block=std::make_unique<Requested_Block_Struct>();
        block->StartOffset=4096; block->EndOffset=8192; block->transferred=1024;
        auto pending=std::make_unique<Pending_Block_Struct>();
        pending->block=block.get(); pending->totalUnzipped=1024;
        client.m_PendingBlocks_list.AddTail(pending.get()); block.release(); pending.release();
    }
    static void ReserveLegacyFile(CUpDownClient& client,CPartFile& file) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("legacy file explicit lab");
        client.ClearDownloadBlockRequests(); client.SetRequestFile(&file);
        auto block=std::make_unique<Requested_Block_Struct>();
        block->StartOffset=0; block->EndOffset=4096; block->transferred=0;
        memcpy(block->FileID,file.GetFileHash(),16);
        auto pending=std::make_unique<Pending_Block_Struct>(); pending->block=block.get();
        client.m_PendingBlocks_list.AddTail(pending.get()); block.release(); pending.release();
        client.SetDownloadState(DS_DOWNLOADING);
    }
    static std::array<uint64,5> LegacyPendingRange(const CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest || client.m_PendingBlocks_list.GetCount()!=1)
            throw std::runtime_error("owned pending range still present");
        const auto* pending=client.m_PendingBlocks_list.GetHead();
        return {1,pending->block->StartOffset,pending->block->EndOffset,pending->block->transferred,pending->totalUnzipped};
    }
    static HWND LegacySocketWindow(CClientReqSocket& socket) { return socket.GetHelperWindowHandle(); }
    static uint64 LegacyParsedBlocks(const CClientReqSocket& socket) { return socket.m_legacyLabParsedBlocks; }
    static bool LegacyHelloPreflight(const CClientReqSocket& socket,const BYTE* bytes,uint32 size) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit legacy HELLO preflight inspection");
        return socket.ValidateDirectHelloIdentity(bytes,size,false);
    }
    static bool LegacyHelloPacket(CClientReqSocket& socket,const BYTE* bytes,uint32 size) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit legacy HELLO packet fixture");
        return socket.ProcessPacket(bytes,size,OP_HELLOANSWER);
    }
    static bool HasPackedError(const CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit packed error inspection");
        for(POSITION pos=client.m_PendingBlocks_list.GetHeadPosition();pos;)
            if(client.m_PendingBlocks_list.GetNext(pos)->fZStreamError) return true;
        return false;
    }
    static bool HasLegacyInflater(const CUpDownClient& client) {
        for(POSITION pos=client.m_PendingBlocks_list.GetHeadPosition();pos;)
            if(client.m_PendingBlocks_list.GetNext(pos)->zStream) return true;
        return false;
    }
    static void TestPackedLimits(CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit packed limit test");
        auto check=[](bool valid) { if(!valid) throw std::runtime_error("production packed expansion limit"); };
        auto encode=[&](const std::vector<BYTE>& input) {
            uLongf size=compressBound(static_cast<uLong>(input.size())); std::vector<BYTE> encoded(size);
            check(compress2(encoded.data(),&size,input.data(),static_cast<uLong>(input.size()),1)==Z_OK);
            encoded.resize(size); return encoded;
        };
        struct Output { BYTE* bytes=new BYTE[8]; ~Output() { delete[] bytes; } };
        struct Stream {
            Requested_Block_Struct range{}; Pending_Block_Struct pending{};
            explicit Stream(uint64 length) { range.EndOffset=length-1; pending.block=&range; }
            ~Stream() { if(pending.zStream) { inflateEnd(pending.zStream); delete pending.zStream; } }
        };
        std::vector<BYTE> expected(512),actual;
        for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i%251);
        const auto encoded=encode(expected); Stream valid(expected.size());
        for(size_t offset=0;offset<encoded.size();) {
            const auto count=(std::min)(size_t(7),encoded.size()-offset);
            Output output; uint32 produced=static_cast<uint32>((std::min)(uint64(8),uint64(expected.size()-valid.pending.totalUnzipped+1)));
            check(client.unzip(&valid.pending,encoded.data()+offset,static_cast<uint32>(count),&output.bytes,&produced)==Z_OK);
            check(produced<=expected.size()-actual.size());
            actual.insert(actual.end(),output.bytes,output.bytes+produced); offset+=count;
        }
        check(actual==expected && valid.pending.totalUnzipped==expected.size());
        for(const bool trailing : {false,true}) {
            auto malformed=encoded;
            if(trailing) malformed.push_back(0x7f); else malformed.back()^=1;
            Stream invalid(expected.size()); Output rejected; uint32 returned=8;
            check(client.unzip(&invalid.pending,malformed.data(),static_cast<uint32>(malformed.size()),&rejected.bytes,&returned)==Z_DATA_ERROR);
            check(returned==0);
        }
        const auto bomb=encode(std::vector<BYTE>(2048,0)); Stream limited(32); Output output; uint32 produced=8;
        check(client.unzip(&limited.pending,bomb.data(),static_cast<uint32>(bomb.size()),&output.bytes,&produced)==Z_DATA_ERROR);
        check(produced==0 && limited.pending.zStream && limited.pending.zStream->total_out<=33);
    }
    static uint64 DirectOwner(const CClientReqSocket& socket) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit native owner inspection");
        return socket.m_directPeerOwner;
    }
    static void CheckNativeTimeoutDelegation(CClientReqSocket& socket) {
        if(!theApp.m_bReachBindingSelfTest || theApp.m_strQuicPairSelfTestRole.IsEmpty() ||
            !socket.m_directPeerOwner || !socket.HasDirectTransferAuthority(socket.m_directPeerHandle))
            throw std::runtime_error("native timeout regression requires live authenticated pair adapter");
        const DWORD saved=socket.timeout_timer;
        socket.timeout_timer=GetTickCount()-600000;
        const bool expired=socket.CheckTimeOut();
        socket.timeout_timer=saved;
        if(expired) throw std::runtime_error("native QUIC adapter must not expire through classic TCP timer");
        Log(_T("QUIC_PAIR NATIVE_TCP_TIMEOUT_DELEGATION PASS stale_tcp_timer=600000"));
    }
    static std::optional<reach::DirectSubscriber> PairSubscriber(CDirectReachabilityManager& manager,uint64 lifetime) {
        if(!theApp.m_bReachBindingSelfTest || theApp.m_strQuicPairSelfTestRole.IsEmpty())
            throw std::runtime_error("explicit pair subscriber inspection");
        return manager.m_directSubscribers->FindLifetime(lifetime);
    }
    static bool PairRequestsExcludeParts(const CUpDownClient& client,const std::vector<UINT>& parts) {
        if(!theApp.m_bReachBindingSelfTest || theApp.m_strQuicPairSelfTestRole.IsEmpty()) return false;
        for(POSITION pos=client.m_PendingBlocks_list.GetHeadPosition();pos;) {
            const auto* pending=client.m_PendingBlocks_list.GetNext(pos);
            if(!pending || !pending->block) return false;
            for(const auto part:parts) if(pending->block->StartOffset<(uint64(part)+1)*PARTSIZE &&
                pending->block->EndOffset>uint64(part)*PARTSIZE) return false;
        }
        return true;
    }
    static void SetReaskTimestamp(CUpDownClient& client,CPartFile& file,DWORD timestamp) {
        if(!theApp.m_bReachBindingSelfTest || client.GetRequestFile()!=&file || !timestamp)
            throw std::runtime_error("explicit reask timestamp fixture prerequisites");
        client.m_fileReaskTimes[&file]=timestamp;
    }
    static void SetConnectTimestamp(CUpDownClient& client,DWORD timestamp) {
        if(!theApp.m_bReachBindingSelfTest || !timestamp)
            throw std::runtime_error("explicit connect timestamp fixture prerequisites");
        client.m_dwLastTriedToConnect=timestamp;
    }
    static unsigned PendingBlocks(const CUpDownClient& client) {
        if(!theApp.m_bReachBindingSelfTest) throw std::runtime_error("explicit pending block inspection");
        return static_cast<unsigned>(client.m_PendingBlocks_list.GetCount());
    }
};

namespace ese { namespace shared_socket_selftest {
inline void Require(bool value,const char* stage) {
    if(!value) throw std::runtime_error(stage);
}
inline std::uint64_t Now() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
struct Identity final : QuicIdentitySigner {
    std::array<std::uint8_t,32> pub{},priv{};
    bool corrupt=false;
    Identity() { Require(eSELive::GenerateBroadcasterKeypair(pub.data(),priv.data()),"peer keypair"); }
    ~Identity() { SecureZeroMemory(priv.data(),priv.size()); }
    bool Sign(const std::uint8_t* data,std::size_t size,std::uint8_t* sig) noexcept override {
        const bool signedMessage=eSELive::SignMessage(priv.data(),pub.data(),data,size,sig);
        if(signedMessage && corrupt) sig[0]^=1;
        return signedMessage;
    }
};
struct Probe final : udp::Inspector {
    udp::Match Control(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    udp::Match Utp(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    bool QuicHeader(const std::uint8_t* p,std::size_t n,std::size_t cid,udp::Header& h) const noexcept override { return udp::DecodeQuicHeader(p,n,cid,h); }
    bool AcceptInitial(const std::uint8_t* p,std::size_t n) const noexcept override { return udp::AcceptQuicInitial(p,n); }
};
struct Port final : QuicSocketPort {
    SOCKET socket=INVALID_SOCKET;
    udp::Endpoint endpoint;
    QuicUdpIngress* ingress=nullptr;
    std::unique_ptr<test::SimulatedQuicPort> memory;
    test::SimulatedQuicPort* pairedMemory=nullptr;
    explicit Port(bool simulated=false) {
        if(simulated) {
            endpoint.address[0]=8; endpoint.address[1]=8; endpoint.address[2]=8; endpoint.address[3]=8;
            endpoint.port=0x1234; memory=std::make_unique<test::SimulatedQuicPort>(endpoint); return;
        }
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        Require(socket!=INVALID_SOCKET,"peer socket");
        try {
            sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            Require(bind(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"peer bind");
            int size=sizeof(address);
            Require(getsockname(socket,reinterpret_cast<sockaddr*>(&address),&size)==0,"peer bound port");
            endpoint.address[0]=127; endpoint.address[3]=1; endpoint.port=ntohs(address.sin_port);
            u_long nonblock=1;
            Require(ioctlsocket(socket,FIONBIO,&nonblock)==0,"peer nonblock");
        } catch(...) { closesocket(socket); socket=INVALID_SOCKET; throw; }
    }
    ~Port() {
        if(memory) { if(ingress) memory->DetachQuicIngress(ingress); return; }
        if(ingress) { auto* old=ingress; ingress=nullptr; old->SocketReset(); }
        if(socket!=INVALID_SOCKET) closesocket(socket);
    }
    bool AttachQuicIngress(QuicUdpIngress* value) override {
        if(!value || ingress) return false;
        if(memory && !memory->AttachQuicIngress(value)) return false;
        ingress=value; return true;
    }
    bool DetachQuicIngress(QuicUdpIngress* value) override {
        if(!value || ingress!=value) return false;
        if(memory) { ingress=nullptr; return memory->DetachQuicIngress(value); }
        ingress=nullptr; value->SocketReset(); return true;
    }
    QuicUdpSendResult SendQuicDatagram(QuicUdpIngress* value,const udp::Endpoint& peer,
        const std::uint8_t* data,std::size_t size) override {
        if(memory) return memory->SendQuicDatagram(value,peer,data,size);
        if(value!=ingress || !data || !size || size>1200 || peer.ipv6 || !peer.port)
            return {QuicUdpSendStatus::Invalid,0};
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(peer.port);
        memcpy(&address.sin_addr,peer.address.data(),4);
        const int sent=sendto(socket,reinterpret_cast<const char*>(data),static_cast<int>(size),0,
            reinterpret_cast<sockaddr*>(&address),sizeof(address));
        if(sent==static_cast<int>(size)) return {QuicUdpSendStatus::Sent,0};
        const auto error=static_cast<std::uint32_t>(WSAGetLastError());
        return {error==WSAEWOULDBLOCK ? QuicUdpSendStatus::WouldBlock : QuicUdpSendStatus::Failed,error};
    }
    void Receive() {
        if(memory) {
            memory->Deliver();
            if(pairedMemory) { pairedMemory->Deliver(); pairedMemory->Poll(Now()); }
            return;
        }
        std::array<std::uint8_t,2048> bytes{};
        for(unsigned i=0;i<128;++i) {
            sockaddr_in source{}; int size=sizeof(source);
            const int n=recvfrom(socket,reinterpret_cast<char*>(bytes.data()),static_cast<int>(bytes.size()),0,
                reinterpret_cast<sockaddr*>(&source),&size);
            if(n==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"peer receive"); return; }
            udp::Endpoint peer; memcpy(peer.address.data(),&source.sin_addr,4); peer.port=ntohs(source.sin_port);
            Require(ingress && ingress->Receive(peer,{bytes.data(),static_cast<std::size_t>(n)}),"peer ingress");
        }
    }
};
inline reach::DirectSessionRoute Route(const udp::Endpoint& remote,std::uint64_t topology) {
    reach::DirectSessionRoute route; route.id=3; route.transport=reach::DirectQuic;
    route.candidate.family=4; route.candidate.address=remote.address; route.candidate.port=remote.port;
    route.candidate.transport_mask=reach::DirectQuic; route.candidate.topology_generation=topology;
    route.candidate.expires_monotonic_ms=Now()+10000; return route;
}
inline QuicPeerConfig Config(const std::array<std::uint8_t,32>& local,
    const std::array<std::uint8_t,32>& remote,const reach::DirectAttemptId& attempt,
    const std::array<std::uint8_t,32>& nonce,bool server,std::uint64_t topology) {
    QuicPeerConfig config; config.local.node=local; config.local.role=server ? 1 : 0;
    config.local.nonce=nonce; config.local.attempt=attempt; config.local.caps=1;
    config.local.topologyGeneration=topology; config.expectedNode=remote; config.pin=remote;
    config.hasPin=true; config.persistent=true; return config;
}
inline void Advance(reach::DirectCoordinator& core,reach::DirectHandle handle,
    reach::DirectEventQueue& events,QuicTransport& transport) {
    const auto batch=core.Advance(handle,Now(),events.Drain());
    for(const auto& action:batch.actions) if(action.type==reach::DirectActionType::Attach)
        Require(transport.AdoptWinner(handle,action.route_id,action.session_epoch),"DCO winner adoption");
}
inline void VerifyDisk(QuicTransport& transport,reach::DirectCoordinator& core,
    reach::DirectEventQueue& events,reach::DirectHandle handle,std::uint64_t owner,
    std::uint64_t topology,const std::array<std::uint8_t,4096>& expected,
    const std::array<std::uint8_t,4096>& received) {
    reach::DirectFileKey file; file.lifetime=reach::NextDirectFileLifetime();
    Require(CKnownFile::CreateHash(expected.data(),static_cast<UINT>(expected.size()),file.hash.data()),"fixture expected MD4");
    auto ledger=std::make_unique<reach::DirectPartContributions>();
    const reach::DirectPartContributor source{owner,handle,3,1,topology};
    Require(ledger->Record(file,0,source,received.size()),"received session provenance");
    const auto snapshot=ledger->Snapshot(file,0,1);
    Require(snapshot.size()==1 && snapshot[0].bytes==received.size(),"owned hash snapshot");
    CString path=thePrefs.GetTempDir();
    Require(path.Left(7).CompareNoCase(_T("D:\\tmp\\"))==0,"isolated disk fixture path");
    path+=_T("\\native-shared-received.part");
    Require(GetFileAttributes(path)==INVALID_FILE_ATTRIBUTES,"fresh received fixture");
    {
        CFile disk(path,CFile::modeCreate|CFile::modeWrite|CFile::shareExclusive);
        disk.Write(received.data(),static_cast<UINT>(received.size())); disk.Flush(); disk.Close();
    }
    PartHashJob_Struct job{}; job.sFilePath=path; job.uLength=received.size();
    job.uGen=1; job.fileLifetime=file.lifetime; job.bNoAICH=true;
    const auto verdict=CPartHashThread::ComputeJob(job);
    Require(verdict && !verdict->bReadError && verdict->fileLifetime==file.lifetime
        && verdict->uGen==1 && !memcmp(verdict->aMD4Hash,file.hash.data(),file.hash.size()),"received disk MD4");
    Require(!ledger->TakeVerified(snapshot[0],1,reach::PartVerification::Corrupt)
        && !transport.ReportVerifiedPart(reach::PartVerification::Corrupt),"corrupt proof forbidden");
    const auto receipt=ledger->TakeVerified(snapshot[0],verdict->uGen,reach::PartVerification::Verified);
    Require(receipt && receipt->source.owner==owner && receipt->source.epoch==1
        && transport.AllowsDelivery(handle,3,1) && transport.ReportVerifiedPart(reach::PartVerification::Verified),"session correlated disk proof");
    Require(!ledger->TakeVerified(snapshot[0],1,reach::PartVerification::Verified)
        && !transport.ReportVerifiedPart(reach::PartVerification::Verified),"single-use verified proof");
    Advance(core,handle,events,transport);
    const auto state=core.Snapshot(handle);
    Require(state && state->transfer_verified && state->state==reach::DirectSessionState::Transferring
        && state->useful_bytes==received.size(),"DCO verified part preserves useful accounting");
}
inline void Run(CClientUDPSocket& socket,std::uint64_t topology,bool rejectPeer=false) {
    Require(topology && socket.GetConnectedPort(),"shared socket bound");
    Require(eSELive::NodeIdentityInit() && eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub(),"persistent host identity");
    std::array<std::uint8_t,32> local{}; memcpy(local.data(),eSELive::NodeIdentityPub(),local.size());
    Identity identity,entropy; Port port; Probe probe;
    identity.corrupt=rejectPeer;
    reach::DirectAttemptId attempt{}; memcpy(attempt.data(),entropy.pub.data(),attempt.size());
    auto pool=std::make_unique<reach::DirectBufferPool>();
    auto events=std::make_unique<reach::DirectEventQueue>();
    auto peerEvents=std::make_unique<reach::DirectEventQueue>();
    auto core=std::make_unique<reach::DirectCoordinator>();
    auto peerCore=std::make_unique<reach::DirectCoordinator>();
    control::PacketBudget budget;
    auto host=CreateQuicSessionHost(socket,*pool,*events,budget);
    Require(host && host->Empty(),"shared host factory");
    QuicSocketOwner peer(port,probe,*pool,*peerEvents);
    struct Cleanup {
        QuicSessionHost& host; QuicSocketOwner& peer;
        reach::DirectEventQueue& events; reach::DirectEventQueue& peerEvents;
        ~Cleanup() { host.Stop(); peer.Stop(); events.Drain(); peerEvents.Drain(); host.Poll(Now()); peer.Poll(Now()); host.RetireClosed(); peer.RetireClosed(); }
    } cleanup{*host,peer,*events,*peerEvents};
    Require(peer.Attach(),"peer attach");
    udp::Endpoint endpoint; endpoint.address[0]=127; endpoint.address[3]=1; endpoint.port=socket.GetConnectedPort();
    const auto route=Route(port.endpoint,topology),peerRoute=Route(endpoint,topology);
    reach::DirectPeerKey key; key.domain=reach::DirectPeerDomain::NodePublicKey; key.identity=identity.pub;
    const auto admitted=core->Request(key,1,attempt,topology,Now()); key.identity=local;
    const auto peerAdmitted=peerCore->Request(key,1,attempt,topology,Now());
    Require(admitted.status==reach::DirectRequestStatus::Created && peerAdmitted.status==reach::DirectRequestStatus::Created,"DCO admission");
    core->SetRoutes(admitted.handle,{route},Now()); peerCore->SetRoutes(peerAdmitted.handle,{peerRoute},Now());
    Require(core->AuthorizesStart(admitted.handle,route,0) && peerCore->AuthorizesStart(peerAdmitted.handle,peerRoute,0),"DCO start authorization");
    const auto peerId=peer.Begin({port.endpoint,true},Config(identity.pub,local,attempt,identity.pub,true,topology),peerAdmitted.handle,peerRoute,&identity);
    const auto id=host->Begin({endpoint,false},Config(local,identity.pub,attempt,entropy.pub,false,topology),admitted.handle,route);
    auto* client=host->Find(id); auto* server=peer.Find(peerId);
    Require(id && peerId && client && server,"native sessions start");
    client->SetReceiveBudget(4096); server->SetReceiveBudget(4096);
    const std::uint8_t early=1;
    Require(client->Send({&early,1}).status==reach::DirectIoStatus::WouldBlock && !client->ReportUsefulBytes(1),"pre-auth data forbidden");
    std::array<std::uint8_t,4096> data{},receivedData{};
    for(std::size_t i=0;i<data.size();++i) data[i]=static_cast<std::uint8_t>(i%251);
    std::size_t sent=0,received=0,reverseSent=0,reverseReceived=0;
    const auto deadline=Now()+8000;
    while(Now()<deadline) {
        // Dispatch only MFC's socket notifications, not UI timers or arbitrary
        // main-window messages. OnReceive remains the real production handler.
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i)
            DispatchMessage(&message);
        port.Receive(); host->Poll(Now()); peer.Poll(Now());
        Advance(*core,admitted.handle,*events,*client); Advance(*peerCore,peerAdmitted.handle,*peerEvents,*server);
        if(rejectPeer) {
            Require(!client->Ready() && !client->ReceivedFront().size && !server->ReceivedFront().size
                && !client->ReportUsefulBytes(1),"bad signature must not permit host delivery");
            if(client->Snapshot().closed) break;
            Sleep(1); continue;
        }
        Require(!client->Snapshot().closed && !server->Snapshot().closed,"native session unexpectedly closed");
        if(client->AllowsDelivery(admitted.handle,route.id,1) && server->AllowsDelivery(peerAdmitted.handle,peerRoute.id,1)) {
            if(sent<data.size()) sent+=client->Send({data.data()+sent,data.size()-sent}).accepted;
            if(reverseSent<data.size()) reverseSent+=server->Send({data.data()+reverseSent,data.size()-reverseSent}).accepted;
        }
        auto consume=[&data,&receivedData,client](QuicTransport& transport,std::size_t& count) {
            const auto bytes=transport.ReceivedFront();
            Require(bytes.size<=data.size()-count && (!bytes.size || memcmp(bytes.data,data.data()+count,bytes.size)==0),"native payload mismatch");
            if(&transport==client && bytes.size) memcpy(receivedData.data()+count,bytes.data,bytes.size);
            count+=bytes.size; Require(transport.ConsumeReceived(bytes.size),"native consume");
            if(bytes.size) Require(transport.ReportUsefulBytes(bytes.size),"native useful progress");
        };
        consume(*server,received); consume(*client,reverseReceived);
        if(received==data.size() && reverseReceived==data.size()) break;
        Sleep(1);
    }
    Advance(*core,admitted.handle,*events,*client); Advance(*peerCore,peerAdmitted.handle,*peerEvents,*server);
    const auto state=core->Snapshot(admitted.handle),peerState=peerCore->Snapshot(peerAdmitted.handle);
    if(rejectPeer) {
        Require(client->Snapshot().closed && state && state->state==reach::DirectSessionState::Failed
            && state->reason==reach::DirectReason::IdentityMismatch && !state->winner
            && !state->useful_bytes && !state->transfer_verified,"bad signature typed DCO failure");
    } else {
        Require(sent==data.size() && received==data.size() && reverseSent==data.size() && reverseReceived==data.size(),"native bidirectional deadline");
        Require(state && peerState && state->state==reach::DirectSessionState::Transferring && peerState->state==reach::DirectSessionState::Transferring
            && state->useful_bytes==data.size() && peerState->useful_bytes==data.size()
            && !state->transfer_verified && !peerState->transfer_verified,"DCO useful is not file integrity");
        VerifyDisk(*client,*core,*events,admitted.handle,id,topology,data,receivedData);
    }
    Require(socket.GetConnectedPort()==endpoint.port,"shared UDP port unchanged");
    host->Stop(); peer.Stop(); events->Drain(); peerEvents->Drain();
    host->Poll(Now()); peer.Poll(Now()); host->RetireClosed(); peer.RetireClosed();
    Require(host->Empty() && peer.Empty() && !pool->Used(),"native session resource drain");
}
enum class HelloCase { Valid, ChangedHash, ChangedNode, MissingNode, DuplicateNode, Truncated, PreHelloData };
inline void RunContactRefresh(CDirectReachabilityManager& manager,std::uint16_t portNumber,bool revokeSession=false,bool allAckBad=false,bool automaticGet=false,bool automaticFind=false,bool dropFind=false,bool dropGet=false) {
    Require(theApp.m_bReachBindingSelfTest && theApp.clientudp,"contact refresh explicit fixture");
    struct Restore {
        CDirectReachabilityManager& manager;
        int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        uint16 port=thePrefs.GetUDPPort();
        ~Restore() { manager.ShutdownQuicHost(); manager.DirectControlSessions()=control::Sessions{};
            thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled);
            thePrefs.SetUDPPort(port); theApp.clientudp->Rebind(); }
    } restore{manager};
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    thePrefs.SetUDPPort(portNumber); Require(theApp.clientudp->Rebind(),"contact UDP rebind");
    manager.TickDirectConnections(); Require(manager.EnableNativeQuicLab(),"contact shared host");
    struct Signer final : control::Signer {
        Identity identity;
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return identity.Sign(p,n,out.data());
        }
    } witness;
    struct Requester final : control::Signer {
        struct Node { std::array<std::uint8_t,32> pub{}; } identity;
        Requester() { Require(eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub(),"contact persistent requester");
            memcpy(identity.pub.data(),eSELive::NodeIdentityPub(),32); }
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return eSELive::NodeIdentitySign(p,n,out.data());
        }
    } requester;
    Port peer;
    auto hooks=MakeKad6HostCryptoHooks();
    hooks.ed25519_sign=[](const kad6::Byte* sk,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* sig) -> bool {
        return n==64 && eSELive::SignMessage(sk,sk+32,p,size,sig);
    };
    struct Secret { std::array<std::uint8_t,64> bytes{}; ~Secret() { SecureZeroMemory(bytes.data(),bytes.size()); } } secret;
    memcpy(secret.bytes.data(),witness.identity.priv.data(),32); memcpy(secret.bytes.data()+32,witness.identity.pub.data(),32);
    const auto utc=static_cast<std::uint64_t>(std::time(nullptr)); Require(utc>1,"contact UTC");
    kad6::K6RouterRecord record; record.node_pub=witness.identity.pub; record.kad_id[0]=1;
    record.epoch=7; record.caps=1; record.valid_from=utc-1; record.valid_until=utc+120;
    kad6::K6Endpoint endpoint; endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr[0]=203; endpoint.addr.addr[2]=113; endpoint.addr.addr[3]=8;
    endpoint.udp_port=123; endpoint.transport_flags=kad6::kK6EpUdpKad6; endpoint.valid_until=record.valid_until;
    record.endpoints.push_back(endpoint);
    std::vector<kad6::Byte> bytes;
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok,"contact old record sign");
    Require(manager.ImportDirectKad6Contact(record.node_pub,bytes.data(),bytes.size()),"contact old record import");
    const auto bootstrapOwner=manager.BeginDirectControlBootstrap(record.node_pub,peer.endpoint,Now()+2000);
    Require(bootstrapOwner!=0,"contact real bootstrap admission");
    control::CookieAuthority authority; control::ChallengeLimit challengeLimit; control::Sessions peerSessions;
    Require(authority.Initialize(),"contact peer cookie authority");
    control::Header bootstrap; std::array<std::uint8_t,32> proof{}; proof[0]=1;
    const auto bootstrapDeadline=Now()+(allAckBad ? 2200 : 1500);
    unsigned probes=0,proves=0,adoptions=0,duplicates=0;
    const auto bootstrapRejected=manager.RejectedDirectControlReplies(); bool sawAckRejection=false;
    control::Datagram firstProve;
    while(Now()<bootstrapDeadline && !manager.DirectControlBootstrapReady(bootstrapOwner)) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        if((revokeSession || allAckBad) && !sawAckRejection && manager.RejectedDirectControlReplies()>bootstrapRejected) {
            Require(!manager.DirectControlBootstrapReady(bootstrapOwner),"corrupt ACK cannot grant bootstrap ready");
            sawAckRejection=true;
        }
        control::Datagram incoming,response; sockaddr_in origin{}; int originSize=sizeof(origin);
        const int length=recvfrom(peer.socket,reinterpret_cast<char*>(incoming.bytes.data()),static_cast<int>(incoming.bytes.size()),0,reinterpret_cast<sockaddr*>(&origin),&originSize);
        if(length==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"bootstrap peer receive"); Sleep(1); continue; }
        udp::Endpoint observed; memcpy(observed.address.data(),&origin.sin_addr,4); observed.port=ntohs(origin.sin_port);
        control::Envelope envelope;
        Require(control::ParseUntrusted(incoming.bytes.data(),static_cast<std::size_t>(length),envelope),"bootstrap envelope");
        if(envelope.header.type==wire::kEseWireUdpProbe) {
            ++probes;
            Require(control::BuildChallenge(authority,challengeLimit,observed,record.node_pub,requester.identity.pub,incoming.bytes.data(),static_cast<std::size_t>(length),Now(),response),"bootstrap real challenge");
            if(allAckBad && probes==1) continue; // loss before response submission
        } else {
            Require(envelope.header.type==wire::kEseWireUdpProve,"bootstrap expected PROVE"); ++proves;
            control::Prove verified;
            const auto admission=control::AdmitProve(authority,peerSessions,observed,record.node_pub,requester.identity.pub,incoming.bytes.data(),static_cast<std::size_t>(length),Now(),verified);
            Require(admission==control::Admission::Accepted || admission==control::Admission::Duplicate,"bootstrap real cookie/signature admission");
            if(admission==control::Admission::Accepted) { ++adoptions; firstProve=incoming; firstProve.size=static_cast<std::size_t>(length); }
            else { ++duplicates; Require(firstProve.size==static_cast<std::size_t>(length) && !memcmp(firstProve.bytes.data(),incoming.bytes.data(),firstProve.size),"bootstrap retry byte exact"); }
            bootstrap=envelope.header;
            Require(control::BuildAck(verified,bootstrap,0,record.node_pub,witness,response),"bootstrap real ACK sign");
            if(allAckBad || (revokeSession && proves==1)) response.bytes[response.size-1]^=1;
        }
        Require(sendto(peer.socket,reinterpret_cast<const char*>(response.bytes.data()),static_cast<int>(response.size),0,reinterpret_cast<const sockaddr*>(&origin),originSize)==static_cast<int>(response.size),"bootstrap peer response");
    }
    if(allAckBad) {
        Require(probes==2 && proves==3 && adoptions==1 && duplicates==2 && sawAckRejection,"bootstrap bounded lost challenge/all bad ACK retries");
        Require(manager.RejectedDirectControlReplies()==bootstrapRejected+3 && !manager.DirectControlBootstrapReady(bootstrapOwner),"bootstrap deadline no Ready");
        Require(!manager.DirectControlSessions().Current(record.node_pub,peer.endpoint,bootstrap,Now()),"bootstrap deadline no session");
        kad6::K6RouterRecord unchanged;
        Require(manager.FreshDirectKad6Contact(record.node_pub,unchanged) && unchanged.epoch==record.epoch,"bootstrap deadline no cache mutation");
        const auto retryOwner=manager.BeginDirectControlBootstrap(record.node_pub,peer.endpoint,Now()+2000);
        Require(retryOwner>bootstrapOwner,"bootstrap deadline releases owned attempt for fresh context");
        manager.CancelDirectControlBootstrap();
        return;
    }
    Require(probes==1 && proves==(revokeSession ? 2U : 1U) && adoptions==1 && duplicates==(revokeSession ? 1U : 0U) &&
        (!revokeSession || sawAckRejection) && manager.DirectControlBootstrapReady(bootstrapOwner),"bootstrap real retry single adoption completion");
    Require(manager.DirectControlSessions().Current(record.node_pub,peer.endpoint,bootstrap,Now()),"bootstrap manager live ledger");
    auto request=bootstrap; request.type=wire::kEseWireUdpK6ContactGet; ++request.sequence;
    control::Datagram get; Require(control::BuildContactGet(request,requester.identity.pub,requester,get),"contact GET sign");
    const auto owner=manager.PrepareDirectKad6ContactRefresh(record.node_pub,peer.endpoint,requester.identity.pub,get,Now()+2000);
    Require(owner!=0,"contact owner admission");
    Require(manager.SendDirectKad6ContactRefresh(owner).status==QuicUdpSendStatus::Sent,"contact GET shared send");
    control::Datagram received; sockaddr_in source{}; int sourceSize=sizeof(source); int count=SOCKET_ERROR;
    const auto deadline=Now()+1500;
    while(Now()<deadline && count==SOCKET_ERROR) {
        count=recvfrom(peer.socket,reinterpret_cast<char*>(received.bytes.data()),static_cast<int>(received.bytes.size()),0,reinterpret_cast<sockaddr*>(&source),&sourceSize);
        if(count==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"contact GET receive"); Sleep(1); }
    }
    Require(count==static_cast<int>(get.size) && !memcmp(received.bytes.data(),get.bytes.data(),get.size),"contact actual GET exact");
    std::array<std::uint8_t,32> digest{};
    Require(control::ContactGetDigest(requester.identity.pub,received.bytes.data(),get.size,digest),"contact GET digest");
    ++record.epoch;
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok,"contact new record sign");
    control::Datagram result;
    Require(control::BuildContactResult(request,requester.identity.pub,digest,bytes.data(),bytes.size(),record.node_pub,witness,hooks,utc,result),"contact result sign");
    auto corrupt=result; corrupt.bytes[corrupt.size-1]^=1;
    const auto rejectedBefore=manager.RejectedDirectControlReplies();
    Require(sendto(peer.socket,reinterpret_cast<const char*>(corrupt.bytes.data()),static_cast<int>(corrupt.size),0,reinterpret_cast<const sockaddr*>(&source),sourceSize)==static_cast<int>(corrupt.size),"contact corrupt response send");
    while(Now()<deadline && manager.RejectedDirectControlReplies()==rejectedBefore) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections(); Sleep(1);
    }
    kad6::K6RouterRecord unchanged;
    Require(manager.RejectedDirectControlReplies()==rejectedBefore+1,"contact corrupt processed rejection");
    Require(manager.FreshDirectKad6Contact(record.node_pub,unchanged) && unchanged.epoch==record.epoch-1,"contact corrupt cache unchanged");
    if(revokeSession) {
        Require(Now()<deadline,"contact revoke before pending deadline");
        manager.DirectControlSessions()=control::Sessions{};
        manager.TickDirectConnections();
        // Do not call Send while absent: its own cancellation would hide a
        // broken pump. Restore first, then test that pump retired the owner.
        Require(manager.DirectControlSessions().AdmitVerified(record.node_pub,peer.endpoint,bootstrap,proof,Now())==control::Admission::Accepted,"contact restore trusted session");
        Require(Now()<deadline,"contact restore before pending deadline");
        Require(manager.SendDirectKad6ContactRefresh(owner).status==QuicUdpSendStatus::Invalid,"contact revoked owner cannot resurrect");
        Require(manager.FreshDirectKad6Contact(record.node_pub,unchanged) && unchanged.epoch==record.epoch-1,"contact revoked cache unchanged");
        Require(theApp.clientudp->GetConnectedPort()==portNumber,"contact revoked shared binding preserved");
        return;
    }
    Require(sendto(peer.socket,reinterpret_cast<const char*>(result.bytes.data()),static_cast<int>(result.size),0,reinterpret_cast<const sockaddr*>(&source),sourceSize)==static_cast<int>(result.size),"contact actual response send");
    kad6::K6RouterRecord cached; bool imported=false;
    while(Now()<deadline && !imported) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        imported=manager.FreshDirectKad6Contact(record.node_pub,cached) && cached.epoch==record.epoch;
        if(!imported) Sleep(1);
    }
    Require(imported,"contact shared ingress manager cache commit");
    Require(manager.SendDirectKad6ContactRefresh(owner).status==QuicUdpSendStatus::Invalid,"contact completed owner single use");
    std::array<std::uint8_t,16> discoveryFile{}; discoveryFile[0]=1;
    Require(manager.BeginDirectKad6Resolution(discoveryFile,123,1000),"discovery manager start");
    Require(manager.AddDirectKad6ResolutionWitness(record.node_pub,peer.endpoint,bootstrap,1),"discovery signed witness live return");
    std::array<discovery::Kad6Lookup::Contact,2> round{};
    if(!automaticFind) Require(manager.BeginDirectKad6FindRound(round)==1 && round[0].node==record.node_pub,"discovery witness selection");
    auto findHeader=request; findHeader.type=wire::kEseWireUdpK6DirectFind; ++findHeader.sequence;
    discovery::DirectFind query; query.file=discoveryFile; query.fileSize=123; query.requester=requester.identity.pub; query.maximum=4;
    control::Datagram find;
    Require(control::BuildDirectFind(findHeader,query,1000,requester,find),"discovery persistent FIND sign");
    uint64 findOwner=0;
    if(automaticFind) Require(manager.EnableDirectKad6AutomaticFinds(),"discovery automatic FIND enable");
    else {
        findOwner=manager.PrepareDirectKad6Find(0,record.node_pub,peer.endpoint,find);
        Require(findOwner && manager.SendDirectKad6Find(findOwner).status==QuicUdpSendStatus::Sent,"discovery manager FIND send");
    }
    control::Datagram observed; int observedSize=SOCKET_ERROR; const auto findDeadline=Now()+1500;
    while(Now()<findDeadline && observedSize==SOCKET_ERROR) {
        if(automaticFind) {
            MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
            manager.TickDirectConnections();
        }
        observedSize=recvfrom(peer.socket,reinterpret_cast<char*>(observed.bytes.data()),static_cast<int>(observed.bytes.size()),0,nullptr,nullptr);
        if(observedSize==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"discovery FIND receive"); Sleep(1); }
    }
    if(automaticFind) {
        discovery::DirectFind receivedQuery;
        Require(observedSize>0 && control::VerifyDirectFind(requester.identity.pub,observed.bytes.data(),
            static_cast<std::size_t>(observedSize),1000,findHeader,receivedQuery),"discovery automatic FIND signature");
        Require(receivedQuery.file==discoveryFile && receivedQuery.fileSize==123 && receivedQuery.maximum==4 &&
            findHeader.sequence>bootstrap.sequence && findHeader.attempt==bootstrap.attempt &&
            findHeader.generation==bootstrap.generation,"discovery automatic FIND correlation");
        Require(control::BuildDirectFind(findHeader,query,1000,requester,find),"discovery automatic FIND oracle");
    }
    Require(observedSize==static_cast<int>(find.size) && !memcmp(observed.bytes.data(),find.bytes.data(),find.size),"discovery actual FIND exact");
    if(dropFind) {
        Require(automaticFind,"discovery lost FIND uses scheduler");
        const auto firstReceived=Now(); observedSize=SOCKET_ERROR;
        while(Now()<findDeadline && observedSize==SOCKET_ERROR) {
            MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
            manager.TickDirectConnections();
            observedSize=recvfrom(peer.socket,reinterpret_cast<char*>(observed.bytes.data()),static_cast<int>(observed.bytes.size()),0,nullptr,nullptr);
            if(observedSize==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"discovery retry FIND receive"); Sleep(1); }
        }
        Require(Now()-firstReceived>=450,"discovery retry FIND not immediate");
        Require(observedSize==static_cast<int>(find.size) && !memcmp(observed.bytes.data(),find.bytes.data(),find.size),"discovery retry FIND original signed bytes");
    }
    std::array<std::uint8_t,159> descriptor{}; memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3;
    descriptor[8]=1; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
    memcpy(descriptor.data()+29,record.node_pub.data(),32);
    discovery::DescriptorSignatureInput descriptorInput; std::array<std::uint8_t,64> descriptorSignature{};
    Require(discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),descriptorInput) &&
        witness.Sign(descriptorInput.bytes.data(),descriptorInput.size,descriptorSignature),"discovery descriptor sign");
    memcpy(descriptor.data()+95,descriptorSignature.data(),64);
    discovery::DirectSource published; published.file=discoveryFile; published.fileSize=123;
    published.node=record.node_pub; published.generation=7; published.serial=1; published.ttl=120;
    Require(control::DescriptorDigest(descriptor.data(),descriptor.size(),published.digest),"discovery descriptor digest");
    std::array<std::uint8_t,173> signedSource{};
    Require(control::BuildDirectSource(published,1000,witness,signedSource),"discovery source sign");
    std::array<std::uint8_t,32> findDigest{};
    Require(control::DirectFindDigest(requester.identity.pub,find.bytes.data(),find.size,1000,findDigest),"discovery FIND digest");
    std::array<discovery::FindEntryView,4> sourceEntries{}; sourceEntries[0]={signedSource.data(),signedSource.size(),120};
    control::Datagram sourceResult;
    Require(control::BuildDirectFindSourcesResult(findHeader,query,findDigest,sourceEntries,1,1000,record.node_pub,witness,sourceResult),"discovery SOURCES sign");
    const auto sendReply=[&](const control::Datagram& response) {
        Require(sendto(peer.socket,reinterpret_cast<const char*>(response.bytes.data()),static_cast<int>(response.size),0,
            reinterpret_cast<const sockaddr*>(&source),sourceSize)==static_cast<int>(response.size),"discovery shared response send");
    };
    discovery::Locator locator; locator.node=published.node; locator.digest=published.digest; locator.serial=1; locator.ttl=119;
    auto descriptorGetHeader=findHeader; descriptorGetHeader.type=wire::kEseWireUdpDescriptorGet; ++descriptorGetHeader.sequence;
    control::Datagram descriptorGet;
    Require(control::BuildDescriptorGet(descriptorGetHeader,discoveryFile,locator,requester.identity.pub,requester,descriptorGet),"discovery persistent GET sign");
    auto badSources=sourceResult; badSources.bytes[badSources.size-1]^=1;
    const auto discoveryRejected=manager.RejectedDirectControlReplies(); sendReply(badSources);
    while(Now()<findDeadline && manager.RejectedDirectControlReplies()==discoveryRejected) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections(); Sleep(1);
    }
    Require(manager.RejectedDirectControlReplies()==discoveryRejected+1,"discovery corrupt SOURCES processed");
    Require(!manager.PrepareDirectKad6DescriptorGet(0,record.node_pub,peer.endpoint,locator,descriptorGet),"discovery corrupt SOURCES grants no GET");
    if(automaticGet) Require(manager.EnableDirectKad6AutomaticGets(),"discovery automatic GET enable");
    sendReply(sourceResult);
    uint64 descriptorOwner=0; bool locatedReady=false;
    while(Now()<findDeadline && !(automaticGet?locatedReady:descriptorOwner!=0)) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        std::array<discovery::Kad6Resolution::LocatedSource,32> located;
        const auto locatedCount=manager.SnapshotDirectKad6LocatedSources(located);
        if(locatedCount) {
            Require(locatedCount==1 && located[0].source.file==discoveryFile && located[0].source.fileSize==123 &&
                located[0].witness==record.node_pub && located[0].witnessEndpoint==peer.endpoint && located[0].locator.ttl<=120,
                "discovery manager located source provenance");
            locator=located[0].locator;
            locatedReady=true;
            if(automaticGet) continue;
            Require(!manager.PrepareDirectKad6LocatedGet(0,32,descriptorGetHeader),"discovery invalid located index rejected");
            control::Header assigned;
            descriptorOwner=manager.PrepareDirectKad6NextLocatedGet(0,0,bootstrap,assigned);
            if(descriptorOwner) {
                Require(assigned.sequence>findHeader.sequence && assigned.attempt==bootstrap.attempt &&
                    assigned.generation==bootstrap.generation && assigned.type==wire::kEseWireUdpDescriptorGet,"discovery reserved GET correlation");
                descriptorGetHeader=assigned;
                Require(control::BuildDescriptorGet(descriptorGetHeader,discoveryFile,locator,requester.identity.pub,requester,descriptorGet),"discovery GET assigned header oracle");
            }
        }
        if(!descriptorOwner) Sleep(1);
    }
    if(!automaticGet) Require(descriptorOwner && manager.SendDirectKad6DescriptorGet(descriptorOwner).status==QuicUdpSendStatus::Sent,"discovery manager GET send");
    observedSize=SOCKET_ERROR;
    while(Now()<findDeadline && observedSize==SOCKET_ERROR) {
        if(automaticGet) {
            MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
            manager.TickDirectConnections();
        }
        observedSize=recvfrom(peer.socket,reinterpret_cast<char*>(observed.bytes.data()),static_cast<int>(observed.bytes.size()),0,nullptr,nullptr);
        if(observedSize==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"discovery GET receive"); Sleep(1); }
    }
    if(automaticGet) {
        Require(manager.DirectKad6AutomaticGetsPrepared()==1,"discovery automatic GET prepared count");
        Require(manager.DirectKad6AutomaticGetLastSend()!=QuicUdpSendStatus::Invalid,"discovery automatic GET send invalid");
        Require(manager.DirectKad6AutomaticGetLastSend()!=QuicUdpSendStatus::WouldBlock,"discovery automatic GET send blocked");
        Require(manager.DirectKad6AutomaticGetLastSend()==QuicUdpSendStatus::Sent,"discovery automatic GET send failed");
        discovery::GetView observedGet;
        control::Envelope observedEnvelope;
        Require(observedSize>0 && control::ParseUntrusted(observed.bytes.data(),static_cast<std::size_t>(observedSize),observedEnvelope),"discovery automatic GET envelope");
        Require(observedEnvelope.header.type==wire::kEseWireUdpDescriptorGet,"discovery automatic GET packet type");
        Require(control::VerifyDescriptorGet(requester.identity.pub,observed.bytes.data(),static_cast<std::size_t>(observedSize),descriptorGetHeader,observedGet),"discovery automatic GET signature");
        Require(observedGet.file==discoveryFile && observedGet.node==locator.node && observedGet.digest==locator.digest,"discovery automatic GET locator");
        Require(descriptorGetHeader.sequence>findHeader.sequence,"discovery automatic GET sequence");
        Require(descriptorGetHeader.attempt==bootstrap.attempt && descriptorGetHeader.generation==bootstrap.generation,"discovery automatic GET session");
        Require(control::BuildDescriptorGet(descriptorGetHeader,discoveryFile,locator,requester.identity.pub,requester,descriptorGet),"discovery automatic GET oracle");
    }
    Require(observedSize==static_cast<int>(descriptorGet.size) && !memcmp(observed.bytes.data(),descriptorGet.bytes.data(),descriptorGet.size),"discovery actual GET exact");
    if(dropGet) {
        Require(automaticGet,"discovery lost GET uses scheduler");
        const auto firstGetReceived=Now(); observedSize=SOCKET_ERROR;
        while(Now()<findDeadline && observedSize==SOCKET_ERROR) {
            MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
            manager.TickDirectConnections();
            observedSize=recvfrom(peer.socket,reinterpret_cast<char*>(observed.bytes.data()),static_cast<int>(observed.bytes.size()),0,nullptr,nullptr);
            if(observedSize==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"discovery retry GET receive"); Sleep(1); }
        }
        Require(Now()-firstGetReceived>=450,"discovery retry GET not immediate");
        Require(observedSize==static_cast<int>(descriptorGet.size) && !memcmp(observed.bytes.data(),descriptorGet.bytes.data(),descriptorGet.size),"discovery retry GET original signed bytes");
        Require(manager.DirectKad6AutomaticGetsPrepared()==1,"discovery retry GET retains owner");
    }
    auto descriptorResponseHeader=descriptorGetHeader; descriptorResponseHeader.type=wire::kEseWireUdpDescriptorResult;
    control::Datagram descriptorResult;
    Require(control::BuildDescriptorResult(descriptorResponseHeader,0,discoveryFile,locator,descriptor.data(),descriptor.size(),record.node_pub,witness,descriptorResult),"discovery RESULT sign");
    discovery::Kad6Resolution::ResolvedCandidate candidate; bool resolved=false;
    auto badDescriptor=descriptorResult; badDescriptor.bytes[badDescriptor.size-1]^=1; sendReply(badDescriptor);
    while(Now()<findDeadline && manager.RejectedDirectControlReplies()==discoveryRejected+1) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections(); Sleep(1);
    }
    Require(manager.RejectedDirectControlReplies()==discoveryRejected+2,"discovery corrupt RESULT processed");
    Require(!manager.PopDirectKad6Resolved(candidate),"discovery corrupt RESULT grants no candidate");
    sendReply(descriptorResult);
    while(Now()<findDeadline && !resolved) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections(); resolved=manager.PopDirectKad6Resolved(candidate); if(!resolved) Sleep(1);
    }
    Require(resolved && candidate.source.file==discoveryFile && candidate.source.fileSize==123 && candidate.witness==record.node_pub &&
        candidate.length==descriptor.size() && !memcmp(candidate.descriptor.data(),descriptor.data(),descriptor.size()),"discovery owned candidate exact");
    Require(!manager.PopDirectKad6Resolved(candidate),"discovery candidate single delivery");
    if(automaticGet) {
        const auto noDuplicateUntil=Now()+100;
        while(Now()<noDuplicateUntil) {
            manager.TickDirectConnections();
            const int extra=recvfrom(peer.socket,reinterpret_cast<char*>(observed.bytes.data()),static_cast<int>(observed.bytes.size()),0,nullptr,nullptr);
            Require(extra==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK,"discovery automatic GET no duplicate on ticks"); Sleep(1);
        }
    }
    manager.CancelDirectKad6Resolution();
    Require(manager.SendDirectKad6Find(findOwner).status==QuicUdpSendStatus::Invalid,"discovery cancelled FIND owner invalid");
    Require(theApp.clientudp->GetConnectedPort()==portNumber,"contact shared binding preserved");
}
inline void RunResolutionAlternates(CDirectReachabilityManager& manager,std::uint16_t portNumber,bool learnCloser=false,bool learnedBootstrap=false,bool throughDownloadQueue=false,bool coldReceiver=false) {
    Require(theApp.m_bReachBindingSelfTest && theApp.clientudp,"alternates explicit fixture");
    Require(!throughDownloadQueue || (learnCloser && learnedBootstrap && theApp.downloadqueue),"queue path requires learned discovery");
    Require(!coldReceiver || throughDownloadQueue,"cold receiver requires product queue path");
    struct Restore {
        CDirectReachabilityManager& manager; int consent=thePrefs.GetEseNetLabConsent();
        bool enabled=thePrefs.GetEseNetLabEnabled(); uint16 port=thePrefs.GetUDPPort();
        ~Restore() { manager.ShutdownQuicHost(); manager.DirectControlSessions()=control::Sessions{};
            thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled);
            thePrefs.SetUDPPort(port); theApp.clientudp->Rebind(); }
    } restore{manager};
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    thePrefs.SetUDPPort(portNumber); Require(theApp.clientudp->Rebind(),"alternates shared rebind");
    manager.TickDirectConnections(); Require(manager.EnableNativeQuicLab(),"alternates shared host");
    struct Signer final : control::Signer {
        Identity identity;
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return identity.Sign(p,n,out.data());
        }
    } first,second;
    Port firstPort,secondPort;
    std::array<std::uint8_t,32> local{};
    Require(eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentityPub(),"alternates local identity");
    memcpy(local.data(),eSELive::NodeIdentityPub(),32);
    auto hooks=MakeKad6HostCryptoHooks();
    hooks.ed25519_sign=[](const kad6::Byte* sk,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* sig) -> bool {
        return n==64 && eSELive::SignMessage(sk,sk+32,p,size,sig);
    };
    const auto utc=static_cast<std::uint64_t>(std::time(nullptr));
    auto import=[&](Signer& signer,unsigned id,bool save) {
        kad6::K6RouterRecord record; record.node_pub=signer.identity.pub; record.kad_id[0]=static_cast<std::uint8_t>(id);
        record.epoch=1; record.caps=1; record.valid_from=utc-1; record.valid_until=utc+120;
        kad6::K6Endpoint endpoint; endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
        endpoint.addr.addr[0]=203; endpoint.addr.addr[2]=113; endpoint.addr.addr[3]=static_cast<std::uint8_t>(id);
        endpoint.udp_port=123; endpoint.transport_flags=kad6::kK6EpUdpKad6; endpoint.valid_until=record.valid_until;
        if(learnedBootstrap && id==2) {
            std::copy(secondPort.endpoint.address.begin(),secondPort.endpoint.address.begin()+4,endpoint.addr.addr.begin());
            endpoint.udp_port=secondPort.endpoint.port;
        }
        record.endpoints.push_back(endpoint);
        struct Secret { std::array<std::uint8_t,64> bytes{}; ~Secret() { SecureZeroMemory(bytes.data(),bytes.size()); } } secret;
        memcpy(secret.bytes.data(),signer.identity.priv.data(),32); memcpy(secret.bytes.data()+32,signer.identity.pub.data(),32);
        std::vector<kad6::Byte> encoded;
        Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,encoded)==kad6::Kad6Status::Ok,"alternates signed record");
        if(save) Require(manager.ImportDirectKad6Contact(record.node_pub,encoded.data(),encoded.size()),"alternates record import");
        return encoded;
    };
    import(first,1,true); const auto secondRecord=import(second,2,!learnCloser);
    control::Header session; session.type=wire::kEseWireUdpProve; session.sequence=1;
    session.generation=manager.GetTopologyGeneration(); session.attempt[0]=1;
    std::array<std::uint8_t,32> proof{}; proof[0]=1;
    // Trusted session fixtures only. Bootstrap acceptance is tested separately.
    Require(manager.DirectControlSessions().AdmitVerified(first.identity.pub,firstPort.endpoint,session,proof,Now())==control::Admission::Accepted,"alternates first trusted session");
    if(!learnCloser) Require(manager.DirectControlSessions().AdmitVerified(second.identity.pub,secondPort.endpoint,session,proof,Now())==control::Admission::Accepted,"alternates second trusted session");
    std::array<std::uint8_t,16> file{}; file[0]=1;
    class DiscoveryClient final : public CUpDownClient {
    public:
        DiscoveryClient(const Identity& identity,CPartFile& file):CUpDownClient(&file,4662,0x0100007f,0,0,false) {
            memcpy(m_eseNodePub,identity.pub.data(),32); m_bEseNodePubSet=true;
            SetUserHash(identity.pub.data()); m_uEseCapabilities|=0x10000000;
            // Keep the legacy transport idle while testing only discovery consumption.
            SetDownloadState(DS_ERROR,_T("explicit discovery queue fixture"));
        }
    };
    std::unique_ptr<DiscoveryClient> downloadClient;
    std::unique_ptr<CPartFile> downloadFile;
    struct QueueCleanup {
        std::unique_ptr<DiscoveryClient>& client; std::unique_ptr<CPartFile>& file; bool cold=false;
        ~QueueCleanup() { if(client) client->SetRequestFile(nullptr);
            if(file) { if(cold) while(!file->srclist.IsEmpty()) delete file->srclist.GetHead();
                file->srclist.RemoveAll();
                theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(file.get());
                theApp.downloadqueue->RemoveFile(file.get()); } }
    } queueCleanup{downloadClient,downloadFile};
    if(throughDownloadQueue) {
        downloadFile=std::make_unique<CPartFile>(_T("ed2k://|file|learned-queue.bin|123|01000000000000000000000000000000|/"));
        Require((downloadFile->GetStatus()==PS_READY || downloadFile->GetStatus()==PS_EMPTY) &&
            !memcmp(downloadFile->GetFileHash(),file.data(),16),"learned queue exact requested file");
        theApp.downloadqueue->AddDownload(downloadFile.get(),false);
        queueCleanup.cold=coldReceiver;
        if(!coldReceiver) {
            downloadClient=std::make_unique<DiscoveryClient>(second.identity,*downloadFile);
            downloadFile->srclist.AddTail(downloadClient.get()); // Explicit existing peer.
        }
    }
    Require(manager.BeginDirectKad6Resolution(file,123,1000),"alternates resolution start");
    Require(manager.AddDirectKad6ResolutionWitness(first.identity.pub,firstPort.endpoint,session,1),"alternates first validated witness");
    if(!learnCloser) Require(manager.AddDirectKad6ResolutionWitness(second.identity.pub,secondPort.endpoint,session,1),"alternates second validated witness");
    Require(manager.EnableDirectKad6AutomaticFinds() && manager.EnableDirectKad6AutomaticGets(),"alternates scheduler enable");
    const auto deadline=Now()+4500;
    auto tick=[&]() { MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections(); };
    auto receive=[&](Port& port,control::Datagram& packet) {
        const int n=recvfrom(port.socket,reinterpret_cast<char*>(packet.bytes.data()),static_cast<int>(packet.bytes.size()),0,nullptr,nullptr);
        if(n==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"alternates peer receive"); return false; }
        packet.size=static_cast<std::size_t>(n); return true;
    };
    auto awaitPacket=[&](Port& port,control::Datagram& packet) {
        while(Now()<deadline) { tick(); if(receive(port,packet)) return; Sleep(1); }
        Require(false,"alternates packet deadline");
    };
    sockaddr_in shared{}; shared.sin_family=AF_INET; shared.sin_addr.s_addr=htonl(INADDR_LOOPBACK); shared.sin_port=htons(portNumber);
    auto send=[&](Port& port,const control::Datagram& packet) {
        Require(sendto(port.socket,reinterpret_cast<const char*>(packet.bytes.data()),static_cast<int>(packet.size),0,
            reinterpret_cast<const sockaddr*>(&shared),sizeof(shared))==static_cast<int>(packet.size),"alternates reply send");
    };
    control::Datagram firstFind,secondFind; awaitPacket(firstPort,firstFind);
    if(learnCloser) {
        control::Header header; discovery::DirectFind query;
        Require(control::VerifyDirectFind(local,firstFind.bytes.data(),firstFind.size,1000,header,query),"closer persistent FIND");
        std::array<std::uint8_t,32> digest{};
        Require(control::DirectFindDigest(local,firstFind.bytes.data(),firstFind.size,1000,digest),"closer FIND digest");
        std::array<discovery::FindEntryView,4> contacts{}; contacts[0]={secondRecord.data(),secondRecord.size(),0};
        control::Kad6FindContacts verifier(hooks,1,utc); control::Datagram closer;
        Require(control::BuildDirectFindCloserResult(header,query,digest,contacts,1,1000,first.identity.pub,first,verifier,closer),"closer signed response");
        auto bad=closer; bad.bytes[bad.size-1]^=1;
        const auto rejected=manager.RejectedDirectControlReplies(); send(firstPort,bad);
        while(Now()<deadline && manager.RejectedDirectControlReplies()==rejected) { tick(); Sleep(1); }
        kad6::K6RouterRecord learned;
        Require(manager.RejectedDirectControlReplies()==rejected+1 && !manager.FreshDirectKad6Contact(second.identity.pub,learned),"closer corrupt response not imported");
        send(firstPort,closer); bool fresh=false;
        while(Now()<deadline && !fresh) { tick(); fresh=manager.FreshDirectKad6Contact(second.identity.pub,learned); if(!fresh) Sleep(1); }
        Require(fresh && learned.node_pub==second.identity.pub,"closer verified record cached");
        const auto probationUntil=Now()+100;
        while(Now()<probationUntil) { tick(); control::Datagram premature;
            Require(!receive(secondPort,premature),"closer probation no FIND"); Sleep(1); }
        Require(!manager.AddDirectKad6ResolutionWitness(second.identity.pub,secondPort.endpoint,session,1),"closer promotion needs live return");
        if(learnedBootstrap) {
            Require(manager.EnableDirectKad6LearnedBootstrap(),"closer learned bootstrap enable");
            control::CookieAuthority authority; control::ChallengeLimit limit;
            auto peerSessions=std::make_unique<control::Sessions>();
            Require(authority.Initialize(),"closer bootstrap cookie authority");
            udp::Endpoint origin; origin.address[0]=127; origin.address[3]=1; origin.port=portNumber;
            unsigned probes=0,proves=0,adoptions=0; bool found=false;
            control::Header proved; const auto bootstrapRejected=manager.RejectedDirectControlReplies();
            while(Now()<deadline && !found) {
                tick(); control::Datagram incoming,response;
                if(!receive(secondPort,incoming)) { Sleep(1); continue; }
                control::Envelope envelope;
                Require(control::ParseUntrusted(incoming.bytes.data(),incoming.size,envelope),"closer bootstrap envelope");
                if(envelope.header.type==wire::kEseWireUdpProbe) {
                    ++probes;
                    Require(control::BuildChallenge(authority,limit,origin,second.identity.pub,local,incoming.bytes.data(),incoming.size,Now(),response),"closer real challenge");
                } else if(envelope.header.type==wire::kEseWireUdpProve) {
                    ++proves; control::Prove proofMessage;
                    const auto admission=control::AdmitProve(authority,*peerSessions,origin,second.identity.pub,local,
                        incoming.bytes.data(),incoming.size,Now(),proofMessage);
                    Require(admission==control::Admission::Accepted || admission==control::Admission::Duplicate,"closer cookie and signature proof");
                    if(admission==control::Admission::Accepted) ++adoptions;
                    proved=envelope.header;
                    Require(control::BuildAck(proofMessage,proved,0,second.identity.pub,second,response),"closer signed ACK");
                    if(proves==1) response.bytes[response.size-1]^=1;
                } else {
                    Require(envelope.header.type==wire::kEseWireUdpK6DirectFind &&
                        control::VerifyDirectFind(local,incoming.bytes.data(),incoming.size,1000,header,query),"closer post-bootstrap signed FIND");
                    Require(header.attempt==proved.attempt && header.generation==proved.generation && header.sequence>proved.sequence &&
                        manager.DirectControlSessions().Current(second.identity.pub,secondPort.endpoint,proved,Now()),"closer bootstrap-bound FIND");
                    secondFind=incoming; found=true; continue;
                }
                send(secondPort,response);
            }
            Require(found && probes==1 && proves==2 && adoptions==1 &&
                manager.RejectedDirectControlReplies()==bootstrapRejected+1,"closer corrupt ACK retry single adoption");
            std::array<std::uint8_t,187> learnedDescriptor{};
            const std::size_t learnedSize=throughDownloadQueue?187:159;
            memcpy(learnedDescriptor.data(),"ESD3",4); learnedDescriptor[4]=3;
            learnedDescriptor[8]=1; learnedDescriptor[16]=7; learnedDescriptor[24]=1; learnedDescriptor[28]=120;
            memcpy(learnedDescriptor.data()+29,second.identity.pub.data(),32);
            if(throughDownloadQueue) {
                learnedDescriptor[93]=1; auto* route=learnedDescriptor.data()+95;
                route[0]=2; route[1]=4; route[2]=7; route[3]=3;
                route[4]=8; route[5]=8; route[6]=8; route[7]=8;
                route[20]=0x12; route[21]=0x34; route[27]=120;
            }
            discovery::DescriptorSignatureInput learnedInput; std::array<std::uint8_t,64> learnedSignature{};
            Require(discovery::BuildSignatureInput(learnedDescriptor.data(),learnedSize,learnedInput) &&
                second.Sign(learnedInput.bytes.data(),learnedInput.size,learnedSignature),"learned descriptor sign");
            memcpy(learnedDescriptor.data()+learnedSize-64,learnedSignature.data(),64);
            discovery::DirectSource learnedSource; learnedSource.node=second.identity.pub; learnedSource.file=file;
            learnedSource.fileSize=123; learnedSource.generation=7; learnedSource.serial=1; learnedSource.ttl=120;
            Require(control::DescriptorDigest(learnedDescriptor.data(),learnedSize,learnedSource.digest),"learned descriptor digest");
            std::array<std::uint8_t,173> encodedSource{};
            Require(control::BuildDirectSource(learnedSource,1000,second,encodedSource),"learned source sign");
            std::array<discovery::FindEntryView,4> learnedEntries{}; learnedEntries[0]={encodedSource.data(),encodedSource.size(),120};
            std::array<std::uint8_t,32> learnedFindDigest{}; control::Datagram learnedSources;
            Require(control::DirectFindDigest(local,secondFind.bytes.data(),secondFind.size,1000,learnedFindDigest) &&
                control::BuildDirectFindSourcesResult(header,query,learnedFindDigest,learnedEntries,1,1000,
                    second.identity.pub,second,learnedSources),"learned SOURCES sign");
            send(secondPort,learnedSources);
            control::Datagram learnedGet; awaitPacket(secondPort,learnedGet);
            control::Header learnedGetHeader; discovery::GetView learnedGetView;
            Require(control::VerifyDescriptorGet(local,learnedGet.bytes.data(),learnedGet.size,learnedGetHeader,learnedGetView) &&
                learnedGetView.file==file && learnedGetView.node==learnedSource.node && learnedGetView.digest==learnedSource.digest &&
                learnedGetHeader.attempt==proved.attempt && learnedGetHeader.generation==proved.generation &&
                learnedGetHeader.sequence>header.sequence,"learned automatic GET bootstrap session");
            discovery::Locator learnedLocator; learnedLocator.node=learnedSource.node; learnedLocator.digest=learnedSource.digest;
            learnedLocator.serial=1; learnedLocator.ttl=119;
            auto learnedResultHeader=learnedGetHeader; learnedResultHeader.type=wire::kEseWireUdpDescriptorResult;
            control::Datagram learnedResult;
            Require(control::BuildDescriptorResult(learnedResultHeader,0,file,learnedLocator,learnedDescriptor.data(),learnedSize,
                second.identity.pub,second,learnedResult),"learned RESULT sign");
            auto corruptResult=learnedResult; corruptResult.bytes[corruptResult.size-1]^=1;
            const auto rejectedResult=manager.RejectedDirectControlReplies(); send(secondPort,corruptResult);
            while(Now()<deadline && manager.RejectedDirectControlReplies()==rejectedResult) { tick(); Sleep(1); }
            discovery::Kad6Resolution::ResolvedCandidate learnedCandidate;
            Require(manager.RejectedDirectControlReplies()==rejectedResult+1 && !manager.PopDirectKad6Resolved(learnedCandidate),"learned corrupt RESULT no candidate");
            if(throughDownloadQueue) {
                const auto topology=manager.GetTopologyGeneration();
                CUpDownClient* receiver=downloadClient.get();
                Require(coldReceiver ? downloadFile->srclist.IsEmpty() : !receiver->NativeDirectCandidates(topology,Now()+150000).remote_generation,
                    "learned corrupt RESULT cannot reach queue client");
                std::array<std::uint8_t,16> originalHash{}; if(receiver) memcpy(originalHash.data(),receiver->GetUserHash(),16);
                const auto credits=receiver?receiver->Credits():nullptr;
                send(secondPort,learnedResult); reach::NativeDirectCandidateSnapshotV1 adopted;
                while(Now()<deadline && !adopted.remote_generation) {
                    tick(); theApp.downloadqueue->Process();
                    if(!receiver && !downloadFile->srclist.IsEmpty()) receiver=downloadFile->srclist.GetHead();
                    if(receiver) adopted=receiver->NativeDirectCandidates(topology,Now()+150000);
                    if(!adopted.remote_generation) Sleep(1);
                }
                Require(receiver && adopted.remote_generation==7 && adopted.peer.expected_node_pub==second.identity.pub &&
                    adopted.count==1 && adopted.candidates[0].source==reach::DirectCandidateSource::KadSource &&
                    adopted.candidates[0].route.evidence==reach::DirectEvidence::Advertised &&
                    adopted.candidates[0].route.address[0]==8 && adopted.candidates[0].route.port==0x1234,
                    "learned manager ingress Process adopts exact signed route into requested client");
                Require(!manager.PopDirectKad6Resolved(learnedCandidate) && manager.DirectKad6AutomaticGetsPrepared()==1,
                    "learned queue consumes owner candidate exactly once");
                const auto lease=adopted.candidates[0].route.expires_monotonic_ms;
                if(coldReceiver) Require(downloadFile->srclist.GetCount()==1 && receiver->IsNativeDirectDiscoveryOnly() &&
                    !receiver->HasEseNodePub() && !receiver->HasValidHash() && !receiver->Credits() &&
                    !receiver->GetIP() && !receiver->GetUserPort() && !receiver->socket &&
                    !receiver->GetNativeDirectDownloadSubscriber() && !manager.DirectConnections().Size(),
                    "learned real RESULT creates cold source without endpoint HELLO credits socket or slot");
                send(secondPort,learnedResult); const auto quiet=Now()+100;
                while(Now()<quiet) { tick(); theApp.downloadqueue->Process(); Sleep(1); }
                adopted=receiver->NativeDirectCandidates(topology,Now()+150000);
                Require(adopted.count==1 && adopted.candidates[0].route.expires_monotonic_ms==lease &&
                    !memcmp(receiver->GetUserHash(),originalHash.data(),16) && receiver->Credits()==credits &&
                    manager.DirectKad6AutomaticGetsPrepared()==1 && !manager.PopDirectKad6Resolved(learnedCandidate),
                    "learned duplicate never renews lease or credits or creates another GET");
                if(coldReceiver) Require(downloadFile->srclist.GetCount()==1 && downloadFile->srclist.GetHead()==receiver,
                    "learned duplicate does not create another cold source");
                manager.CancelDirectKad6Resolution();
                Require(receiver->NativeDirectCandidates(topology,Now()+150000).remote_generation==7,
                    "learned consumed snapshot lifetime independent of resolution owner");
                return;
            }
            send(secondPort,learnedResult); bool candidateReady=false;
            while(Now()<deadline && !candidateReady) { tick(); candidateReady=manager.PopDirectKad6Resolved(learnedCandidate); if(!candidateReady) Sleep(1); }
            Require(candidateReady && learnedCandidate.source.file==file && learnedCandidate.source.fileSize==123 &&
                learnedCandidate.witness==second.identity.pub && learnedCandidate.source.node==second.identity.pub &&
                learnedCandidate.length==learnedSize && !memcmp(learnedCandidate.descriptor.data(),learnedDescriptor.data(),learnedSize),"learned exact owned candidate");
            Require(!manager.PopDirectKad6Resolved(learnedCandidate) && manager.DirectKad6AutomaticGetsPrepared()==1,"learned candidate once");
            manager.CancelDirectKad6Resolution(); return;
        }
        Require(manager.DirectControlSessions().AdmitVerified(second.identity.pub,secondPort.endpoint,session,proof,Now())==control::Admission::Accepted,"closer trusted return fixture");
        Require(!manager.AddDirectKad6ResolutionWitness(second.identity.pub,secondPort.endpoint,session,2),"closer cannot change capability bit");
        Require(manager.AddDirectKad6ResolutionWitness(second.identity.pub,secondPort.endpoint,session,1),"closer promote existing probation");
        awaitPacket(secondPort,secondFind);
        Require(control::VerifyDirectFind(local,secondFind.bytes.data(),secondFind.size,1000,header,query) && query.file==file,"closer promoted FIND automatic");
        manager.CancelDirectKad6Resolution(); return;
    }
    awaitPacket(secondPort,secondFind);
    control::Header firstFindHeader,secondFindHeader; discovery::DirectFind firstQuery,secondQuery;
    Require(control::VerifyDirectFind(local,firstFind.bytes.data(),firstFind.size,1000,firstFindHeader,firstQuery) &&
        control::VerifyDirectFind(local,secondFind.bytes.data(),secondFind.size,1000,secondFindHeader,secondQuery) &&
        firstQuery.file==file && secondQuery.file==file,"alternates signed FINDs");
    std::array<std::uint8_t,159> descriptor{}; memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3;
    descriptor[8]=1; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
    memcpy(descriptor.data()+29,first.identity.pub.data(),32);
    discovery::DescriptorSignatureInput input; std::array<std::uint8_t,64> signature{};
    Require(discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),input) && first.Sign(input.bytes.data(),input.size,signature),"alternates descriptor sign");
    memcpy(descriptor.data()+95,signature.data(),64);
    discovery::DirectSource source; source.node=first.identity.pub; source.file=file; source.fileSize=123;
    source.generation=7; source.serial=1; source.ttl=120;
    Require(control::DescriptorDigest(descriptor.data(),descriptor.size(),source.digest),"alternates descriptor digest");
    std::array<std::uint8_t,173> signedSource{}; Require(control::BuildDirectSource(source,1000,first,signedSource),"alternates source sign");
    std::array<discovery::FindEntryView,4> entries{}; entries[0]={signedSource.data(),signedSource.size(),120};
    auto sources=[&](Signer& signer,const control::Datagram& find,const control::Header& header,const discovery::DirectFind& query) {
        std::array<std::uint8_t,32> digest{}; control::Datagram result;
        Require(control::DirectFindDigest(local,find.bytes.data(),find.size,1000,digest) &&
            control::BuildDirectFindSourcesResult(header,query,digest,entries,1,1000,signer.identity.pub,signer,result),"alternates SOURCES sign");
        return result;
    };
    send(firstPort,sources(first,firstFind,firstFindHeader,firstQuery));
    control::Datagram firstGet; awaitPacket(firstPort,firstGet);
    control::Header firstGetHeader; discovery::GetView firstView;
    Require(control::VerifyDescriptorGet(local,firstGet.bytes.data(),firstGet.size,firstGetHeader,firstView) &&
        firstView.file==file && firstView.digest==source.digest,"alternates first GET");
    send(secondPort,sources(second,secondFind,secondFindHeader,secondQuery));
    const auto firstGetAt=Now(); control::Datagram secondGet; awaitPacket(secondPort,secondGet);
    Require(Now()-firstGetAt>=1900 && manager.DirectKad6AutomaticGetsPrepared()==2,"alternates waits first owner expiry");
    control::Header secondGetHeader; discovery::GetView secondView;
    Require(control::VerifyDescriptorGet(local,secondGet.bytes.data(),secondGet.size,secondGetHeader,secondView) &&
        secondView.file==file && secondView.node==source.node && secondView.digest==source.digest,"alternates second GET");
    discovery::Locator locator; locator.node=source.node; locator.digest=source.digest; locator.serial=1; locator.ttl=119;
    auto resultHeader=firstGetHeader; resultHeader.type=wire::kEseWireUdpDescriptorResult;
    control::Datagram late;
    Require(control::BuildDescriptorResult(resultHeader,0,file,locator,descriptor.data(),descriptor.size(),first.identity.pub,first,late),"alternates late RESULT sign");
    send(firstPort,late); tick(); discovery::Kad6Resolution::ResolvedCandidate candidate;
    Require(!manager.PopDirectKad6Resolved(candidate),"alternates late first no candidate");
    resultHeader=secondGetHeader; resultHeader.type=wire::kEseWireUdpDescriptorResult;
    control::Datagram result;
    Require(control::BuildDescriptorResult(resultHeader,0,file,locator,descriptor.data(),descriptor.size(),second.identity.pub,second,result),"alternates second RESULT sign");
    send(secondPort,result); bool resolved=false;
    while(Now()<deadline && !resolved) { tick(); resolved=manager.PopDirectKad6Resolved(candidate); if(!resolved) Sleep(1); }
    Require(resolved && candidate.witness==second.identity.pub && candidate.source.node==first.identity.pub &&
        candidate.length==descriptor.size() && !memcmp(candidate.descriptor.data(),descriptor.data(),descriptor.size()),"alternates owned candidate");
    Require(!manager.PopDirectKad6Resolved(candidate),"alternates candidate once");
    const auto quiet=Now()+100;
    while(Now()<quiet) { tick(); control::Datagram extra; Require(!receive(secondPort,extra),"alternates no duplicate GET"); Sleep(1); }
    Require(manager.DirectKad6AutomaticGetsPrepared()==2,"alternates no repeated witness");
    manager.CancelDirectKad6Resolution();
}
inline void RunControlResponder(CDirectReachabilityManager& manager,std::uint16_t portNumber) {
    Require(theApp.m_bReachBindingSelfTest && theApp.clientudp,"responder explicit fixture");
    struct Restore {
        CDirectReachabilityManager& manager; int consent=thePrefs.GetEseNetLabConsent();
        bool enabled=thePrefs.GetEseNetLabEnabled(); uint16 port=thePrefs.GetUDPPort();
        ~Restore() { manager.ShutdownQuicHost(); thePrefs.SetEseNetLabConsent(consent);
            thePrefs.SetEseNetLabEnabled(enabled); thePrefs.SetUDPPort(port); theApp.clientudp->Rebind(); }
    } restore{manager};
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    thePrefs.SetUDPPort(portNumber); Require(theApp.clientudp->Rebind(),"responder shared rebind");
    manager.TickDirectConnections(); Require(manager.EnableNativeQuicLab(),"responder host enable");
    struct Signer final : control::Signer {
        Identity identity;
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override { return identity.Sign(p,n,out.data()); }
    } peerSigner;
    Port peer,reboundPeer; udp::Endpoint local; local.address[0]=127; local.address[3]=1; local.port=portNumber;
    std::array<std::uint8_t,32> localPub{}; memcpy(localPub.data(),eSELive::NodeIdentityPub(),32);
    const auto deadline=Now()+1800;
    const auto owner=manager.ExpectDirectControlBootstrap(peerSigner.identity.pub,peer.endpoint,deadline);
    Require(owner!=0,"responder expected peer registration");
    Require(peer.endpoint.port!=reboundPeer.endpoint.port,"responder distinct rebound source port");
    const auto reboundOwner=manager.ExpectDirectControlBootstrap(peerSigner.identity.pub,reboundPeer.endpoint,deadline);
    Require(reboundOwner!=0 && reboundOwner!=owner,"responder authorized rebound endpoint");
    control::Header header; header.type=wire::kEseWireUdpProbe; header.generation=7; header.sequence=1;
    control::Probe probe; probe.node=peerSigner.identity.pub; probe.peer=localPub;
    const auto hooks=MakeKad6HostCryptoHooks();
    Require(hooks.random_bytes(header.attempt.data(),header.attempt.size()) && hooks.random_bytes(probe.nonce.data(),probe.nonce.size()),"responder fixture CSPRNG context");
    control::Initiator initiator; Require(initiator.Start(header,probe,local,Now(),deadline),"responder peer start");
    sockaddr_in destination{}; destination.sin_family=AF_INET; destination.sin_addr.s_addr=htonl(INADDR_LOOPBACK); destination.sin_port=htons(portNumber);
    const auto send=[&](const std::uint8_t* p,std::size_t n) {
        Require(sendto(peer.socket,reinterpret_cast<const char*>(p),static_cast<int>(n),0,reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(n),"responder peer actual send");
    };
    const auto rejectedBefore=manager.RejectedDirectControlReplies();
    bool corruptSent=false,corruptRejected=false,cookieSent=false,cookieRejected=false,reboundSent=false,reboundRejected=false; unsigned challenges=0,acks=0;
    control::Datagram validProve,ackPacket;
    while(Now()<deadline && initiator.State()!=control::InitiatorState::Ready) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        if(corruptSent && !corruptRejected && manager.RejectedDirectControlReplies()>rejectedBefore) {
            Require(!manager.DirectControlSessions().Current(peerSigner.identity.pub,peer.endpoint,header,Now()),"responder corrupt signature no session");
            corruptRejected=true;
        }
        if(cookieSent && !cookieRejected && manager.RejectedDirectControlReplies()==rejectedBefore+2) {
            Require(!manager.DirectControlSessions().Current(peerSigner.identity.pub,peer.endpoint,header,Now()),"responder signed wrong cookie no session");
            cookieRejected=true;
        }
        if(reboundSent && !reboundRejected && manager.RejectedDirectControlReplies()==rejectedBefore+3) {
            Require(!manager.DirectControlSessions().Current(peerSigner.identity.pub,reboundPeer.endpoint,header,Now()) &&
                !manager.DirectControlSessions().Current(peerSigner.identity.pub,peer.endpoint,header,Now()),"responder rebound cookie no session");
            reboundRejected=true;
        }
        const auto pending=initiator.Pending(Now());
        if(pending.size && (!corruptSent || (corruptRejected && (!cookieSent ||
            (cookieRejected && (!reboundSent || reboundRejected)))))) {
            if(initiator.State()==control::InitiatorState::Prove && !corruptSent) {
                validProve.size=pending.size; memcpy(validProve.bytes.data(),pending.data,pending.size);
                auto corrupt=validProve; corrupt.bytes[corrupt.size-1]^=1;
                send(corrupt.bytes.data(),corrupt.size); corruptSent=true;
            } else if(initiator.State()==control::InitiatorState::Prove && !cookieSent) {
                auto changed=validProve;
                Require(changed.size==control::HeaderSize+212,"responder full PROVE cookie offset");
                changed.bytes[control::HeaderSize+128]^=1;
                control::SignatureInput input; std::array<std::uint8_t,64> signature{};
                Require(control::BuildSignatureInput(changed.bytes.data(),changed.size,input) &&
                    peerSigner.Sign(input.bytes.data(),input.size,signature),"responder wrong cookie resign");
                memcpy(changed.bytes.data()+changed.size-64,signature.data(),signature.size());
                Require(control::VerifyEnvelopeSignature(peerSigner.identity.pub,changed.bytes.data(),changed.size),"responder wrong cookie signature valid");
                send(changed.bytes.data(),changed.size); cookieSent=true;
            } else if(initiator.State()==control::InitiatorState::Prove && !reboundSent) {
                Require(control::VerifyEnvelopeSignature(peerSigner.identity.pub,validProve.bytes.data(),validProve.size),"responder rebound original signature valid");
                Require(sendto(reboundPeer.socket,reinterpret_cast<const char*>(validProve.bytes.data()),static_cast<int>(validProve.size),0,
                    reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(validProve.size),"responder rebound actual proof send");
                reboundSent=true;
            } else { send(pending.data,pending.size); Require(initiator.Submitted(Now()),"responder peer submission"); }
        }
        control::Datagram response; sockaddr_in origin{}; int originSize=sizeof(origin);
        const int length=recvfrom(peer.socket,reinterpret_cast<char*>(response.bytes.data()),static_cast<int>(response.bytes.size()),0,reinterpret_cast<sockaddr*>(&origin),&originSize);
        if(length==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"responder peer receive"); Sleep(1); continue; }
        Require(origin.sin_port==destination.sin_port && origin.sin_addr.s_addr==destination.sin_addr.s_addr,"responder exact response source");
        if(initiator.State()==control::InitiatorState::Probe) {
            Require(initiator.ChallengeReceived(local,response.bytes.data(),static_cast<std::size_t>(length),Now(),peerSigner),"responder production challenge"); ++challenges;
        } else {
            Require(initiator.AckReceived(local,response.bytes.data(),static_cast<std::size_t>(length),Now()),"responder persistent ACK verify");
            ackPacket=response; ackPacket.size=static_cast<std::size_t>(length); ++acks;
        }
    }
    Require(corruptRejected && cookieRejected && reboundRejected && challenges==1 && acks==1 && initiator.State()==control::InitiatorState::Ready,"responder actual bootstrap completion");
    Require(manager.DirectControlSessions().Current(peerSigner.identity.pub,peer.endpoint,header,Now()),"responder production session admission");
    send(validProve.bytes.data(),validProve.size); bool duplicateAck=false;
    while(Now()<deadline && !duplicateAck) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        control::Datagram response;
        const int length=recvfrom(peer.socket,reinterpret_cast<char*>(response.bytes.data()),static_cast<int>(response.bytes.size()),0,nullptr,nullptr);
        if(length==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"responder duplicate receive"); Sleep(1); continue; }
        Require(length==static_cast<int>(ackPacket.size) && !memcmp(response.bytes.data(),ackPacket.bytes.data(),ackPacket.size),"responder duplicate exact ACK"); duplicateAck=true;
    }
    Require(duplicateAck && manager.RejectedDirectControlReplies()==rejectedBefore+3,"responder duplicate not rejected or readopted");
    auto reboundHeader=header; auto reboundProbe=probe;
    Require(hooks.random_bytes(reboundHeader.attempt.data(),reboundHeader.attempt.size()) &&
        hooks.random_bytes(reboundProbe.nonce.data(),reboundProbe.nonce.size()) &&
        reboundHeader.attempt!=header.attempt && reboundProbe.nonce!=probe.nonce,"responder rebound fresh CSPRNG context");
    control::Initiator rebound;
    Require(!manager.DirectControlSessions().Current(peerSigner.identity.pub,reboundPeer.endpoint,reboundHeader,Now()),"responder rebound starts without session");
    Require(rebound.Start(reboundHeader,reboundProbe,local,Now(),deadline),"responder rebound fresh start");
    unsigned reboundChallenges=0,reboundAcks=0;
    while(Now()<deadline && rebound.State()!=control::InitiatorState::Ready) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        const auto pending=rebound.Pending(Now());
        if(pending.size) {
            Require(sendto(reboundPeer.socket,reinterpret_cast<const char*>(pending.data),static_cast<int>(pending.size),0,
                reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(pending.size),"responder rebound fresh UDP send");
            Require(rebound.Submitted(Now()),"responder rebound submission");
        }
        control::Datagram response; sockaddr_in origin{}; int originSize=sizeof(origin);
        const int length=recvfrom(reboundPeer.socket,reinterpret_cast<char*>(response.bytes.data()),static_cast<int>(response.bytes.size()),0,
            reinterpret_cast<sockaddr*>(&origin),&originSize);
        if(length==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"responder rebound receive"); Sleep(1); continue; }
        Require(origin.sin_port==destination.sin_port && origin.sin_addr.s_addr==destination.sin_addr.s_addr,"responder rebound exact source");
        if(rebound.State()==control::InitiatorState::Probe) {
            Require(rebound.ChallengeReceived(local,response.bytes.data(),static_cast<std::size_t>(length),Now(),peerSigner),"responder rebound new challenge"); ++reboundChallenges;
        } else {
            Require(rebound.AckReceived(local,response.bytes.data(),static_cast<std::size_t>(length),Now()),"responder rebound signed ACK"); ++reboundAcks;
        }
    }
    Require(reboundChallenges==1 && reboundAcks==1 && rebound.State()==control::InitiatorState::Ready &&
        manager.DirectControlSessions().Current(peerSigner.identity.pub,reboundPeer.endpoint,reboundHeader,Now()),"responder rebound fresh session established");
    Require(manager.DirectControlSessions().Current(peerSigner.identity.pub,peer.endpoint,header,Now()) &&
        manager.RejectedDirectControlReplies()==rejectedBefore+3,"responder original session preserved after rebound");
    manager.CancelDirectControlResponder(owner);
    manager.CancelDirectControlResponder(reboundOwner);
    Port disabledPeer;
    std::array<std::uint8_t,16> resolutionFile{}; resolutionFile[0]=1;
    Require(!manager.BeginDirectKad6Resolution(resolutionFile,0,1000),"resolution invalid size rejected");
    Require(manager.BeginDirectKad6Resolution(resolutionFile,123,1000),"resolution manager owned start");
    Require(!manager.BeginDirectKad6Resolution(resolutionFile,123,1000),"resolution duplicate live rejected");
    const auto disabledOwner=manager.BeginDirectControlBootstrap(peerSigner.identity.pub,disabledPeer.endpoint,Now()+1800);
    Require(disabledOwner!=0,"disable fixture pending initiator");
    thePrefs.SetEseNetLabEnabled(false);
    const auto disabledUntil=Now()+350;
    while(Now()<disabledUntil) {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        manager.TickDirectConnections();
        control::Datagram unexpected;
        const int length=recvfrom(disabledPeer.socket,reinterpret_cast<char*>(unexpected.bytes.data()),static_cast<int>(unexpected.bytes.size()),0,nullptr,nullptr);
        Require(length==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK,"disabled initiator sends zero UDP packets");
        Require(!manager.DirectControlBootstrapReady(disabledOwner),"disabled initiator never ready");
        Sleep(1);
    }
    Require(!manager.BeginDirectControlBootstrap(peerSigner.identity.pub,disabledPeer.endpoint,Now()+1800),"disabled rejects new bootstrap");
    Require(!manager.BeginDirectKad6Resolution(resolutionFile,123,1000),"disabled rejects resolution");
    thePrefs.SetEseNetLabEnabled(true);
    const auto restartedOwner=manager.BeginDirectControlBootstrap(peerSigner.identity.pub,disabledPeer.endpoint,Now()+1800);
    Require(restartedOwner && restartedOwner!=disabledOwner,"reenabled fresh bootstrap owner");
    manager.CancelDirectControlBootstrap();
    Require(manager.BeginDirectKad6Resolution(resolutionFile,123,1000),"resolution disable pump retired old owner");
    manager.CancelDirectKad6Resolution();
    Require(manager.BeginDirectKad6Resolution(resolutionFile,123,1000),"resolution explicit cancellation permits new operation");
    manager.CancelDirectKad6Resolution();
    Require(theApp.clientudp->GetConnectedPort()==portNumber,"responder shared binding preserved");
}
inline void RunDiscoveryConsumer(CDirectReachabilityManager& manager,bool throughQueue=false,bool coldSource=false) {
    struct RestoreLab {
        int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        ~RestoreLab() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled); }
    } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    Identity identity;
    class FixtureClient final : public CUpDownClient {
    public:
        explicit FixtureClient(const Identity& value):CUpDownClient(static_cast<CPartFile*>(nullptr),4662,0x0100007f,0,0,false) {
            memcpy(m_eseNodePub,value.pub.data(),32); m_bEseNodePubSet=true;
            SetUserHash(value.pub.data()); m_uEseCapabilities|=0x10000000;
        }
    };
    FixtureClient client(identity);
    auto file=std::make_unique<CPartFile>(_T("ed2k://|file|discovery-consumer.bin|4097|5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A|/"));
    Require(file->GetStatus()==PS_READY || file->GetStatus()==PS_EMPTY,"discovery real file");
    struct Detach {
        CUpDownClient& client; CPartFile& file; bool queued=false,cold=false;
        ~Detach() { client.SetRequestFile(nullptr);
            if(cold) while(!file.srclist.IsEmpty()) delete file.srclist.GetHead();
            file.srclist.RemoveAll();
            if(queued) { theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(&file);
                theApp.downloadqueue->RemoveFile(&file); } }
    } detach{client,*file};
    discovery::ResolvedKad6Candidate candidate;
    const auto now=Now(); candidate.receivedMs=now; candidate.until=now+5000;
    candidate.localGeneration=manager.GetTopologyGeneration(); candidate.length=187;
    auto* descriptor=candidate.descriptor.data(); memcpy(descriptor,"ESD3",4); descriptor[4]=3;
    descriptor[8]=1; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
    memcpy(descriptor+29,identity.pub.data(),32); memcpy(descriptor+61,client.GetUserHash(),16); descriptor[93]=1;
    auto* route=descriptor+95; route[0]=2; route[1]=4; route[2]=7; route[3]=3;
    route[4]=8; route[5]=8; route[6]=8; route[7]=8; route[20]=0x12; route[21]=0x34; route[27]=120;
    discovery::DescriptorSignatureInput input;
    Require(discovery::BuildSignatureInput(descriptor,candidate.length,input) &&
        identity.Sign(input.bytes.data(),input.size,descriptor+123),"discovery signed route descriptor");
    auto& source=candidate.source; memcpy(source.file.data(),file->GetFileHash(),16);
    source.fileSize=file->GetFileSize(); source.node=identity.pub; source.generation=7; source.serial=1; source.ttl=120;
    Require(control::DescriptorDigest(descriptor,candidate.length,source.digest),"discovery descriptor digest");
    class SourceSigner final : public control::Signer {
    public:
        Identity& identity; explicit SourceSigner(Identity& value):identity(value) {}
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& signature) noexcept override { return identity.Sign(p,n,signature.data()); }
    } signer(identity);
    std::array<std::uint8_t,173> record{};
    Require(control::BuildDirectSource(source,file->GetFileSize(),signer,record) &&
        discovery::DecodeSource(record.data(),record.size(),file->GetFileSize(),source),"discovery signed file binding");
    {
        auto noQuic=candidate;
        // Preserve an unknown signed capability, but it must not enable QUIC.
        noQuic.descriptor[5]=0x80; noQuic.descriptor[8]=0;
        Require(discovery::BuildSignatureInput(noQuic.descriptor.data(),noQuic.length,input) &&
            identity.Sign(input.bytes.data(),input.size,noQuic.descriptor.data()+123) &&
            control::DescriptorDigest(noQuic.descriptor.data(),noQuic.length,noQuic.source.digest) &&
            control::BuildDirectSource(noQuic.source,file->GetFileSize(),signer,record) &&
            discovery::DecodeSource(record.data(),record.size(),file->GetFileSize(),noQuic.source),
            "discovery unknown-only caps signed binding");
        reach::NativeDirectCandidateSnapshotV1 checked;
        Require(discovery::Kad6Resolution::NativeSnapshot(noQuic,noQuic.source.file,
            noQuic.source.fileSize,manager.GetTopologyGeneration(),now,checked) &&
            checked.count==1 && checked.candidates[0].route.transport_mask==3 &&
            checked.candidates[0].route.evidence==reach::DirectEvidence::Advertised &&
            noQuic.descriptor[5]==0x80,"signed caps do not activate unannounced QUIC");
    }
    if(coldSource) {
        Require(theApp.downloadqueue,"cold source queue");
        theApp.downloadqueue->AddDownload(file.get(),false); detach.queued=true; detach.cold=true;
        auto invalid=candidate; invalid.descriptor[invalid.length-1]^=1;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(invalid) && file->srclist.IsEmpty(),"cold invalid descriptor no source");
        invalid=candidate; ++invalid.source.fileSize;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(invalid) && file->srclist.IsEmpty(),"cold wrong size no source");
        invalid=candidate; invalid.source.signature[0]^=1;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(invalid) && file->srclist.IsEmpty(),"cold invalid signed source no source");
        Require(theApp.downloadqueue->AdoptDirectKad6Discovery(candidate) && file->srclist.GetCount()==1,"cold node source created for requested file");
        auto* first=file->srclist.GetHead();
        Require(first!=&client && first->IsNativeDirectDiscoveryOnly() && !first->HasEseNodePub() && !first->HasValidHash() &&
            !first->Credits() && !first->GetIP() && !first->GetConnectIP() && !first->GetUserPort() &&
            !first->SupportsEseNetLabV1Target() && first->NativeDirectExpectedNode()==identity.pub,
            "cold expected key creates neither HELLO identity nor credits nor endpoint nor consent");
        const auto snapshot=first->NativeDirectCandidates(manager.GetTopologyGeneration(),Now()+150000);
        Require(snapshot.count==1 && snapshot.peer.expected_node_pub==identity.pub && snapshot.peer.expected_user_hash &&
            snapshot.peer.trust==reach::DirectIdentityTrust::Unknown && snapshot.candidates[0].route.evidence==reach::DirectEvidence::Advertised,
            "cold source retains signed owned candidate without upgrading evidence");
        auto wrongNode=identity.pub; wrongNode[0]^=1;
        auto wrongHash=*snapshot.peer.expected_user_hash; wrongHash[0]^=1;
        Require(theApp.clientlist->FindClientByLifetime(first->GetDirectClientLifetime())==first &&
            !theApp.clientlist->FindClientByLifetime(0) &&
            first->MatchesNativeDirectBoundIdentity(identity.pub,*snapshot.peer.expected_user_hash) &&
            !first->MatchesNativeDirectBoundIdentity(wrongNode,*snapshot.peer.expected_user_hash) &&
            !first->MatchesNativeDirectBoundIdentity(identity.pub,wrongHash) &&
            !first->HasEseNodePub() && !first->HasValidHash() && !first->Credits(),
            "cold lifetime association and expected bound identity do not mutate HELLO or credits");
        const auto lease=snapshot.candidates[0].route.expires_monotonic_ms;
        auto duplicate=candidate; duplicate.until+=1000;
        Require(theApp.downloadqueue->AdoptDirectKad6Discovery(duplicate) && file->srclist.GetCount()==1 && file->srclist.GetHead()==first &&
            first->NativeDirectCandidates(manager.GetTopologyGeneration(),Now()+150000).candidates[0].route.expires_monotonic_ms==lease,
            "cold duplicate reuses exact source and cannot renew lease");
        Require(!first->TryToConnect() && first->AskForDownload() && !first->socket &&
            !first->GetNativeDirectDownloadSubscriber() && !manager.DirectConnections().Size(),"cold source has no implicit legacy socket or slot");
        for(unsigned repeat=0;repeat<32;++repeat) Require(first->AskForDownload(),"unknown-trust repeated reask keeps source alive");
        Require(!first->socket && !first->GetNativeDirectDownloadSubscriber() && !manager.DirectConnections().Size(),
            "automatic reasks never adopt unknown trust or allocate repeated attempts");
        first->RequestNativeDirectDownload(Now());
        Require(!first->GetNativeDirectDownloadSubscriber() && !manager.DirectConnections().Size(),"cold expired offer cannot allocate DCO subscriber");
        Identity otherIdentity; SourceSigner otherSigner(otherIdentity); auto other=candidate;
        memcpy(other.descriptor.data()+29,otherIdentity.pub.data(),32); other.source.node=otherIdentity.pub;
        Require(discovery::BuildSignatureInput(other.descriptor.data(),other.length,input) &&
            otherIdentity.Sign(input.bytes.data(),input.size,other.descriptor.data()+123) &&
            control::DescriptorDigest(other.descriptor.data(),other.length,other.source.digest) &&
            control::BuildDirectSource(other.source,file->GetFileSize(),otherSigner,record) &&
            discovery::DecodeSource(record.data(),record.size(),file->GetFileSize(),other.source),"cold second key signed descriptor and source");
        Require(theApp.downloadqueue->AdoptDirectKad6Discovery(other) && file->srclist.GetCount()==2,"cold distinct node source created");
        auto* second=file->srclist.GetTail();
        Require(second!=first && !first->Compare(second) && !first->Compare(second,true) &&
            !second->Compare(first) && !second->Compare(first,true),"cold zero endpoints and identical claimed hash never merge different nodes");
        Require(!first->Compare(&client) && !client.Compare(first) && !first->Compare(&client,true) && !client.Compare(first,true),
            "cold expected node cannot be attached by unproven HELLO node tag even when the key matches");
        theApp.downloadqueue->Process();
        Require(file->srclist.GetCount()==2 && !first->socket && !second->socket && !manager.DirectConnections().Size(),
            "cold Process keeps pending sources without transport or READY");
        manager.InvalidateLocalTopology();
        Require(theApp.downloadqueue->RetireExpiredDirectKad6Sources()==2 && file->srclist.IsEmpty(),
            "cold stale topology retires owned source clients and releases source count");
        return;
    }
    std::array<std::uint8_t,16> originalHash{}; memcpy(originalHash.data(),client.GetUserHash(),16);
    const auto originalCredits=client.Credits();
    const auto originalCandidates=client.NativeDirectCandidates(manager.GetTopologyGeneration(),now+15000);
    Require(!client.AdoptNativeDirectDiscovery(candidate),"discovery no requested file rejected");
    client.SetRequestFile(file.get());
    if(throughQueue) {
        Require(theApp.downloadqueue && !theApp.downloadqueue->AdoptDirectKad6Discovery(candidate,false),
            "discovery queue rejects file not in requested queue");
        theApp.downloadqueue->AddDownload(file.get(),false); detach.queued=true;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(candidate,false),"discovery known-only queue does not invent absent peer");
        // Explicit pre-existing source fixture, not evidence of cold-source admission.
        file->srclist.AddTail(&client);
        auto wrongSize=candidate; ++wrongSize.source.fileSize;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(wrongSize,false),"discovery queue requires exact file size");
        auto wrongNode=candidate; wrongNode.source.node[0]^=1;
        Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(wrongNode,false),"discovery queue never matches peer by endpoint/hash alone");
    }
    auto altered=candidate; altered.source.file[0]^=1;
    Require(!client.AdoptNativeDirectDiscovery(altered),"discovery wrong file rejected");
    altered=candidate; ++altered.localGeneration;
    Require(!client.AdoptNativeDirectDiscovery(altered),"discovery wrong local topology rejected");
    altered=candidate; altered.until=now;
    Require(!client.AdoptNativeDirectDiscovery(altered),"discovery expired result rejected");
    Require(throughQueue ? theApp.downloadqueue->AdoptDirectKad6Discovery(candidate,false) : client.AdoptNativeDirectDiscovery(candidate),
        "discovery real requested file adopted");
    altered=candidate; altered.until+=1000;
    Require(client.AdoptNativeDirectDiscovery(altered) &&
        client.NativeDirectCandidates(manager.GetTopologyGeneration(),Now()+15000).candidates[0].route.expires_monotonic_ms==candidate.until,
        "discovery duplicate cannot renew original absolute lease");
    candidate.descriptor[4]=0; // Borrowed input is not retained by the client.
    const auto cap=Now()+1000;
    const auto snapshot=client.NativeDirectCandidates(manager.GetTopologyGeneration(),cap);
    Require(snapshot.count==1 && snapshot.remote_generation==7 && snapshot.peer.expected_node_pub==identity.pub &&
        snapshot.peer.expected_user_hash==originalHash && snapshot.peer.trust==reach::DirectIdentityTrust::Unknown &&
        snapshot.candidates[0].source==reach::DirectCandidateSource::KadSource &&
        snapshot.candidates[0].route.evidence==reach::DirectEvidence::Advertised &&
        snapshot.candidates[0].route.expires_monotonic_ms==cap && snapshot.candidates[0].route.port==0x1234,
        "discovery client owns snapshot with bounded TTL and no evidence upgrade");
    Require(!memcmp(client.GetUserHash(),originalHash.data(),16) && client.Credits()==originalCredits,
        "discovery does not mutate user hash or credit identity");
    const auto changedTopology=client.NativeDirectCandidates(manager.GetTopologyGeneration()+1,cap);
    Require(changedTopology.count==originalCandidates.count && !changedTopology.remote_generation,
        "discovery old topology cannot be rebased");
    for(std::size_t i=0;i<changedTopology.count;++i)
        Require(changedTopology.candidates[i].source==reach::DirectCandidateSource::NativeEndpoint,
            "discovery stale topology preserves only independent native endpoints");
    client.SetRequestFile(nullptr);
    const auto detached=client.NativeDirectCandidates(manager.GetTopologyGeneration(),cap);
    Require(detached.count==originalCandidates.count && !detached.remote_generation,
        "discovery detach retires source evidence");
}
// Real manager control/bootstrap/resolution over the test-only logical network.
// The witness is explicitly supplied; this is not public NAT or seed discovery.
inline void ResolveSimulatedSource(CDirectReachabilityManager& manager,
    Port& port,test::SimulatedQuicPort& localPort,Identity& identity,
    const discovery::ResolvedKad6Candidate& advertised,const std::array<std::uint8_t,173>& sourceBytes,CPartFile& file) {
    // The fixture reuses the same witness across multiple independent files.
    // Exercise cold expiry once; subsequent files get its already refreshed
    // contact, rather than violating the production 60-second refresh fence.
    static bool exercisedExpiredContact=false;
    const bool needsRefresh=!exercisedExpiredContact;
    struct Inbox final : QuicUdpIngress {
        std::vector<QuicUdpRouter::PendingControl> packets;
        bool Receive(const udp::Endpoint& peer,reach::DirectByteView bytes) noexcept override {
            if(packets.size()>=16 || bytes.size>1200) return false;
            try { QuicUdpRouter::PendingControl packet; packet.peer=peer; packet.size=bytes.size;
                memcpy(packet.bytes.data(),bytes.data,bytes.size); packets.push_back(packet); return true; }
            catch(...) { return false; }
        }
        void Poll(std::uint64_t) override {}
        void SocketReset() noexcept override { packets.clear(); }
    } inbox;
    Require(port.AttachQuicIngress(&inbox),"discovery simulated witness ingress");
    struct Cleanup {
        CDirectReachabilityManager& manager; Port& port; Inbox& inbox;
        ~Cleanup() { manager.CancelDirectKad6Resolution(); manager.CancelDirectControlBootstrap(); port.DetachQuicIngress(&inbox); }
    } cleanup{manager,port,inbox};
    struct Signer final : control::Signer {
        Identity& identity; explicit Signer(Identity& value):identity(value) {}
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& sig) noexcept override { return identity.Sign(p,n,sig.data()); }
    } signer(identity);
    std::array<std::uint8_t,32> requester{}; memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
    auto hooks=MakeKad6HostCryptoHooks();
    hooks.ed25519_sign=[](const kad6::Byte* sk,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* sig) -> bool {
        return n==64 && eSELive::SignMessage(sk,sk+32,p,size,sig);
    };
    struct Secret { std::array<std::uint8_t,64> bytes{}; ~Secret() { SecureZeroMemory(bytes.data(),bytes.size()); } } secret;
    memcpy(secret.bytes.data(),identity.priv.data(),32); memcpy(secret.bytes.data()+32,identity.pub.data(),32);
    const auto utc=static_cast<std::uint64_t>(std::time(nullptr));
    kad6::K6RouterRecord record; record.node_pub=identity.pub; record.kad_id[0]=3; record.epoch=Now();
    record.caps=discovery::K6_CAP_DIRECT_INDEX_V1;
    record.valid_from=needsRefresh ? utc-120 : utc-1;
    record.valid_until=needsRefresh ? utc-1 : utc+120;
    kad6::K6Endpoint endpoint; endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr=port.endpoint.address; endpoint.udp_port=port.endpoint.port;
    endpoint.transport_flags=kad6::kK6EpUdpKad6; endpoint.valid_until=record.valid_until; record.endpoints.push_back(endpoint);
    std::vector<kad6::Byte> recordBytes;
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,recordBytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(identity.pub,recordBytes.data(),recordBytes.size()),"discovery signed explicit witness contact");
    kad6::K6RouterRecord stale;
    Require(manager.FreshDirectKad6Contact(identity.pub,stale)==!needsRefresh,"discovery cache freshness matches fixture");
    ++record.epoch; record.valid_from=utc-1; record.valid_until=utc+120;
    record.endpoints[0].valid_until=record.valid_until;
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,recordBytes)==kad6::Kad6Status::Ok,
        "discovery fresh replacement signed by same witness");
    control::CookieAuthority authority; control::ChallengeLimit limit; auto sessions=std::make_unique<control::Sessions>();
    Require(authority.Initialize(),"discovery cookie authority");
    Require(manager.TryBeginQueuedKad6Resolution(advertised.source.file,advertised.source.fileSize),
        "discovery normal per-file queue scheduler with registered capability");
    Require(!manager.TryBeginQueuedKad6Resolution(advertised.source.file,advertised.source.fileSize),
        "discovery duplicate queue tick cannot steal active lookup");
    control::Header context; unsigned finds=0,gets=0,refreshes=0;
    bool done=false; unsigned timerMessages=0; const auto deadline=Now()+4000;
    while(Now()<deadline && !done) {
        manager.TickDirectConnections(); port.memory->Deliver();
        auto packets=std::move(inbox.packets); inbox.packets.clear();
        for(const auto& packet:packets) {
            Require(packet.peer==localPort.Endpoint(),"discovery requester logical endpoint");
            control::Envelope envelope; control::Datagram response;
            Require(control::ParseUntrusted(packet.bytes.data(),packet.size,envelope),"discovery control envelope");
            if(envelope.header.type==wire::kEseWireUdpProbe) {
                Require(control::BuildChallenge(authority,limit,packet.peer,identity.pub,requester,packet.bytes.data(),packet.size,Now(),response),"discovery real cookie challenge");
            } else if(envelope.header.type==wire::kEseWireUdpProve) {
                control::Prove verified;
                Require(control::AdmitProve(authority,*sessions,packet.peer,identity.pub,requester,packet.bytes.data(),packet.size,Now(),verified)==control::Admission::Accepted,"discovery signed witness PROVE");
                context=envelope.header;
                Require(control::BuildAck(verified,context,0,identity.pub,signer,response),"discovery control-only signed ACK");
            } else if(envelope.header.type==wire::kEseWireUdpK6ContactGet) {
                ++refreshes; control::Header header; std::array<std::uint8_t,32> digest{};
                Require(control::VerifyContactGet(requester,packet.bytes.data(),packet.size,header) &&
                    control::ContactGetDigest(requester,packet.bytes.data(),packet.size,digest),"discovery signed contact GET");
                Require(control::BuildContactResult(header,requester,digest,recordBytes.data(),recordBytes.size(),identity.pub,
                    signer,hooks,utc,response),"discovery signed same-key refreshed contact");
            } else if(envelope.header.type==wire::kEseWireUdpK6DirectFind) {
                Require(refreshes==unsigned(needsRefresh),"discovery no FIND before required refresh");
                ++finds; control::Header header; discovery::DirectFind query; std::array<std::uint8_t,32> digest{};
                Require(control::VerifyDirectFind(requester,packet.bytes.data(),packet.size,advertised.source.fileSize,header,query) &&
                    query.file==advertised.source.file && control::DirectFindDigest(requester,packet.bytes.data(),packet.size,advertised.source.fileSize,digest),"discovery real signed FIND exact file");
                std::array<discovery::FindEntryView,4> entries{}; entries[0]={sourceBytes.data(),sourceBytes.size(),120};
                Require(control::BuildDirectFindSourcesResult(header,query,digest,entries,1,advertised.source.fileSize,identity.pub,signer,response),"discovery signed SOURCES");
            } else {
                ++gets; control::Header header; discovery::GetView query;
                Require(control::VerifyDescriptorGet(requester,packet.bytes.data(),packet.size,header,query) &&
                    query.file==advertised.source.file && query.node==identity.pub && query.digest==advertised.source.digest,"discovery signed GET exact locator");
                discovery::Locator locator; locator.node=identity.pub; locator.digest=advertised.source.digest; locator.serial=1; locator.ttl=119;
                header.type=wire::kEseWireUdpDescriptorResult;
                Require(control::BuildDescriptorResult(header,0,advertised.source.file,locator,advertised.descriptor.data(),advertised.length,identity.pub,signer,response),"discovery signed RESULT");
            }
            Require(port.SendQuicDatagram(&inbox,packet.peer,response.bytes.data(),response.size).status==QuicUdpSendStatus::Sent,"discovery witness datagram response");
        }
        localPort.Deliver(); manager.TickDirectConnections();
        if(gets==1) {
            // Source creation and possible admission must both come through
            // the real application timer, not an extra harness Process call.
            MSG message{};
            for(unsigned count=0;count<256 && file.srclist.IsEmpty() && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++count) {
                if(message.message==WM_TIMER) ++timerMessages;
                TranslateMessage(&message); DispatchMessage(&message);
            }
            done=file.srclist.GetCount()==1;
        }
        if(!done) Sleep(1);
    }
    Require(done && refreshes==unsigned(needsRefresh) && finds==1 && gets==1 && timerMessages>0,"discovery timer manager mailbox consumed into production queue");
    discovery::ResolvedKad6Candidate extra;
    Require(!manager.PopDirectKad6Resolved(extra) &&
        manager.ConsumeDirectKad6DownloadSources(*theApp.downloadqueue)==0,"discovery mailbox source single delivery");
    Log(_T("REACH_SELFTEST V164 PASS: normal per-file Kad6 scheduler signed registered-cap contact bootstrap FIND GET timer source single delivery; simulated witness no physical NAT claim"));
    if(needsRefresh) {
        exercisedExpiredContact=true;
        Log(_T("REACH_SELFTEST V165 PASS: expired signed contact bootstrap CONTACT_GET same-key fresh CONTACT_RESULT before normal FIND GET; simulated witness no physical NAT claim"));
    }
}
inline void MultipartHash(const BYTE* bytes,std::array<BYTE,32>& parts,std::array<BYTE,16>& root) {
    Require(CKnownFile::CreateHash(bytes,PARTSIZE,parts.data()) &&
        CKnownFile::CreateHash(bytes+PARTSIZE,4097,parts.data()+16) &&
        CKnownFile::CreateHash(parts.data(),32,root.data()),"multipart real eD2K part hashes and root");
}
inline void RunProductUpload(CDirectReachabilityManager& manager,CUpDownClient& client,
    QuicEd2kWriter& writer,QuicTransport& transport,Ed2kFramer& reader,Port& port,QuicSocketOwner& peer,
    reach::DirectCoordinator& core,reach::DirectEventQueue& events,reach::DirectHandle peerHandle,
    std::uint32_t peerRoute,bool packed=false) {
    Require(theApp.m_bReachBindingSelfTest && client.socket && client.socket->HasAuthenticatedDirectConnection()
        && theApp.uploadqueue && theApp.sharedfiles && theApp.uploadqueue->GetUploadQueueLength()==0
        && theApp.uploadqueue->GetWaitingUserCount()==0,"product upload isolated authenticated prerequisites");
    const CString directory=thePrefs.GetTempDir();
    Require(directory.Left(7).CompareNoCase(_T("D:\\tmp\\"))==0,"product upload isolated disk directory");
    // The extension deliberately follows the uploader's no-compression policy;
    // this fixture exercises plain32, not the packed-packet acceptance contract.
    const CString name=packed?_T("native-upload-source.txt"):_T("native-upload-source.zip"),path=directory+_T("\\")+name;
    Log(_T("PRODUCT_UPLOAD_SELFTEST stage: create isolated source"));
    Require(GetFileAttributes(path)==INVALID_FILE_ATTRIBUTES,"product upload fresh source file");
    std::vector<BYTE> expected(65537),actual(expected.size()),seen(expected.size());
    std::uint32_t state=0x6c71a953;
    for(auto& byte:expected) { state=state*1664525u+1013904223u; byte=static_cast<BYTE>(state>>24); }
    if(packed) for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i%251);
    { CFile disk(path,CFile::modeCreate|CFile::modeWrite|CFile::shareExclusive);
      disk.Write(expected.data(),static_cast<UINT>(expected.size())); disk.Flush(); }
    auto source=std::make_unique<CKnownFile>();
    Log(_T("PRODUCT_UPLOAD_SELFTEST stage: hash actual source"));
    Require(source->CreateFromFile(directory,name,nullptr),"product upload actual file hash and metadata");
    std::array<BYTE,16> digest{};
    Require(CKnownFile::CreateHash(expected.data(),static_cast<UINT>(expected.size()),digest.data()) &&
        !memcmp(digest.data(),source->GetFileHash(),16),"product upload real file MD4");
    struct UploadCleanup {
        CUpDownClient& client; std::unique_ptr<CKnownFile>& file; bool shared=false;
        ~UploadCleanup() {
            theApp.uploadqueue->RemoveFromUploadQueue(&client,_T("Native upload selftest cleanup"));
            theApp.uploadqueue->RemoveFromWaitingQueue(&client);
            if(shared) theApp.sharedfiles->RemoveFile(file.get());
            // An unsuccessful deadline must not free an outstanding disk read.
            if(file && InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&file->nInUse),0,0)>0)
                file.release();
        }
    } cleanup{client,source};
    Log(_T("PRODUCT_UPLOAD_SELFTEST stage: register shared source"));
    Require(theApp.sharedfiles->SafeAddKFile(source.get(),true),"product upload register actual shared file");
    cleanup.shared=true;
    auto queue=[&](Packet& packet) { return writer.Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}); };
    CSafeMemFile start(16); start.WriteHash16(source->GetFileHash());
    Packet startPacket(start,OP_EDONKEYPROT,OP_STARTUPLOADREQ);
    Require(queue(startPacket).status==reach::DirectIoStatus::Accepted,"product upload peer asks normal slot");
    Log(_T("PRODUCT_UPLOAD_SELFTEST stage: slot request queued"));
    unsigned slots=0,packets=0,loops=0; std::uint64_t unique=0;
    std::vector<BYTE> compressed; std::uint32_t compressedSize=0;
    const auto deadline=Now()+15000;
    while(Now()<deadline && unique<expected.size()) {
        ++loops;
        if(loops<=4) Log(_T("PRODUCT_UPLOAD_SELFTEST loop%u: flush"),loops);
        const auto sent=writer.Flush(transport,peerHandle,peerRoute,1);
        Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"product upload request flush");
        MSG message{};
        if(loops<=4) Log(_T("PRODUCT_UPLOAD_SELFTEST loop%u: dispatch messages"),loops);
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++i) {
            TranslateMessage(&message); DispatchMessage(&message);
        }
        if(loops<=4) Log(_T("PRODUCT_UPLOAD_SELFTEST loop%u: poll network"),loops);
        port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now());
        if(loops<=4) Log(_T("PRODUCT_UPLOAD_SELFTEST loop%u: manager tick"),loops);
        manager.TickDirectConnections();
        Advance(core,peerHandle,events,transport);
        const auto received=PumpQuicEd2k(transport,reader,peerHandle,peerRoute,1,[&](const Ed2kFramer& frame) {
            Log(_T("PRODUCT_UPLOAD_SELFTEST response: protocol=%u opcode=%u bytes=%I64u"),
                unsigned(frame.Header()[0]),unsigned(frame.Header()[5]),static_cast<ULONGLONG>(frame.Payload().size));
            const auto bytes=frame.Payload(); const auto opcode=frame.Header()[5];
            Require(frame.Header()[0]==(opcode==OP_COMPRESSEDPART?OP_EMULEPROT:OP_EDONKEYPROT),"product upload exact protocol");
            if(opcode==OP_ACCEPTUPLOADREQ) {
                Require(++slots==1 && client.GetUploadState()==US_UPLOADING &&
                    theApp.uploadqueue->IsDownloading(&client) && theApp.uploadqueue->GetUploadQueueLength()==1,
                    "product upload one actual slot before block request");
                CSafeMemFile request(40); request.WriteHash16(source->GetFileHash());
                request.WriteUInt32(0); request.WriteUInt32(0); request.WriteUInt32(0);
                request.WriteUInt32(static_cast<UINT>(expected.size())); request.WriteUInt32(0); request.WriteUInt32(0);
                Packet packet(request,OP_EDONKEYPROT,OP_REQUESTPARTS);
                Require(queue(packet).status==reach::DirectIoStatus::Accepted,"product upload requests actual disk range");
            } else if(opcode==OP_SENDINGPART) {
                Require(!packed,"compressible product upload must use packed packets");
                Require(slots==1 && bytes.size>=24 && !memcmp(bytes.data,source->GetFileHash(),16),"product upload exact file packet");
                CSafeMemFile block(const_cast<BYTE*>(bytes.data+16),8);
                const auto begin=block.ReadUInt32(),end=block.ReadUInt32();
                Require(begin<end && end<=expected.size() && bytes.size==24+end-begin,"product upload bounds and exact payload length");
                Require(!memcmp(bytes.data+24,expected.data()+begin,end-begin),"product upload disk bytes exact");
                for(auto i=begin;i<end;++i) { actual[i]=bytes.data[24+i-begin]; if(!seen[i]) { seen[i]=1; ++unique; } }
                ++packets;
            } else if(opcode==OP_COMPRESSEDPART) {
                Require(packed && slots==1 && bytes.size>24 && !memcmp(bytes.data,source->GetFileHash(),16),"product upload compressed file packet");
                CSafeMemFile block(const_cast<BYTE*>(bytes.data+16),8);
                const auto begin=block.ReadUInt32(),total=block.ReadUInt32();
                Require(begin==0 && total>0 && total<expected.size() && (!compressedSize || compressedSize==total),"product upload compressed range and total");
                compressedSize=total;
                Require(bytes.size-24<=total-compressed.size(),"product upload bounded compressed accumulation");
                compressed.insert(compressed.end(),bytes.data+24,bytes.data+bytes.size);
                ++packets;
                if(compressed.size()==total) {
                    uLongf outputSize=static_cast<uLongf>(actual.size());
                    Require(uncompress(actual.data(),&outputSize,compressed.data(),static_cast<uLong>(compressed.size()))==Z_OK
                        && outputSize==expected.size() && actual==expected,"product upload decompressed bytes exact");
                    unique=actual.size();
                }
            } else {
                Require(false,"product upload unexpected response opcode");
            }
            return true;
        });
        Require(received.valid,"product upload response framing");
        Sleep(1);
    }
    Log(_T("PRODUCT_UPLOAD_SELFTEST state: slots=%u packets=%u unique=%I64u uploadState=%u reads=%d payloadAdded=%I64u"),
        slots,packets,static_cast<ULONGLONG>(unique),unsigned(client.GetUploadState()),source->nInUse,
        static_cast<ULONGLONG>(client.GetQueueSessionUploadAdded()));
    std::array<BYTE,16> receivedHash{};
    Require(slots==1 && (packed?packets>0:packets>1) && unique==expected.size() && actual==expected &&
        CKnownFile::CreateHash(actual.data(),static_cast<UINT>(actual.size()),receivedHash.data()) && receivedHash==digest,
        "product upload normal slot disk worker throttler native stream exact file MD4");
}
inline void RunMultipartTransfer(CDirectReachabilityManager& manager,CUpDownClient& client,CPartFile& file,
    QuicEd2kWriter& writer,QuicTransport& transport,Ed2kFramer& reader,Port& port,QuicSocketOwner& peer,
    reach::DirectCoordinator& core,reach::DirectEventQueue& events,reach::DirectHandle handle,
    reach::DirectHandle peerHandle,std::uint32_t peerRoute) {
    std::vector<BYTE> expected(PARTSIZE+4097);
    for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+41);
    std::array<BYTE,32> partHashes{}; std::array<BYTE,16> root{};
    MultipartHash(expected.data(),partHashes,root);
    Require(file.GetFileSize()==expected.size() && file.GetPartCount()==2 &&
        !memcmp(root.data(),file.GetFileHash(),16),"multipart original signed file and two parts");
    struct Range { std::uint32_t next,end; };
    std::vector<Range> ranges;
    // Model UploadClient::AddReqBlock: exact requests already pending or served
    // are ignored. Keep original bounds, not the advancing send cursor.
    std::vector<Range> admittedRanges;
    unsigned duplicates=0,names=0,statuses=0,hashsets=0,slots=0,requests=0,partMask=0;
    std::vector<Range> servedCoverage;
    std::uint64_t served=0,uniqueServed=0; bool completed=false,verified=false; unsigned hashCallbacks=0;
    auto queue=[&](Packet& packet) { return writer.Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}); };
    std::array<std::uint64_t,5> phaseMs{}; unsigned loops=0;
    const auto deadline=Now()+20000;
    while(Now()<deadline && !completed) {
        ++loops; auto phaseStart=Now();
        const auto sent=writer.Flush(transport,peerHandle,peerRoute,1);
        Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"multipart native writer flush");
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
        port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
        Advance(core,peerHandle,events,transport);
        phaseMs[0]+=Now()-phaseStart; phaseStart=Now();
        const auto received=PumpQuicEd2k(transport,reader,peerHandle,peerRoute,1,[&](const Ed2kFramer& frame) {
            try {
            if(frame.Header()[0]!=OP_EDONKEYPROT) return true;
            const auto bytes=frame.Payload(); const auto opcode=frame.Header()[5];
            if(opcode!=OP_REQUESTFILENAME && opcode!=OP_SETREQFILEID && opcode!=OP_HASHSETREQUEST &&
                opcode!=OP_STARTUPLOADREQ && opcode!=OP_REQUESTPARTS) return true;
            Require(bytes.size>=16 && !memcmp(bytes.data,file.GetFileHash(),16),"multipart request exact signed file ID");
            if(opcode==OP_REQUESTFILENAME) {
                Require(++names==1,"multipart filename request once");
                CSafeMemFile answer(64); answer.WriteHash16(file.GetFileHash());
                answer.WriteString(_T("native-multipart.bin"),client.GetUnicodeSupport());
                Packet packet(answer,OP_EDONKEYPROT,OP_REQFILENAMEANSWER);
                Require(queue(packet).status==reach::DirectIoStatus::Accepted,"multipart requested filename reply");
            } else if(opcode==OP_SETREQFILEID) {
                Require(++statuses==1,"multipart file status request once");
                CSafeMemFile answer(19); answer.WriteHash16(file.GetFileHash()); answer.WriteUInt16(2); answer.WriteUInt8(3);
                Packet packet(answer,OP_EDONKEYPROT,OP_FILESTATUS);
                Require(queue(packet).status==reach::DirectIoStatus::Accepted,"multipart requested two-part status reply");
            } else if(opcode==OP_HASHSETREQUEST) {
                Require(++hashsets==1 && statuses==1,"multipart requested MD4 hashset after status");
                CSafeMemFile answer(50); answer.WriteHash16(file.GetFileHash()); answer.WriteUInt16(2); answer.Write(partHashes.data(),32);
                Packet packet(answer,OP_EDONKEYPROT,OP_HASHSETANSWER);
                Require(queue(packet).status==reach::DirectIoStatus::Accepted,"multipart requested real hashset reply");
            } else if(opcode==OP_STARTUPLOADREQ) {
                Require(++slots==1 && hashsets==1,"multipart slot after verified hashset");
                Packet packet(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT);
                Require(queue(packet).status==reach::DirectIoStatus::Accepted,"multipart requested slot reply");
            } else {
                Require(slots==1 && bytes.size==40,"multipart real block request");
                CSafeMemFile request(const_cast<BYTE*>(bytes.data+16),24);
                std::array<std::uint32_t,3> starts{},ends{};
                for(auto& value:starts) value=request.ReadUInt32();
                for(auto& value:ends) value=request.ReadUInt32();
                ++requests;
                if(requests<=12) Log(_T("MULTIPART_SELFTEST request%u: starts=%u,%u,%u ends=%u,%u,%u"),
                    requests,starts[0],starts[1],starts[2],ends[0],ends[1],ends[2]);
                for(unsigned i=0;i<3;++i) if(ends[i]) {
                    // AddReqBlock accepts a bounded range across part boundaries.
                    Require(starts[i]<ends[i] && ends[i]<=expected.size() &&
                        ends[i]-starts[i]<=EMBLOCKSIZE*3,"multipart requested bounds within file and uploader limit");
                    const auto duplicate=std::find_if(admittedRanges.begin(),admittedRanges.end(),
                        [&](const Range& prior) { return prior.next==starts[i] && prior.end==ends[i]; });
                    if(duplicate!=admittedRanges.end()) { ++duplicates; continue; }
                    Require(ranges.size()<24 && admittedRanges.size()<128,"multipart bounded unique block requests");
                    admittedRanges.push_back({starts[i],ends[i]});
                    ranges.push_back({starts[i],ends[i]});
                }
            }
            return true;
            } catch(const std::exception& error) {
                Log(_T("MULTIPART_SELFTEST request callback failure: %hs"),error.what());
                throw;
            }
        });
        if(!received.valid) Log(_T("MULTIPART_SELFTEST invalid request: ready=%u closed=%u completedBytes=%I64u served=%I64u unique=%u duplicates=%u ranges=%u hashes=%u fileStatus=%u"),
            unsigned(transport.Ready()),unsigned(transport.Snapshot().closed),
            static_cast<ULONGLONG>(file.GetCompletedSize()),static_cast<ULONGLONG>(served),
            unsigned(admittedRanges.size()),duplicates,unsigned(ranges.size()),hashCallbacks,unsigned(file.GetStatus()));
        Require(received.valid,"multipart request framing");
        phaseMs[1]+=Now()-phaseStart; phaseStart=Now();
        if(!ranges.empty()) {
            auto& range=ranges.front();
            const auto count=(std::min)((std::min)(std::uint32_t(32768),range.end-range.next),
                std::uint32_t(PARTSIZE-range.next%PARTSIZE));
            CSafeMemFile data(24+count); data.WriteHash16(file.GetFileHash()); data.WriteUInt32(range.next);
            data.WriteUInt32(range.next+count); data.Write(expected.data()+range.next,count);
            Packet packet(data,OP_EDONKEYPROT,OP_SENDINGPART);
            const auto queued=queue(packet);
            Require(queued.status==reach::DirectIoStatus::Accepted || queued.status==reach::DirectIoStatus::WouldBlock,"multipart bounded chunk admission");
            if(queued.status==reach::DirectIoStatus::Accepted) {
                // Different requests may overlap (not just exact duplicates).
                // Count the union, while still sending what the real peer asks.
                auto start=range.next,end=range.next+count;
                auto position=servedCoverage.begin();
                while(position!=servedCoverage.end() && position->end<start) ++position;
                while(position!=servedCoverage.end() && position->next<=end) {
                    start=(std::min)(start,position->next); end=(std::max)(end,position->end);
                    uniqueServed-=position->end-position->next;
                    position=servedCoverage.erase(position);
                }
                uniqueServed+=end-start; servedCoverage.insert(position,{start,end});
                Require(servedCoverage.size()<=128,"multipart bounded served coverage");
                partMask|=1u<<(range.next/PARTSIZE); served+=count; range.next+=count;
                if(range.next==range.end) ranges.erase(ranges.begin());
            }
        }
        phaseMs[2]+=Now()-phaseStart; phaseStart=Now();
        if(file.GetStatus()!=PS_COMPLETING && file.GetStatus()!=PS_COMPLETE) file.FlushBuffer();
        phaseMs[3]+=Now()-phaseStart; phaseStart=Now();
        for(const auto id:{TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) {
            while(PeekMessage(&message,theApp.emuledlg->m_hWnd,id,id,PM_REMOVE)) {
                if(id==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==&file) ++hashCallbacks;
                if(id==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==&file) completed=true;
                DispatchMessage(&message); manager.TickDirectConnections();
                const auto proof=manager.DirectConnections().Snapshot(handle);
                verified=verified || (proof && proof->transfer_verified && proof->useful_bytes==expected.size());
            }
        }
        Sleep(1);
        phaseMs[4]+=Now()-phaseStart;
    }
    const auto finalProof=manager.DirectConnections().Snapshot(handle);
    Log(_T("MULTIPART_SELFTEST timing: loops=%u networkMs=%I64u requestsMs=%I64u queueMs=%I64u diskMs=%I64u messagesSleepMs=%I64u peerQueued=%I64u localQueued=%I64u peerUnclaimed=%I64u localUnclaimed=%I64u"),
        loops,static_cast<ULONGLONG>(phaseMs[0]),static_cast<ULONGLONG>(phaseMs[1]),
        static_cast<ULONGLONG>(phaseMs[2]),static_cast<ULONGLONG>(phaseMs[3]),static_cast<ULONGLONG>(phaseMs[4]),
        static_cast<ULONGLONG>(port.memory?port.memory->Queued():0),static_cast<ULONGLONG>(port.pairedMemory?port.pairedMemory->Queued():0),
        static_cast<ULONGLONG>(port.memory?port.memory->Unclaimed():0),static_cast<ULONGLONG>(port.pairedMemory?port.pairedMemory->Unclaimed():0));
    Log(_T("MULTIPART_SELFTEST request admission: unique=%u duplicates=%u"),
        unsigned(admittedRanges.size()),duplicates);
    Log(_T("MULTIPART_SELFTEST payload coverage: raw=%I64u unique=%I64u repeated=%I64u segments=%u"),
        static_cast<ULONGLONG>(served),static_cast<ULONGLONG>(uniqueServed),
        static_cast<ULONGLONG>(served-uniqueServed),unsigned(servedCoverage.size()));
    const auto receipts=manager.SnapshotDirectPartContributions(file.NativeDirectFileKey(),0,1);
    auto* receiver=receipts.empty()?nullptr:manager.FindNativeQuicLab(receipts[0].source.owner);
    Log(_T("MULTIPART_SELFTEST flow: downloadState=%u pendingBlocks=%u completedBytes=%I64u gap0=%I64u gap1=%I64u writerPending=%I64u peerPending=%I64u peerTxPool=%I64u receiverFound=%u receiverReady=%u receiverConsumed=%I64u receiverRxPool=%I64u"),
        unsigned(client.GetDownloadState()),CNativeDirectSelfTestAccess::PendingBlocks(client),
        static_cast<ULONGLONG>(file.GetCompletedSize()),static_cast<ULONGLONG>(file.GetTotalGapSizeInPart(0)),
        static_cast<ULONGLONG>(file.GetTotalGapSizeInPart(1)),static_cast<ULONGLONG>(writer.Remaining()),
        static_cast<ULONGLONG>(transport.Pending(4).size),static_cast<ULONGLONG>(transport.TxPool().Used()),
        unsigned(receiver!=nullptr),unsigned(receiver && receiver->Ready()),
        static_cast<ULONGLONG>(receiver?receiver->ConsumedData():0),static_cast<ULONGLONG>(receiver?receiver->RxPool().Used():0));
    Log(_T("MULTIPART_SELFTEST state: completed=%u verified=%u hashes=%u names=%u status=%u hashsets=%u slots=%u requests=%u parts=%u served=%I64u useful=%I64u fileStatus=%u writes=%u hashPending=%u ranges=%u"),
        unsigned(completed),unsigned(verified),hashCallbacks,names,statuses,hashsets,slots,requests,partMask,
        static_cast<ULONGLONG>(served),static_cast<ULONGLONG>(finalProof?finalProof->useful_bytes:0),
        unsigned(file.GetStatus()),unsigned(file.m_iWrites),unsigned(file.IsPartHashPending()),unsigned(ranges.size()));
    Require(completed && verified && hashCallbacks>=2 && names==1 && statuses==1 && hashsets==1 && slots==1 &&
        requests>1 && partMask==3 && uniqueServed==expected.size() && served>=uniqueServed &&
        finalProof && finalProof->useful_bytes==expected.size() && file.GetStatus()==PS_COMPLETE &&
        !file.IsCorruptedPart(0) && !file.IsCorruptedPart(1),"multipart real hash workers and completion");
    CFile disk(file.GetFilePath(),CFile::modeRead|CFile::shareDenyNone); std::vector<BYTE> actual(expected.size());
    Require(disk.GetLength()==expected.size() && disk.Read(actual.data(),static_cast<UINT>(actual.size()))==actual.size() &&
        actual==expected,"multipart completed disk exact across part boundary");
}
inline void RunLegacyPartialFile(CDirectReachabilityManager& manager,CUpDownClient& client,
    SOCKET& remote,reach::DirectHandle handle,const std::function<void()>& pump,bool corrupt=false,
    const std::function<void()>& reconnect={},bool packed=false,
    const std::function<int(const char*,int)>& streamSend={},const std::function<int(char*,int)>& streamReceive={}) {
    const bool utp=static_cast<bool>(streamSend);
    Require(utp==static_cast<bool>(streamReceive) && (!utp || (!corrupt && !reconnect && !packed)),"legacy stream fixture supported mode");
    auto sendBytes=[&](const char* bytes,int size) { return utp?streamSend(bytes,size):send(remote,bytes,size,0); };
    auto receiveBytes=[&](char* bytes,int size) { return utp?streamReceive(bytes,size):recv(remote,bytes,size,0); };
    std::array<BYTE,4097> expected{};
    for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+(utp?151:packed?137:reconnect?127:corrupt?113:107));
    std::array<BYTE,16> hash{};
    Require(CKnownFile::CreateHash(expected.data(),static_cast<UINT>(expected.size()),hash.data()),"legacy file MD4");
    CString text; for(const auto b:hash) text.AppendFormat(_T("%02X"),b);
    CString link; link.Format(_T("ed2k://|file|legacy-partial.bin|4097|%s|/"),(LPCTSTR)text);
    auto file=std::make_unique<CPartFile>(link);
    struct Cleanup {
        CUpDownClient& client; std::unique_ptr<CPartFile>& file;
        ~Cleanup() {
            client.ClearDownloadBlockRequests(); client.SetRequestFile(nullptr); client.SetDownloadState(DS_NONE);
            if(file->GetStatus()==PS_COMPLETING || file->GetStatus()==PS_COMPLETE) {
                file.release(); return; // completion host owns this object
            }
            theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(file.get());
            theApp.downloadqueue->RemoveFile(file.get());
            if(file->m_iWrites>0) file.release(); // retain outstanding IOCP ownership on failure
        }
    } cleanup{client,file};
    Require(file->GetStatus()==PS_READY || file->GetStatus()==PS_EMPTY,"legacy real PartFile ready");
    theApp.downloadqueue->AddDownload(file.get(),false);
    auto requestBlocks=[&](uint32 expectedStart=0) {
        client.ClearDownloadBlockRequests(); client.SetRequestFile(file.get()); client.SetDownloadState(DS_ONQUEUE);
        CSafeMemFile status(18); status.WriteHash16(hash.data()); status.WriteUInt16(0); // peer has complete file
        Packet available(status,OP_EDONKEYPROT,OP_FILESTATUS),slot(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT);
        std::vector<char> outbound;
        for(auto* message:{&available,&slot}) {
            const auto* bytes=message->GetPacket(); outbound.insert(outbound.end(),bytes,bytes+message->GetRealPacketSize());
        }
        std::vector<BYTE> incoming; size_t offset=0; bool requested=false; const auto deadline=Now()+8000;
        while(Now()<deadline && !requested) {
            if(offset<outbound.size()) {
                const int count=sendBytes(outbound.data()+offset,static_cast<int>(outbound.size()-offset));
                Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"TCP status slot wire send");
                if(count>0) offset+=count;
            }
            pump(); Require(client.socket,"TCP request retains socket");
            client.socket->SendControlData(64*1024,0); // production socket send path, bounded fixture flush
            BYTE buffer[4096]; const int count=receiveBytes(reinterpret_cast<char*>(buffer),sizeof buffer);
            Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"TCP request wire receive");
            if(count>0) incoming.insert(incoming.end(),buffer,buffer+count);
            Require(incoming.size()<=64*1024,"TCP request fixture bounded framing");
            while(incoming.size()>=6) {
                uint32 length=0; memcpy(&length,incoming.data()+1,4);
                Require(length>0 && length<=64*1024-5,"TCP request frame length");
                if(incoming.size()<size_t(length)+5) break;
                if(incoming[0]==OP_EDONKEYPROT && incoming[5]==OP_REQUESTPARTS) {
                    Require(length==41 && !memcmp(incoming.data()+6,hash.data(),16),"TCP generated block request file exact");
                    CSafeMemFile ranges(incoming.data()+22,24); uint32 starts[3],ends[3];
                    for(auto& start:starts) start=ranges.ReadUInt32();
                    for(auto& end:ends) end=ranges.ReadUInt32();
                    bool full=false;
                    for(unsigned i=0;i<3;++i) {
                        Require((starts[i]==0 && ends[i]==0) || (starts[i]==expectedStart && ends[i]==4097),"TCP generated request bounds");
                        full=full || ends[i]==4097;
                    }
                    Require(full,"TCP production requested full missing file"); requested=true;
                }
                incoming.erase(incoming.begin(),incoming.begin()+length+5);
            }
            Sleep(1);
        }
        Require(requested && client.GetDownloadState()==DS_DOWNLOADING,"TCP slot production creates and sends block requests");
    };
    requestBlocks();
    CSafeMemFile data(4120); data.WriteHash16(hash.data()); data.WriteUInt32(0); data.WriteUInt32(4096);
    data.Write(expected.data(),4096); Packet packet(data,OP_EDONKEYPROT,OP_SENDINGPART);
    const auto* wire=packet.GetPacket(); size_t sent=0;
    std::vector<char> initial(wire,wire+packet.GetRealPacketSize());
    if(packed) {
        std::vector<BYTE> encoded(compressBound(4097)+64); z_stream encoder{};
        Require(deflateInit(&encoder,1)==Z_OK,"TCP recovery packed encoder");
        struct EndEncoder { z_stream& value; ~EndEncoder() { deflateEnd(&value); } } endEncoder{encoder};
        encoder.next_in=expected.data(); encoder.avail_in=4096;
        encoder.next_out=encoded.data(); encoder.avail_out=static_cast<uInt>(encoded.size());
        Require(deflate(&encoder,Z_SYNC_FLUSH)==Z_OK && encoder.avail_in==0,"TCP incomplete compressed stream flush");
        const auto prefix=encoder.total_out;
        encoder.next_in=expected.data()+4096; encoder.avail_in=1;
        Require(deflate(&encoder,Z_FINISH)==Z_STREAM_END,"TCP full compressed stream size");
        initial.clear();
        for(size_t offset=0;offset<prefix;) {
            const auto count=(std::min)(size_t(37),size_t(prefix)-offset);
            CSafeMemFile fragment(64); fragment.WriteHash16(hash.data()); fragment.WriteUInt32(0);
            fragment.WriteUInt32(static_cast<uint32>(encoder.total_out)); fragment.Write(encoded.data()+offset,static_cast<UINT>(count));
            Packet compressed(fragment,OP_EMULEPROT,OP_COMPRESSEDPART);
            const auto* bytes=compressed.GetPacket(); initial.insert(initial.end(),bytes,bytes+compressed.GetRealPacketSize()); offset+=count;
        }
    }
    const auto deadline=Now()+8000;
    while(Now()<deadline) {
        if(sent<initial.size()) {
            const int count=sendBytes(initial.data()+sent,static_cast<int>(initial.size()-sent));
            Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"legacy file wire send");
            if(count>0) sent+=count;
        }
        pump(); manager.TickDirectConnections();
        const auto state=manager.DirectConnections().Snapshot(handle);
        if(sent==initial.size() && state && state->useful_bytes==4096) break;
        Sleep(1);
    }
    const auto state=manager.DirectConnections().Snapshot(handle);
    const auto receipts=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
    Require(state && state->state==reach::DirectSessionState::Transferring && state->useful_bytes==4096 &&
        !state->transfer_verified && file->IsComplete(0,4095) && !file->IsComplete(4096,4096) &&
        receipts.size()==1 && receipts[0].bytes==4096 && receipts[0].source.kind==reach::DirectPartOwnerKind::Legacy,
        "TCP real payload accepted by PartFile with legacy provenance and no integrity proof");
    Require(theApp.m_pPartFileWriteThread && theApp.m_pPartFileWriteThread->IsRunning(),"legacy production IOCP worker");
    file->FlushBuffer(); const auto writeDeadline=Now()+8000;
    while(file->m_iWrites>0 && Now()<writeDeadline) { pump(); Sleep(1); }
    Require(file->m_iWrites==0,"legacy IOCP writes drained"); file->FlushBuffer();
    CFile disk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
    std::array<BYTE,4096> stored{};
    Require(disk.Read(stored.data(),4096)==4096 && !memcmp(stored.data(),expected.data(),4096),"legacy disk bytes exact");
    disk.Close();
    Require(file->IsCompleteBD(0,4095) && !file->IsCompleteBD(4096,4096) &&
        !manager.DirectConnections().Snapshot(handle)->transfer_verified,"legacy disk alone is not hash proof");
    if(!utp) Log(_T("REACH_SELFTEST V116 PASS: real TCP wire 4096 accepted PartFile legacy provenance useful bytes exact IOCP disk no integrity while final gap; seeded reservation no full hash recovery mixed race"));
    if(!packed) {
    Require(client.socket,"legacy duplicate live socket");
    const auto parsedBefore=CNativeDirectSelfTestAccess::LegacyParsedBlocks(*client.socket);
    sent=0; bool duplicateParsed=false; const auto duplicateDeadline=Now()+8000;
    while(Now()<duplicateDeadline) {
        if(sent<packet.GetRealPacketSize()) {
            const int count=sendBytes(wire+sent,static_cast<int>(packet.GetRealPacketSize()-sent));
            Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"legacy duplicate wire send");
            if(count>0) sent+=count;
        }
        pump(); manager.TickDirectConnections();
        if(client.socket && CNativeDirectSelfTestAccess::LegacyParsedBlocks(*client.socket)==parsedBefore+1) {
            duplicateParsed=true; break;
        }
        Sleep(1);
    }
    const auto duplicated=manager.DirectConnections().Snapshot(handle);
    const auto afterDuplicate=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
    Require(duplicateParsed && duplicated && duplicated->useful_bytes==4096 && !duplicated->transfer_verified &&
        file->GetCompletedSize()==4096 && afterDuplicate.size()==1 && afterDuplicate[0].bytes==4096 &&
        afterDuplicate[0].revision==receipts[0].revision && afterDuplicate[0].part_revision==receipts[0].part_revision,
        "legacy duplicate actually parsed without useful bytes or provenance inflation");
    if(!utp) Log(_T("REACH_SELFTEST V118 PASS: TCP duplicate4096 actually parsed no useful byte receipt revision or completion inflation; no overlapping ranges recovery F1"));
    }
    if(reconnect) {
        if(packed) Require(CNativeDirectSelfTestAccess::HasLegacyInflater(client),"old TCP compressed stream inflater active before close");
        reconnect();
        if(packed) Require(!CNativeDirectSelfTestAccess::HasLegacyInflater(client),"new TCP route discarded old inflater");
        Require(file->IsCompleteBD(0,4095) && !file->IsComplete(4096,4096) && client.GetRequestFile()==file.get(),
            "TCP recovery retains accepted file disk range and original file");
        requestBlocks(4096);
    }
    CSafeMemFile last(25); last.WriteHash16(hash.data()); last.WriteUInt32(4096); last.WriteUInt32(4097);
    BYTE lastByte=expected[4096]; if(corrupt) lastByte^=1;
    last.Write(&lastByte,1); Packet finalPacket(last,OP_EDONKEYPROT,OP_SENDINGPART);
    sent=0; bool hashCallback=false,completedCallback=false,verified=false;
    auto finish=[&](Packet& incoming,uint64 expectedUseful,bool rejectHash) {
    sent=0;
    const auto completionDeadline=Now()+8000;
    while(Now()<completionDeadline && !(verified && completedCallback)) {
        if(sent<incoming.GetRealPacketSize()) {
            const int count=sendBytes(incoming.GetPacket()+sent,static_cast<int>(incoming.GetRealPacketSize()-sent));
            Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"legacy final byte wire send");
            if(count>0) sent+=count;
        }
        pump(); manager.TickDirectConnections();
        if(file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE) file->FlushBuffer();
        MSG message{};
        for(const auto messageId:{TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) {
            while(PeekMessage(&message,theApp.emuledlg->m_hWnd,messageId,messageId,PM_REMOVE)) {
                if(messageId==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) hashCallback=true;
                if(messageId==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) completedCallback=true;
                DispatchMessage(&message);
            }
        }
        manager.TickDirectConnections();
        const auto current=manager.DirectConnections().Snapshot(handle);
        verified=current && current->transfer_verified && current->useful_bytes==expectedUseful;
        if(rejectHash && hashCallback && file->IsCorruptedPart(0)) break;
        Sleep(1);
    }
    };
    finish(finalPacket,4097,corrupt);
    if(corrupt) {
        const auto rejected=manager.DirectConnections().Snapshot(handle);
        Require(hashCallback && !completedCallback && !verified && rejected && !rejected->transfer_verified &&
            rejected->useful_bytes==4097 && file->IsCorruptedPart(0) && file->GetTotalGapSizeInPart(0)==4097 &&
            !file->IsPartHashPending() && file->m_iWrites==0 && file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE,
            "TCP corrupt hash regaps full part without integrity or completion");
        Log(_T("REACH_SELFTEST V119 PASS: TCP corrupt final byte real hash rejection regaps4097 no VerifiedPart or completion; no F1 mixed recovery"));
        auto* sameSocket=client.socket;
        requestBlocks();
        CSafeMemFile repair(4121); repair.WriteHash16(hash.data()); repair.WriteUInt32(0); repair.WriteUInt32(4097);
        repair.Write(expected.data(),4097); Packet repaired(repair,OP_EDONKEYPROT,OP_SENDINGPART);
        hashCallback=false; completedCallback=false; verified=false;
        finish(repaired,8194,false);
        Require(client.socket==sameSocket && sameSocket && sameSocket->HasAuthenticatedDirectConnection(),
            "TCP repair preserves original authenticated socket");
    }
    Require(hashCallback && completedCallback && verified && file->GetStatus()==PS_COMPLETE,
        "legacy real hash callback produces verified-part and file completion");
    CFile completed(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
    std::array<BYTE,4097> completeBytes{};
    Require(completed.GetLength()==4097 && completed.Read(completeBytes.data(),4097)==4097 && completeBytes==expected,
        "legacy complete disk exact after real hash");
    if(utp) return; // caller records uTP-specific scope, never borrow TCP markers
    if(corrupt) Log(_T("REACH_SELFTEST V120 PASS: TCP corrected4097 same authenticated socket new real hash callback VerifiedPart completed disk exact useful8194; seeded repair reservation no route recovery F1"));
    else Log(_T("REACH_SELFTEST V117 PASS: real TCP final byte PartFile IOCP hash worker callback VerifiedPart and completed4097 disk exact; seeded reservation no corruption recovery mixed race F1"));
    Log(_T("REACH_SELFTEST V121 PASS: TCP wire FILESTATUS and ACCEPTUPLOADREQ production creates OP_REQUESTPARTS exact4097 no seeded block reservation initial and repair; explicit source file assignment no discovery mixed recovery F1"));
    if(reconnect) Log(_T("REACH_SELFTEST V122 PASS: TCP partial4096 actual close new route2 fresh RSA adopted epoch2 original PartFile retained request only4096..4097 final real hash completed exact; no mixed QUIC uTP race F1"));
    if(packed) Log(_T("REACH_SELFTEST V123 PASS: TCP compressed37 fragments4096 real IOCP partial old inflater active close fresh route epoch2 discards decoder keeps disk requests gap1 plain final hash complete exact; no uTP QUIC mixed F1"));
}

inline void RunLegacyTcpOwner(CDirectReachabilityManager& manager,bool wrongDestination=false,bool invalidHello=false,bool wireHello=false,bool validHello=false,unsigned secureIdentCase=0,bool mergeIdentity=false) {
    const bool scheduled=secureIdentCase>=6 && secureIdentCase<=9;
    const bool consumerOwned=secureIdentCase==3 || secureIdentCase==5 || scheduled;
    Require(!mergeIdentity || secureIdentCase==3,"identity merge uses actual prepared RSA consumer");
    if(consumerOwned) Require(manager.InstallQuicDownloadConsumer(),"legacy prepared consumer installed before admission");
    Log(_T("LEGACY_OWNER_SELFTEST stage: begin"));
    Require(theApp.m_bReachBindingSelfTest && !manager.DirectConnections().Size(),"legacy TCP owner explicit isolated lab");
    struct RestoreLab { int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        ~RestoreLab() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled); } } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    SOCKET listener=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP),remote=INVALID_SOCKET;
    Require(listener!=INVALID_SOCKET,"legacy TCP listener created");
    struct CloseSockets { SOCKET& listener; SOCKET& remote;
        ~CloseSockets() { if(remote!=INVALID_SOCKET) closesocket(remote); if(listener!=INVALID_SOCKET) closesocket(listener); } } closeSockets{listener,remote};
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    Require(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof address)==0 && listen(listener,1)==0,"legacy TCP loopback listener");
    int length=sizeof address; Require(getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0,"legacy TCP ephemeral endpoint");
    u_long nonblocking=1; Require(ioctlsocket(listener,FIONBIO,&nonblocking)==0,"legacy TCP nonblocking accept");
    Log(_T("LEGACY_OWNER_SELFTEST stage: listener"));
    auto* client=new CUpDownClient(static_cast<CPartFile*>(nullptr),ntohs(address.sin_port),0x0100007f,0,0,false);
    std::array<BYTE,16> expectedHash{}; expectedHash[0]=0x97; expectedHash[15]=1;
    expectedHash[14]=static_cast<BYTE>(secureIdentCase); // isolate per-peer key/credit state
    if(mergeIdentity) expectedHash[13]=0x59; // fresh RSA peer, not a pin rotation of the earlier case3
    client->SetUserHash(expectedHash.data()); // expectation only, no SecureIdent proof
    CUpDownClient* transferClient=client;
    std::array<uint64,5> originalRange{};
    if(scheduled) {
        CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*transferClient);
        originalRange=CNativeDirectSelfTestAccess::LegacyPendingRange(*transferClient);
    }
    if(secureIdentCase==5) {
        transferClient=new CUpDownClient(static_cast<CPartFile*>(nullptr),ntohs(address.sin_port),0x0100007f,0,0,false);
        transferClient->SetUserHash(expectedHash.data()); theApp.clientlist->AddClient(transferClient);
        CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*transferClient);
        originalRange=CNativeDirectSelfTestAccess::LegacyPendingRange(*transferClient);
        Require(client->EnableDirectRouteCreditIsolation(expectedHash,theApp.clientcredits->FindCredit(expectedHash.data())),
            "separate preauth route client initialized with readonly expected pin");
    }
    CClientCredits* globalCredits=nullptr; CreditStruct globalCreditBefore{};
    uint32 globalChallengeFor=0,globalChallengeFrom=0;
    std::unique_ptr<CUpDownClient> otherRoute;
    if(secureIdentCase==4) {
        globalCredits=theApp.clientcredits->GetCredit(expectedHash.data());
        globalCreditBefore=*globalCredits->GetDataStruct();
        globalChallengeFor=globalCredits->m_dwCryptRndChallengeFor; globalChallengeFrom=globalCredits->m_dwCryptRndChallengeFrom;
        Require(client->EnableDirectRouteCreditIsolation(expectedHash) && !client->EnableDirectRouteCreditIsolation(expectedHash),
            "private route credit context created once before socket handshake");
        otherRoute=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),ntohs(address.sin_port),0x0100007f,0,0,false);
        Require(otherRoute->EnableDirectRouteCreditIsolation(expectedHash) && client->Credits()!=otherRoute->Credits() &&
            client->Credits()!=globalCredits && otherRoute->Credits()!=globalCredits,"same hash routes have independent credit contexts");
        theApp.clientlist->AddClient(otherRoute.get());
        otherRoute->Credits()->m_dwCryptRndChallengeFor=0x5a17;
    }
    theApp.clientlist->AddClient(client);
    const auto lifetime=transferClient->GetDirectClientLifetime();
    auto* socket=scheduled ? nullptr : new CClientReqSocket(client); client->socket=socket;
    Log(_T("LEGACY_OWNER_SELFTEST stage: client socket"));
    struct Cleanup { CDirectReachabilityManager& manager; uint64 lifetime; CUpDownClient* client; CClientReqSocket* socket;
        reach::DirectHandle handle; bool consumerOwned=false; CUpDownClient* temporary=nullptr;
        ~Cleanup() { Log(_T("LEGACY_OWNER_SELFTEST stage: cleanup begin")); manager.RetireDirectClient(lifetime);
            if(theApp.listensocket->IsValidSocket(socket)) { socket->SetClient(nullptr); socket->Safe_Delete(); }
            if(theApp.clientlist->IsValidClient(client)) { client->socket=nullptr; delete client; }
            if(temporary && theApp.clientlist->IsValidClient(temporary)) { temporary->socket=nullptr; delete temporary; }
            // This fixture owns the TCP socket directly, not through the still
            // pending mixed consumer. It must not claim adapter retirement.
            if(handle.generation && !consumerOwned) { manager.DirectConnections().Cancel(handle,reach::DirectReason::Disabled); manager.DirectConnections().Release(handle); }
            // Tick deliberately does not drain without a consumer. This lab
            // owned and released its sole attempt above, so explicitly consume
            // scalar subscriber retirements before another fixture acquires.
            if(!consumerOwned) manager.PumpDirectEvents();
            manager.TickDirectConnections(); manager.TickDirectConnections(); Log(_T("LEGACY_OWNER_SELFTEST stage: cleanup done")); } } cleanup{manager,lifetime,transferClient,socket};
    if(transferClient!=client) cleanup.temporary=client;
    reach::NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=manager.GetTopologyGeneration();
    if(scheduled) snapshot.peer.expected_user_hash=expectedHash;
    std::unique_ptr<CUpDownClient> identityTarget;
    reach::DirectHandle identityTargetHandle{};
    struct IdentityTargetCleanup {
        CDirectReachabilityManager& manager; std::unique_ptr<CUpDownClient>& client;
        ~IdentityTargetCleanup() {
            if(client) { manager.RetireDirectClient(client->GetDirectClientLifetime()); client.reset();
                manager.TickDirectConnections(); manager.TickDirectConnections(); }
        }
    } identityTargetCleanup{manager,identityTarget};
    if(mergeIdentity) {
        identityTarget=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),static_cast<uint16>(ntohs(address.sin_port)),0x0100007f,0,0,false);
        identityTarget->SetUserHash(expectedHash.data()); theApp.clientlist->AddClient(identityTarget.get());
        auto known=snapshot; known.peer.expected_user_hash=expectedHash;
        const auto knownToken=manager.AcquireDirectSubscriber(identityTarget->GetDirectClientLifetime(),reach::DirectConsumerKind::Download);
        const auto knownRequest=manager.RequestDirectConnection(known,identityTarget->GetDirectClientLifetime(),1,knownToken);
        Require(knownRequest.request.status==reach::DirectRequestStatus::Created,"known merge target gathering admission");
        identityTargetHandle=knownRequest.request.handle;
    }
    const auto token=manager.AcquireDirectSubscriber(lifetime,reach::DirectConsumerKind::Download);
    const auto admitted=manager.RequestDirectConnection(snapshot,lifetime,1,token);
    Require(token && admitted.request.status==reach::DirectRequestStatus::Created,"legacy TCP owned admission");
    cleanup.handle=admitted.request.handle;
    cleanup.consumerOwned=consumerOwned;
    Log(_T("LEGACY_OWNER_SELFTEST stage: admitted"));
    if(scheduled) {
        const auto beforeUnavailable=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(beforeUnavailable && !transferClient->GetRequestFile() &&
            manager.BeginOwnedObservedTcpDownload(admitted.request.handle)==CDirectReachabilityManager::DirectTcpStartResult::Unavailable,
            "observed TCP start requires resumable file before route reservation");
        const auto afterUnavailable=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(afterUnavailable && afterUnavailable->state==beforeUnavailable->state &&
            afterUnavailable->epoch==beforeUnavailable->epoch && afterUnavailable->highest_route_id==beforeUnavailable->highest_route_id &&
            !transferClient->socket && !CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1) &&
            manager.HasDirectTransferSubscription(lifetime,admitted.request.handle),
            "unavailable observed TCP start preserves attempt subscription epoch and route allocation");
        const auto originalIP=transferClient->GetIP();
        transferClient->SetIP(inet_addr("8.8.4.4")); // selection only; never register/schedule this endpoint
        reach::NativeDirectTransportPolicy policy; policy.enabled_transports=reach::DirectTcp;
        const auto selected=manager.SelectDirectDownloadRoutes(admitted.request.handle,policy,42);
        Log(_T("MIXED_SELECTOR_SELFTEST diagnostic: routes=%u status=%u snapshot=%u lowid=%u peerDomain=%u"),
            static_cast<unsigned>(selected.routes.size()),static_cast<unsigned>(selected.status),static_cast<unsigned>(selected.snapshot_status),
            static_cast<unsigned>(transferClient->HasLowID()),static_cast<unsigned>(manager.DirectConnections().Snapshot(admitted.request.handle)->peer.domain));
        Require(selected.snapshot_status==reach::NativeSnapshotStatus::Ok && selected.routes.empty(),
            "host selector rejects advertised TCP without observed transport evidence");
        auto changed=expectedHash; changed[0]^=1; transferClient->SetUserHash(changed.data());
        Require(manager.SelectDirectDownloadRoutes(admitted.request.handle,policy,42).snapshot_status==reach::NativeSnapshotStatus::InvalidGeneration,
            "host mixed selector rejects changed owner identity");
        transferClient->SetUserHash(expectedHash.data());
        policy.enabled_transports=128;
        Require(manager.SelectDirectDownloadRoutes(admitted.request.handle,policy,42).routes.empty(),"host mixed selector rejects unknown adapter mask");
        policy.enabled_transports=reach::DirectTcp;
        Require(manager.SelectDirectDownloadRoutes(admitted.request.handle,policy,0).routes.empty() &&
            manager.SelectDirectQuicDownloadRoutes(admitted.request.handle,policy).routes.empty() &&
            !transferClient->socket && manager.DirectConnections().Snapshot(admitted.request.handle)->state==reach::DirectSessionState::Gathering &&
            !CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,42),
            "selection starts no socket and preserves QUIC-only wrapper contract");
        transferClient->SetIP(originalIP);
    }
    reach::DirectSessionRoute route; route.id=1; route.transport=reach::DirectTcp;
    route.candidate.id=1; route.candidate.family=4; route.candidate.address[0]=127; route.candidate.address[3]=1;
    route.candidate.port=ntohs(address.sin_port); route.candidate.transport_mask=reach::DirectTcp;
    if(wrongDestination) route.candidate.port=route.candidate.port==65535 ? 65534 : route.candidate.port+1;
    route.candidate.topology_generation=snapshot.local_generation; route.candidate.expires_monotonic_ms=Now()+8000;
    auto forged=route; ++forged.candidate.port;
    if(scheduled) {
        Require(manager.RegisterDirectLegacyRoute(admitted.request.handle,route) &&
            !manager.RegisterDirectLegacyRoute(admitted.request.handle,route) &&
            !CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1),
            "legacy route reservation unique no socket before DCO Start");
        Require(!manager.ScheduleDirectQuicRoutes(admitted.request.handle,{forged}) &&
            manager.ScheduleDirectQuicRoutes(admitted.request.handle,{route}),"consumer rejects mutated candidate then executes authoritative Start");
        socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1);
        Require(socket && socket->client && socket->client!=transferClient && !transferClient->socket,
            "DCO Start creates isolated real TCP socket without replacing original");
        client=socket->client; cleanup.socket=socket;
        uint32 expectedConnectIP=0; memcpy(&expectedConnectIP,route.candidate.address.data(),4);
        Require(client->GetConnectIP()==expectedConnectIP,"DCO Start legacy client retains exact network-order authorized IPv4 before HELLO");
        Log(_T("REACH_SELFTEST V131 PASS: scheduled legacy temporary client ConnectIP matches authorized IPv4 bytes before HELLO; loopback not public selector or uTP acceptance"));
    } else {
    const auto start=manager.DirectConnections().SetRoutes(admitted.request.handle,{route},Now());
    Require(start.actions.size()==1 && start.actions[0].type==reach::DirectActionType::Start,"legacy TCP explicit loopback route start");
    Require(!socket->RegisterLegacyDirectRoute(admitted.request.handle,forged,0,lifetime) &&
        socket->RegisterLegacyDirectRoute(admitted.request.handle,route,0,lifetime) &&
        !socket->RegisterLegacyDirectRoute(admitted.request.handle,route,0,lifetime),"legacy TCP exact route single owner");
    }
    Log(_T("LEGACY_OWNER_SELFTEST stage: registered"));
    if(consumerOwned && !scheduled) Require(!manager.RegisterPreparedDirectLegacyRoute(admitted.request.handle,forged,*socket,0) &&
        manager.RegisterPreparedDirectLegacyRoute(admitted.request.handle,route,*socket,0) &&
        !manager.RegisterPreparedDirectLegacyRoute(admitted.request.handle,route,*socket,0),
        "prepared consumer rejects forged duplicate and owns exact TCP socket");
    CSafeMemFile hello; hello.WriteHash16(expectedHash.data()); hello.WriteUInt32(0); hello.WriteUInt16(ntohs(address.sin_port));
    hello.WriteUInt32(0); hello.WriteUInt32(0); hello.WriteUInt16(0);
    const auto helloSize=static_cast<uint32>(hello.GetLength());
    std::unique_ptr<BYTE[]> helloBytes(hello.Detach());
    Require(CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,helloBytes.get(),helloSize),"legacy expected HELLO structural preflight");
    helloBytes[0]^=1;
    Require(!CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,helloBytes.get(),helloSize),"legacy changed HELLO hash rejected before mutation");
    helloBytes[0]^=1;
    auto changedHash=expectedHash; changedHash[1]^=1; client->SetUserHash(changedHash.data());
    Require(CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,helloBytes.get(),helloSize),"legacy preflight uses frozen expectation not mutable client hash");
    client->SetUserHash(expectedHash.data());
    Require(!CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,helloBytes.get(),helloSize-1) &&
        !CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,nullptr,helloSize) &&
        !socket->HasAuthenticatedDirectConnection(),"legacy truncated null HELLO rejected and no authentication granted");
    if(!scheduled) Require(socket->Create(AF_INET),"legacy TCP MFC socket created");
    auto helperWindow=CNativeDirectSelfTestAccess::LegacySocketWindow(*socket);
    Require(helperWindow!=nullptr,"legacy TCP actual AsyncSocketEx notification window");
    if(!scheduled) Require(socket->Connect(reinterpret_cast<sockaddr*>(&address),sizeof address) || WSAGetLastError()==WSAEWOULDBLOCK,"legacy TCP actual connect initiated");
    Log(_T("LEGACY_OWNER_SELFTEST stage: connect initiated"));
    std::vector<reach::DirectSessionEvent> received;
    auto pump=[&]() { MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,helperWindow,WM_SOCKETEX_TRIGGER,0xBFFF,PM_REMOVE);++i) DispatchMessage(&message);
        if(consumerOwned) manager.TickDirectConnections();
        else { auto events=manager.DirectEvents().Drain(); received.insert(received.end(),events.begin(),events.end()); }
        Sleep(1); };
    const auto connectedDeadline=Now()+8000;
    auto awaitingConnection=[&]() { const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(state.has_value(),"prepared TCP attempt remains live during connect");
        return state->state!=reach::DirectSessionState::Authenticating; };
    while(Now()<connectedDeadline && (remote==INVALID_SOCKET || (consumerOwned ?
        awaitingConnection() : received.empty()))) {
        if(remote==INVALID_SOCKET) remote=accept(listener,nullptr,nullptr);
        pump();
    }
    if(wrongDestination) {
        Require(remote!=INVALID_SOCKET && received.size()==1 && received[0].type==reach::DirectEventType::Closed &&
            received[0].reason==reach::DirectReason::IdentityMismatch && received[0].sequence==1 &&
            received[0].route_id==1 && received[0].session_epoch==0,
            "real TCP different destination closed before Connected or authentication");
        manager.DirectConnections().Advance(admitted.request.handle,Now(),received);
        const auto rejected=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(rejected && rejected->winner==0 && !rejected->useful_bytes && !rejected->transfer_verified,
            "different TCP endpoint grants no winner bytes or proof");
        return;
    }
    Require(remote!=INVALID_SOCKET && (consumerOwned || (received.size()==1 && received[0].type==reach::DirectEventType::Connected &&
        received[0].route_id==1 && received[0].session_epoch==0 && received[0].sequence==1)),
        "real TCP OnConnect emits exactly one owned Connected");
    Log(_T("LEGACY_OWNER_SELFTEST stage: connected event"));
    if(!consumerOwned) manager.DirectConnections().Advance(admitted.request.handle,Now(),received);
    received.clear();
    const auto connected=manager.DirectConnections().Snapshot(admitted.request.handle);
    Require(connected && connected->state==reach::DirectSessionState::Authenticating && connected->winner==0 &&
        connected->useful_bytes==0 && !connected->transfer_verified && !socket->HasAuthenticatedDirectConnection(),"TCP connected grants no identity winner useful bytes or proof");
    if(validHello) {
        Require(CNativeDirectSelfTestAccess::LegacyHelloPacket(*socket,helloBytes.get(),helloSize),
            "expected legacy HELLOANSWER reaches normal production parser");
        Require(theApp.clientlist->IsValidClient(client) && client->socket==socket && socket->client==client &&
            (secureIdentCase>=5 || client->GetDirectClientLifetime()==lifetime) && !memcmp(client->GetUserHash(),expectedHash.data(),16),
            "valid legacy HELLOANSWER preserves registered client lifetime");
        if(secureIdentCase) {
            Require(secureIdentCase<=9 && theApp.clientcredits->CryptoAvailable() && client->Credits(),"legacy real SecureIdent prerequisites");
            CryptoPP::AutoSeededRandomPool random;
            // Match the existing legacy SecureIdent fixture key size/encoding;
            // this ephemeral signer is not a new product cryptographic policy.
            CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(random,384);
            CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(signer);
            std::array<BYTE,MAXPUBKEYSIZE+1> publicPacket{};
            CryptoPP::ArraySink keySink(publicPacket.data()+1,MAXPUBKEYSIZE);
            verifier.GetMaterial().Save(keySink); keySink.MessageEnd();
            publicPacket[0]=static_cast<BYTE>(keySink.TotalPutLength());
            const auto priorKeyLength=client->Credits()->GetSecIDKeyLen();
            client->ProcessPublicKeyPacket(nullptr,0);
            client->ProcessPublicKeyPacket(nullptr,10);
            for(uint32 shortSize=0;shortSize<10;++shortSize)
                client->ProcessPublicKeyPacket(publicPacket.data(),shortSize);
            client->ProcessPublicKeyPacket(publicPacket.data(),251);
            Require(client->Credits()->GetSecIDKeyLen()==priorKeyLength,
                "legacy malformed public key null short oversized preserves key before valid RSA exchange");
            client->ProcessPublicKeyPacket(publicPacket.data(),publicPacket[0]+1);
            Require(client->Credits()->GetSecIDKeyLen()==publicPacket[0],"legacy ephemeral public key accepted by production handler");
            client->SendSecIdentStatePacket();
            Require(client->Credits()->m_dwCryptRndChallengeFor!=0,"legacy production challenge generated");
            CreditStruct empty{}; CClientCredits target(empty);
            Require(target.SetSecureIdent(theApp.clientcredits->GetPublicKey(),theApp.clientcredits->GetPubKeyLen()),"legacy signer targets actual local public key");
            target.m_dwCryptRndChallengeFrom=client->Credits()->m_dwCryptRndChallengeFor;
            std::array<BYTE,201> signature{};
            signature[0]=theApp.clientcredits->CreateSignature(&target,signature.data()+1,200,0,0,&signer);
            Require(signature[0]>=10,"legacy real RSA signature generated");
            if(secureIdentCase==2) signature[1]^=1;
            if(secureIdentCase>=5) Require(!transferClient->socket && !transferClient->Credits() &&
                CNativeDirectSelfTestAccess::LegacyPendingRange(*transferClient)==originalRange &&
                manager.HasDirectTransferSubscription(lifetime,admitted.request.handle),
                "original transfer remains untouched throughout separate route HELLO and challenge");
            client->ProcessSignaturePacket(signature.data(),signature[0]+1);
            if(consumerOwned) {
                const auto routeLifetime=client->GetDirectClientLifetime();
                manager.TickDirectConnections();
                const auto adopted=manager.DirectConnections().Snapshot(admitted.request.handle);
                if(mergeIdentity) {
                    const auto destination=manager.DirectConnections().Snapshot(identityTargetHandle);
                    const auto rebound=manager.ResolveDirectSubscriber(token);
                    Log(_T("IDENTITY_MERGE_SELFTEST state: source=%u target=%u subscribers=%u rebound=%u terminal=%u sourceSocket=%u targetSocket=%u rsa=%u"),
                        adopted ? unsigned(adopted->state):255u,destination ? unsigned(destination->state):255u,
                        destination ? unsigned(destination->subscribers):0u,unsigned(rebound && rebound->attempt && rebound->attempt->slot==identityTargetHandle.slot),
                        unsigned(rebound && bool(rebound->terminal_reason)),unsigned(transferClient->socket!=nullptr),
                        unsigned(identityTarget->socket!=nullptr),unsigned(transferClient->HasPassedSecureIdent(false)));
                    Require((!adopted || adopted->state==reach::DirectSessionState::Cancelled) && destination &&
                        destination->state==reach::DirectSessionState::Gathering && destination->subscribers==2 &&
                        !destination->winner && !destination->useful_bytes && !destination->transfer_verified &&
                        rebound && rebound->attempt && rebound->attempt->slot==identityTargetHandle.slot &&
                        rebound->attempt->generation==identityTargetHandle.generation && !rebound->terminal_reason &&
                        manager.DirectTransferClientLifetime(identityTargetHandle)==identityTarget->GetDirectClientLifetime() &&
                        !transferClient->socket && !identityTarget->socket,
                        "real RSA provisional merge closes source before attach data and rebinds without terminal or owner replacement");
                    manager.TickDirectConnections();
                    Require(!manager.DirectConnections().Snapshot(admitted.request.handle),"redundant actual TCP owner fully drained and released");
                    Log(_T("REACH_SELFTEST V159 PASS: actual TCP HELLO fresh RSA provisional identity merges subscribers into known gathering peer source closes before attach zero payload and drained; target has no transport not dual connected session proof"));
                    return;
                }
                Require(adopted && adopted->state==reach::DirectSessionState::Ready && adopted->winner==1 && adopted->epoch==1 &&
                    socket->HasAuthenticatedDirectConnection() && !adopted->useful_bytes && !adopted->transfer_verified,
                    "consumer adopts actual SecureIdent winner without manual Advance or Adopt");
                if(!scheduled) {
                    Require(adopted->peer.domain==reach::DirectPeerDomain::UserHash &&
                        !std::memcmp(adopted->peer.identity.data(),expectedHash.data(),16),"actual RSA promotes provisional DCO key before attachment");
                    Log(_T("REACH_SELFTEST V158 PASS: actual TCP HELLO fresh RSA promotes provisional DCO identity before single attach; expected hash alone did not promote"));
                }
                if(secureIdentCase>=5) {
                    Require(socket->client==transferClient && transferClient->socket==socket &&
                        transferClient->GetDirectClientLifetime()==lifetime && !manager.HasDirectTransferSubscription(routeLifetime,admitted.request.handle) &&
                        !theApp.clientlist->FindClientByLifetime(routeLifetime) && transferClient->HasPassedSecureIdent(false) &&
                        !transferClient->HasIsolatedDirectRouteCredits() &&
                        CNativeDirectSelfTestAccess::LegacyPendingRange(*transferClient)==originalRange,
                        "consumer promotes winner to original client preserving pending ranges and deletes temporary route client");
                    client=transferClient;
                }
                CNativeDirectSelfTestAccess::TestTcpObservation(manager,*client,route);
                const auto contributor=socket->LegacyDirectPartContributor();
                Require(contributor && manager.ValidateLegacyDirectPartDelivery(*contributor)==socket,
                    "authenticated adopted legacy contributor resolves original socket");
                auto changed=*contributor; ++changed.owner;
                Require(!manager.ValidateLegacyDirectPartDelivery(changed),"legacy contributor wrong lifetime rejected");
                changed=*contributor; ++changed.epoch;
                Require(!manager.ValidateLegacyDirectPartDelivery(changed),"legacy contributor wrong epoch rejected");
                changed=*contributor; ++changed.route;
                Require(!manager.ValidateLegacyDirectPartDelivery(changed),"legacy contributor wrong route rejected");
                changed=*contributor; ++changed.topology;
                Require(!manager.ValidateLegacyDirectPartDelivery(changed),"legacy contributor wrong topology rejected");
                changed=*contributor; changed.kind=reach::DirectPartOwnerKind::Quic;
                Require(!manager.ValidateLegacyDirectPartDelivery(changed),"legacy contributor wrong domain rejected");
                client->ProcessSignaturePacket(signature.data(),signature[0]+1);
                manager.TickDirectConnections();
                Require(socket->HasAuthenticatedDirectConnection(),"consumer duplicate authentication preserves adopted socket");
                if(scheduled) {
                    std::function<void()> reconnect;
                    if(secureIdentCase>=8) reconnect=[&]() {
                        auto* originalSocket=socket;
                        closesocket(remote); remote=INVALID_SOCKET;
                        const auto closedDeadline=Now()+8000;
                        while(Now()<closedDeadline && client->socket) pump();
                        const auto lost=manager.DirectConnections().Snapshot(admitted.request.handle);
                        Require(lost && lost->state==reach::DirectSessionState::Recovering && lost->epoch==1 &&
                            lost->useful_bytes==4096 && !client->socket && originalSocket->GetSocketHandle()==INVALID_SOCKET,
                            "TCP partial real close enters recovery and retains useful total");
                        Require(CNativeDirectSelfTestAccess::HasPendingOwnedRecovery(manager,admitted.request.handle,1),
                            "TCP loss retains owned recovery intent after actual socket drain");
                        pump();
                        const auto waiting=manager.DirectConnections().Snapshot(admitted.request.handle);
                        Require(waiting && waiting->state==lost->state && waiting->epoch==lost->epoch &&
                            waiting->highest_route_id==lost->highest_route_id && waiting->useful_bytes==lost->useful_bytes &&
                            !client->socket && CNativeDirectSelfTestAccess::HasPendingOwnedRecovery(manager,admitted.request.handle,1),
                            "TCP recovery pump without eligible evidence preserves intent and creates no route");
                        Log(_T("REACH_SELFTEST V143 PASS: TCP actual partial4096 socket loss retains owned recovery intent epoch highwater useful bytes no unproven automatic route; subsequent explicit route repair not public fallback"));
                        auto next=route; next.id=2; next.candidate.id=2; next.candidate.expires_monotonic_ms=Now()+8000;
                        Require(manager.RegisterDirectLegacyRoute(admitted.request.handle,next) &&
                            manager.ScheduleDirectQuicRoutes(admitted.request.handle,{next}),"TCP recovery authorized new route Start");
                        socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,2);
                        Require(socket && socket!=originalSocket && socket->client!=client,"TCP recovery isolated fresh socket");
                        helperWindow=CNativeDirectSelfTestAccess::LegacySocketWindow(*socket);
                        const auto connectDeadline=Now()+8000;
                        while(Now()<connectDeadline) {
                            if(remote==INVALID_SOCKET) remote=accept(listener,nullptr,nullptr);
                            pump(); const auto current=manager.DirectConnections().Snapshot(admitted.request.handle);
                            if(remote!=INVALID_SOCKET && current && current->state==reach::DirectSessionState::Authenticating) break;
                        }
                        Require(remote!=INVALID_SOCKET,"TCP recovery fresh remote accepted");
                        auto* temporary=socket->client;
                        Require(CNativeDirectSelfTestAccess::LegacyHelloPacket(*socket,helloBytes.get(),helloSize),"TCP recovery expected HELLO");
                        temporary->ProcessPublicKeyPacket(publicPacket.data(),publicPacket[0]+1);
                        temporary->SendSecIdentStatePacket();
                        CreditStruct blank{}; CClientCredits freshTarget(blank);
                        Require(freshTarget.SetSecureIdent(theApp.clientcredits->GetPublicKey(),theApp.clientcredits->GetPubKeyLen()),"TCP recovery signature target");
                        freshTarget.m_dwCryptRndChallengeFrom=temporary->Credits()->m_dwCryptRndChallengeFor;
                        std::array<BYTE,201> freshSignature{};
                        freshSignature[0]=theApp.clientcredits->CreateSignature(&freshTarget,freshSignature.data()+1,200,0,0,&signer);
                        Require(freshSignature[0]>=10,"TCP recovery fresh RSA challenge signature");
                        temporary->ProcessSignaturePacket(freshSignature.data(),freshSignature[0]+1);
                        manager.TickDirectConnections();
                        const auto resumed=manager.DirectConnections().Snapshot(admitted.request.handle);
                        Require(resumed && resumed->epoch==2 && resumed->winner==2 && resumed->useful_bytes==4096 &&
                            !resumed->transfer_verified && client->socket==socket && socket->HasAuthenticatedDirectConnection(),
                            "TCP recovery fresh authentication adopts original at epoch2");
                    };
                    RunLegacyPartialFile(manager,*client,remote,admitted.request.handle,pump,secureIdentCase==7,reconnect,secureIdentCase==9);
                    CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*client);
                }
                if(secureIdentCase<5) CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*client);
                const auto range=CNativeDirectSelfTestAccess::LegacyPendingRange(*client);
                const auto* credits=client->Credits();
                closesocket(remote); remote=INVALID_SOCKET;
                const auto closeDeadline=Now()+8000;
                while(Now()<closeDeadline && client->socket) pump();
                const auto closed=manager.DirectConnections().Snapshot(admitted.request.handle);
                Require(socket->GetSocketHandle()==INVALID_SOCKET,
                    "legacy consumer OS close releases actual socket immediately despite delayed wrapper deletion");
                Require(!manager.ValidateLegacyDirectPartDelivery(*contributor),"closed legacy contributor rejected");
                Require(closed && closed->state==reach::DirectSessionState::Recovering && !client->socket &&
                    client->GetDirectClientLifetime()==lifetime && client->Credits()==credits &&
                    CNativeDirectSelfTestAccess::LegacyPendingRange(*client)==range &&
                    manager.HasDirectTransferSubscription(lifetime,admitted.request.handle),
                    "consumer handles OS close and drains TCP route preserving transfer for recovery");
                manager.RetireDirectClient(lifetime);
                manager.TickDirectConnections(); manager.TickDirectConnections();
                Require(!manager.DirectConnections().Snapshot(admitted.request.handle) && !manager.DirectConnections().Size() &&
                    manager.DirectEvents().Drain().empty(),"consumer subscriber retirement releases attempt after route drain");
                return;
            }
            const auto authenticated=manager.DirectEvents().Drain();
            Require(authenticated.size()==1 && authenticated[0].sequence==2 && authenticated[0].route_id==1 &&
                authenticated[0].session_epoch==0 && authenticated[0].type==(secureIdentCase!=2 ?
                    reach::DirectEventType::Authenticated : reach::DirectEventType::AuthenticationFailed) &&
                authenticated[0].reason==(secureIdentCase!=2 ? reach::DirectReason::None : reach::DirectReason::IdentityMismatch),
                "real VerifyIdent result emits one exact owned DCO authentication event");
            client->ProcessSignaturePacket(signature.data(),signature[0]+1);
            Require(manager.DirectEvents().Drain().empty(),"duplicate SecureIdent signature gives no second event");
            const auto actions=manager.DirectConnections().Advance(admitted.request.handle,Now(),authenticated);
            const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
            Require(state && !state->useful_bytes && !state->transfer_verified,"SecureIdent gives no file bytes or proof");
            if(secureIdentCase==4) {
                Require(client->HasPassedSecureIdent(false) && state->state==reach::DirectSessionState::Ready && state->winner==1 &&
                    !memcmp(globalCredits->GetDataStruct(),&globalCreditBefore,sizeof globalCreditBefore) &&
                    globalCredits->m_dwCryptRndChallengeFor==globalChallengeFor && globalCredits->m_dwCryptRndChallengeFrom==globalChallengeFrom &&
                    otherRoute->Credits()->m_dwCryptRndChallengeFor==0x5a17 && !otherRoute->HasPassedSecureIdent(false),
                    "real route RSA verification leaves global credits and other route challenge proof untouched");
                Require(!socket->AdoptLegacyDirectRoute(admitted.request.handle,1,1),
                    "temporary isolated client cannot be adopted as transfer client");
                CreditStruct pinned=*client->Credits()->GetDataStruct();
                pinned.nUploadedLo=1234; pinned.nDownloadedLo=5678;
                CClientCredits destination(pinned);
                destination.m_dwCryptRndChallengeFor=0x12345678;
                destination.m_dwCryptRndChallengeFrom=0x87654321;
                const auto destinationBefore=*destination.GetDataStruct();
                auto commit=[&](const BYTE* key,const BYTE* signedBytes,uint32 challenge,uint8 kind) {
                    return theApp.clientcredits->PromoteDirectIdent(destination,key,publicPacket[0],
                        signedBytes,signature[0],challenge,client->GetIP(),kind); };
                auto corrupt=signature; corrupt[1]^=1;
                auto changedKey=publicPacket; changedKey[1]^=1;
                const auto challenge=client->Credits()->m_dwCryptRndChallengeFor;
                Require(!commit(publicPacket.data()+1,corrupt.data()+1,challenge,0) &&
                    !commit(publicPacket.data()+1,signature.data()+1,challenge^1,0) &&
                    !commit(changedKey.data()+1,signature.data()+1,challenge,0) &&
                    !commit(publicPacket.data()+1,signature.data()+1,challenge,255) &&
                    !memcmp(destination.GetDataStruct(),&destinationBefore,sizeof destinationBefore) &&
                    destination.GetCurrentIdentState(client->GetIP())!=IS_IDENTIFIED,
                    "promotion rejects signature challenge key and kind without destination mutation");
                Require(commit(publicPacket.data()+1,signature.data()+1,challenge,0) &&
                    destination.GetCurrentIdentState(client->GetIP())==IS_IDENTIFIED &&
                    !memcmp(destination.GetDataStruct(),&destinationBefore,sizeof destinationBefore) &&
                    destination.m_dwCryptRndChallengeFor==0x12345678 && destination.m_dwCryptRndChallengeFrom==0x87654321,
                    "promotion rechecks real RSA pinned key preserves counters and independent destination challenges");
                return; // winner promotion into original transfer client follows separately
            }
            if(secureIdentCase==1) {
                Require(client->HasPassedSecureIdent(false) && state->state==reach::DirectSessionState::Ready && state->winner==1 &&
                    state->epoch==1 && actions.actions.size()==1 && actions.actions[0].type==reach::DirectActionType::Attach,
                    "valid real RSA selects one winner and new epoch Attach not socket adoption");
                auto staleHandle=admitted.request.handle; ++staleHandle.generation;
                Require(!socket->AdoptLegacyDirectRoute(staleHandle,1,1) &&
                    !socket->AdoptLegacyDirectRoute(admitted.request.handle,2,1) &&
                    !socket->AdoptLegacyDirectRoute(admitted.request.handle,1,0) &&
                    !socket->AdoptLegacyDirectRoute(admitted.request.handle,1,2),"legacy adoption rejects wrong generation route epoch");
                Require(socket->AdoptLegacyDirectRoute(admitted.request.handle,1,1) &&
                    socket->HasAuthenticatedDirectConnection() &&
                    !socket->AdoptLegacyDirectRoute(admitted.request.handle,1,1),"legacy exact winner adopted once");
                const auto downloadBefore=client->GetDownloadState();
                const auto* fileBefore=client->GetRequestFile();
                const auto* creditBefore=client->Credits();
                CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*client);
                const auto rangeBefore=CNativeDirectSelfTestAccess::LegacyPendingRange(*client);
                closesocket(remote); remote=INVALID_SOCKET; received.clear();
                const auto deadline=Now()+8000;
                while(Now()<deadline && received.empty()) pump();
                Require(received.size()==1 && received[0].type==reach::DirectEventType::Closed &&
                    received[0].sequence==3 && received[0].session_epoch==1 && received[0].route_id==1,
                    "adopted TCP OS close carries adopted epoch exactly once");
                Require(theApp.clientlist->IsValidClient(client) && client->GetDirectClientLifetime()==lifetime &&
                    !client->socket && client->GetDownloadState()==downloadBefore && client->GetRequestFile()==fileBefore &&
                    client->Credits()==creditBefore && !memcmp(client->GetUserHash(),expectedHash.data(),16) &&
                    manager.HasDirectTransferSubscription(lifetime,admitted.request.handle),
                    "owned TCP close preserves logical client transfer identity state and subscription");
                Require(CNativeDirectSelfTestAccess::LegacyPendingRange(*client)==rangeBefore,
                    "owned TCP close preserves pending block offsets transferred and decompression accounting");
                manager.DirectConnections().Advance(admitted.request.handle,Now(),received);
            } else Require(!client->HasPassedSecureIdent(false) && !state->winner && state->state==reach::DirectSessionState::Failed,
                "corrupt real RSA fails identity no winner");
            return;
        }
        const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(state && state->state==reach::DirectSessionState::Authenticating && !state->winner &&
            !state->useful_bytes && !state->transfer_verified && manager.DirectEvents().Drain().empty() &&
            !socket->HasAuthenticatedDirectConnection(),"matching HELLO and ConnectionEstablished are not DCO authentication");
        return;
    }
    if(invalidHello) {
        const auto* creditsBefore=client->Credits();
        const auto handshakeBefore=client->CheckHandshakeFinished();
        helloBytes[0]^=1;
        if(wireHello) {
            Packet packet(OP_HELLOANSWER,helloSize,OP_EDONKEYPROT);
            memcpy(packet.pBuffer,helloBytes.get(),helloSize);
            const auto bytes=packet.GetPacket(); const auto size=packet.GetRealPacketSize();
            uint32 sent=0; const auto deadline=Now()+8000;
            while(Now()<deadline && (sent<size || received.empty())) {
                if(sent<size) {
                    const auto count=send(remote,bytes+sent,static_cast<int>(size-sent),0);
                    if(count>0) sent+=static_cast<uint32>(count);
                    else Require(count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK,"legacy wire HELLO send progress");
                }
                pump();
            }
            Require(sent==size && received.size()==1,"legacy HELLO traverses actual TCP receive packet callback");
        } else {
            Require(!CNativeDirectSelfTestAccess::LegacyHelloPacket(*socket,helloBytes.get(),helloSize),
                "legacy production packet handler rejects changed HELLO hash");
        }
        Require(!memcmp(client->GetUserHash(),expectedHash.data(),16) && client->Credits()==creditsBefore &&
            client->CheckHandshakeFinished()==handshakeBefore && !socket->HasAuthenticatedDirectConnection(),
            "rejected legacy HELLO preserves identity credits and handshake");
        const auto rejectedEvents=wireHello ? received : manager.DirectEvents().Drain();
        Require(rejectedEvents.size()==1 && rejectedEvents[0].type==reach::DirectEventType::AuthenticationFailed &&
            rejectedEvents[0].reason==reach::DirectReason::IdentityMismatch && rejectedEvents[0].sequence==2 &&
            rejectedEvents[0].route_id==1 && rejectedEvents[0].session_epoch==0,
            "rejected legacy HELLO emits one exact owned authentication failure");
        manager.DirectConnections().Advance(admitted.request.handle,Now(),rejectedEvents);
        const auto failed=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(failed && !failed->winner && !failed->useful_bytes && !failed->transfer_verified,
            "legacy rejected HELLO gives no DCO winner bytes proof");
        helloBytes[0]^=1; // even the originally expected hash cannot revive a terminal owner
        Require(!CNativeDirectSelfTestAccess::LegacyHelloPreflight(*socket,helloBytes.get(),helloSize),
            "terminal legacy owner rejects late matching HELLO");
        return;
    }
    closesocket(remote); remote=INVALID_SOCKET;
    Log(_T("LEGACY_OWNER_SELFTEST stage: remote closed"));
    const auto closeDeadline=Now()+8000;
    while(Now()<closeDeadline && received.empty()) pump();
    Require(received.size()==1 && received[0].type==reach::DirectEventType::Closed && received[0].sequence==2 &&
        received[0].reason==reach::DirectReason::DirectUnreachable,"real TCP peer close emits one typed owned event");
    Log(_T("LEGACY_OWNER_SELFTEST stage: closed event"));
    manager.DirectConnections().Advance(admitted.request.handle,Now(),received);
}

inline void RunKnownDirectAdmission(CDirectReachabilityManager& manager) {
    Require(theApp.m_bReachBindingSelfTest && !manager.DirectConnections().Size(),"known normal admission isolated fixture");
    struct Restore { int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        ~Restore() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled); } } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    Require(manager.InstallQuicDownloadConsumer(),"known normal admission consumer");
    auto file=std::make_unique<CPartFile>(_T("ed2k://|file|normal-admission.bin|4097|A8A80000000000000000000000000042|/"));
    Require(file->GetStatus()==PS_READY || file->GetStatus()==PS_EMPTY,"known normal admission eligible file");
    class Client final : public CUpDownClient {
    public: Client():CUpDownClient(static_cast<CPartFile*>(nullptr),4662,INADDR_LOOPBACK,0,0,false) { m_uEseCapabilities|=0x10000000; }
    };
    auto client=std::make_unique<Client>(); std::array<BYTE,16> hash{}; hash[0]=0xA8; hash[15]=0x42;
    client->SetUserHash(hash.data()); client->SetRequestFile(file.get()); theApp.clientlist->AddClient(client.get());
    const auto lifetime=client->GetDirectClientLifetime();
    struct Cleanup { CDirectReachabilityManager& manager; CUpDownClient& client;
        ~Cleanup() { manager.RetireDirectClient(client.GetDirectClientLifetime()); manager.TickDirectConnections(); manager.TickDirectConnections(); client.SetRequestFile(nullptr); }
    } cleanup{manager,*client};
    Require(!client->GetNativeDirectDownloadSubscriber() && client->TryToConnect() && !client->socket,
        "normal TryToConnect automatically admits capable download no classic socket");
    const auto token=client->GetNativeDirectDownloadSubscriber();
    Require(token!=0,"normal TryToConnect creates owned subscriber without manual Request");
    manager.TickDirectConnections(); manager.TickDirectConnections();
    Require(manager.TakeDirectTerminal(token,lifetime)==reach::DirectReason::BootstrapRequired && !manager.TakeDirectTerminal(token,lifetime) &&
        !manager.DirectConnections().Size() && !client->socket && !client->Credits() && client->GetRequestFile()==file.get(),
        "normal missing trust produces typed bootstrap failure no advertised TCP upgrade");
    Require(client->TryToConnect() && !client->socket && !manager.DirectConnections().Size() &&
        client->GetDirectClientLifetime()==lifetime && !memcmp(client->GetUserHash(),hash.data(),16),"normal cooldown creates no classic cascade after typed failure");
}

inline void RunLegacyReservationCancellation(CDirectReachabilityManager& manager,bool consumerFailure=false) {
    Require(theApp.m_bReachBindingSelfTest && !manager.DirectConnections().Size(),"legacy reservation cancellation isolated fixture");
    struct RestoreLab { int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        ~RestoreLab() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled); } } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    Require(manager.InstallQuicDownloadConsumer(),"reservation cancellation consumer");
    auto client=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),4662,INADDR_LOOPBACK,0,0,false);
    std::array<BYTE,16> hash{}; hash[0]=0xA6; hash[14]=consumerFailure ? 1 : 0; hash[15]=0x32; client->SetUserHash(hash.data());
    theApp.clientlist->AddClient(client.get());
    CNativeDirectSelfTestAccess::SeedLegacyPendingRange(*client);
    const auto range=CNativeDirectSelfTestAccess::LegacyPendingRange(*client);
    const auto lifetime=client->GetDirectClientLifetime();
    struct Cleanup { CDirectReachabilityManager& manager; uint64 lifetime;
        ~Cleanup() { manager.RetireDirectClient(lifetime); manager.TickDirectConnections(); manager.TickDirectConnections(); }
    } cleanup{manager,lifetime};
    reach::NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=manager.GetTopologyGeneration(); snapshot.peer.expected_user_hash=hash;
    const auto token=manager.AcquireDirectSubscriber(lifetime,reach::DirectConsumerKind::Download);
    const auto admitted=manager.RequestDirectConnection(snapshot,lifetime,1,token);
    Require(token && admitted.request.status==reach::DirectRequestStatus::Created,"reservation cancellation admission");
    reach::DirectSessionRoute route; route.id=1; route.transport=reach::DirectTcp; route.candidate.id=1;
    route.candidate.family=4; route.candidate.address[0]=127; route.candidate.address[3]=1;
    route.candidate.port=4662; route.candidate.transport_mask=reach::DirectTcp;
    route.candidate.topology_generation=snapshot.local_generation; route.candidate.expires_monotonic_ms=Now()+8000;
    Require(manager.RegisterDirectLegacyRoute(admitted.request.handle,route) &&
        CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
        !CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1) && !client->socket,
        "reserved legacy adapter creates no socket without Start");
    auto second=route; second.id=2; second.candidate.id=2; ++second.candidate.port;
    Require(manager.RegisterDirectLegacyRoute(admitted.request.handle,second),"second legacy reservation before Start");
    auto rejected=route; rejected.id=3; rejected.candidate.id=3; rejected.candidate.port=0;
    Require(!manager.RegisterDirectLegacyRoute(admitted.request.handle,rejected) &&
        !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,3) &&
        CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
        CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,2) &&
        !CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,2),
        "invalid third reservation leaves only two owned unscheduled contexts");
    if(consumerFailure) {
        CNativeDirectSelfTestAccess::FailLegacyReservationsForTest(manager,admitted.request.handle);
        manager.TickDirectConnections(); manager.TickDirectConnections();
        Require(!manager.DirectConnections().Snapshot(admitted.request.handle) &&
            !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
            !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,2) &&
            manager.TakeDirectTerminal(token,lifetime)==reach::DirectReason::NoRoute &&
            !manager.TakeDirectTerminal(token,lifetime),"consumer failure drains both reservations and delivers terminal exactly once");
    }
    manager.RetireDirectClient(lifetime);
    manager.TickDirectConnections(); manager.TickDirectConnections();
    Require(!manager.ResolveDirectSubscriber(token) && !manager.DirectConnections().Snapshot(admitted.request.handle) &&
        !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
        !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,2) && !client->socket &&
        theApp.clientlist->IsValidClient(client.get()) && client->GetDirectClientLifetime()==lifetime &&
        !memcmp(client->GetUserHash(),hash.data(),16) && CNativeDirectSelfTestAccess::LegacyPendingRange(*client)==range,
        "cancel before Start drains reservation attempt subscription and preserves original client ranges");
    Require(!manager.RegisterDirectLegacyRoute(admitted.request.handle,route) &&
        !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) && !manager.DirectConnections().Size(),
        "late legacy reservation cannot resurrect retired handle");
}

inline void RunLegacyUtpStart(CDirectReachabilityManager& manager,uint16 fixturePort,bool authenticate=false,bool corruptSignature=false,bool transferFile=false,bool cancelConnecting=false) {
    Require(!cancelConnecting || (!authenticate && !transferFile),"owned uTP cancellation before identity");
    Require(!transferFile || (authenticate && !corruptSignature),"owned uTP file needs valid identity");
    Require(!corruptSignature || authenticate,"owned uTP corrupt signature requires identity exchange");
    Require(theApp.m_bReachBindingSelfTest && theApp.clientudp && fixturePort && !manager.DirectConnections().Size(),"owned uTP isolated fixture");
    struct RestoreLab {
        int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled(),punch=thePrefs.GetUtpHolePunchEnabled();
        uint16 port=thePrefs.GetUDPPort();
        ~RestoreLab() { thePrefs.SetUDPPort(port); theApp.clientudp->Rebind(); thePrefs.SetUtpHolePunchEnabled(punch); thePrefs.SetEseNetLabEnabled(enabled); thePrefs.SetEseNetLabConsent(consent); }
    } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true); thePrefs.SetUtpHolePunchEnabled(true);
    thePrefs.SetUDPPort(fixturePort);
    if(theApp.clientudp->GetConnectedPort()!=fixturePort) Require(theApp.clientudp->Rebind(),"owned uTP fixture UDP bind");
    Require(theApp.clientudp->IsUtpReady() && manager.InstallQuicDownloadConsumer(),"owned uTP shared UDP ready");
    struct Peer {
        SOCKET udp=INVALID_SOCKET; utp_context* context=nullptr; utp_socket* current=nullptr;
        std::array<uint8,65536> bytes{}; size_t count=0; unsigned accepted=0,errors=0; bool failed=false;
        ~Peer() { if(context) utp_destroy(context); if(udp!=INVALID_SOCKET) closesocket(udp); }
        static uint64 Send(utp_callback_arguments* args) noexcept {
            auto* p=static_cast<Peer*>(utp_context_get_userdata(args->context));
            if(sendto(p->udp,reinterpret_cast<const char*>(args->buf),static_cast<int>(args->len),0,args->address,args->address_len)!=static_cast<int>(args->len)) p->failed=true;
            return 0;
        }
        static uint64 Accept(utp_callback_arguments* args) noexcept {
            auto* p=static_cast<Peer*>(utp_context_get_userdata(args->context));
            if(p->current) { p->failed=true; utp_close(args->socket); } else { p->current=args->socket; ++p->accepted; }
            return 0;
        }
        static uint64 Read(utp_callback_arguments* args) noexcept {
            auto* p=static_cast<Peer*>(utp_context_get_userdata(args->context));
            if(args->socket!=p->current || args->len>p->bytes.size()-p->count) p->failed=true;
            else { memcpy(p->bytes.data()+p->count,args->buf,args->len); p->count+=args->len; }
            utp_read_drained(args->socket); return 0;
        }
        static uint64 Error(utp_callback_arguments* args) noexcept {
            auto* p=static_cast<Peer*>(utp_context_get_userdata(args->context)); ++p->errors; return 0;
        }
    } peer;
    peer.udp=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    Require(peer.udp!=INVALID_SOCKET,"owned uTP peer UDP");
    sockaddr_in endpoint{}; endpoint.sin_family=AF_INET; endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    Require(!bind(peer.udp,reinterpret_cast<sockaddr*>(&endpoint),sizeof endpoint),"owned uTP peer bind");
    int length=sizeof endpoint; u_long nonblocking=1;
    Require(!getsockname(peer.udp,reinterpret_cast<sockaddr*>(&endpoint),&length) && !ioctlsocket(peer.udp,FIONBIO,&nonblocking),"owned uTP peer endpoint");
    peer.context=utp_init(2); Require(peer.context!=nullptr,"owned uTP peer context");
    utp_context_set_userdata(peer.context,&peer);
    utp_set_callback(peer.context,UTP_SENDTO,&Peer::Send); utp_set_callback(peer.context,UTP_ON_ACCEPT,&Peer::Accept);
    utp_set_callback(peer.context,UTP_ON_READ,&Peer::Read); utp_set_callback(peer.context,UTP_ON_ERROR,&Peer::Error);
    auto client=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),ntohs(endpoint.sin_port),INADDR_LOOPBACK,0,0,false);
    std::array<BYTE,16> hash{}; hash[0]=0xA7; hash[14]=cancelConnecting?4:transferFile?3:corruptSignature?2:(authenticate?1:0); hash[15]=0x36; client->SetUserHash(hash.data()); theApp.clientlist->AddClient(client.get());
    const auto lifetime=client->GetDirectClientLifetime();
    struct Cleanup { CDirectReachabilityManager& manager; uint64 lifetime;
        ~Cleanup() { manager.RetireDirectClient(lifetime); manager.TickDirectConnections(); manager.TickDirectConnections(); }
    } cleanup{manager,lifetime};
    reach::NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=manager.GetTopologyGeneration(); snapshot.peer.expected_user_hash=hash;
    const auto token=manager.AcquireDirectSubscriber(lifetime,reach::DirectConsumerKind::Download);
    const auto admitted=manager.RequestDirectConnection(snapshot,lifetime,1,token);
    Require(token && admitted.request.status==reach::DirectRequestStatus::Created,"owned uTP admission");
    reach::DirectSessionRoute route; route.id=1; route.transport=reach::DirectUtp; route.candidate.id=1;
    route.candidate.family=4; memcpy(route.candidate.address.data(),&endpoint.sin_addr,4); route.candidate.port=ntohs(endpoint.sin_port);
    route.candidate.transport_mask=reach::DirectUtp; route.candidate.topology_generation=snapshot.local_generation; route.candidate.expires_monotonic_ms=Now()+8000;
    Require(manager.RegisterDirectLegacyRoute(admitted.request.handle,route) && manager.ScheduleDirectQuicRoutes(admitted.request.handle,{route}),"owned uTP authorized Start");
    auto* socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1);
    Require(socket && socket->GetUtpLayer() && socket->client && socket->client!=client.get() && !client->socket && socket->client->GetConnectIP()==endpoint.sin_addr.s_addr,"owned uTP isolated exact IPv4 start");
    if(cancelConnecting) {
        auto* layer=socket->GetUtpLayer(); sockaddr_storage address{}; int size=sizeof address;
        Require(layer->GetState()==connecting && layer->GetPeerName(reinterpret_cast<sockaddr*>(&address),&size),"owned uTP pending actual session before close");
        layer->Close(); layer->Close(); size=sizeof address;
        Require(!layer->GetPeerName(reinterpret_cast<sockaddr*>(&address),&size),"owned uTP pending close detaches session idempotently");
        manager.RetireDirectClient(lifetime); manager.TickDirectConnections(); manager.TickDirectConnections();
        Require(!manager.DirectConnections().Snapshot(admitted.request.handle) && !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
            !manager.ResolveDirectSubscriber(token) && !client->socket && !client->Credits() &&
            client->GetDirectClientLifetime()==lifetime && theApp.clientlist->IsValidClient(client.get()),"owned uTP pending cancel drains original untouched");
        return;
    }
    auto hasHello=[&]() {
        if(peer.count<6 || peer.bytes[0]!=OP_EDONKEYPROT || peer.bytes[5]!=OP_HELLO) return false;
        uint32 frameSize=0; memcpy(&frameSize,peer.bytes.data()+1,4);
        return frameSize>=1 && frameSize<=peer.bytes.size()-5 && peer.count>=frameSize+5;
    };
    bool filePhase=false;
    auto pump=[&]() {
        MSG message;
        if(!filePhase) while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
        else {
            while(PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE)) DispatchMessage(&message);
            if(socket) {
                const auto window=CNativeDirectSelfTestAccess::LegacySocketWindow(*socket);
                while(PeekMessage(&message,window,WM_SOCKETEX_TRIGGER,0xBFFF,PM_REMOVE)) DispatchMessage(&message);
            }
        }
        socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1);
        if(socket) socket->SendControlData(64*1024,0);
        CUtpSocket::Process(); // Normal periodic libutp write/ACK/timeout pump, absent during synchronous lab execution.
        char datagram[2048]; sockaddr_storage from{}; int fromLength=sizeof from;
        int received=0;
        while((received=recvfrom(peer.udp,datagram,sizeof datagram,0,reinterpret_cast<sockaddr*>(&from),&fromLength))>0) {
            utp_process_udp(peer.context,reinterpret_cast<const uint8*>(datagram),received,reinterpret_cast<sockaddr*>(&from),fromLength); fromLength=sizeof from;
        }
        utp_issue_deferred_acks(peer.context); utp_check_timeouts(peer.context); manager.TickDirectConnections();
        Require(!peer.failed && !peer.errors,"owned uTP peer pump errors");
        Sleep(1);
    };
    const auto deadline=Now()+6000;
    while(Now()<deadline) {
        pump();
        const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
        if(peer.failed || peer.errors || (state && state->state==reach::DirectSessionState::Authenticating && peer.accepted==1 && hasHello())) break;
    }
    const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
    socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,admitted.request.handle,1);
    sockaddr_in actual{}; int actualLength=sizeof actual;
    if(!state) {
        const auto terminal=manager.TakeDirectTerminal(token,lifetime);
        Log(_T("OWNED_UTP_TERMINAL_SELFTEST reason=%u topology=%llu expected=%llu"),terminal?static_cast<unsigned>(*terminal):999,
            static_cast<unsigned long long>(manager.GetTopologyGeneration()),static_cast<unsigned long long>(snapshot.local_generation));
    }
    if(peer.failed || peer.errors || peer.accepted!=1 || !hasHello() || !state || state->state!=reach::DirectSessionState::Authenticating)
        Log(_T("OWNED_UTP_START_SELFTEST accepted=%u errors=%u failed=%u bytes=%u hello=%u state=%u socket=%u"),peer.accepted,peer.errors,peer.failed?1:0,
            static_cast<unsigned>(peer.count),hasHello()?1:0,state?static_cast<unsigned>(state->state):999,socket?1:0);
    Require(!peer.failed && !peer.errors && peer.accepted==1 && hasHello() && state && state->state==reach::DirectSessionState::Authenticating && !state->winner &&
        socket && socket->GetUtpLayer() && socket->GetUtpLayer()->GetPeerName(reinterpret_cast<sockaddr*>(&actual),&actualLength) &&
        actualLength==sizeof actual && actual.sin_family==AF_INET && actual.sin_addr.s_addr==endpoint.sin_addr.s_addr && actual.sin_port==endpoint.sin_port && !client->socket,
        "owned uTP real connect HELLO exact endpoint no authentication winner");
    if(authenticate) {
        auto* isolated=socket->client; const auto isolatedLifetime=isolated->GetDirectClientLifetime();
        auto sendWire=[&](BYTE protocol,BYTE opcode,const BYTE* payload,uint32 size,const std::function<bool()>& done,bool expectTerminal=false) {
            CSafeMemFile body; body.Write(payload,size); Packet packet(body,protocol,opcode);
            size_t offset=0; const auto until=Now()+4000;
            while(Now()<until && (offset<packet.GetRealPacketSize() || !done())) {
                if(offset<packet.GetRealPacketSize()) {
                    const auto written=utp_write(peer.current,packet.GetPacket()+offset,packet.GetRealPacketSize()-offset);
                    Require(written>=0,"owned uTP identity write"); if(written>0) offset+=static_cast<size_t>(written);
                }
                pump();
                Require(expectTerminal || manager.DirectConnections().Snapshot(admitted.request.handle).has_value(),"owned uTP identity attempt remains live");
            }
            Require(offset==packet.GetRealPacketSize() && done(),"owned uTP identity wire actually processed");
        };
        CSafeMemFile hello; hello.WriteHash16(hash.data()); hello.WriteUInt32(0); hello.WriteUInt16(ntohs(endpoint.sin_port));
        hello.WriteUInt32(0); hello.WriteUInt32(0); hello.WriteUInt16(0);
        const auto helloSize=static_cast<uint32>(hello.GetLength()); auto helloBytes=std::unique_ptr<BYTE[]>(hello.Detach());
        sendWire(OP_EDONKEYPROT,OP_HELLOANSWER,helloBytes.get(),helloSize,[&] { return isolated->Credits()!=nullptr && isolated->CheckHandshakeFinished(); });
        Require(!client->socket && !socket->HasAuthenticatedDirectConnection(),"owned uTP HELLO grants no identity");
        CSafeMemFile info; info.WriteUInt8(0x30); info.WriteUInt8(EMULE_PROTOCOL); info.WriteUInt32(1);
        CTag features(ET_FEATURES,uint32(1)); features.WriteTagToFile(info);
        const auto infoSize=static_cast<uint32>(info.GetLength()); auto infoBytes=std::unique_ptr<BYTE[]>(info.Detach());
        sendWire(OP_EMULEPROT,OP_EMULEINFOANSWER,infoBytes.get(),infoSize,[&] { return isolated->Credits()->m_dwCryptRndChallengeFor!=0; });
        uint32 challenge=0; size_t cursor=0; const auto challengeDeadline=Now()+4000;
        while(Now()<challengeDeadline && !challenge) {
            pump();
            while(peer.count-cursor>=6) {
                uint32 frameSize=0; memcpy(&frameSize,peer.bytes.data()+cursor+1,4);
                Require(frameSize>0 && frameSize<=peer.bytes.size()-5,"owned uTP challenge bounded frame");
                if(peer.count-cursor<frameSize+5) break;
                if(peer.bytes[cursor]==OP_EMULEPROT && peer.bytes[cursor+5]==OP_SECIDENTSTATE) {
                    Require(frameSize==6 && peer.bytes[cursor+6]==IS_KEYANDSIGNEEDED,"owned uTP wire key and signature challenge");
                    memcpy(&challenge,peer.bytes.data()+cursor+7,4); Require(challenge!=0,"owned uTP wire challenge nonzero");
                }
                cursor+=frameSize+5;
            }
        }
        Require(challenge && challenge==isolated->Credits()->m_dwCryptRndChallengeFor && !client->socket,"owned uTP peer receives actual local challenge before adoption");
        CryptoPP::AutoSeededRandomPool random; CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(random,384);
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(signer);
        std::array<BYTE,MAXPUBKEYSIZE+1> publicPacket{}; CryptoPP::ArraySink sink(publicPacket.data()+1,MAXPUBKEYSIZE);
        verifier.GetMaterial().Save(sink); sink.MessageEnd(); publicPacket[0]=static_cast<BYTE>(sink.TotalPutLength());
        sendWire(OP_EMULEPROT,OP_PUBLICKEY,publicPacket.data(),publicPacket[0]+1,[&] { return isolated->Credits()->GetSecIDKeyLen()==publicPacket[0]; });
        Require(!client->socket && !socket->HasAuthenticatedDirectConnection(),"owned uTP public key alone grants no identity");
        CreditStruct blank{}; CClientCredits target(blank);
        Require(target.SetSecureIdent(theApp.clientcredits->GetPublicKey(),theApp.clientcredits->GetPubKeyLen()),"owned uTP actual local RSA target");
        target.m_dwCryptRndChallengeFrom=challenge; std::array<BYTE,201> signature{};
        signature[0]=theApp.clientcredits->CreateSignature(&target,signature.data()+1,200,0,0,&signer);
        Require(signature[0]>=10,"owned uTP real RSA signature");
        if(corruptSignature) signature[1]^=1;
        sendWire(OP_EMULEPROT,OP_SIGNATURE,signature.data(),signature[0]+1,[&] {
            const auto current=manager.DirectConnections().Snapshot(admitted.request.handle);
            if(corruptSignature) return !current;
            return current && current->state==reach::DirectSessionState::Ready && current->winner==1 && current->epoch==1;
        },corruptSignature);
        if(corruptSignature) {
            Require(!CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) && !client->socket && !client->Credits() &&
                client->GetDirectClientLifetime()==lifetime && !memcmp(client->GetUserHash(),hash.data(),16) &&
                !theApp.clientlist->FindClientByLifetime(isolatedLifetime) &&
                manager.TakeDirectTerminal(token,lifetime)==reach::DirectReason::IdentityMismatch && !manager.TakeDirectTerminal(token,lifetime),
                "owned uTP corrupt wire signature rejects identity drains route terminal once original untouched");
        } else {
        const auto adopted=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(adopted && !adopted->useful_bytes && !adopted->transfer_verified && client->socket==socket && socket->client==client.get() &&
            client->GetDirectClientLifetime()==lifetime && client->HasPassedSecureIdent(false) && !client->HasIsolatedDirectRouteCredits() &&
            socket->HasAuthenticatedDirectConnection() && !socket->ObservedLegacyTcpCandidate() &&
            !theApp.clientlist->FindClientByLifetime(isolatedLifetime),"owned uTP actual signature adopts original no TCP proof or useful file bytes");
        }
    }
    if(transferFile) {
        filePhase=true; size_t readCursor=0; SOCKET unused=INVALID_SOCKET;
        auto sendStream=[&](const char* bytes,int size) {
            const auto written=utp_write(peer.current,const_cast<char*>(bytes),static_cast<size_t>(size));
            if(written==0) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
            return static_cast<int>(written);
        };
        auto receiveStream=[&](char* bytes,int size) {
            const auto available=peer.count-readCursor;
            if(!available) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
            const auto count=(std::min)(available,static_cast<size_t>(size)); memcpy(bytes,peer.bytes.data()+readCursor,count); readCursor+=count;
            return static_cast<int>(count);
        };
        RunLegacyPartialFile(manager,*client,unused,admitted.request.handle,pump,false,{},false,sendStream,receiveStream);
    }
    manager.RetireDirectClient(lifetime); manager.TickDirectConnections(); manager.TickDirectConnections();
    Require(!manager.DirectConnections().Snapshot(admitted.request.handle) && !CNativeDirectSelfTestAccess::HasLegacyReservation(manager,admitted.request.handle,1) &&
        !manager.ResolveDirectSubscriber(token) && !client->socket && theApp.clientlist->IsValidClient(client.get()),"owned uTP retirement preserves original");
}

inline void RunClassicTcpObservation(CDirectReachabilityManager& manager,unsigned variant=0) {
    Require(variant<=3 && theApp.m_bReachBindingSelfTest && !manager.DirectConnections().Size(),"classic observation explicit fixture");
    struct RestoreLab { int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        ~RestoreLab() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled); } } restore;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    SOCKET listener=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP),remote=INVALID_SOCKET;
    struct CloseSockets { SOCKET& listener; SOCKET& remote;
        ~CloseSockets() { if(remote!=INVALID_SOCKET) closesocket(remote); if(listener!=INVALID_SOCKET) closesocket(listener); }
    } closeSockets{listener,remote};
    Require(listener!=INVALID_SOCKET,"classic TCP listener");
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    Require(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof address)==0 && listen(listener,1)==0,"classic TCP bind listen");
    int length=sizeof address; Require(getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0,"classic TCP owned endpoint");
    u_long nonblocking=1; Require(ioctlsocket(listener,FIONBIO,&nonblocking)==0,"classic listener nonblocking");
    auto client=std::make_unique<CUpDownClient>(static_cast<CPartFile*>(nullptr),ntohs(address.sin_port),INADDR_LOOPBACK,0,0,false);
    std::array<BYTE,16> hash{}; hash[0]=0xA5; hash[14]=static_cast<BYTE>(variant); hash[15]=0x26;
    client->SetUserHash(hash.data()); theApp.clientlist->AddClient(client.get());
    auto* socket=new CClientReqSocket(client.get()); client->socket=socket;
    struct Cleanup { CDirectReachabilityManager& manager; CUpDownClient& client; CClientReqSocket* socket;
        ~Cleanup() { manager.RetireDirectClient(client.GetDirectClientLifetime());
            if(theApp.listensocket->IsValidSocket(socket)) { socket->SetClient(nullptr); socket->Safe_Delete(); }
            client.socket=nullptr; manager.TickDirectConnections(); }
    } cleanup{manager,*client,socket};
    Require(socket->Create(AF_INET),"classic actual socket Create"); socket->WaitForOnConnect();
    const auto window=CNativeDirectSelfTestAccess::LegacySocketWindow(*socket);
    auto pump=[&]() { MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,window,WM_SOCKETEX_TRIGGER,0xBFFF,PM_REMOVE);++i) DispatchMessage(&message);
        manager.TickDirectConnections(); Sleep(1); };
    Require(socket->Connect(reinterpret_cast<sockaddr*>(&address),sizeof address) || WSAGetLastError()==WSAEWOULDBLOCK,"classic actual Connect");
    const auto deadline=Now()+8000;
    while(Now()<deadline && (remote==INVALID_SOCKET || !CNativeDirectSelfTestAccess::ClassicTransportCaptured(*socket))) {
        if(remote==INVALID_SOCKET) remote=accept(listener,nullptr,nullptr); pump();
    }
    if(!CNativeDirectSelfTestAccess::ClassicTransportCaptured(*socket))
        Log(_T("CLASSIC_OBSERVATION_SELFTEST capture missing: accepted=%u connected=%u ip=%08X connectIP=%08X peer=%08X port=%u expectedPort=%u hash=%u lab=%u"),
            unsigned(remote!=INVALID_SOCKET),unsigned(socket->IsConnected()),client->GetIP(),client->GetConnectIP(),socket->GetPeerAddressV4(),
            unsigned(client->GetUserPort()),unsigned(ntohs(address.sin_port)),unsigned(client->HasValidHash()),unsigned(thePrefs.IsEseNetLabActive()));
    Require(remote!=INVALID_SOCKET && CNativeDirectSelfTestAccess::ClassicTransportCaptured(*socket) &&
        !socket->ObservedLegacyTcpCandidate() && !manager.DirectConnections().Size(),"classic Connected captures transport but grants no proof or DCO");
    Require(ioctlsocket(remote,FIONBIO,&nonblocking)==0,"classic wire remote nonblocking");
    auto sendWire=[&](BYTE protocol,BYTE opcode,const BYTE* payload,uint32 size,const std::function<bool()>& done) {
        CSafeMemFile body; body.Write(payload,size); Packet packet(body,protocol,opcode);
        size_t offset=0; const auto until=Now()+8000;
        while(Now()<until && (offset<packet.GetRealPacketSize() || !done())) {
            if(offset<packet.GetRealPacketSize()) {
                const int count=send(remote,packet.GetPacket()+offset,static_cast<int>(packet.GetRealPacketSize()-offset),0);
                Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"classic identity TCP wire send");
                if(count>0) offset+=count;
            }
            pump();
        }
        Require(offset==packet.GetRealPacketSize() && done(),"classic identity TCP wire actually processed");
    };
    CSafeMemFile hello; hello.WriteHash16(hash.data()); hello.WriteUInt32(0); hello.WriteUInt16(ntohs(address.sin_port));
    hello.WriteUInt32(0); hello.WriteUInt32(0); hello.WriteUInt16(0);
    const auto helloSize=static_cast<uint32>(hello.GetLength()); auto bytes=std::unique_ptr<BYTE[]>(hello.Detach());
    client->SendHelloPacket();
    sendWire(OP_EDONKEYPROT,OP_HELLOANSWER,bytes.get(),helloSize,[&] { return client->Credits()!=nullptr && client->CheckHandshakeFinished(); });
    Require(client->Credits() && !socket->ObservedLegacyTcpCandidate(),"classic HELLO grants no TCP identity proof");
    CryptoPP::AutoSeededRandomPool random; CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(random,384);
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(signer);
    std::array<BYTE,MAXPUBKEYSIZE+1> publicPacket{}; CryptoPP::ArraySink sink(publicPacket.data()+1,MAXPUBKEYSIZE);
    verifier.GetMaterial().Save(sink); sink.MessageEnd(); publicPacket[0]=static_cast<BYTE>(sink.TotalPutLength());
    auto sendPublicKey=[&] { sendWire(OP_EMULEPROT,OP_PUBLICKEY,publicPacket.data(),publicPacket[0]+1,[&] { return client->Credits()->GetSecIDKeyLen()==publicPacket[0]; }); };
    if(variant!=3) sendPublicKey();
    socket->NotifyLegacySecureIdentResult(true);
    Require(!socket->ObservedLegacyTcpCandidate(),"classic no own challenge cannot manufacture proof");
    Require(client->Credits()->m_dwCryptRndChallengeFor==0,"classic challenge not generated before capability negotiation");
    CSafeMemFile info; info.WriteUInt8(0x30); info.WriteUInt8(EMULE_PROTOCOL); info.WriteUInt32(1);
    CTag features(ET_FEATURES,uint32(1)); features.WriteTagToFile(info);
    const auto infoSize=static_cast<uint32>(info.GetLength()); auto infoBytes=std::unique_ptr<BYTE[]>(info.Detach());
    sendWire(OP_EMULEPROT,OP_EMULEINFOANSWER,infoBytes.get(),infoSize,[&] { return client->Credits()->m_dwCryptRndChallengeFor!=0; });
    // Derive the signature from the peer-visible transcript, not local credits.
    std::vector<BYTE> challengeWire; uint32 wireChallenge=0;
    const auto challengeDeadline=Now()+8000;
    while(Now()<challengeDeadline && !wireChallenge) {
        pump(); socket->SendControlData(64*1024,0);
        BYTE buffer[4096]; const int count=recv(remote,reinterpret_cast<char*>(buffer),sizeof buffer,0);
        Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"classic challenge wire receive");
        if(count>0) challengeWire.insert(challengeWire.end(),buffer,buffer+count);
        Require(challengeWire.size()<=64*1024,"classic challenge bounded framing");
        while(challengeWire.size()>=6) {
            uint32 frameLength=0; memcpy(&frameLength,challengeWire.data()+1,4);
            Require(frameLength>0 && frameLength<=64*1024-5,"classic challenge frame length");
            if(challengeWire.size()<size_t(frameLength)+5) break;
            if(challengeWire[0]==OP_EMULEPROT && challengeWire[5]==OP_SECIDENTSTATE) {
                Require(!wireChallenge && frameLength==6 &&
                    (challengeWire[6]==IS_SIGNATURENEEDED || challengeWire[6]==IS_KEYANDSIGNEEDED),"classic challenge wire state exact");
                Require(challengeWire[6]==(variant==3 ? IS_KEYANDSIGNEEDED : IS_SIGNATURENEEDED),"classic requested identity material matches peer key state");
                memcpy(&wireChallenge,challengeWire.data()+7,4);
                Require(wireChallenge!=0,"classic challenge wire nonzero");
            }
            challengeWire.erase(challengeWire.begin(),challengeWire.begin()+frameLength+5);
        }
    }
    Require(wireChallenge && wireChallenge==client->Credits()->m_dwCryptRndChallengeFor,"classic challenge received matches own producer");
    if(variant==3) {
        Require(!client->Credits()->GetSecIDKeyLen() && !socket->ObservedLegacyTcpCandidate(),"classic standard challenge before peer key grants no proof");
        sendPublicKey();
        Require(!socket->ObservedLegacyTcpCandidate(),"classic standard public key without signature grants no proof");
    }
    CreditStruct blank{}; CClientCredits target(blank);
    Require(target.SetSecureIdent(theApp.clientcredits->GetPublicKey(),theApp.clientcredits->GetPubKeyLen()),"classic real RSA target");
    target.m_dwCryptRndChallengeFrom=wireChallenge;
    std::array<BYTE,201> signature{};
    signature[0]=theApp.clientcredits->CreateSignature(&target,signature.data()+1,200,0,0,&signer);
    Require(signature[0]>=10,"classic generated signature");
    if(variant==1) signature[1]^=1;
    if(variant==2) CNativeDirectSelfTestAccess::ChangeClassicChallengeForTest(*socket);
    const auto parsedBefore=CNativeDirectSelfTestAccess::ClassicParsedSignatures(*socket);
    sendWire(OP_EMULEPROT,OP_SIGNATURE,signature.data(),signature[0]+1,[&] { return CNativeDirectSelfTestAccess::ClassicParsedSignatures(*socket)==parsedBefore+1; });
    const auto observed=socket->ObservedLegacyTcpCandidate();
    if(variant==1 || variant==2) { Require(!observed,"classic corrupt signature or mismatching socket challenge has no observation"); return; }
    Require(observed && observed->transport_mask==reach::DirectTcp && observed->evidence==reach::DirectEvidence::Observed &&
        observed->family==4 && observed->address[0]==127 && observed->port==ntohs(address.sin_port) &&
        observed->topology_generation==manager.GetTopologyGeneration() && observed->expires_monotonic_ms>Now(),"classic actual TCP fresh RSA produces bounded own endpoint observation");
    reach::DirectSessionRoute route; route.candidate=*observed;
    CNativeDirectSelfTestAccess::TestTcpObservation(manager,*client,route);
    sendWire(OP_EMULEPROT,OP_SIGNATURE,signature.data(),signature[0]+1,[&] { return CNativeDirectSelfTestAccess::ClassicParsedSignatures(*socket)==parsedBefore+2; });
    Require(socket->ObservedLegacyTcpCandidate()->expires_monotonic_ms==observed->expires_monotonic_ms,"classic duplicate signature does not refresh observation TTL");
}

inline void RunQuicToTcpFileRecovery(CDirectReachabilityManager& manager,CUpDownClient& client,
    CPartFile& file,reach::DirectHandle handle,const std::array<BYTE,4097>& expected,QuicTransport& oldTransport) {
    CNativeDirectSelfTestAccess::TestRecoveryFileStates();
    Require(CNativeDirectSelfTestAccess::RecoveryFileEligible(&file),"actual partial file eligible for recovery");
    const auto before=manager.DirectConnections().Snapshot(handle);
    Require(before && before->epoch==1 && before->useful_bytes==4096 && client.socket &&
        file.IsCompleteBD(0,4095) && file.GetTotalGapSizeInPart(0)==1,"mixed recovery real partial prerequisites");
    const auto oldSource=manager.SnapshotDirectPartContributions(file.NativeDirectFileKey(),0,1);
    Require(oldSource.size()==1 && oldSource[0].source.kind==reach::DirectPartOwnerKind::Quic,"mixed initial QUIC provenance");
    // Explicit local transport failure, not a claim of physical NAT/loss testing.
    oldTransport.Close(reach::DirectReason::DirectUnreachable);
    HWND tcpWindow=nullptr;
    auto pump=[&]() {
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
        if(tcpWindow) for(unsigned i=0;i<256 && PeekMessage(&message,tcpWindow,WM_SOCKETEX_TRIGGER,0xBFFF,PM_REMOVE);++i) DispatchMessage(&message);
        manager.TickDirectConnections(); Sleep(1);
    };
    const auto lostDeadline=Now()+8000;
    while(Now()<lostDeadline && client.socket) pump();
    const auto lost=manager.DirectConnections().Snapshot(handle);
    Require(lost && lost->state==reach::DirectSessionState::Recovering && lost->epoch==1 &&
        lost->useful_bytes==4096 && !client.socket && client.GetRequestFile()==&file,"QUIC close preserves original partial file");
    Require(CNativeDirectSelfTestAccess::HasPendingOwnedRecovery(manager,handle,1),"QUIC recovery intent survives adapter drain without a TCP proof");
    CNativeDirectSelfTestAccess::TestPinnedOwnedRecovery(manager,handle);
    Log(_T("REACH_SELFTEST V144 PASS: actual QUIC loss preserves prepared pinned recovery policy bounded probe cadence rejects changed pin node attempt topology TOFU persistence stale handle without route mutation; no public QUIC recovery or uTP consent"));
    Require(CNativeDirectSelfTestAccess::RecoveryFileEligible(&file) &&
        manager.BeginOwnedObservedTcpDownload(handle)==CDirectReachabilityManager::DirectTcpStartResult::Unavailable,
        "actual partial file without eligible TCP evidence starts no observed route");
    const auto noRoute=manager.DirectConnections().Snapshot(handle);
    Require(noRoute && noRoute->state==lost->state && noRoute->epoch==lost->epoch &&
        noRoute->highest_route_id==lost->highest_route_id && noRoute->useful_bytes==lost->useful_bytes &&
        !client.socket && client.GetRequestFile()==&file && file.IsCompleteBD(0,4095) && file.GetTotalGapSizeInPart(0)==1 &&
        manager.HasDirectTransferSubscription(client.GetDirectClientLifetime(),handle) &&
        CNativeDirectSelfTestAccess::HasPendingOwnedRecovery(manager,handle,1),
        "unavailable TCP start preserves actual partial disk gaps subscription and pending recovery");
    Log(_T("REACH_SELFTEST V130 PASS: actual resumable partial4096 gap1 without eligible TCP route returns Unavailable preserves disk owner subscription recovery intent epoch highwater; no positive automatic fallback"));
    pump();
    Require(manager.DirectConnections().Snapshot(handle)->highest_route_id==3 && !client.socket,
        "normal recovery pump creates no unproven TCP route or socket");
    SOCKET listener=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP),remote=INVALID_SOCKET;
    struct CloseSockets { SOCKET& listener; SOCKET& remote;
        ~CloseSockets() { if(remote!=INVALID_SOCKET) closesocket(remote); if(listener!=INVALID_SOCKET) closesocket(listener); }
    } closeSockets{listener,remote};
    Require(listener!=INVALID_SOCKET,"mixed TCP listener");
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    Require(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof address)==0 && listen(listener,1)==0,"mixed TCP bind listen");
    int length=sizeof address; Require(getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0,"mixed TCP endpoint");
    u_long nonblocking=1; Require(ioctlsocket(listener,FIONBIO,&nonblocking)==0,"mixed nonblocking listener");
    udp::Endpoint endpoint; endpoint.address[0]=127; endpoint.address[3]=1; endpoint.port=ntohs(address.sin_port);
    auto next=Route(endpoint,manager.GetTopologyGeneration()); next.id=lost->NextRouteId(); next.transport=reach::DirectTcp;
    Require(lost->highest_route_id==3 && next.id==4,"mixed recovery allocates above Core high water");
    next.candidate.id=4; next.candidate.transport_mask=reach::DirectTcp;
    next.candidate.expires_monotonic_ms=Now()+8000;
    Require(manager.RegisterDirectLegacyRoute(handle,next) && manager.ScheduleDirectQuicRoutes(handle,{next}),"mixed TCP authorized Start");
    auto* socket=CNativeDirectSelfTestAccess::LegacyConsumerSocket(manager,handle,4);
    Require(socket && socket->client!=&client,"mixed isolated TCP preauth client");
    tcpWindow=CNativeDirectSelfTestAccess::LegacySocketWindow(*socket);
    Require(tcpWindow!=nullptr,"mixed TCP notification window");
    const auto connectedDeadline=Now()+8000;
    while(Now()<connectedDeadline) {
        if(remote==INVALID_SOCKET) remote=accept(listener,nullptr,nullptr);
        pump(); const auto current=manager.DirectConnections().Snapshot(handle);
        if(remote!=INVALID_SOCKET && current && current->state==reach::DirectSessionState::Authenticating) break;
    }
    Require(remote!=INVALID_SOCKET && ioctlsocket(remote,FIONBIO,&nonblocking)==0,"mixed TCP accepted nonblocking");
    CSafeMemFile hello(128); hello.WriteHash16(client.GetUserHash()); hello.WriteUInt32(htonl(INADDR_LOOPBACK));
    hello.WriteUInt16(endpoint.port); hello.WriteUInt32(2);
    CTag name(CT_NAME,_T("mixed-recovery-peer")); name.WriteTagToFile(hello);
    const auto node=client.NativeDirectExpectedNode(); Require(node.has_value(),"mixed expected node retained");
    CTag nodeTag(static_cast<uint8>(TAG_ESE_NODE_PUB),static_cast<size_t>(32),node->data()); nodeTag.WriteTagToFile(hello);
    hello.WriteUInt32(0); hello.WriteUInt16(0); const auto helloSize=static_cast<uint32>(hello.GetLength());
    auto helloBytes=std::unique_ptr<BYTE[]>(hello.Detach());
    Require(CNativeDirectSelfTestAccess::LegacyHelloPacket(*socket,helloBytes.get(),helloSize),"mixed matching HELLO");
    auto* temporary=socket->client;
    CryptoPP::AutoSeededRandomPool random;
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(random,384);
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(signer);
    std::array<BYTE,MAXPUBKEYSIZE+1> publicPacket{}; CryptoPP::ArraySink sink(publicPacket.data()+1,MAXPUBKEYSIZE);
    verifier.GetMaterial().Save(sink); sink.MessageEnd(); publicPacket[0]=static_cast<BYTE>(sink.TotalPutLength());
    temporary->ProcessPublicKeyPacket(publicPacket.data(),publicPacket[0]+1); temporary->SendSecIdentStatePacket();
    CreditStruct blank{}; CClientCredits target(blank);
    Require(target.SetSecureIdent(theApp.clientcredits->GetPublicKey(),theApp.clientcredits->GetPubKeyLen()),"mixed signature target");
    target.m_dwCryptRndChallengeFrom=temporary->Credits()->m_dwCryptRndChallengeFor;
    std::array<BYTE,201> signature{};
    signature[0]=theApp.clientcredits->CreateSignature(&target,signature.data()+1,200,0,0,&signer);
    Require(signature[0]>=10,"mixed fresh RSA signature"); temporary->ProcessSignaturePacket(signature.data(),signature[0]+1);
    pump(); const auto adopted=manager.DirectConnections().Snapshot(handle);
    Require(adopted && adopted->epoch==2 && adopted->winner==4 && adopted->useful_bytes==4096 &&
        !adopted->transfer_verified && client.socket==socket && socket->HasAuthenticatedDirectConnection() &&
        client.GetRequestFile()==&file && file.IsCompleteBD(0,4095) &&
        !manager.ValidateNativeQuicDelivery(oldSource[0].source.owner,handle,oldSource[0].source.route,1),"mixed fresh TCP adoption fences old QUIC delivery");
    client.SetDownloadState(DS_ONQUEUE);
    CSafeMemFile status(18); status.WriteHash16(file.GetFileHash()); status.WriteUInt16(0);
    Packet available(status,OP_EDONKEYPROT,OP_FILESTATUS),slot(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT);
    std::vector<char> outgoing;
    for(auto* packet:{&available,&slot}) { const auto* bytes=packet->GetPacket(); outgoing.insert(outgoing.end(),bytes,bytes+packet->GetRealPacketSize()); }
    auto sendBytes=[&](const char* bytes,size_t size,size_t& offset) {
        if(offset==size) return;
        const int sent=send(remote,bytes+offset,static_cast<int>(size-offset),0);
        Require(sent>0 || (sent==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"mixed TCP wire send");
        if(sent>0) offset+=sent;
    };
    size_t sent=0; std::vector<BYTE> incoming; bool requested=false; const auto requestDeadline=Now()+8000;
    while(Now()<requestDeadline && !requested) {
        sendBytes(outgoing.data(),outgoing.size(),sent); pump(); socket->SendControlData(64*1024,0);
        BYTE buffer[4096]; const int count=recv(remote,reinterpret_cast<char*>(buffer),sizeof buffer,0);
        Require(count>0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK),"mixed TCP request receive");
        if(count>0) incoming.insert(incoming.end(),buffer,buffer+count);
        Require(incoming.size()<=64*1024,"mixed bounded TCP framing");
        while(incoming.size()>=6) {
            uint32 frameLength=0; memcpy(&frameLength,incoming.data()+1,4);
            Require(frameLength && frameLength<=64*1024-5,"mixed TCP frame length");
            if(incoming.size()<size_t(frameLength)+5) break;
            if(incoming[0]==OP_EDONKEYPROT && incoming[5]==OP_REQUESTPARTS) {
                Require(frameLength==41 && !memcmp(incoming.data()+6,file.GetFileHash(),16),"mixed exact request hash");
                CSafeMemFile ranges(incoming.data()+22,24); uint32 starts[3],ends[3];
                for(auto& value:starts) value=ranges.ReadUInt32(); for(auto& value:ends) value=ranges.ReadUInt32();
                for(unsigned i=0;i<3;++i) { Require((starts[i]==0 && ends[i]==0) || (starts[i]==4096 && ends[i]==4097),"mixed requests only pending byte"); requested=requested || ends[i]==4097; }
            }
            incoming.erase(incoming.begin(),incoming.begin()+frameLength+5);
        }
    }
    Require(requested && client.GetDownloadState()==DS_DOWNLOADING,"mixed production gap request");
    CSafeMemFile data(25); data.WriteHash16(file.GetFileHash()); data.WriteUInt32(4096); data.WriteUInt32(4097); data.Write(expected.data()+4096,1);
    Packet last(data,OP_EDONKEYPROT,OP_SENDINGPART); sent=0; bool hashed=false,completed=false;
    const auto completionDeadline=Now()+8000;
    while(Now()<completionDeadline && !completed) {
        sendBytes(last.GetPacket(),last.GetRealPacketSize(),sent); pump();
        if(file.GetStatus()!=PS_COMPLETING && file.GetStatus()!=PS_COMPLETE) file.FlushBuffer();
        MSG message{};
        for(const auto id:{TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) while(PeekMessage(&message,theApp.emuledlg->m_hWnd,id,id,PM_REMOVE)) {
            if(id==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==&file) hashed=true;
            if(id==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==&file) completed=true;
            DispatchMessage(&message);
        }
        manager.TickDirectConnections();
    }
    const auto final=manager.DirectConnections().Snapshot(handle);
    Require(hashed && completed && file.GetStatus()==PS_COMPLETE && final && final->epoch==2 &&
        final->useful_bytes==4097 && final->transfer_verified,"mixed real hash completion");
    Require(!CNativeDirectSelfTestAccess::RecoveryFileEligible(&file),"actual completed file ineligible for recovery");
    CFile disk(file.GetFilePath(),CFile::modeRead|CFile::shareDenyNone); std::array<BYTE,4097> actual{};
    Require(disk.GetLength()==4097 && disk.Read(actual.data(),4097)==4097 && actual==expected,"mixed completed disk exact");
    Log(_T("REACH_SELFTEST V124 PASS: QUIC partial4096 IOCP local transport close TCP route4 fresh RSA epoch2 original file gap1 wire request final real hash completed exact; explicit routes no physical loss uTP F1"));
}

inline void TestControlSessionRecoverySequence() {
    auto ledger=std::make_unique<control::Sessions>();
    std::array<std::uint8_t,32> node{},first{},second{},third{};
    node.fill(7); first.fill(11); second.fill(22); third.fill(33);
    udp::Endpoint endpoint; endpoint.address[0]=8; endpoint.address[3]=8; endpoint.port=4662;
    control::Header initial; initial.type=wire::kEseWireUdpProbe; initial.attempt.fill(9);
    initial.generation=1; initial.sequence=1;
    Require(ledger->AdmitVerified(node,endpoint,initial,first,1000)==control::Admission::Accepted,"recovery sequence initial trusted fixture session");
    auto renewed=initial;
    Require(ledger->NextBootstrap(node,endpoint,renewed,2000,renewed) && renewed.sequence==2 &&
        ledger->ReadmitVerified(node,endpoint,renewed,second,2100)==control::Admission::Accepted,
        "recovery sequence alias-safe reservation and fresh exact verified readmission");
    Require(!ledger->Current(node,endpoint,initial,2200) && ledger->Current(node,endpoint,renewed,2200) &&
        ledger->AdmitVerified(node,endpoint,initial,first,2200)==control::Admission::Rejected &&
        ledger->AdmitVerified(node,endpoint,renewed,second,2200)==control::Admission::Duplicate,
        "renewed bootstrap fences old context and duplicate never renews TTL");
    auto next=renewed;
    Require(ledger->NextBootstrap(node,endpoint,next,2300,next) && next.sequence==3,"recovery sequence increments across repeated recovery");
    for(unsigned variant=0;variant<6;++variant) {
        auto bad=next; auto peer=node; auto remote=endpoint; auto digest=third;
        switch(variant) {
        case 0: bad.sequence=2; break;
        case 1: ++remote.port; break;
        case 2: ++bad.generation; break;
        case 3: bad.attempt[0]^=1; break;
        case 4: peer[0]^=1; break;
        case 5: digest=second; break;
        }
        auto copy=std::make_unique<control::Sessions>(*ledger);
        Require(copy->ReadmitVerified(peer,remote,bad,digest,2400)==control::Admission::Rejected &&
            !copy->Current(node,endpoint,renewed,32100),"recovery wrong context/digest cannot renew idle lifetime");
    }
    Require(ledger->ReadmitVerified(node,endpoint,next,third,32100)==control::Admission::Rejected &&
        !ledger->NextBootstrap(node,endpoint,next,32100,next),"expired recovery tombstone cannot resurrect");
    auto overflow=std::make_unique<control::Sessions>(); initial.sequence=(std::numeric_limits<std::uint32_t>::max)();
    Require(overflow->AdmitVerified(node,endpoint,initial,first,1000)==control::Admission::Accepted &&
        !overflow->NextBootstrap(node,endpoint,initial,1100,initial),"recovery sequence exhaustion cannot wrap");
    Log(_T("REACH_SELFTEST V146 PASS: control recovery fresh verified higher sequence exact active session old replay wrong endpoint generation attempt peer digest rejected duplicate no TTL renewal expired tombstone rejected alias safe and overflow closed; trusted ledger fixture not wire authentication"));
}

inline void RequestRecoveryFixtureRanges(CUpDownClient& client,CPartFile& file,
    QuicTransport& transport,QuicEd2kWriter& writer,Ed2kFramer& reader,
    reach::DirectHandle peerHandle,uint32 route,uint64 epoch,const std::function<void()>& pump,uint32 start) {
    auto queue=[&](Packet& outgoing) {
        Require(writer.Queue({reinterpret_cast<const std::uint8_t*>(outgoing.GetPacket()),outgoing.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
            "recovery negotiation application packet queue");
    };
    bool nameAnswered=false,slotQueued=false,requested=false;
    const auto deadline=Now()+8000;
    while(Now()<deadline && !requested) {
        pump();
        const auto parsed=PumpQuicEd2k(transport,reader,peerHandle,route,epoch,[&](const Ed2kFramer& frame) {
            const auto bytes=frame.Payload();
            if(frame.Header()[0]!=OP_EDONKEYPROT) return true;
            if(frame.Header()[5]==OP_REQUESTFILENAME) {
                Require(!nameAnswered && bytes.size>=16 && !memcmp(bytes.data,file.GetFileHash(),16),"recovery automatically requests original signed file name");
                CSafeMemFile answer(64); answer.WriteHash16(file.GetFileHash()); answer.WriteString(_T("cold-binding.bin"),client.GetUnicodeSupport());
                Packet reply(answer,OP_EDONKEYPROT,OP_REQFILENAMEANSWER); queue(reply); nameAnswered=true;
            } else if(frame.Header()[5]==OP_STARTUPLOADREQ) {
                Require(nameAnswered && !slotQueued && bytes.size==16 && !memcmp(bytes.data,file.GetFileHash(),16),"recovery filename answer triggers actual slot request");
                Packet reply(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT); queue(reply); slotQueued=true;
            } else if(frame.Header()[5]==OP_REQUESTPARTS) {
                Require(slotQueued && !requested && bytes.size==40,"recovery real requested block frame");
                CSafeMemFile request(const_cast<BYTE*>(bytes.data),static_cast<UINT>(bytes.size));
                std::array<BYTE,16> hash{}; request.ReadHash16(hash.data());
                Require(!memcmp(hash.data(),file.GetFileHash(),16),"recovery requested blocks original file ID");
                std::array<uint32,3> starts{},ends{};
                for(auto& value:starts) value=request.ReadUInt32();
                for(auto& value:ends) value=request.ReadUInt32();
                bool range=false;
                for(unsigned i=0;i<3;++i) {
                    Require((starts[i]==0 && ends[i]==0) || (starts[i]==start && ends[i]==4097),"recovery requests only the actual file gap");
                    range=range || ends[i]==4097;
                }
                Require(range && client.GetDownloadState()==DS_DOWNLOADING,"recovery slot creates production pending ranges");
                requested=true;
            }
            return true;
        });
        Require(parsed.valid,"recovery file negotiation framing"); Sleep(1);
    }
    Require(nameAnswered && slotQueued && requested,"recovery automatic file request and slot deadline");
}

inline void RunAutomaticQuicRecovery(CDirectReachabilityManager& manager,CUpDownClient& client,
    reach::DirectHandle handle,Identity& identity,Port& port,test::SimulatedQuicPort& localPort,
    QuicSocketOwner& peer,reach::DirectBufferPool& pool,reach::DirectEventQueue& events,
    reach::DirectCoordinator& peerCore,reach::DirectHandle peerHandle,QuicTransport& oldPeerTransport,
    std::unique_ptr<QuicEd2kWriter>& oldWriter,std::unique_ptr<Ed2kFramer>& oldReader,
    control::Sessions& remoteSessions,control::CookieAuthority& authority,
    const control::Datagram& initialProof,bool partialLoss=false) {
    std::array<std::uint8_t,32> node{}; memcpy(node.data(),eSELive::NodeIdentityPub(),32);
    auto* file=client.GetRequestFile(); auto* credits=client.Credits();
    const auto lifetime=client.GetDirectClientLifetime(),token=client.GetNativeDirectDownloadSubscriber();
    const auto initial=manager.DirectConnections().Snapshot(handle);
    Require(initial && initial->state==reach::DirectSessionState::Ready && initial->epoch==1 &&
        !initial->useful_bytes && file && client.socket && client.CheckHandshakeFinished(),"automatic recovery established source prerequisites");
    std::array<BYTE,4097> expected{};
    for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+(partialLoss?173:167));
    std::array<BYTE,16> expectedHash{};
    Require(CKnownFile::CreateHash(expected.data(),static_cast<UINT>(expected.size()),expectedHash.data()) &&
        !memcmp(file->GetFileHash(),expectedHash.data(),16),"recovered requested source file digest matches payload");
    if(partialLoss) {
        const auto oldPeer=peerCore.Snapshot(peerHandle);
        Require(oldPeer && oldPeer->winner && oldWriter && oldReader,"partial loss old peer application channel");
        auto pump=[&]() {
            const auto sent=oldWriter->Flush(oldPeerTransport,peerHandle,oldPeer->winner,1);
            Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"partial loss original writer flush");
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            port.Receive(); peer.Poll(Now()); manager.TickDirectConnections(); Advance(peerCore,peerHandle,events,oldPeerTransport);
        };
        RequestRecoveryFixtureRanges(client,*file,oldPeerTransport,*oldWriter,*oldReader,peerHandle,oldPeer->winner,1,pump,0);
        CSafeMemFile data(4120); data.WriteHash16(file->GetFileHash()); data.WriteUInt32(0); data.WriteUInt32(4096); data.Write(expected.data(),4096);
        Packet packet(data,OP_EDONKEYPROT,OP_SENDINGPART);
        Require(oldWriter->Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
            "partial loss actual epoch1 payload queued");
        const auto deadline=Now()+8000;
        while(Now()<deadline) {
            pump(); const auto state=manager.DirectConnections().Snapshot(handle);
            if(state && state->useful_bytes==4096) break;
            Sleep(1);
        }
        file->FlushBuffer(); const auto writeDeadline=Now()+8000;
        while(file->m_iWrites>0 && Now()<writeDeadline) { pump(); Sleep(1); }
        Require(file->m_iWrites==0,"partial loss epoch1 IOCP drained before close"); file->FlushBuffer();
        Require(file->IsCompleteBD(0,4095) && file->GetTotalGapSizeInPart(0)==1 && file->GetCompletedSize()==4096,
            "partial loss epoch1 accepted disk range with gap1");
        CFile disk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone); std::array<BYTE,4096> bytes{};
        Require(disk.Read(bytes.data(),4096)==4096 && !memcmp(bytes.data(),expected.data(),4096),"partial loss epoch1 disk exact");
        // Real elapsed idle for Control/1, while authenticated duplicate data
        // keeps the QUIC path alive. No synthetic ledger timestamps or TTL
        // renewal: the already accepted range must not count twice.
        const auto idleStart=Now(); auto nextKeepalive=idleStart;
        while(Now()-idleStart<65000) {
            if(Now()>=nextKeepalive) {
                Require(oldWriter->Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
                    "control idle duplicate keepalive queued");
                nextKeepalive=Now()+5000;
            }
            pump();
            const auto state=manager.DirectConnections().Snapshot(handle);
            Require(state && state->state==reach::DirectSessionState::Transferring && state->epoch==1 &&
                state->useful_bytes==4096 && client.GetRequestFile()==file && client.Credits()==credits && client.socket,
                "control idle preserves authenticated download and useful range");
            Sleep(1);
        }
        control::Header expired; expired.attempt=initial->attempt_id;
        expired.generation=initial->topology_generation; expired.sequence=1;
        Require(!manager.DirectControlSessions().Current(identity.pub,port.endpoint,expired,Now()),
            "control session really expired after65s while data path survived");
        Require(!remoteSessions.Current(node,localPort.Endpoint(),expired,Now()),
            "remote original control session expired after65s too");
        Log(_T("REACH_SELFTEST V149 IDLE: real65s Control/1 expired authenticated QUIC duplicate keepalive useful4096 unchanged"));
    }
    const auto before=manager.DirectConnections().Snapshot(handle);
    const auto preLossReceipt=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
    Require(before && before->state==(partialLoss?reach::DirectSessionState::Transferring:reach::DirectSessionState::Ready) &&
        before->epoch==1 && before->useful_bytes==(partialLoss?4096:0) && !before->transfer_verified,
        "automatic loss exact initial state and useful bytes");
    if(partialLoss) Require(preLossReceipt.size()==1 && preLossReceipt[0].bytes==4096 && preLossReceipt[0].source.epoch==1,
        "partial loss epoch1 provenance before retirement");
    TestControlSessionRecoverySequence();
    auto* receiver=manager.FindNativeQuicLab(CNativeDirectSelfTestAccess::DirectOwner(*client.socket));
    Require(receiver!=nullptr,"automatic recovery old owned receiver");
    oldWriter.reset(); oldReader.reset(); // release reservations before retiring their pools
    receiver->Close(reach::DirectReason::DirectUnreachable);
    peer.Stop(); Advance(peerCore,peerHandle,events,oldPeerTransport); peer.Poll(Now()); peer.RetireClosed();
    Require(peer.Empty(),"automatic recovery old remote transport physically retired");
    control::PacketBudget budget;
    auto responder=CreateQuicSessionHost(port,pool,events,budget);
    Require(responder && responder->ExpectControlBootstrap(identity.pub,node,localPort.Endpoint(),199,Now()+2000),
        "automatic recovery remote consent prepared before normal pump");
    control::ChallengeLimit limit;
    control::PendingBootstrapChallenge pending;
    if(partialLoss) {
        control::Prove replay;
        Require(!control::VerifyProve(authority,localPort.Endpoint(),identity.pub,node,
            initialProof.bytes.data(),initialProof.size,Now(),replay),"expired original remote proof rejected by real cookie authority");
    }
    struct Signer final : control::Signer {
        Identity& identity; explicit Signer(Identity& value):identity(value) {}
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
            return identity.Sign(p,n,out.data());
        }
    } signer(identity);
    bool ackQueued=false; unsigned probes=0,proofs=0;
    const auto bootstrapDeadline=Now()+2000;
    while(Now()<bootstrapDeadline && !ackQueued) {
        manager.TickDirectConnections(); port.memory->Deliver();
        const auto current=manager.DirectConnections().Snapshot(handle);
        Require(current && current->attempt_id==before->attempt_id && current->epoch==1 && !current->winner &&
            current->useful_bytes==before->useful_bytes &&
            current->state==reach::DirectSessionState::Recovering && !client.socket &&
            current->highest_route_id==before->highest_route_id,"automatic recovery cannot schedule before signed ACK");
        QuicUdpRouter::PendingControl packet;
        while(responder->PopControlReply(packet)) {
            control::Envelope envelope; control::Datagram response;
            Require(packet.owner==199 && packet.peer==localPort.Endpoint() &&
                control::ParseUntrusted(packet.bytes.data(),packet.size,envelope) &&
                envelope.header.attempt==before->attempt_id,"automatic recovery exact wire attempt and endpoint");
            Require(envelope.header.sequence>1,"automatic recovery fresh bootstrap does not replay initial sequence");
            if(envelope.header.type==wire::kEseWireUdpProbe) {
                ++probes;
                Require(control::BuildChallenge(authority,limit,packet.peer,identity.pub,node,
                    packet.bytes.data(),packet.size,Now(),response),"automatic recovery fresh CHALLENGE");
                control::Probe probe; control::Envelope issued; control::Challenge challenge;
                Require(control::Decode(envelope.payload,envelope.payloadSize,probe) &&
                    control::ParseUntrusted(response.bytes.data(),response.size,issued) &&
                    control::Decode(issued.payload,issued.payloadSize,challenge) &&
                    pending.Remember(envelope.header,probe,challenge,Now(),bootstrapDeadline),"recovery remote challenge correlation retained");
            } else {
                ++proofs; control::Prove verified;
                auto admission=control::AdmitProve(authority,remoteSessions,packet.peer,identity.pub,node,
                    packet.bytes.data(),packet.size,Now(),verified);
                if(admission==control::Admission::Rejected) {
                    Require(control::VerifyProve(authority,packet.peer,identity.pub,node,packet.bytes.data(),packet.size,Now(),verified) &&
                        pending.Matches(envelope.header,verified,Now()),"expired remote new proof authenticated and correlated");
                    std::array<std::uint8_t,32> digest{}; const auto crypto=MakeKad6HostCryptoHooks();
                    Require(crypto.sha256 && crypto.sha256(packet.bytes.data(),packet.size,digest.data()),"expired remote actual proof digest");
                    admission=remoteSessions.ReadmitFreshVerified(node,packet.peer,envelope.header,digest,pending.Issued(),Now());
                }
                Require(admission==control::Admission::Accepted &&
                    control::BuildAck(verified,envelope.header,4,identity.pub,signer,response),"automatic recovery verified PROVE signed ACK4");
                ackQueued=true;
            }
            Require(responder->SendControl(localPort.Endpoint(),{response.bytes.data(),response.size}).status==QuicUdpSendStatus::Sent,
                "automatic recovery control response queued");
        }
        if(!ackQueued) localPort.Deliver(); // final ACK waits for the new remote native listener
        Sleep(1);
    }
    Require(ackQueued && probes==1 && proofs==1 && !client.socket,"automatic recovery normal pump negotiates exactly one bootstrap");
    responder->Stop(); events.Drain(); responder->Poll(Now());
    Require(responder->Empty() && peer.Attach(),"automatic recovery remote control hands ingress to native listener");
    auto route=Route(localPort.Endpoint(),before->topology_generation);
    const auto peerBefore=peerCore.Snapshot(peerHandle);
    Require(peerBefore && peerBefore->state==reach::DirectSessionState::Recovering && peerBefore->epoch==1,
        "automatic recovery remote test DCO preserves epoch");
    route.id=peerBefore->NextRouteId(); route.candidate.id=route.id;
    peerCore.SetRoutes(peerHandle,{route},Now());
    Identity entropy;
    auto config=Config(identity.pub,node,before->attempt_id,entropy.pub,true,before->topology_generation);
    config.sessionEpoch=1; memcpy(config.local.userHash.data(),identity.pub.data(),16);
    const auto owner=peer.Begin({port.endpoint,true},config,peerHandle,route,&identity);
    auto* transport=peer.Find(owner); Require(transport!=nullptr,"automatic recovery remote native runtime");
    auto reader=std::make_unique<Ed2kFramer>(transport->RxPool());
    auto writer=std::make_unique<QuicEd2kWriter>(transport->TxPool());
    bool hello=false;
    const auto handshakeDeadline=Now()+8000;
    while(Now()<handshakeDeadline && !hello) {
        port.Receive(); peer.Poll(Now()); manager.TickDirectConnections();
        Advance(peerCore,peerHandle,events,*transport);
        if(transport->AllowsDelivery(peerHandle,route.id,2)) {
            const auto parsed=PumpQuicEd2k(*transport,*reader,peerHandle,route.id,2,[&](const Ed2kFramer& frame) {
                const auto bytes=frame.Payload();
                Require(frame.Header()[0]==OP_EDONKEYPROT && frame.Header()[5]==OP_HELLO && bytes.size>=17 &&
                    bytes.data[0]==16 && !memcmp(bytes.data+1,thePrefs.GetUserHash(),16),"automatic recovery fresh production HELLO");
                hello=true; return true;
            });
            Require(parsed.valid,"automatic recovery native HELLO framing");
        }
        Sleep(1);
    }
    Require(hello && client.socket,"automatic recovery handshake and original adoption");
    CSafeMemFile answer(128); answer.WriteHash16(identity.pub.data());
    answer.WriteUInt32(inet_addr("8.8.8.8")); answer.WriteUInt16(4662); answer.WriteUInt32(3);
    CTag name(CT_NAME,_T("recovered-native-peer")); name.WriteTagToFile(answer);
    CTag caps(TAG_ESE_CAPS,uint32(0x10000000)); caps.WriteTagToFile(answer);
    CTag nodeTag(static_cast<uint8>(TAG_ESE_NODE_PUB),static_cast<size_t>(32),identity.pub.data()); nodeTag.WriteTagToFile(answer);
    answer.WriteUInt32(0); answer.WriteUInt16(0);
    Packet packet(answer,OP_EDONKEYPROT,OP_HELLOANSWER);
    Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
        "automatic recovery peer HELLOANSWER queued");
    const auto answerDeadline=Now()+8000;
    while(Now()<answerDeadline && !client.CheckHandshakeFinished()) {
        const auto sent=writer->Flush(*transport,peerHandle,route.id,2);
        Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"automatic recovery HELLOANSWER flush");
        port.Receive(); peer.Poll(Now()); manager.TickDirectConnections(); Advance(peerCore,peerHandle,events,*transport); Sleep(1);
    }
    const auto recovered=manager.DirectConnections().Snapshot(handle);
    Require(recovered && recovered->state==reach::DirectSessionState::Ready && recovered->epoch==2 &&
        recovered->winner==before->NextRouteId() && recovered->attempt_id==before->attempt_id && recovered->useful_bytes==before->useful_bytes &&
        !recovered->transfer_verified && manager.DirectConnections().Size()==1 &&
        client.GetDirectClientLifetime()==lifetime && client.GetNativeDirectDownloadSubscriber()==token &&
        client.GetRequestFile()==file && client.Credits()==credits && client.CheckHandshakeFinished() &&
        client.socket->HasAuthenticatedDirectConnection() && !memcmp(client.GetUserHash(),identity.pub.data(),16),
        "automatic recovery preserves original attempt source file credits token lifetime and authenticates epoch2");
    if(!partialLoss) Log(_T("REACH_SELFTEST V145 PASS: simulated public endpoint QUIC Ready loss normal recovery pump fresh PROBE CHALLENGE PROVE signed ACK selector new native handshake HELLOANSWER original adopted epoch2 same attempt file credits token lifetime; no manual local routes file payload physical network or two products"));
    auto pump=[&]() {
        const auto sent=writer->Flush(*transport,peerHandle,route.id,2);
        Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"recovered epoch2 writer flush");
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
        port.Receive(); peer.Poll(Now()); manager.TickDirectConnections(); Advance(peerCore,peerHandle,events,*transport);
    };
    auto queue=[&](Packet& outgoing) {
        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(outgoing.GetPacket()),outgoing.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
            "recovered epoch2 application packet queue");
    };
    RequestRecoveryFixtureRanges(client,*file,*transport,*writer,*reader,peerHandle,route.id,2,pump,partialLoss?4096:0);
    if(!partialLoss) {
    CSafeMemFile partial(4120); partial.WriteHash16(file->GetFileHash());
    partial.WriteUInt32(0); partial.WriteUInt32(4096); partial.Write(expected.data(),4096);
    Packet block(partial,OP_EDONKEYPROT,OP_SENDINGPART); queue(block);
    const auto partialDeadline=Now()+8000;
    while(Now()<partialDeadline) {
        pump(); const auto state=manager.DirectConnections().Snapshot(handle);
        if(state && state->useful_bytes==4096) break;
        Sleep(1);
    }
    const auto useful=manager.DirectConnections().Snapshot(handle);
    auto receipt=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
    Require(useful && useful->state==reach::DirectSessionState::Transferring && useful->epoch==2 &&
        useful->useful_bytes==4096 && !useful->transfer_verified && file->IsComplete(0,4095) &&
        file->GetTotalGapSizeInPart(0)==1 && receipt.size()==1 && receipt[0].bytes==4096 &&
        receipt[0].source.kind==reach::DirectPartOwnerKind::Quic && receipt[0].source.epoch==2,
        "recovered epoch2 payload accepted with exact provenance and no early integrity");
    Require(theApp.m_pPartFileWriteThread && theApp.m_pPartFileWriteThread->IsRunning(),"recovery actual IOCP writer");
    file->FlushBuffer(); const auto writeDeadline=Now()+8000;
    while(file->m_iWrites>0 && Now()<writeDeadline) { pump(); Sleep(1); }
    Require(file->m_iWrites==0,"recovery IOCP writes drained"); file->FlushBuffer();
    CFile partialDisk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
    std::array<BYTE,4096> partialBytes{};
    Require(partialDisk.Read(partialBytes.data(),4096)==4096 && !memcmp(partialBytes.data(),expected.data(),4096),"recovery partial disk bytes exact");
    partialDisk.Close();
    auto* active=manager.FindNativeQuicLab(receipt[0].source.owner);
    Require(active!=nullptr,"recovery live epoch2 receiver"); const auto consumed=active->ConsumedData();
    queue(block); const auto duplicateDeadline=Now()+8000; bool duplicateConsumed=false;
    while(Now()<duplicateDeadline) {
        pump(); active=manager.FindNativeQuicLab(receipt[0].source.owner);
        if(active && active->ConsumedData()-consumed>=block.GetRealPacketSize()) { duplicateConsumed=true; break; }
        Sleep(1);
    }
    const auto unchanged=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
    const auto duplicateState=manager.DirectConnections().Snapshot(handle);
    Require(duplicateConsumed && duplicateState && duplicateState->epoch==2 && duplicateState->useful_bytes==4096 &&
        !duplicateState->transfer_verified && unchanged.size()==1 && unchanged[0].bytes==4096 &&
        unchanged[0].revision==receipt[0].revision && unchanged[0].part_revision==receipt[0].part_revision,
        "recovered actual duplicate consumed without useful or provenance inflation");
    } else {
        const auto retained=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
        Require(file->IsCompleteBD(0,4095) && file->GetCompletedSize()==4096 && file->GetTotalGapSizeInPart(0)==1 &&
            retained.size()==1 && retained[0].bytes==preLossReceipt[0].bytes &&
            retained[0].source.epoch==1 && retained[0].revision==preLossReceipt[0].revision &&
            retained[0].part_revision==preLossReceipt[0].part_revision,"automatic recovery preserves accepted epoch1 disk and provenance");
        CFile disk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone); std::array<BYTE,4096> bytes{};
        Require(disk.Read(bytes.data(),4096)==4096 && !memcmp(bytes.data(),expected.data(),4096),"automatic recovered epoch1 disk bytes unchanged");
    }
    CSafeMemFile final(25); final.WriteHash16(file->GetFileHash()); final.WriteUInt32(4096); final.WriteUInt32(4097); final.Write(expected.data()+4096,1);
    Packet tail(final,OP_EDONKEYPROT,OP_SENDINGPART); queue(tail);
    bool hashed=false,completed=false,verified=false; const auto completionDeadline=Now()+8000;
    while(Now()<completionDeadline && !(verified && completed)) {
        pump();
        if(file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE) file->FlushBuffer();
        MSG message{};
        for(const auto id:{TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) while(PeekMessage(&message,theApp.emuledlg->m_hWnd,id,id,PM_REMOVE)) {
            if(id==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==file) hashed=true;
            if(id==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==file) completed=true;
            DispatchMessage(&message);
        }
        manager.TickDirectConnections();
        const auto state=manager.DirectConnections().Snapshot(handle);
        verified=state && state->epoch==2 && state->attempt_id==before->attempt_id && state->useful_bytes==4097 && state->transfer_verified;
        Sleep(1);
    }
    Require(hashed && completed && verified && file->GetStatus()==PS_COMPLETE,"recovered real hash worker callback and file completion");
    CFile completedDisk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone); std::array<BYTE,4097> finalBytes{};
    Require(completedDisk.GetLength()==4097 && completedDisk.Read(finalBytes.data(),4097)==4097 && finalBytes==expected,"recovered completed disk exact4097");
    if(!partialLoss) Log(_T("REACH_SELFTEST V147 PASS: automatic QUIC Ready loss epoch2 normal filename slot REQUESTPARTS no seeded reservation partial4096 IOCP disk exact duplicate consumed no inflation final real hash completed4097 same attempt; simulated endpoint not Transferring loss F1 two products or physical network"));
    else {
        Log(_T("REACH_SELFTEST V148 PASS: automatic QUIC Transferring loss epoch1 useful4096 IOCP disk preserved fresh bootstrap selector AUTH epoch2 same attempt filename slot REQUESTPARTS only4096..4097 old provenance unchanged final byte real hash completed4097 exact; simulated endpoints no F1 two products physical network or expired control session"));
        Log(_T("REACH_SELFTEST V149 PASS: real65s control idle retained high-water fresh automatic bootstrap QUIC AUTH epoch2 requests gap1 hash completed4097 exact; simulated endpoints one host no F1 two products or physical network"));
        Log(_T("REACH_SELFTEST V150 PASS: both original control ledgers expired real65s retained fresh correlated signed renewal old PROVE cookie rejected same download gap1 hash exact4097; remote fixture not second product"));
    }
}

inline void RunConsumer(CDirectReachabilityManager& manager,std::uint16_t portNumber,HelloCase helloCase=HelloCase::Valid,bool fileData=false,bool corruptFileData=false,bool coldIdentity=false,bool serverSide=false,bool firstUse=false,bool automaticHandoff=false,Identity* sharedIdentity=nullptr,bool automaticCaller=false,bool multipart=false,bool productUpload=false,bool packedUpload=false,bool packedDownload=false,bool allPackedDownload=false,bool malformedPacked=false,bool i64Download=false,bool mixedRecovery=false,bool automaticRecovery=false,bool partialRecovery=false) {
    const bool rejectHello=helloCase!=HelloCase::Valid;
    Require(!mixedRecovery || (fileData && !packedDownload && !corruptFileData && !coldIdentity && !serverSide && !rejectHello && !i64Download),"mixed recovery plain explicit file scope");
    Require(!packedUpload || (productUpload && !serverSide && !rejectHello),"packed upload explicit valid peer scope");
    Require(!packedDownload || (fileData && !coldIdentity && !corruptFileData && !serverSide && !automaticCaller && !multipart),"packed download explicit file scope");
    Require(!allPackedDownload || packedDownload,"all packed download explicit scope");
    Require(!malformedPacked || allPackedDownload,"malformed packed explicit continued stream scope");
    Require(!i64Download || (fileData && !coldIdentity && !corruptFileData && !serverSide && !automaticCaller && !multipart && !malformedPacked),"I64 download explicit valid file scope");
    Require(theApp.m_bReachBindingSelfTest && theApp.clientudp && !manager.DirectConnections().Size(),"explicit consumer lab prerequisites");
    struct ProfileRestore {
        int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        uint16 port=thePrefs.GetUDPPort();
        ~ProfileRestore() { thePrefs.SetEseNetLabConsent(consent); thePrefs.SetEseNetLabEnabled(enabled);
            thePrefs.SetUDPPort(port); theApp.clientudp->Rebind(); }
    } restore;
    if(firstUse) {
        Require(coldIdentity && !serverSide && !rejectHello,"first-use cold client fixture scope");
    }
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    thePrefs.SetUDPPort(portNumber); Require(theApp.clientudp->Rebind(),"consumer UDP rebind");
    manager.TickDirectConnections();
    udp::Endpoint simulatedLocal; simulatedLocal.address[0]=9; simulatedLocal.address[1]=9;
    simulatedLocal.address[2]=9; simulatedLocal.address[3]=9; simulatedLocal.port=portNumber;
    test::SimulatedQuicPort simulatedPort(simulatedLocal); control::PacketBudget simulatedBudget;
    Require(!automaticHandoff || (coldIdentity && (firstUse || automaticCaller) && !serverSide && !rejectHello),"automatic handoff fixture scope");
    Require(!automaticCaller || (automaticHandoff && !firstUse && sharedIdentity),"automatic caller requires previously authenticated peer");
    Require(!automaticRecovery || (automaticCaller && !fileData && !multipart && !rejectHello),"automatic recovery handshake fixture scope");
    Require(!partialRecovery || automaticRecovery,"partial loss requires automatic recovery fixture");
    Require(!multipart || (automaticCaller && fileData && !corruptFileData),"multipart integrated known-pin fixture scope");
    Require(manager.EnableNativeQuicLab(),"explicit manager host activation");
    Identity freshIdentity,entropy; Identity& identity=sharedIdentity ? *sharedIdentity : freshIdentity;
    Port port(automaticHandoff); Probe probe;
    if(automaticHandoff) {
        manager.ShutdownQuicHost();
        Require(simulatedPort.Link(*port.memory),"MFC simulated namespace link");
        port.pairedMemory=&simulatedPort;
        auto host=CreateQuicSessionHost(simulatedPort,manager.DirectBuffers(),manager.DirectEvents(),simulatedBudget);
        Require(manager.AdoptQuicHost(host),"MFC adopts simulated production factory host");
    }
    class FixtureClient final : public CUpDownClient {
    public:
        FixtureClient(const Identity& identity,bool cold):CUpDownClient(static_cast<CPartFile*>(nullptr),cold?0:4662,cold?0:0x0100007f,0,0,false) {
            if(cold) return;
            // Expected fixture identity, not proof of authentication. Only the
            // native exporter/signature exchange can subsequently authorize IO.
            memcpy(m_eseNodePub,identity.pub.data(),32); m_bEseNodePubSet=true;
            SetUserHash(identity.pub.data());
            m_uEseCapabilities|=0x10000000; // explicit consenting fixture peer
        }
        void ChangeExpectedNodeForFixture(const std::array<std::uint8_t,32>& node) {
            memcpy(m_eseNodePub,node.data(),node.size()); m_bEseNodePubSet=true;
        }
        void ReserveDownload(CPartFile& file) {
            SetRequestFile(&file);
            auto block=std::make_unique<Requested_Block_Struct>();
            block->StartOffset=0; block->EndOffset=4096; block->transferred=0;
            memcpy(block->FileID,file.GetFileHash(),16);
            auto pending=std::make_unique<Pending_Block_Struct>(); pending->block=block.get();
            m_PendingBlocks_list.AddTail(pending.get()); block.release(); pending.release();
            SetDownloadState(DS_DOWNLOADING);
        }
    };
    std::unique_ptr<CPartFile> coldFile;
    std::optional<discovery::ResolvedKad6Candidate> duplicateEvidence;
    std::unique_ptr<CUpDownClient> client=std::make_unique<FixtureClient>(identity,coldIdentity); theApp.clientlist->AddClient(client.get());
    struct ColdQueueCleanup {
        std::unique_ptr<CPartFile>& file; std::unique_ptr<CUpDownClient>& client; bool registered=false;
        ~ColdQueueCleanup() {
            if(!registered || !file) return; // moved file is guarded by FileCleanup below
            if(client) { const auto pos=file->srclist.Find(client.get()); if(pos) file->srclist.RemoveAt(pos); }
            theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(file.get());
            theApp.downloadqueue->RemoveFile(file.get());
        }
    } coldQueueCleanup{coldFile,client};
    if(coldIdentity) {
        Require(!fileData || !rejectHello,"cold file requires valid HELLO");
        std::vector<BYTE> coldBytes(multipart?PARTSIZE+4097:4097);
        for(size_t i=0;i<coldBytes.size();++i) coldBytes[i]=static_cast<BYTE>(i*31+(partialRecovery?173:automaticRecovery?167:multipart?41:automaticCaller?35:automaticHandoff?29:firstUse?23:19));
        if(corruptFileData) coldBytes[0]^=0x80;
        std::array<BYTE,16> coldHash{};
        if(multipart) { std::array<BYTE,32> parts{}; MultipartHash(coldBytes.data(),parts,coldHash); }
        else Require(CKnownFile::CreateHash(coldBytes.data(),static_cast<UINT>(coldBytes.size()),coldHash.data()),"cold requested file hash");
        CString encodedHash; for(const auto byte:coldHash) encodedHash.AppendFormat(_T("%02X"),byte);
        CString coldLink; coldLink.Format(_T("ed2k://|file|cold-binding.bin|%u|%s|/"),static_cast<UINT>(coldBytes.size()),(LPCTSTR)encodedHash);
        coldFile=std::make_unique<CPartFile>(coldLink);
        client->SetRequestFile(coldFile.get());
        discovery::ResolvedKad6Candidate evidence; evidence.length=187;
        evidence.receivedMs=Now(); evidence.until=evidence.receivedMs+15000;
        evidence.localGeneration=manager.GetTopologyGeneration();
        auto* bytes=evidence.descriptor.data(); memcpy(bytes,"ESD3",4); bytes[4]=3; bytes[8]=1;
        bytes[16]=7; bytes[24]=1; bytes[28]=120;
        memcpy(bytes+29,identity.pub.data(),32); memcpy(bytes+61,identity.pub.data(),16); bytes[93]=1;
        auto* endpoint=bytes+95; endpoint[0]=2; endpoint[1]=4; endpoint[2]=4;
        endpoint[4]=8; endpoint[5]=8; endpoint[6]=8; endpoint[7]=8;
        endpoint[20]=0x12; endpoint[21]=0x34; endpoint[27]=120;
        discovery::DescriptorSignatureInput signedInput;
        Require(discovery::BuildSignatureInput(bytes,evidence.length,signedInput) &&
            identity.Sign(signedInput.bytes.data(),signedInput.size,bytes+123),"cold consumer descriptor signature");
        auto& source=evidence.source; memcpy(source.file.data(),coldFile->GetFileHash(),16);
        source.fileSize=coldFile->GetFileSize(); source.node=identity.pub; source.generation=7; source.serial=1; source.ttl=120;
        class Signer final : public control::Signer {
        public: Identity& identity; explicit Signer(Identity& value):identity(value) {}
            bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override { return identity.Sign(p,n,out.data()); }
        } signer(identity);
        std::array<std::uint8_t,173> signedSource{};
        Require(control::DescriptorDigest(bytes,evidence.length,source.digest) &&
            control::BuildDirectSource(source,source.fileSize,signer,signedSource) &&
            discovery::DecodeSource(signedSource.data(),signedSource.size(),coldFile->GetFileSize(),source),"cold consumer signed evidence creation");
        if(!automaticCaller) Require(client->InitialiseNativeDirectDiscovery(evidence),"cold consumer signed expectation adoption");
        else {
            // Let the production queue create the actual cold CUpDownClient.
            client.reset();
            theApp.downloadqueue->AddDownload(coldFile.get(),false);
            coldQueueCleanup.registered=true;
            auto corrupt=evidence; corrupt.descriptor[corrupt.length-1]^=1;
            Require(!theApp.downloadqueue->AdoptDirectKad6Discovery(corrupt) && coldFile->srclist.IsEmpty(),
                "queue rejects corrupt signed discovery before source insertion");
            ResolveSimulatedSource(manager,port,simulatedPort,identity,evidence,signedSource,*coldFile);
            Require(coldFile->srclist.GetCount()==1,
                "manager mailbox creates cold source from verified signed discovery");
            client.reset(coldFile->srclist.GetHead());
            const auto lifetime=client->GetDirectClientLifetime();
            const auto subscriberBeforeDuplicate=client->GetNativeDirectDownloadSubscriber();
            duplicateEvidence=evidence;
            const bool duplicateAdopted=theApp.downloadqueue->AdoptDirectKad6Discovery(evidence);
            Log(_T("DISCOVERY_DUPLICATE_SELFTEST state: adopted=%u subscriberBefore=%I64u subscriberAfter=%I64u sourceCount=%u sameClient=%u sameLifetime=%u downloadState=%u"),
                unsigned(duplicateAdopted),static_cast<ULONGLONG>(subscriberBeforeDuplicate),
                static_cast<ULONGLONG>(client->GetNativeDirectDownloadSubscriber()),unsigned(coldFile->srclist.GetCount()),
                unsigned(coldFile->srclist.GetHead()==client.get()),unsigned(client->GetDirectClientLifetime()==lifetime),unsigned(client->GetDownloadState()));
            Require(duplicateAdopted==(!subscriberBeforeDuplicate) && coldFile->srclist.GetCount()==1 &&
                coldFile->srclist.GetHead()==client.get() && client->GetDirectClientLifetime()==lifetime &&
                client->GetNativeDirectDownloadSubscriber()==subscriberBeforeDuplicate,
                "duplicate discovery preserves production source lifetime");
        }
        Require(!client->HasEseNodePub() && !client->HasValidHash() && !client->Credits(),"cold consumer initially unidentified");
        Require(!client->SupportsEseNetLabV1Target(),"cold QUIC offer does not fabricate HELLO capabilities");
    }
    auto pool=std::make_unique<reach::DirectBufferPool>(); auto events=std::make_unique<reach::DirectEventQueue>();
    auto core=std::make_unique<reach::DirectCoordinator>();
    control::PacketBudget responderBudget;
    std::unique_ptr<QuicSessionHost> responder;
    if(automaticHandoff) {
        responder=CreateQuicSessionHost(port,*pool,*events,responderBudget);
        Require(responder!=nullptr,"simulated responder factory host before timer admission");
        std::array<std::uint8_t,32> requester{}; memcpy(requester.data(),eSELive::NodeIdentityPub(),32);
        Require(responder->ExpectControlBootstrap(identity.pub,requester,simulatedPort.Endpoint(),99,Now()+2000),
            "simulated responder context before timer admission");
    }
    QuicSocketOwner peer(port,probe,*pool,*events);
    struct Cleanup {
        CDirectReachabilityManager& manager; QuicSocketOwner& peer; reach::DirectEventQueue& events;
        ~Cleanup() { manager.ShutdownDirectHost(); peer.Stop(); events.Drain(); peer.Poll(Now()); peer.RetireClosed(); }
    } cleanup{manager,peer,*events};
    if(!automaticHandoff) Require(peer.Attach(),"consumer peer ingress");
    const auto topology=manager.GetTopologyGeneration();
    reach::NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=topology;
    snapshot.peer.expected_node_pub=identity.pub;
    reach::NativeDirectRequestResult admitted;
    trust::Record callerTrust;
    if(automaticCaller) {
        Require(manager.LoadDirectQuicPeerTrust(identity.pub,callerTrust)==trust::LoadResult::Loaded &&
            callerTrust.node==identity.pub,"automatic caller starts with durable known pin");
        Require(coldFile && !theApp.IsConnected(),"periodic native caller fixture has no classic network connection");
        Require(coldFile->srclist.GetCount()==1 && coldFile->srclist.GetHead()==client.get() &&
            theApp.downloadqueue->GetFileByID(coldFile->GetFileHash())==coldFile.get(),
            "discovery source and requested file stay registered for timer negotiation");
        // Dispatch elapsed Windows messages: the existing 100ms UploadTimer
        // must reach the queue/source caller, not a direct harness Process call.
        const auto timerDeadline=Now()+1500;
        while(Now()<timerDeadline && !client->GetNativeDirectDownloadSubscriber()) {
            MSG message;
            for(unsigned count=0;count<256 && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++count) {
                TranslateMessage(&message); DispatchMessage(&message);
            }
            Sleep(1);
        }
        const auto record=manager.ResolveDirectSubscriber(client->GetNativeDirectDownloadSubscriber());
        Require(record && record->attempt && record->client_lifetime==client->GetDirectClientLifetime() &&
            manager.DirectConnections().Size()==1 && !client->socket,"automatic caller creates exact lifetime admission without legacy socket");
        admitted.request.handle=*record->attempt; admitted.request.status=reach::DirectRequestStatus::Created;
        const auto originalToken=record->token;
        const auto beforeDuplicate=manager.DirectConnections().Snapshot(admitted.request.handle);
        const auto lifetime=client->GetDirectClientLifetime();
        Require(duplicateEvidence && beforeDuplicate &&
            !theApp.downloadqueue->AdoptDirectKad6Discovery(*duplicateEvidence),"active discovery duplicate fenced");
        const auto afterDuplicate=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(afterDuplicate && afterDuplicate->attempt_id==beforeDuplicate->attempt_id &&
            afterDuplicate->epoch==beforeDuplicate->epoch && afterDuplicate->subscribers==beforeDuplicate->subscribers &&
            client->GetNativeDirectDownloadSubscriber()==originalToken && client->GetDirectClientLifetime()==lifetime &&
            coldFile->srclist.GetCount()==1 && coldFile->srclist.GetHead()==client.get(),
            "active duplicate preserves source token lifetime attempt epoch and subscriber count");
        Log(_T("DISCOVERY_DUPLICATE_SELFTEST active: rejected=1 tokenPreserved=1 lifetimePreserved=1 attemptPreserved=1 sourceCount=1"));
        const auto repeatDeadline=Now()+300;
        while(Now()<repeatDeadline) {
            MSG message;
            for(unsigned count=0;count<256 && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++count) {
                TranslateMessage(&message); DispatchMessage(&message);
            }
            Sleep(1);
        }
        Require(client->GetNativeDirectDownloadSubscriber()==originalToken &&
            manager.DirectConnections().Size()==1 && !client->socket,"automatic caller repeated reask is single-flight");
    } else admitted=client->RequestNativeDirectDownload(Now()+15000);
    const auto token=client->GetNativeDirectDownloadSubscriber();
    Require(admitted.request.status==reach::DirectRequestStatus::Created,"consumer DCO request");
    const auto joined=client->RequestNativeDirectDownload(Now()+15000);
    Require(token && client->GetNativeDirectDownloadSubscriber()==token
        && joined.request.status==reach::DirectRequestStatus::Joined
        && joined.request.handle.slot==admitted.request.handle.slot
        && joined.request.handle.generation==admitted.request.handle.generation,
        "client-owned repeated admission joins existing attempt");
    const auto state=manager.DirectConnections().Snapshot(admitted.request.handle);
    Require(state.has_value(),"consumer attempt snapshot");
    Require(state->topology_generation==topology,"consumer attempt local topology snapshot");
    if(!coldIdentity) {
        Require(!client->socket && client->TryToConnect(),"normal TryToConnect joins admitted known peer without classic cascade");
        const auto after=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(after && after->state==state->state && after->epoch==state->epoch && after->subscribers==state->subscribers &&
            !client->socket && client->GetNativeDirectDownloadSubscriber()==token,"normal TryToConnect preserves admitted attempt and creates no socket");
        Log(_T("REACH_SELFTEST V141 PASS: known capable client normal TryToConnect recognizes live owned DCO admission no parallel classic socket token state epoch preserved; not initial automatic admission or public fallback"));
    }
    if(coldIdentity && !automaticHandoff) {
        reach::NativeDirectTransportPolicy selection;
        selection.enabled_transports=reach::DirectQuic;
        selection.udp_path_validated=true; selection.quic_binding_available=true;
        Require(manager.SelectDirectQuicDownloadRoutes(admitted.request.handle,selection).routes.empty(),
            "manager owned source QUIC selection requires endpoint validation");
        const auto owned=client->NativeDirectCandidates(topology,Now()+15000);
        Require(owned.count==1,"manager cold selection owned candidate");
        const auto& advertised=owned.candidates[0].route;
        auto& validation=selection.validated_udp_paths[0]; validation.node=identity.pub;
        validation.address=advertised.address; validation.family=advertised.family;
        validation.port=advertised.port; validation.topology_generation=topology;
        validation.expires_monotonic_ms=Now()+2000; selection.validated_udp_count=1;
        const auto selected=manager.SelectDirectQuicDownloadRoutes(admitted.request.handle,selection);
        Require(selected.routes.size()==1 && selected.routes[0].transport==reach::DirectQuic &&
            selected.routes[0].candidate.address==advertised.address &&
            selected.routes[0].candidate.expires_monotonic_ms<=validation.expires_monotonic_ms &&
            !client->socket && client->IsNativeDirectDiscoveryOnly(),
            "manager selects subscribed owned source without starting transport or identity mutation");
        CNativeDirectSelfTestAccess::TestMixedSelector(manager,*client,admitted.request.handle,selection);
        ++validation.port;
        Require(manager.SelectDirectQuicDownloadRoutes(admitted.request.handle,selection).routes.empty(),
            "manager cannot apply validation from another endpoint");
        udp::Endpoint negotiation; negotiation.address=advertised.address;
        negotiation.ipv6=advertised.family==6; negotiation.port=advertised.port;
        auto unrelated=negotiation; ++unrelated.port;
        Require(!manager.BeginDirectQuicDownloadBootstrap(admitted.request.handle,unrelated,Now()+1500),
            "download bootstrap rejects endpoint absent from owned source");
        Require(manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty(),
            "download selection has no implicit return grant");
        const auto negotiationOwner=manager.BeginDirectQuicDownloadBootstrap(admitted.request.handle,negotiation,Now()+1500);
        Require(negotiationOwner && !manager.DirectControlBootstrapReady(negotiationOwner) &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty() &&
            !client->socket && client->IsNativeDirectDiscoveryOnly(),
            "owned download bootstrap preparation grants no data or legacy identity");
        auto unrelatedHandle=admitted.request.handle; ++unrelatedHandle.generation;
        Require(!manager.EnableDirectQuicDownloadHandoff(unrelatedHandle,true) &&
            manager.EnableDirectQuicDownloadHandoff(admitted.request.handle,true) &&
            !manager.EnableDirectQuicDownloadHandoff(admitted.request.handle,true) &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty() &&
            !client->socket && client->IsNativeDirectDiscoveryOnly(),
            "handoff policy is owned single-use preparation without return grant or transport");
        // Do not Poll: the advertised fixture endpoint is not a loopback peer.
        manager.CancelDirectControlBootstrap();
        Require(!manager.EnableDirectQuicDownloadHandoff(admitted.request.handle,true),"cancelled negotiation revokes handoff preparation");
        Require(!manager.DirectControlBootstrapReady(negotiationOwner) &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty(),
            "cancelled download bootstrap cannot authorize route selection");
        Require(!manager.BeginOwnedDirectQuicDownload(unrelatedHandle,true),"owned scheduler rejects unrelated attempt handle");
        const auto ownedOwner=manager.BeginOwnedDirectQuicDownload(admitted.request.handle,true);
        Require(ownedOwner && !manager.DirectControlBootstrapReady(ownedOwner) &&
            !manager.EnableDirectQuicDownloadHandoff(admitted.request.handle,true) &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty() && !client->socket,
            "owned scheduler prepares candidate and handoff without transport before signed ACK");
        manager.CancelDirectControlBootstrap(); // No Poll: fixture's public endpoint is not a test peer.
        control::Header sharedContext; sharedContext.type=wire::kEseWireUdpProbe;
        sharedContext.attempt=state->attempt_id; sharedContext.generation=topology; sharedContext.sequence=1;
        Require(manager.RequestSharedDirectControlAttempt(token,sharedContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest,
            "shared manager admission without authenticated session rejects");
        // Explicit trusted-session injection tests only the manager ownership
        // adapter, not cookie/signature negotiation or product data consent.
        const auto previousSessions=manager.DirectControlSessions();
        std::array<std::uint8_t,32> proofDigest{}; proofDigest.fill(17);
        Require(manager.DirectControlSessions().AdmitVerified(identity.pub,negotiation,sharedContext,proofDigest,Now())==control::Admission::Accepted,
            "shared manager explicit fixture control session");
        const auto sharedAdmission=manager.RequestSharedDirectControlAttempt(token,sharedContext,negotiation);
        Require(sharedAdmission.request.status==reach::DirectRequestStatus::Joined &&
            sharedAdmission.request.handle.slot==admitted.request.handle.slot &&
            sharedAdmission.request.handle.generation==admitted.request.handle.generation &&
            manager.DirectConnections().Snapshot(admitted.request.handle)->subscribers==state->subscribers &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty() &&
            !client->socket && client->IsNativeDirectDiscoveryOnly(),
            "shared control join preserves lifetime attempt and grants no data");
        Require(manager.RequestSharedDirectControlAttempt(token,sharedContext,unrelated).request.status==reach::DirectRequestStatus::InvalidRequest,
            "shared manager context cannot authorize another endpoint");
        auto wrongContext=sharedContext; wrongContext.attempt[0]^=0x80;
        Require(manager.RequestSharedDirectControlAttempt(token,wrongContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest &&
            manager.DirectConnections().Snapshot(admitted.request.handle)->subscribers==state->subscribers,
            "shared manager rejects mismatched wire attempt without subscription mutation");
        const auto discoveryToken=manager.AcquireDirectSubscriber(client->GetDirectClientLifetime(),reach::DirectConsumerKind::Discovery);
        Require(discoveryToken && manager.RequestSharedDirectControlAttempt(discoveryToken,sharedContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest,
            "discovery subscriber is not transfer admission authority");
        manager.RetireDirectSubscriber(discoveryToken);
        const auto orphanLifetime=(std::numeric_limits<std::uint64_t>::max)();
        Require(!theApp.clientlist->FindClientByLifetime(orphanLifetime),"orphan lifetime fixture has no registered client");
        const auto orphanToken=manager.AcquireDirectSubscriber(orphanLifetime,reach::DirectConsumerKind::Download);
        Require(orphanToken && manager.RequestSharedDirectControlAttempt(orphanToken,sharedContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest,
            "unregistered client lifetime cannot admit shared attempt");
        manager.RetireDirectSubscriber(orphanToken);
        Require(manager.RequestSharedDirectControlAttempt(orphanToken,sharedContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest &&
            manager.DirectConnections().Snapshot(admitted.request.handle)->subscribers==state->subscribers,
            "retired subscriber cannot regain shared admission or alter existing attempt");
        manager.DirectControlSessions()=previousSessions;
        Require(manager.RequestSharedDirectControlAttempt(token,sharedContext,negotiation).request.status==reach::DirectRequestStatus::InvalidRequest &&
            manager.DirectConnections().Snapshot(admitted.request.handle)->subscribers==state->subscribers &&
            manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty() &&
            !client->socket && client->IsNativeDirectDiscoveryOnly(),
            "revoked control session cannot readmit bound subscriber or grant data");
    }
    Require(!manager.ResetConsumedDirectSubscriber(token,client->GetDirectClientLifetime())
        && !client->TakeNativeDirectDownloadTerminal(),"live attempt cannot reset or invent terminal cause");
    udp::Endpoint local; local.address[0]=127; local.address[3]=1; local.port=theApp.clientudp->GetConnectedPort();
    if(automaticHandoff) local=simulatedLocal;
    auto route=Route(port.endpoint,topology); route.candidate.id=1;
    const auto peerRoute=Route(local,topology);
    std::array<std::uint8_t,32> node{}; memcpy(node.data(),eSELive::NodeIdentityPub(),32);
    auto config=Config(node,identity.pub,state->attempt_id,entropy.pub,serverSide,topology);
    memcpy(config.local.userHash.data(),thePrefs.GetUserHash(),16);
    auto peerConfig=Config(identity.pub,node,state->attempt_id,identity.pub,!serverSide,topology);
    memcpy(peerConfig.local.userHash.data(),identity.pub.data(),16);
    reach::DirectPeerKey key; key.domain=reach::DirectPeerDomain::NodePublicKey; key.identity=node;
    const auto peerAdmitted=core->Request(key,1,state->attempt_id,topology,Now());
    Require(peerAdmitted.status==reach::DirectRequestStatus::Created,"consumer peer DCO request");
    core->SetRoutes(peerAdmitted.handle,{peerRoute},Now());
    if(firstUse) {
        config.hasPin=false; config.pin={};
        Require(!manager.RegisterDirectQuicRoute(admitted.request.handle,route,{local,serverSide},config),"consumer rejects unknown trust without first-use policy");
        config.allowFirstUse=true;
        Require(!manager.RegisterDirectQuicRoute(admitted.request.handle,route,{local,serverSide},config),"consumer rejects first-use without durable committer");
        trust::Record missing;
        Require(manager.LoadDirectQuicPeerTrust(identity.pub,missing)==trust::LoadResult::Missing &&
            !manager.ConfigureDirectQuicPeerTrust(config,false),"profile unknown key does not enable implicit first-use");
        Require(manager.ConfigureDirectQuicPeerTrust(config,true) && !config.hasPin && config.allowFirstUse && config.trustCommitter,
            "explicit profile first-use config preserves pin absence until authenticated persistence");
    }
    control::CookieAuthority recoveryAuthority;
    auto recoverySessions=std::make_unique<control::Sessions>();
    control::Datagram recoveryInitialProof;
    if(!automaticHandoff) Require(manager.RegisterDirectQuicRoute(admitted.request.handle,route,{local,serverSide},config)
        && manager.ScheduleDirectQuicRoutes(admitted.request.handle,{route}),"consumer owned route schedule");
    else {
        std::array<std::uint8_t,32> requester=node;
        auto& authority=recoveryAuthority; control::ChallengeLimit limit;
        auto& sessions=recoverySessions;
        Require(authority.Initialize(),"simulated responder cookie authority");
        struct AckSigner final : control::Signer {
            Identity& identity; explicit AckSigner(Identity& value):identity(value) {}
            bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override { return identity.Sign(p,n,out.data()); }
        } signer(identity);
        const bool slowPreparation=firstUse && !automaticCaller;
        const auto preparationStarted=Now();
        if(slowPreparation) CNativeDirectSelfTestAccess::DelayNextQuicPolicy(manager,1600);
        if(!automaticCaller) Require(manager.BeginOwnedDirectQuicDownload(admitted.request.handle,true)!=0,"explicit automatic handoff preparation");
        if(slowPreparation) Log(_T("SLOW_POLICY_SELFTEST elapsed=%I64u issuedAgo=%I64u"),
            static_cast<ULONGLONG>(Now()-preparationStarted),static_cast<ULONGLONG>(Now()-CNativeDirectSelfTestAccess::QuicPolicyIssued(manager)));
        if(slowPreparation) Require(CNativeDirectSelfTestAccess::QuicPolicyIssued(manager)>=preparationStarted+1600,
            "control deadline starts after real slow policy preparation");
        Require(!client->socket && manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty(),"automatic preparation has no premature transport");
        bool ackQueued=false; unsigned probes=0,proofs=0,adoptions=0;
        control::Datagram firstProof; const auto until=Now()+1500;
        while(Now()<until && !ackQueued) {
            manager.TickDirectConnections(); port.memory->Deliver();
            QuicUdpRouter::PendingControl packet;
            while(responder->PopControlReply(packet)) {
                control::Envelope envelope; control::Datagram response;
                Require(packet.owner==99 && packet.peer==local && control::ParseUntrusted(packet.bytes.data(),packet.size,envelope),"automatic responder owned packet");
                bool lose=false;
                if(envelope.header.type==wire::kEseWireUdpProbe) {
                    ++probes;
                    Require(control::BuildChallenge(authority,limit,packet.peer,identity.pub,requester,packet.bytes.data(),packet.size,Now(),response),"automatic cookie challenge");
                    lose=automaticCaller && probes==1;
                }
                else {
                    ++proofs; control::Prove verified;
                    const auto admission=control::AdmitProve(authority,*sessions,packet.peer,identity.pub,requester,packet.bytes.data(),packet.size,Now(),verified);
                    Require(admission==control::Admission::Accepted || admission==control::Admission::Duplicate,"automatic signed PROVE");
                    if(admission==control::Admission::Accepted) {
                        ++adoptions; firstProof.size=packet.size;
                        memcpy(firstProof.bytes.data(),packet.bytes.data(),packet.size);
                        if(automaticRecovery) {
                            recoveryInitialProof=firstProof;
                            Require(sessions->RetainDownload(requester,packet.peer,envelope.header,1,Now()),"remote original recovery control ledger retained");
                        }
                    } else Require(firstProof.size==packet.size && !memcmp(firstProof.bytes.data(),packet.bytes.data(),packet.size),"automatic retry signed PROVE byte exact");
                    Require(envelope.header.attempt==state->attempt_id && control::BuildAck(verified,envelope.header,4,identity.pub,signer,response),"automatic ACK4 exact DCO attempt");
                    lose=automaticCaller && proofs==1;
                    ackQueued=!lose;
                }
                if(lose) Require(port.memory->DropNext(1),"automatic selected response loss");
                Require(responder->SendControl(local,{response.bytes.data(),response.size}).status==QuicUdpSendStatus::Sent,"automatic response queued");
                if(lose) Require(!client->socket && manager.DirectConnections().Size()==1 &&
                    client->GetNativeDirectDownloadSubscriber()==token &&
                    manager.SelectOwnedDirectQuicDownloadRoutes(admitted.request.handle).routes.empty(),"lost control response grants no route or duplicate attempt");
            }
            // Leave final ACK queued until the peer native listener is attached.
            if(!ackQueued) simulatedPort.Deliver();
        }
        if(!ackQueued || client->socket) {
            const auto failedHandoff=manager.DirectConnections().Snapshot(admitted.request.handle);
            const auto diagnosticNow=Now();
            const auto diagnosticCandidates=client->NativeDirectCandidates(manager.GetTopologyGeneration(),diagnosticNow+15000);
            trust::Record diagnosticTrust;
            const auto diagnosticTrustState=manager.LoadDirectQuicPeerTrust(identity.pub,diagnosticTrust);
            Log(_T("ACK_HANDOFF_SELFTEST admission: available=%u discoveryCurrent=%u candidates=%u transferSubscriber=%u downloadState=%u trust=%u attemptState=%u epoch=%I64u automaticCaller=%u"),
                unsigned(manager.DirectQuicDownloadAvailable()),
                unsigned(client->HasCurrentNativeDirectDiscovery(manager.GetTopologyGeneration(),diagnosticNow)),
                unsigned(diagnosticCandidates.count),unsigned(manager.HasDirectTransferSubscription(client->GetDirectClientLifetime(),admitted.request.handle)),
                unsigned(client->GetDownloadState()),unsigned(diagnosticTrustState),
                failedHandoff ? unsigned(failedHandoff->state) : 255u,
                static_cast<ULONGLONG>(failedHandoff ? failedHandoff->epoch : 0),unsigned(automaticCaller));
            Log(_T("ACK_HANDOFF_SELFTEST diagnostic: ackQueued=%u socket=%u probes=%u proofs=%u adoptions=%u dropped=%I64u liveAttempt=%u subscriber=%I64u"),
                unsigned(ackQueued),unsigned(client->socket!=nullptr),probes,proofs,adoptions,
                static_cast<ULONGLONG>(port.memory->Dropped()),unsigned(bool(failedHandoff)),
                static_cast<ULONGLONG>(client->GetNativeDirectDownloadSubscriber()));
        }
        Require(ackQueued && !client->socket,"ACK queued without manual route registration");
        if(slowPreparation) Log(_T("REACH_SELFTEST V161 PASS: real1600ms policy preparation before fresh1500ms control deadline then signed ACK4 queued no socket no Core deadline extension; historical zero-PROBE failure class reproduced separately"));
        if(automaticCaller) Require(probes==2 && proofs==2 && adoptions==1 && port.memory->Dropped()==2,
            "automatic lost challenge and ACK bounded retries single admission");
        responder->Stop(); events->Drain(); responder->Poll(Now());
        Require(responder->Empty() && peer.Attach(),"control responder transfers ingress to native peer");
    }
    if(serverSide) for(const bool pendingConsent : {true,false}) {
        const auto previousControlSessions=manager.DirectControlSessions();
        const auto rejectedPolicies=manager.RejectedDirectQuicPreparationPolicies();
        const auto until=Now()+2000;
        const auto responder=manager.ExpectDirectControlBootstrap(identity.pub,port.endpoint,until);
        Require(responder && !manager.AuthorizeDirectQuicControlResponder(responder,admitted.request.handle,route.id+1),
            "server consent rejects absent route");
        auto changedNode=identity.pub; changedNode[0]^=0x80;
        static_cast<FixtureClient*>(client.get())->ChangeExpectedNodeForFixture(changedNode);
        Require(!manager.AuthorizeDirectQuicControlResponder(responder,admitted.request.handle,route.id),
            "server consent rejects changed current client identity");
        static_cast<FixtureClient*>(client.get())->ChangeExpectedNodeForFixture(identity.pub); // no pump while fixture identity is changed
        if(pendingConsent) {
            Require(!manager.AuthorizeDirectQuicControlRequest(responder,0,identity.pub) &&
                !manager.AuthorizeDirectQuicControlRequest(responder,token,changedNode),"pending server consent rejects missing subscriber and wrong pin");
            Require(manager.AuthorizeDirectQuicControlRequest(responder,token,identity.pub) &&
                !manager.AuthorizeDirectQuicControlRequest(responder,token,identity.pub) &&
                !manager.AuthorizeDirectQuicControlResponder(responder,admitted.request.handle,route.id),
                "pending server consent single use and cannot mix prepared-route authorization");
        } else Require(manager.AuthorizeDirectQuicControlResponder(responder,admitted.request.handle,route.id) &&
            !manager.AuthorizeDirectQuicControlResponder(responder,admitted.request.handle,route.id),
            "prepared real server route authorizes responder exactly once");
        control::Header header; header.type=wire::kEseWireUdpProbe; header.attempt=state->attempt_id;
        header.generation=topology; header.sequence=1;
        control::Probe request; request.node=identity.pub; request.peer=node; request.nonce=entropy.pub; request.mask=4;
        control::Initiator initiator;
        struct ConsentSigner final : control::Signer {
            Identity& identity; explicit ConsentSigner(Identity& value):identity(value) {}
            bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
                return identity.Sign(p,n,out.data());
            }
        } signer(identity);
        Require(initiator.Start(header,request,local,Now(),until),"server consent real initiator");
        sockaddr_in destination{}; destination.sin_family=AF_INET;
        destination.sin_addr.s_addr=htonl(INADDR_LOOPBACK); destination.sin_port=htons(local.port);
        while(Now()<until && initiator.State()!=control::InitiatorState::Ready) {
            const auto pending=initiator.Pending(Now());
            if(pending.size) {
                Require(sendto(port.socket,reinterpret_cast<const char*>(pending.data),static_cast<int>(pending.size),0,
                    reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(pending.size),
                    "server consent actual UDP request");
                Require(initiator.Submitted(Now()),"server consent submitted request");
            }
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            manager.TickDirectConnections();
            control::Datagram received; sockaddr_in source{}; int length=sizeof(source);
            const auto size=recvfrom(port.socket,reinterpret_cast<char*>(received.bytes.data()),static_cast<int>(received.bytes.size()),0,
                reinterpret_cast<sockaddr*>(&source),&length);
            if(size!=SOCKET_ERROR) {
                Require(source.sin_addr.s_addr==htonl(INADDR_LOOPBACK) && ntohs(source.sin_port)==local.port,
                    "server consent exact UDP response endpoint");
                control::Envelope envelope;
                Require(control::ParseUntrusted(received.bytes.data(),size,envelope),"server consent response envelope");
                if(envelope.header.type==wire::kEseWireUdpChallenge)
                    Require(initiator.ChallengeReceived(local,received.bytes.data(),size,Now(),signer),"server consent cookie challenge");
                else Require(envelope.header.type==wire::kEseWireUdpAck &&
                    initiator.AckReceived(local,received.bytes.data(),size,Now()),"server consent signed ACK");
            } else Require(WSAGetLastError()==WSAEWOULDBLOCK,"server consent nonblocking receive");
            Sleep(1);
        }
        Require(initiator.State()==control::InitiatorState::Ready && initiator.Selected()==(pendingConsent ? 0 : 4),
            "server consent signed ACK preserves public endpoint policy");
        if(pendingConsent) {
            const auto unchanged=manager.DirectConnections().Snapshot(admitted.request.handle);
            const auto existingRoutes=manager.DirectConnections().RoutesSnapshot(admitted.request.handle);
            Require(manager.RejectedDirectQuicPreparationPolicies()==rejectedPolicies+1 &&
                unchanged && unchanged->attempt_id==state->attempt_id && unchanged->subscribers==state->subscribers &&
                manager.DirectConnections().Size()==1 && existingRoutes && existingRoutes->size()==1 &&
                (*existingRoutes)[0].candidate.expires_monotonic_ms==route.candidate.expires_monotonic_ms,
                "pending PROVE loopback rejection creates no attempt or replacement route and renews no lease");
        }
        manager.CancelDirectControlResponder(responder);
        // Isolate the rejected preparation fixture from the independent V71
        // prepared-route handshake. No product session reset is being tested.
        if(pendingConsent) manager.DirectControlSessions()=previousControlSessions;
    }
    const auto peerId=peer.Begin({port.endpoint,!serverSide},peerConfig,peerAdmitted.handle,peerRoute,&identity);
    auto* transport=peer.Find(peerId); Require(transport!=nullptr,"consumer peer session"); transport->SetReceiveBudget(65536);
    auto reader=std::make_unique<Ed2kFramer>(transport->RxPool()); bool hello=false;
    if(serverSide) {
        Require(!coldIdentity && !fileData && !rejectHello,"server fixture explicit valid identity scope");
        CSafeMemFile initial(128); initial.WriteUInt8(16); initial.WriteHash16(peerConfig.local.userHash.data());
        initial.WriteUInt32(htonl(INADDR_LOOPBACK)); initial.WriteUInt16(4662); initial.WriteUInt32(2);
        CTag name(CT_NAME,_T("native-loopback-peer")); name.WriteTagToFile(initial);
        CTag nodeTag(static_cast<uint8>(TAG_ESE_NODE_PUB),static_cast<size_t>(32),identity.pub.data()); nodeTag.WriteTagToFile(initial);
        initial.WriteUInt32(0); initial.WriteUInt16(0);
        Packet packet(initial,OP_EDONKEYPROT,OP_HELLO);
        auto writer=std::make_unique<QuicEd2kWriter>(transport->TxPool());
        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,
            "QUIC initiator queues real incoming HELLO");
        const auto deadline=Now()+8000;
        while(Now()<deadline && !hello) {
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now());
            manager.TickDirectConnections(); Advance(*core,peerAdmitted.handle,*events,*transport);
            if(transport->AllowsDelivery(peerAdmitted.handle,peerRoute.id,1)) {
                const auto sent=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"server fixture HELLO flush");
                const auto result=PumpQuicEd2k(*transport,*reader,peerAdmitted.handle,peerRoute.id,1,[&](const Ed2kFramer& frame) {
                    const auto payload=frame.Payload();
                    Require(frame.Header()[0]==OP_EDONKEYPROT && frame.Header()[5]==OP_HELLOANSWER &&
                        payload.size>=16 && !memcmp(payload.data,thePrefs.GetUserHash(),16),"server production HELLOANSWER exact identity");
                    hello=true; return true;
                });
                Require(result.valid,"server fixture HELLOANSWER framing");
            }
            Sleep(1);
        }
        Require(hello && client->socket && client->CheckHandshakeFinished() && client->HasEseNodePub() &&
            !memcmp(client->GetEseNodePub(),identity.pub.data(),32) &&
            !memcmp(client->GetUserHash(),peerConfig.local.userHash.data(),16),"server real HELLO parser and HELLOANSWER handshake");
        const auto ready=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(ready && ready->state==reach::DirectSessionState::Ready && !ready->useful_bytes && !ready->transfer_verified,
            "server HELLO handshake is not file progress");
        Require(CNativeDirectSelfTestAccess::HasRetainedControl(manager,admitted.request.handle),"real server consent retained while live");
        writer.reset();
        auto* oldServer=manager.FindNativeQuicLab(CNativeDirectSelfTestAccess::DirectOwner(*client->socket));
        Require(oldServer!=nullptr,"server recovery original owned transport");
        oldServer->Close(reach::DirectReason::DirectUnreachable);
        manager.TickDirectConnections();
        CNativeDirectSelfTestAccess::TestConsentedServerRecoveryPreparation(manager,*client,admitted.request.handle,identity.pub,ready->highest_route_id);
        manager.RetireDirectClient(client->GetDirectClientLifetime());
        manager.TickDirectConnections(); manager.TickDirectConnections();
        Require(!manager.DirectConnections().Snapshot(admitted.request.handle) && !manager.DirectBuffers().Used(),"server fixture retirement drains");
        CNativeDirectSelfTestAccess::TestRetiredControlLedger(manager,admitted.request.handle,identity.pub,
            port.endpoint,ready->attempt_id,ready->topology_generation);
        reader.reset(); peer.Stop(); events->Drain(); peer.Poll(Now()); peer.RetireClosed();
        Require(peer.Empty() && !pool->Used(),"server fixture peer drains");
        return;
    }
    const auto deadline=Now()+8000;
    while(Now()<deadline && !hello) {
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
        port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now());
        manager.TickDirectConnections(); Advance(*core,peerAdmitted.handle,*events,*transport);
        if(transport->AllowsDelivery(peerAdmitted.handle,peerRoute.id,1)) {
            const auto result=PumpQuicEd2k(*transport,*reader,peerAdmitted.handle,peerRoute.id,1,[&](const Ed2kFramer& frame) {
                const auto payload=frame.Payload();
                Require(frame.Header()[0]==OP_EDONKEYPROT && frame.Header()[5]==OP_HELLO
                    && payload.size>=17 && payload.data[0]==16 && !memcmp(payload.data+1,thePrefs.GetUserHash(),16),"consumer emitted real HELLO");
                if(firstUse) {
                    trust::Record saved;
                    Require(manager.LoadDirectQuicPeerTrust(identity.pub,saved)==trust::LoadResult::Loaded &&
                        saved.node==identity.pub && saved.version==1 && saved.kind==trust::Kind::Tofu,
                        "MFC first-use trust persisted before peer receives production HELLO");
                    auto reconnect=config;
                    Require(manager.ConfigureDirectQuicPeerTrust(reconnect,false) && reconnect.hasPin &&
                        reconnect.pin==identity.pub && !reconnect.allowFirstUse && !reconnect.trustCommitter,
                        "profile reconnect loads known pin without TOFU commit or renewed record");
                }
                hello=true; return true;
            });
            Require(result.valid,"consumer peer HELLO framing");
        }
        Sleep(1);
    }
    const auto expectedAddress=automaticHandoff ? inet_addr("8.8.8.8") : htonl(INADDR_LOOPBACK);
    if(automaticHandoff && (!hello || !client->socket)) {
        const auto observed=manager.DirectConnections().Snapshot(admitted.request.handle);
        const auto peerState=transport->Snapshot();
        Log(_T("REACH_SELFTEST simulated handoff diagnostic: attempt=%d state=%d socket=%d hello=%d peerReady=%d peerClosed=%d queued=%u/%u unclaimed=%u/%u"),
            observed.has_value(),observed ? static_cast<int>(observed->state) : -1,client->socket!=nullptr,hello,
            transport->Ready(),peerState.closed,static_cast<unsigned>(simulatedPort.Queued()),
            static_cast<unsigned>(port.memory->Queued()),static_cast<unsigned>(simulatedPort.Unclaimed()),
            static_cast<unsigned>(port.memory->Unclaimed()));
    }
    Require(hello && client->socket && client->socket->GetPeerCAddress()==CAddress::FromIPv4NetworkOrder(expectedAddress)
        && client->socket->GetPeerAddressV4()==expectedAddress,"consumer logical authenticated endpoint");
    const auto ready=manager.DirectConnections().Snapshot(admitted.request.handle);
    Require(ready && ready->state==reach::DirectSessionState::Ready && !ready->useful_bytes && !ready->transfer_verified,"HELLO is not file progress");
    CNativeDirectSelfTestAccess::TestDiagnosticWinner(manager,admitted.request.handle);
    Require(!client->CheckHandshakeFinished(),"outgoing HELLO awaits real answer");
    if(coldIdentity) Require(client->IsNativeDirectDiscoveryOnly() && !client->HasValidHash() && !client->Credits(),
        "authenticated cold socket does not fabricate HELLO identity or credit before answer");
    auto* originalSocket=client->socket;
    Require(!originalSocket->HasAuthenticatedDirectConnection(),"native periodic reask rejects unfinished HELLO handshake");
    Require(client->TryToConnect() && client->socket==originalSocket && originalSocket->IsConnected()
        && manager.DirectConnections().Size()==1 && !client->CheckHandshakeFinished(),
        "TryToConnect reuses adopted native socket while HELLO pending");
    CSafeMemFile answer(128);
    auto helloHash=peerConfig.local.userHash; if(helloCase==HelloCase::ChangedHash) helloHash[0]^=1;
    answer.WriteHash16(helloHash.data()); answer.WriteUInt32(htonl(INADDR_LOOPBACK));
    // Slot retirement tracks identity by IP + advertised user port. This
    // independent uploader must not impersonate the next fixture's 4662 peer.
    // Use its owned ephemeral endpoint; keep normal tracking/ban policy intact.
    answer.WriteUInt16(productUpload?port.endpoint.port:4662);
    answer.WriteUInt32((helloCase==HelloCase::MissingNode ? 1 : helloCase==HelloCase::DuplicateNode ? 3 : 2)+((packedUpload || packedDownload)?1:0)+(automaticRecovery?1:0));
    CTag name(CT_NAME,_T("native-loopback-peer")); name.WriteTagToFile(answer);
    if(automaticRecovery) { CTag caps(TAG_ESE_CAPS,uint32(0x10000000)); caps.WriteTagToFile(answer); }
    auto helloNode=identity.pub; if(helloCase==HelloCase::ChangedNode) helloNode[0]^=1;
    CTag nodeTag(static_cast<uint8>(TAG_ESE_NODE_PUB),static_cast<size_t>(32),helloNode.data());
    if(helloCase!=HelloCase::MissingNode) nodeTag.WriteTagToFile(answer);
    if(helloCase==HelloCase::DuplicateNode) nodeTag.WriteTagToFile(answer);
    if(packedUpload || packedDownload) { CTag compression(CT_EMULE_MISCOPTIONS1,uint32(1u<<20)); compression.WriteTagToFile(answer); }
    answer.WriteUInt32(0);
    if(helloCase!=HelloCase::Truncated) answer.WriteUInt16(0);
    Packet packet(answer,OP_EDONKEYPROT,helloCase==HelloCase::PreHelloData?OP_SENDINGPART:OP_HELLOANSWER);
    auto writer=std::make_unique<QuicEd2kWriter>(transport->TxPool());
    Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(packet.GetPacket()),packet.GetRealPacketSize()}).status
        ==reach::DirectIoStatus::Accepted,"peer serialized HELLOANSWER queue");
    const auto answerDeadline=Now()+8000;
    while(Now()<answerDeadline && !client->CheckHandshakeFinished()) {
        const auto flushed=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
        Require(flushed.status==reach::DirectIoStatus::Accepted || flushed.status==reach::DirectIoStatus::WouldBlock,"peer HELLOANSWER flush");
        MSG message{};
        for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
        port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
        Advance(*core,peerAdmitted.handle,*events,*transport);
        if(!theApp.clientlist->IsValidClient(client.get())) { client.release(); Require(false,"HELLOANSWER unexpectedly deleted client"); }
        if(rejectHello && !manager.DirectConnections().Snapshot(admitted.request.handle)) break;
        Sleep(1);
    }
    if(rejectHello) {
        Require(!client->CheckHandshakeFinished() && !client->GetUserName() &&
            (coldIdentity ? (client->IsNativeDirectDiscoveryOnly() && !client->HasValidHash() && !client->Credits()
                && client->NativeDirectExpectedNode()==identity.pub)
                : (client->HasEseNodePub() && !memcmp(client->GetEseNodePub(),identity.pub.data(),32)
                    && !memcmp(client->GetUserHash(),peerConfig.local.userHash.data(),16)))
            && !manager.ResetConsumedDirectSubscriber(token,client->GetDirectClientLifetime()),
            "invalid HELLO identity rejected before legacy mutation with typed reason");
        const auto unreadRetry=client->RequestNativeDirectDownload(Now()+15000);
        Require(unreadRetry.request.status!=reach::DirectRequestStatus::Created
            && unreadRetry.request.status!=reach::DirectRequestStatus::Joined
            && client->GetNativeDirectDownloadSubscriber()==token && !manager.DirectConnections().Size(),
            "unread terminal cannot be overwritten by another admission");
        Require(client->TakeNativeDirectDownloadTerminal()==reach::DirectReason::IdentityMismatch
            && !client->TakeNativeDirectDownloadTerminal(),"client terminal typed and single use");
        Require(!manager.ResetConsumedDirectSubscriber(token,client->GetDirectClientLifetime()+1),"wrong lifetime cannot reset terminal");
        const auto fresh=client->RequestNativeDirectDownload(Now()+15000);
        Require(fresh.request.status==reach::DirectRequestStatus::Created
            && client->GetNativeDirectDownloadSubscriber()!=token
            && !manager.ResolveDirectSubscriber(token)
            && (fresh.request.handle.slot!=admitted.request.handle.slot
                || fresh.request.handle.generation!=admitted.request.handle.generation),
            "explicit admission after consumed drained terminal gets fresh token generation");
    } else {
    Require(client->socket && client->CheckHandshakeFinished() && client->HasEseNodePub()
        && !memcmp(client->GetEseNodePub(),identity.pub.data(),32)
        && !memcmp(client->GetUserHash(),peerConfig.local.userHash.data(),16)
        && client->GetIP()==expectedAddress,"real incoming HELLOANSWER parser preserves bound identity and endpoint");
    if(automaticCaller) {
        trust::Record unchanged;
        Require(manager.LoadDirectQuicPeerTrust(identity.pub,unchanged)==trust::LoadResult::Loaded &&
            unchanged.node==callerTrust.node && unchanged.version==callerTrust.version && unchanged.kind==callerTrust.kind,
            "automatic known-pin second handshake does not replace or renew trust");
    }
    const auto answered=manager.DirectConnections().Snapshot(admitted.request.handle);
    Require(answered && answered->state==reach::DirectSessionState::Ready && !answered->useful_bytes
        && !answered->transfer_verified,"HELLOANSWER does not imply file progress");
    Require(client->TryToConnect() && client->socket==originalSocket && originalSocket->IsConnected()
        && originalSocket->HasAuthenticatedDirectConnection()
        && manager.DirectConnections().Size()==1 && client->CheckHandshakeFinished(),
        "TryToConnect reuses native session after real handshake");
    const auto reused=manager.DirectConnections().Snapshot(admitted.request.handle);
    Require(reused && reused->epoch==answered->epoch && reused->winner==answered->winner
        && reused->attempt_id==answered->attempt_id && !reused->useful_bytes && !reused->transfer_verified,
        "repeated TryToConnect preserves owner attempt winner epoch and progress");
    }
    if(automaticRecovery) {
        coldQueueCleanup.registered=false; // this scope owns failure-safe async/completion cleanup
        struct RecoveryFileCleanup {
            CUpDownClient& client; std::unique_ptr<CPartFile>& owned;
            ~RecoveryFileCleanup() {
                if(!owned) return;
                const auto pos=owned->srclist.Find(&client); if(pos) owned->srclist.RemoveAt(pos);
                client.ClearDownloadBlockRequests(); client.SetRequestFile(nullptr); client.SetDownloadState(DS_NONE);
                if(owned->GetStatus()==PS_COMPLETING || owned->GetStatus()==PS_COMPLETE) { owned.release(); return; }
                theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(owned.get());
                theApp.downloadqueue->RemoveFile(owned.get());
                if(owned->m_iWrites>0 || owned->IsPartHashPending()) owned.release();
            }
        } recoveryFileCleanup{*client,coldFile};
        RunAutomaticQuicRecovery(manager,*client,admitted.request.handle,identity,port,simulatedPort,
            peer,*pool,*events,*core,peerAdmitted.handle,*transport,writer,reader,
            *recoverySessions,recoveryAuthority,recoveryInitialProof,partialRecovery);
    }
    if(productUpload) {
        Require(!fileData && !coldIdentity && !rejectHello,"product upload separate valid native session");
        try {
            RunProductUpload(manager,*client,*writer,*transport,*reader,port,peer,*core,*events,
                peerAdmitted.handle,peerRoute.id,packedUpload);
        } catch(CException* error) {
            TCHAR message[512]{}; error->GetErrorMessage(message,_countof(message));
            Log(_T("PRODUCT_UPLOAD_SELFTEST MFC exception: %s"),message);
            const CStringA text(message); error->Delete();
            throw std::runtime_error(static_cast<const char*>(text));
        }
    }
    if(fileData && multipart) {
        auto file=std::move(coldFile);
        Require(file!=nullptr,"multipart requested file present");
        struct MultipartCleanup {
            CUpDownClient& client; CPartFile& file; std::unique_ptr<CPartFile>& owned;
            ~MultipartCleanup() {
                const auto pos=file.srclist.Find(&client); if(pos) file.srclist.RemoveAt(pos);
                client.ClearDownloadBlockRequests(); client.SetRequestFile(nullptr); client.SetDownloadState(DS_NONE);
                if(file.GetStatus()==PS_COMPLETING || file.GetStatus()==PS_COMPLETE) { owned.release(); return; }
                theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(&file);
                theApp.downloadqueue->RemoveFile(&file);
                if(file.m_iWrites>0 || file.IsPartHashPending()) owned.release();
            }
        } multipartCleanup{*client,*file,file};
        Require(client->GetRequestFile()==file.get() && file->srclist.GetCount()==1 &&
            file->srclist.GetHead()==client.get() && theApp.downloadqueue->GetFileByID(file->GetFileHash())==file.get(),
            "multipart source and signed file continuously registered after real HELLO");
        RunMultipartTransfer(manager,*client,*file,*writer,*transport,*reader,port,peer,*core,*events,
            admitted.request.handle,peerAdmitted.handle,peerRoute.id);
    } else if(fileData) {
        Require(!rejectHello && theApp.downloadqueue,"file fixture requires valid handshake and queue");
        std::array<BYTE,4097> expected{};
        for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+(mixedRecovery?149:coldIdentity?(automaticCaller?35:automaticHandoff?29:firstUse?23:19):7));
        if(packedDownload) for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+(malformedPacked?73:allPackedDownload?61:53));
        if(i64Download && !packedDownload) CNativeDirectSelfTestAccess::TestLargeOffsetPartFile();
        if(i64Download) for(size_t i=0;i<expected.size();++i) expected[i]=static_cast<BYTE>(i*31+(packedDownload?89:83));
        if(corruptFileData) expected[0]^=0x80; // distinct file ID from prior completed fixture
        std::array<BYTE,16> expectedHash{};
        Require(CKnownFile::CreateHash(expected.data(),static_cast<UINT>(expected.size()),expectedHash.data()),
            "expected complete file MD4 from source bytes");
        CString hash; for(const auto byte : expectedHash) hash.AppendFormat(_T("%02X"),byte);
        CString link; link.Format(_T("ed2k://|file|native-partial.bin|4097|%s|/"),(LPCTSTR)hash);
        auto file=coldIdentity?std::move(coldFile):std::make_unique<CPartFile>(link);
        Require(file!=nullptr,"real requested file present");
        struct FileCleanup {
            CUpDownClient& client; CPartFile& file; std::unique_ptr<CPartFile>& owned;
            ~FileCleanup() {
                const auto pos=file.srclist.Find(&client); if(pos) file.srclist.RemoveAt(pos);
                client.ClearDownloadBlockRequests(); client.SetRequestFile(nullptr);
                client.SetDownloadState(DS_NONE);
                if(file.GetStatus()==PS_COMPLETING || file.GetStatus()==PS_COMPLETE) {
                    owned.release(); return; // completion/known-file host owns it
                }
                theApp.emuledlg->transferwnd->GetDownloadList()->RemoveFile(&file);
                theApp.downloadqueue->RemoveFile(&file);
                // On a failing lab deadline the IOCP worker may still reference
                // the object/buffers. Retain it until process exit, never free
                // live asynchronous writes while unwinding the failed fixture.
                if(file.m_iWrites>0) owned.release(); }
        } fileCleanup{*client,*file,file};
        Require(!memcmp(file->GetFileHash(),expectedHash.data(),16) &&
            (!coldIdentity || client->GetRequestFile()==file.get()),"download retains original signed requested file");
        Require(file->GetStatus()==PS_READY || file->GetStatus()==PS_EMPTY,"real file creation");
        if(!automaticCaller) theApp.downloadqueue->AddDownload(file.get(),false);
        else Require(file->srclist.GetCount()==1 && file->srclist.GetHead()==client.get() &&
            theApp.downloadqueue->GetFileByID(file->GetFileHash())==file.get(),
            "same discovered source and file registered through authenticated handshake");
        auto negotiateBlocks=[&]() {
            // Drive production status/slot parsing and CreateBlockRequests;
            // never insert Requested_Block/Pending_Block fixtures on this path.
            bool nameAnswered=false,slotQueued=false,requested=false; const auto requestDeadline=Now()+8000;
            while(Now()<requestDeadline && !requested) {
                const auto sent=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(sent.status==reach::DirectIoStatus::Accepted || sent.status==reach::DirectIoStatus::WouldBlock,"automatic status/slot flush");
                MSG message{};
                for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
                port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
                Advance(*core,peerAdmitted.handle,*events,*transport);
                const auto result=PumpQuicEd2k(*transport,*reader,peerAdmitted.handle,peerRoute.id,1,[&](const Ed2kFramer& frame) {
                    const auto bytes=frame.Payload();
                    if(frame.Header()[0]==OP_EDONKEYPROT && frame.Header()[5]==OP_REQUESTFILENAME) {
                        Require(!nameAnswered && bytes.size>=16 && !memcmp(bytes.data,file->GetFileHash(),16),"automatic initial filename request exact signed file");
                        CSafeMemFile answer(64); answer.WriteHash16(file->GetFileHash());
                        answer.WriteString(_T("cold-binding.bin"),client->GetUnicodeSupport());
                        Packet name(answer,OP_EDONKEYPROT,OP_REQFILENAMEANSWER);
                        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(name.GetPacket()),name.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,"automatic requested filename answer");
                        nameAnswered=true; return true;
                    }
                    if(frame.Header()[0]==OP_EDONKEYPROT && frame.Header()[5]==OP_STARTUPLOADREQ) {
                        Require(nameAnswered && !slotQueued && bytes.size==16 && !memcmp(bytes.data,file->GetFileHash(),16),"automatic upload request follows filename answer");
                        Packet slot(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT);
                        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(slot.GetPacket()),slot.GetRealPacketSize()}).status==reach::DirectIoStatus::Accepted,"automatic requested upload slot");
                        slotQueued=true; return true;
                    }
                    if(frame.Header()[5]!=OP_REQUESTPARTS) return true;
                    Require(frame.Header()[0]==OP_EDONKEYPROT && bytes.size==40,"automatic block request frame");
                    CSafeMemFile request(const_cast<BYTE*>(bytes.data),static_cast<UINT>(bytes.size));
                    std::array<BYTE,16> hash{}; request.ReadHash16(hash.data());
                    Require(!memcmp(hash.data(),file->GetFileHash(),16),"automatic block request signed file ID");
                    std::array<uint32,3> starts{},ends{};
                    for(auto& value:starts) value=request.ReadUInt32();
                    for(auto& value:ends) value=request.ReadUInt32();
                    bool fullRange=false;
                    for(unsigned i=0;i<3;++i) {
                        Require(starts[i]==0 && (ends[i]==0 || ends[i]==4097),"automatic request bounds");
                        fullRange=fullRange || ends[i]==4097;
                    }
                    Require(fullRange && client->GetDownloadState()==DS_DOWNLOADING,"automatic slot creates real pending block");
                    requested=true; return true;
                });
                Require(result.valid,"automatic request framing");
                Sleep(1);
            }
            Require(nameAnswered && slotQueued && requested,"automatic filename/slot/OP_REQUESTPARTS deadline");
        };
        if(!automaticCaller) static_cast<FixtureClient*>(client.get())->ReserveDownload(*file);
        else negotiateBlocks();
        std::array<BYTE,4096> payload{}; memcpy(payload.data(),expected.data(),payload.size());
        CSafeMemFile blockData(4120); blockData.WriteHash16(file->GetFileHash());
        if(i64Download) { blockData.WriteUInt64(0); blockData.WriteUInt64(4096); }
        else { blockData.WriteUInt32(0); blockData.WriteUInt32(4096); }
        blockData.Write(payload.data(),4096);
        Packet blockPacket(blockData,i64Download?OP_EMULEPROT:OP_EDONKEYPROT,i64Download?OP_SENDINGPART_I64:OP_SENDINGPART);
        const auto beforePayload=manager.DirectConnections().Snapshot(admitted.request.handle);
        if(automaticCaller) Require(beforePayload && port.memory->Dropped()==2 && port.memory->DropNext(2),
            "automatic bulk injects two QUIC datagram losses after control retries");
        uLongf compressedBytes=0; unsigned packedFrames=0;
        std::vector<BYTE> compressedTail; uint32 compressedTotal=0;
        if(packedDownload) {
            compressedBytes=compressBound(static_cast<uLong>(payload.size()))+64; std::vector<BYTE> encoded(compressedBytes);
            if(allPackedDownload) {
                z_stream encoder{}; Require(deflateInit(&encoder,1)==Z_OK,"all packed encoder init");
                struct EndEncoder { z_stream& stream; ~EndEncoder() { deflateEnd(&stream); } } endEncoder{encoder};
                encoder.next_in=payload.data(); encoder.avail_in=static_cast<uInt>(payload.size());
                encoder.next_out=encoded.data(); encoder.avail_out=static_cast<uInt>(encoded.size());
                Require(deflate(&encoder,Z_SYNC_FLUSH)==Z_OK && encoder.avail_in==0 && encoder.avail_out>0,"all packed initial flush");
                compressedBytes=encoder.total_out;
                encoder.next_in=&expected[4096]; encoder.avail_in=1;
                Require(deflate(&encoder,Z_FINISH)==Z_STREAM_END && encoder.avail_in==0,"all packed final byte encoder");
                compressedTail.assign(encoded.data()+compressedBytes,encoded.data()+encoder.total_out);
                Require(!compressedTail.empty(),"all packed final tail exists");
                if(malformedPacked) compressedTail.back()^=1;
                compressedTotal=static_cast<uint32>(encoder.total_out);
            } else {
                Require(compress2(encoded.data(),&compressedBytes,payload.data(),static_cast<uLong>(payload.size()),1)==Z_OK,
                    "native packed source encoding");
                compressedTotal=static_cast<uint32>(compressedBytes);
            }
            Require(compressedBytes<payload.size(),"native packed compression gain");
            std::vector<BYTE> framed;
            for(size_t offset=0;offset<compressedBytes;) {
                const auto count=(std::min)(size_t(37),size_t(compressedBytes)-offset);
                CSafeMemFile packed(64); packed.WriteHash16(file->GetFileHash());
                if(i64Download) packed.WriteUInt64(0); else packed.WriteUInt32(0);
                packed.WriteUInt32(compressedTotal);
                packed.Write(encoded.data()+offset,static_cast<UINT>(count));
                Packet fragment(packed,OP_EMULEPROT,i64Download?OP_COMPRESSEDPART_I64:OP_COMPRESSEDPART);
                const auto* bytes=reinterpret_cast<const BYTE*>(fragment.GetPacket());
                framed.insert(framed.end(),bytes,bytes+fragment.GetRealPacketSize());
                offset+=count; ++packedFrames;
            }
            Require(packedFrames>1,"native packed multiple application fragments");
            Require(writer->Queue({framed.data(),framed.size()}).status==reach::DirectIoStatus::Accepted,
                "native packed framed stream queue");
        } else Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(blockPacket.GetPacket()),blockPacket.GetRealPacketSize()}).status
            ==reach::DirectIoStatus::Accepted,"real file packet queue");
        const auto blockDeadline=Now()+8000;
        bool received=false;
        while(Now()<blockDeadline) {
            const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
            Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"file packet flush");
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
            Advance(*core,peerAdmitted.handle,*events,*transport);
            const auto current=manager.DirectConnections().Snapshot(admitted.request.handle);
            if(current && current->useful_bytes==4096) { received=true; break; }
            Sleep(1);
        }
        const bool transferredExact=packedDownload ? (file->GetTransferred()>0 && file->GetTransferred()<=compressedBytes) : file->GetTransferred()==4096;
        if(packedDownload) Log(_T("NATIVE_PACKED_SELFTEST state: frames=%u compressed=%I64u transferred=%I64u completed=%I64u"),
            packedFrames,static_cast<ULONGLONG>(compressedBytes),static_cast<ULONGLONG>(file->GetTransferred()),static_cast<ULONGLONG>(file->GetCompletedSize()));
        if(!received || !transferredExact || !file->IsComplete(0,4095) || file->IsComplete(4096,4096)) {
            const auto failed=manager.DirectConnections().Snapshot(admitted.request.handle);
            auto* stalledReceiver=client->socket ? manager.FindNativeQuicLab(CNativeDirectSelfTestAccess::DirectOwner(*client->socket)) : nullptr;
            Log(_T("NATIVE_FILE_SELFTEST sender failure: pending=%I64u txUsed=%I64u receiverFront=%I64u packetBytes=%u bannedLocal=%u filteredLocal=%u"),
                static_cast<ULONGLONG>(transport->Pending(4).size),static_cast<ULONGLONG>(transport->TxPool().Used()),
                static_cast<ULONGLONG>(stalledReceiver?stalledReceiver->ReceivedFront().size:0),unsigned(blockPacket.GetRealPacketSize()),
                unsigned(theApp.clientlist->IsBannedClient(htonl(INADDR_LOOPBACK))),
                unsigned(theApp.ipfilter->IsFiltered(htonl(INADDR_LOOPBACK))));
            Log(_T("NATIVE_FILE_SELFTEST receiver failure: present=%u consumed=%I64u rxUsed=%I64u fileStatus=%u stopped=%u requestMatches=%u"),
                unsigned(stalledReceiver!=nullptr),static_cast<ULONGLONG>(stalledReceiver?stalledReceiver->ConsumedData():0),
                static_cast<ULONGLONG>(stalledReceiver?stalledReceiver->RxPool().Used():0),unsigned(file->GetStatus()),
                unsigned(file->IsStopped()),unsigned(client->GetRequestFile()==file.get()));
            Log(_T("NATIVE_FILE_SELFTEST partial failure: received=%u transferred=%I64u completed=%I64u useful=%I64u attemptPresent=%u downloadState=%u pendingBlocks=%u peerReady=%u peerClosed=%u writerPending=%I64u socketAuthenticated=%u"),
                unsigned(received),static_cast<ULONGLONG>(file->GetTransferred()),static_cast<ULONGLONG>(file->GetCompletedSize()),
                static_cast<ULONGLONG>(failed?failed->useful_bytes:0),unsigned(failed.has_value()),
                unsigned(client->GetDownloadState()),CNativeDirectSelfTestAccess::PendingBlocks(*client),
                unsigned(transport->Ready()),unsigned(transport->Snapshot().closed),static_cast<ULONGLONG>(writer->Remaining()),
                unsigned(client->socket && client->socket->HasAuthenticatedDirectConnection()));
        }
        Require(received && transferredExact && file->IsComplete(0,4095)
            && !file->IsComplete(4096,4096),"native bytes accepted by real PartFile with final gap");
        const auto current=manager.DirectConnections().Snapshot(admitted.request.handle);
        if(automaticCaller) Require(current && beforePayload && port.memory->Dropped()==4 &&
            current->attempt_id==beforePayload->attempt_id && current->epoch==beforePayload->epoch &&
            current->winner==beforePayload->winner && client->GetNativeDirectDownloadSubscriber()==token &&
            manager.DirectConnections().Size()==1 && !transport->Snapshot().closed,
            "native QUIC loss recovery preserves winner epoch attempt and subscription");
        Require(current && current->state==reach::DirectSessionState::Transferring && !current->transfer_verified,
            "partial file useful progress is not integrity proof");
        const auto beforeDuplicate=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
        Require(beforeDuplicate.size()==1 && beforeDuplicate[0].bytes==4096,"owned initial file receipt");
        auto* receiver=manager.FindNativeQuicLab(beforeDuplicate[0].source.owner);
        Require(receiver!=nullptr,"live native receiver for duplicate consumption");
        const auto consumedBefore=receiver->ConsumedData();
        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(blockPacket.GetPacket()),blockPacket.GetRealPacketSize()}).status
            ==reach::DirectIoStatus::Accepted,"duplicate file packet queued");
        const auto duplicateDeadline=Now()+8000;
        bool duplicateConsumed=false;
        while(Now()<duplicateDeadline) {
            const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
            Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"duplicate flush");
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
            Advance(*core,peerAdmitted.handle,*events,*transport);
            receiver=manager.FindNativeQuicLab(beforeDuplicate[0].source.owner);
            if(receiver && receiver->ConsumedData()-consumedBefore>=blockPacket.GetRealPacketSize()) { duplicateConsumed=true; break; }
            Sleep(1);
        }
        const auto afterDuplicate=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
        const auto duplicateState=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(duplicateConsumed && duplicateState && duplicateState->useful_bytes==4096 && !duplicateState->transfer_verified
            && afterDuplicate.size()==1 && afterDuplicate[0].bytes==4096
            && afterDuplicate[0].revision==beforeDuplicate[0].revision
            && afterDuplicate[0].part_revision==beforeDuplicate[0].part_revision
            && file->IsComplete(0,4095) && !file->IsComplete(4096,4096),
            "consumed duplicate does not inflate useful bytes or mutate accepted receipt");
        Require(theApp.m_pPartFileWriteThread && theApp.m_pPartFileWriteThread->IsRunning(),"production write worker running");
        file->FlushBuffer();
        const auto writeDeadline=Now()+8000;
        while(file->m_iWrites>0 && Now()<writeDeadline) Sleep(1);
        Require(file->m_iWrites==0,"production queued writes drained before fixture destruction");
        file->FlushBuffer(); // consume completed IOCP buffer entries
        Require(file->IsCompleteBD(0,4095) && !file->IsCompleteBD(4096,4096),"disk range complete with final gap");
        CFile disk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
        std::array<BYTE,4096> stored{};
        Require(disk.Read(stored.data(),4096)==4096 && stored==payload,"native PartFile disk bytes exact");
        const auto diskState=manager.DirectConnections().Snapshot(admitted.request.handle);
        Require(diskState && diskState->useful_bytes==4096 && !diskState->transfer_verified,
            "disk write alone is not integrity verification");
        disk.Close();
        if(mixedRecovery) RunQuicToTcpFileRecovery(manager,*client,*file,admitted.request.handle,expected,*receiver);
        else {
        Require(theApp.m_pPartHashThread && theApp.m_pPartHashThread->IsRunning(),"production hash worker running");
        CSafeMemFile lastData(25); lastData.WriteHash16(file->GetFileHash());
        if(i64Download) lastData.WriteUInt64(allPackedDownload?0:4096); else lastData.WriteUInt32(allPackedDownload?0:4096);
        if(i64Download && !allPackedDownload) lastData.WriteUInt64(4097);
        else lastData.WriteUInt32(allPackedDownload?compressedTotal:4097);
        BYTE lastByte=expected[4096]; if(corruptFileData) lastByte^=1;
        if(allPackedDownload) lastData.Write(compressedTail.data(),static_cast<UINT>(compressedTail.size()));
        else lastData.Write(&lastByte,1);
        Packet lastPacket(lastData,(allPackedDownload || i64Download)?OP_EMULEPROT:OP_EDONKEYPROT,
            allPackedDownload?(i64Download?OP_COMPRESSEDPART_I64:OP_COMPRESSEDPART):(i64Download?OP_SENDINGPART_I64:OP_SENDINGPART));
        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(lastPacket.GetPacket()),lastPacket.GetRealPacketSize()}).status
            ==reach::DirectIoStatus::Accepted,"last file byte queued");
        bool hashCallback=false,completedCallback=false,verified=false;
        const auto completeDeadline=Now()+8000;
        while(Now()<completeDeadline && !(verified && completedCallback)) {
            const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
            Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"last byte flush");
            MSG message{};
            for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
            port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
            Advance(*core,peerAdmitted.handle,*events,*transport);
            if(file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE) file->FlushBuffer();
            for(const auto messageId : {TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) {
                while(PeekMessage(&message,theApp.emuledlg->m_hWnd,messageId,messageId,PM_REMOVE)) {
                    if(messageId==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) hashCallback=true;
                    if(messageId==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) completedCallback=true;
                    DispatchMessage(&message);
                }
            }
            manager.TickDirectConnections();
            const auto proof=manager.DirectConnections().Snapshot(admitted.request.handle);
            verified=proof && proof->transfer_verified && proof->useful_bytes==4097;
            if(corruptFileData && hashCallback && file->IsCorruptedPart(0)) break;
            if(malformedPacked && CNativeDirectSelfTestAccess::HasPackedError(*client) && file->m_iWrites==0) break;
            Sleep(1);
        }
        if(malformedPacked) {
            const auto rejected=manager.DirectConnections().Snapshot(admitted.request.handle);
            Require(CNativeDirectSelfTestAccess::HasPackedError(*client) && !hashCallback && !completedCallback && !verified &&
                rejected && !rejected->transfer_verified && rejected->useful_bytes==4096 &&
                file->GetCompletedSize()==4096 && file->GetTotalGapSizeInPart(0)==1 && file->m_iWrites==0 &&
                !file->IsPartHashPending() && file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE,
                "native bad packed checksum cannot write final byte or grant hash completion proof");
            receiver=manager.FindNativeQuicLab(beforeDuplicate[0].source.owner);
            Require(receiver!=nullptr,"errored packed reservation retains native receiver");
            const auto consumedAfterError=receiver->ConsumedData();
            CSafeMemFile lateData(25); lateData.WriteHash16(file->GetFileHash());
            lateData.WriteUInt32(4096); lateData.WriteUInt32(4097); lateData.Write(&lastByte,1);
            Packet latePacket(lateData,OP_EDONKEYPROT,OP_SENDINGPART);
            Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(latePacket.GetPacket()),latePacket.GetRealPacketSize()}).status
                ==reach::DirectIoStatus::Accepted,"late valid byte after packed error queued");
            bool lateConsumed=false;
            const auto lateDeadline=Now()+8000;
            while(Now()<lateDeadline) {
                const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"late byte flush");
                MSG message{};
                for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
                port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
                Advance(*core,peerAdmitted.handle,*events,*transport);
                receiver=manager.FindNativeQuicLab(beforeDuplicate[0].source.owner);
                if(receiver && receiver->ConsumedData()-consumedAfterError>=latePacket.GetRealPacketSize()) { lateConsumed=true; break; }
                Sleep(1);
            }
            const auto lateState=manager.DirectConnections().Snapshot(admitted.request.handle);
            const auto lateReceipt=manager.SnapshotDirectPartContributions(file->NativeDirectFileKey(),0,1);
            Require(lateConsumed && CNativeDirectSelfTestAccess::HasPackedError(*client) &&
                lateState && lateState->attempt_id==rejected->attempt_id && lateState->epoch==rejected->epoch &&
                lateState->useful_bytes==4096 && !lateState->transfer_verified &&
                lateReceipt.size()==1 && lateReceipt[0].revision==beforeDuplicate[0].revision &&
                lateReceipt[0].part_revision==beforeDuplicate[0].part_revision && lateReceipt[0].bytes==4096 &&
                file->GetCompletedSize()==4096 && file->GetTotalGapSizeInPart(0)==1 && file->m_iWrites==0 &&
                !file->IsPartHashPending() && file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE,
                "consumed valid late byte cannot revive errored packed reservation or change integrity receipt");
            Packet releasePacket(OP_OUTOFPARTREQS,0,OP_EDONKEYPROT);
            Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(releasePacket.GetPacket()),releasePacket.GetRealPacketSize()}).status
                ==reach::DirectIoStatus::Accepted,"remote slot release after packed error queued");
            const auto releaseDeadline=Now()+8000;
            while(Now()<releaseDeadline && client->GetDownloadState()!=DS_ONQUEUE) {
                const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"remote slot release flush");
                MSG message{};
                for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
                port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
                Advance(*core,peerAdmitted.handle,*events,*transport); Sleep(1);
            }
            Require(client->GetDownloadState()==DS_ONQUEUE && CNativeDirectSelfTestAccess::PendingBlocks(*client)==0 &&
                !CNativeDirectSelfTestAccess::HasPackedError(*client) && client->socket==originalSocket &&
                originalSocket->HasAuthenticatedDirectConnection() && file->GetTotalGapSizeInPart(0)==1 &&
                file->GetCompletedSize()==4096 && !file->IsPartHashPending(),
                "production remote slot release clears errored reservation without disconnecting or completing file");
            CSafeMemFile recoveryStatus(18); recoveryStatus.WriteHash16(file->GetFileHash()); recoveryStatus.WriteUInt16(0);
            Packet recoveryOffer(recoveryStatus,OP_EDONKEYPROT,OP_FILESTATUS);
            Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(recoveryOffer.GetPacket()),recoveryOffer.GetRealPacketSize()}).status
                ==reach::DirectIoStatus::Accepted,"recovery file availability queued");
            bool recoverySlot=false,recoveryRequested=false;
            const auto recoveryDeadline=Now()+8000;
            while(Now()<recoveryDeadline && !(verified && completedCallback)) {
                const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"packed recovery flush");
                MSG message{};
                for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
                port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
                Advance(*core,peerAdmitted.handle,*events,*transport);
                const auto pumped=PumpQuicEd2k(*transport,*reader,peerAdmitted.handle,peerRoute.id,1,[&](const Ed2kFramer& frame) {
                    const auto bytes=frame.Payload();
                    if(frame.Header()[0]!=OP_EDONKEYPROT) return true;
                    if(frame.Header()[5]==OP_STARTUPLOADREQ) {
                        Require(!recoverySlot && bytes.size==16 && !memcmp(bytes.data,file->GetFileHash(),16),"recovery requests normal upload slot");
                        Packet slot(OP_ACCEPTUPLOADREQ,0,OP_EDONKEYPROT);
                        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(slot.GetPacket()),slot.GetRealPacketSize()}).status
                            ==reach::DirectIoStatus::Accepted,"recovery slot accepted");
                        recoverySlot=true;
                    } else if(frame.Header()[5]==OP_REQUESTPARTS) {
                        Require(recoverySlot && !recoveryRequested && bytes.size==40,"recovery generates fresh block request");
                        CSafeMemFile request(const_cast<BYTE*>(bytes.data),static_cast<UINT>(bytes.size));
                        std::array<BYTE,16> hash{}; request.ReadHash16(hash.data());
                        Require(!memcmp(hash.data(),file->GetFileHash(),16),"recovery block request file hash");
                        std::array<uint32,3> starts{},ends{};
                        for(auto& value:starts) value=request.ReadUInt32();
                        for(auto& value:ends) value=request.ReadUInt32();
                        bool missingByte=false;
                        for(unsigned i=0;i<3;++i) {
                            Require((starts[i]==0 && ends[i]==0) || (starts[i]==4096 && ends[i]==4097),"recovery requests only missing byte");
                            missingByte=missingByte || ends[i]==4097;
                        }
                        Require(missingByte && !CNativeDirectSelfTestAccess::HasPackedError(*client),"recovery has new valid pending reservation");
                        Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(latePacket.GetPacket()),latePacket.GetRealPacketSize()}).status
                            ==reach::DirectIoStatus::Accepted,"requested recovery byte queued");
                        recoveryRequested=true;
                    }
                    return true;
                });
                Require(pumped.valid,"packed recovery peer requests parse");
                if(file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE) file->FlushBuffer();
                for(const auto messageId : {TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) {
                    while(PeekMessage(&message,theApp.emuledlg->m_hWnd,messageId,messageId,PM_REMOVE)) {
                        if(messageId==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) hashCallback=true;
                        if(messageId==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) completedCallback=true;
                        DispatchMessage(&message);
                    }
                }
                manager.TickDirectConnections();
                const auto recovered=manager.DirectConnections().Snapshot(admitted.request.handle);
                verified=recovered && recovered->transfer_verified && recovered->useful_bytes==4097;
                Sleep(1);
            }
            Require(recoverySlot && recoveryRequested && hashCallback && completedCallback && verified &&
                file->GetStatus()==PS_COMPLETE && client->socket==originalSocket && originalSocket->HasAuthenticatedDirectConnection(),
                "packed checksum recovery requests new byte and completes with real hash on same authenticated socket");
            CFile recoveryDisk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
            std::array<BYTE,4097> recoveryBytes{};
            Require(recoveryDisk.GetLength()==4097 && recoveryDisk.Read(recoveryBytes.data(),4097)==4097 && recoveryBytes==expected,
                "packed checksum recovery completed disk exact");
        } else if(corruptFileData) {
            const auto rejected=manager.DirectConnections().Snapshot(admitted.request.handle);
            Require(hashCallback && !completedCallback && !verified && rejected && !rejected->transfer_verified
                && rejected->useful_bytes==4097 && file->IsCorruptedPart(0)
                && file->GetTotalGapSizeInPart(0)==4097 && !file->IsPartHashPending()
                && file->m_iWrites==0 && file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE,
                "real corrupt hash callback regaps file without native integrity proof or completion");
            if(automaticCaller) {
                Require(client->GetDownloadState()==DS_NONEEDEDPARTS &&
                    originalSocket->HasAuthenticatedDirectConnection() && !theApp.IsConnected(),
                    "corrupt part periodic repair starts on authenticated offline native session");
                Require(file->srclist.GetCount()==1 && file->srclist.GetHead()==client.get() &&
                    theApp.downloadqueue->GetFileByID(file->GetFileHash())==file.get(),
                    "original discovery source remains registered for periodic repair");
                auto waitTimer=[&](std::uint64_t deadline) {
                    while(Now()<deadline) {
                        MSG message;
                        for(unsigned count=0;count<256 && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++count) {
                            TranslateMessage(&message); DispatchMessage(&message);
                        }
                        Sleep(1);
                    }
                };
                const auto beforeReask=client->GetLastAskedTime();
                Require(beforeReask && client->GetTimeUntilReask()>0,"repair respects unexpired per-file reask deadline");
                waitTimer(Now()+1100);
                Require(client->GetLastAskedTime()==beforeReask && client->socket==originalSocket &&
                    client->GetDownloadState()==DS_NONEEDEDPARTS,"periodic repair does not bypass cooldown");
                const DWORD expired=::GetTickCount()-FILEREASKTIME*2-1;
                CNativeDirectSelfTestAccess::SetReaskTimestamp(*client,*file,expired);
                Require(client->GetTimeUntilReask()==0,"repair seeded elapsed per-file deadline");
                {
                    struct UploadStateRestore {
                        CUpDownClient& client; EUploadState state;
                        ~UploadStateRestore() { client.SetUploadState(state); }
                    } restoreState{*client,client->GetUploadState()};
                    CNativeDirectSelfTestAccess::SetConnectTimestamp(*client,::GetTickCount()-MIN2MS(20)-1);
                    client->SetUploadState(US_BANNED);
                    waitTimer(Now()+2100);
                    Require(client->GetLastAskedTime()==expired && client->socket==originalSocket,
                        "expired native repair reask cannot bypass banned peer state");
                }
                const auto reaskDeadline=Now()+2500;
                while(Now()<reaskDeadline && client->GetLastAskedTime()==expired) waitTimer(Now()+10);
                Require(client->GetLastAskedTime()!=expired && client->GetTimeUntilReask()>0 &&
                    client->socket==originalSocket && originalSocket->HasAuthenticatedDirectConnection(),
                    "periodic timer reasks corrupt part on same authenticated socket without classic network");
                negotiateBlocks();
            } else { client->ClearDownloadBlockRequests(); static_cast<FixtureClient*>(client.get())->ReserveDownload(*file); }
            CSafeMemFile repairData(4121); repairData.WriteHash16(file->GetFileHash());
            repairData.WriteUInt32(0); repairData.WriteUInt32(4097); repairData.Write(expected.data(),4097);
            Packet repairPacket(repairData,OP_EDONKEYPROT,OP_SENDINGPART);
            Require(writer->Queue({reinterpret_cast<const std::uint8_t*>(repairPacket.GetPacket()),repairPacket.GetRealPacketSize()}).status
                ==reach::DirectIoStatus::Accepted,"correct repair bytes queued on same session");
            hashCallback=false; completedCallback=false; verified=false;
            const auto repairDeadline=Now()+8000;
            while(Now()<repairDeadline && !(verified && completedCallback)) {
                const auto result=writer->Flush(*transport,peerAdmitted.handle,peerRoute.id,1);
                Require(result.status==reach::DirectIoStatus::Accepted || result.status==reach::DirectIoStatus::WouldBlock,"repair flush");
                MSG message{};
                for(unsigned i=0;i<256 && PeekMessage(&message,nullptr,WM_SOCKET_NOTIFY,WM_SOCKET_DEAD,PM_REMOVE);++i) DispatchMessage(&message);
                port.Receive(); theApp.clientudp->PollQuicIngress(); peer.Poll(Now()); manager.TickDirectConnections();
                Advance(*core,peerAdmitted.handle,*events,*transport);
                if(file->GetStatus()!=PS_COMPLETING && file->GetStatus()!=PS_COMPLETE) file->FlushBuffer();
                for(const auto messageId : {TM_PARTHASHED,TM_FINISHEDHASHING,TM_FILECOMPLETED}) {
                    while(PeekMessage(&message,theApp.emuledlg->m_hWnd,messageId,messageId,PM_REMOVE)) {
                        if(messageId==TM_PARTHASHED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) hashCallback=true;
                        if(messageId==TM_FILECOMPLETED && reinterpret_cast<CPartFile*>(message.lParam)==file.get()) completedCallback=true;
                        DispatchMessage(&message);
                    }
                }
                manager.TickDirectConnections();
                const auto repaired=manager.DirectConnections().Snapshot(admitted.request.handle);
                verified=repaired && repaired->transfer_verified && repaired->useful_bytes==8194;
                Sleep(1);
            }
            Require(hashCallback && completedCallback && verified && file->GetStatus()==PS_COMPLETE && !file->IsCorruptedPart(0),
                "repair new real hash callback clears corruption and proves part on same session");
            CFile repairedDisk(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
            std::array<BYTE,4097> repairedBytes{};
            Require(repairedDisk.GetLength()==4097 && repairedDisk.Read(repairedBytes.data(),4097)==4097 && repairedBytes==expected,
                "repaired completed disk file exact");
        } else {
        Require(hashCallback && completedCallback && verified && file->GetStatus()==PS_COMPLETE,
            "real hash callback proves native part and completes file");
        CFile finished(file->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
        std::array<BYTE,4097> finalBytes{};
        Require(finished.GetLength()==4097 && finished.Read(finalBytes.data(),4097)==4097 && finalBytes==expected,
            "completed native file bytes exact");
        }
    }
        }
    writer.reset();
    manager.RetireDirectClient(client->GetDirectClientLifetime());
    manager.TickDirectConnections(); manager.TickDirectConnections();
    Require(!manager.DirectConnections().Snapshot(admitted.request.handle) && !manager.DirectBuffers().Used(),"consumer retirement drains attempt");
    reader.reset(); peer.Stop(); events->Drain(); peer.Poll(Now()); peer.RetireClosed();
    Require(peer.Empty() && !pool->Used(),"consumer peer drain");
}
} }
