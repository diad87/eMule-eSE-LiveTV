#pragma once
// Two real products, explicit isolated same-host LAN enrollment. No peer socket
// fixture, manual route scheduling, seeded block reservations or forged ACK.
namespace ese { namespace pair_selftest {
inline bool Run() {
    using shared_socket_selftest::Require;
    using shared_socket_selftest::Now;
    CNativeDirectSelfTestAccess::TestWindowIsolation();
    const bool upload=theApp.m_strQuicPairSelfTestRole==_T("upload");
    Require(upload || theApp.m_strQuicPairSelfTestRole==_T("download"),"pair role");
    Require(theApp.directreachability && theApp.clientudp && theApp.listensocket && theApp.downloadqueue &&
        theApp.uploadqueue && theApp.sharedfiles && !thePrefs.IsUPnPEnabled() && !thePrefs.DoAutoConnect(),"pair isolated prerequisites");
    const CString config=thePrefs.GetMuleDirectory(EMULE_CONFIGDIR), ini=config+_T("quic-pair.ini");
    const bool configuredHighres=GetPrivateProfileInt(_T("eMule"),_T("HighresTimer"),0,
        config+_T("preferences.ini"))!=0;
    Require(thePrefs.GetHighresTimer()==configuredHighres,"pair HighresTimer loaded from eMule section");
    Log(_T("QUIC_PAIR PREFERENCES highres_configured=%u highres_loaded=%u"),
        static_cast<UINT>(configuredHighres),static_cast<UINT>(thePrefs.GetHighresTimer()));
    TCHAR rootText[MAX_PATH]={},addressText[64]={};
    GetPrivateProfileString(_T("Pair"),_T("Root"),_T(""),rootText,_countof(rootText),ini);
    GetPrivateProfileString(_T("Pair"),_T("Address"),_T(""),addressText,_countof(addressText),ini);
    const CString root=rootText,address=addressText;
    const bool interrupt=GetPrivateProfileInt(_T("Pair"),_T("Interrupt"),0,ini)!=0;
    const UINT networkLossMs=GetPrivateProfileInt(_T("Pair"),_T("NetworkLossMs"),0,ini);
    const bool recovery=interrupt || networkLossMs!=0;
    Require(!networkLossMs || (!interrupt && networkLossMs>=1000 && networkLossMs<=45000),"pair bounded exclusive silent network loss");
    Require((root.Left(7).CompareNoCase(_T("D:\\tmp\\"))==0 || root.Left(7).CompareNoCase(_T("C:\\tmp\\"))==0) && address==thePrefs.GetBindAddr(),"pair fresh tmp private bind");
    const auto peerTcp=static_cast<uint16>(GetPrivateProfileInt(_T("Pair"),_T("PeerTcp"),0,ini));
    const auto peerUdp=static_cast<uint16>(GetPrivateProfileInt(_T("Pair"),_T("PeerUdp"),0,ini));
    const auto interfaceId=GetPrivateProfileInt(_T("Pair"),_T("Interface"),0,ini);
    const uint32 ip=inet_addr(CT2A(address));
    Require(ip!=INADDR_NONE && peerTcp && peerUdp && interfaceId,"pair enrollment endpoint");
    auto& manager=*theApp.directreachability;
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    RefreshEseV9PreviewCaps(); // same consent-to-HELLO capability refresh as normal startup
    Require((g_uEseCapsRuntime & ESE_CAP_NETLAB_V1)!=0,"pair current local consent advertised on real HELLO");
    Require(eSELive::NodeIdentityInit() && eSELive::NodeIdentityIsPersistent(),"pair persistent local identity");
    Require(theApp.listensocket->StartListening() && theApp.clientudp->Create(),"pair binds real MFC sockets");
    manager.SynchronizeLocalSocketBindings();
    Require(manager.EnableNativeQuicLab(),"pair production native shared UDP host");
    auto publish=[&](const CString& name,const BYTE* bytes,UINT count) {
        const CString path=root+_T("\\")+name,temp=path+_T(".tmp");
        Require(GetFileAttributes(path)==INVALID_FILE_ATTRIBUTES && GetFileAttributes(temp)==INVALID_FILE_ATTRIBUTES,"pair fresh publication");
        { CFile disk(temp,CFile::modeCreate|CFile::modeWrite|CFile::shareExclusive); disk.Write(bytes,count); disk.Flush(); }
        Require(MoveFileEx(temp,path,MOVEFILE_WRITE_THROUGH)!=FALSE,"pair atomic publication no replace");
    };
    CUpDownClient* pairClient=nullptr; uint64 observedUpload=0,pairLifetime=0,nextTrace=0;
    bool uploadInterrupted=false;
    uint64 uploadLossStarted=0;
    std::optional<reach::DirectCoordinatorSnapshot> uploadBefore;
    uint64 uploadToken=0;
    // Pair-only observations of real scheduling; never scale clocks or budgets.
    uint64 sampleStart=Now(),lastPump=sampleStart,pumpCount=0,sleepTotal=0,workTotal=0,maxGap=0;
    theApp.HandleDebugLogQueue();
    auto pump=[&] {
        const auto pumpStart=Now();
        maxGap=(std::max)(maxGap,pumpStart-lastPump); lastPump=pumpStart; ++pumpCount;
        MSG message{};
        for(unsigned n=0;n<256 && PeekMessage(&message,nullptr,0,0,PM_REMOVE);++n) {
            TranslateMessage(&message); DispatchMessage(&message);
        }
        if(upload && recovery && !uploadInterrupted && GetFileAttributes(root+_T("\\interrupt.request"))!=INVALID_FILE_ATTRIBUTES) {
            Require(pairClient && pairClient->socket,"pair interruption actual upload adapter");
            CNativeDirectSelfTestAccess::CheckNativeTimeoutDelegation(*pairClient->socket);
            const auto record=CNativeDirectSelfTestAccess::PairSubscriber(manager,pairLifetime);
            Require(record && record->attempt,"pair interruption original upload subscription");
            uploadToken=record->token; uploadBefore=manager.DirectConnections().Snapshot(*record->attempt);
            Require(uploadBefore && uploadBefore->winner && uploadBefore->epoch==1,"pair interruption upload epoch1");
            if(networkLossMs) {
                ese::udp::Endpoint lossPeer; memcpy(lossPeer.address.data(),&ip,4); lossPeer.port=peerUdp;
                const auto expectedNode=pairClient->NativeDirectExpectedNode();
                Require(expectedNode && theApp.clientudp->ArmPairUdpLoss(*expectedNode,lossPeer,networkLossMs),"pair upload exact endpoint silent UDP loss");
                uploadLossStarted=Now();
                Log(_T("QUIC_PAIR NETWORK_LOSS upload milliseconds=%u no_close=1"),networkLossMs);
            } else {
                auto* transport=manager.FindNativeQuicLab(CNativeDirectSelfTestAccess::DirectOwner(*pairClient->socket));
                Require(transport!=nullptr,"pair interruption actual upload QUIC transport");
                transport->Close(reach::DirectReason::DirectUnreachable);
                Require(transport->Snapshot().closed,"pair interruption upload transport closed");
            }
            uploadInterrupted=true; const BYTE marker=1; publish(_T("interrupt.ack"),&marker,1);
            if(!networkLossMs) Log(_T("QUIC_PAIR INTERRUPT upload epoch1 transport closed"));
        }
        manager.TickDirectConnections();
        theApp.uploadqueue->Process();
        if(pairClient && theApp.clientlist->IsValidClient(pairClient)) observedUpload=(std::max)(observedUpload,pairClient->GetQueueSessionPayloadUp());
        if(pairLifetime && Now()>=nextTrace) { CNativeDirectSelfTestAccess::TracePair(manager,pairLifetime); nextTrace=Now()+1000; }
        const auto beforeSleep=Now(); workTotal+=beforeSleep-pumpStart;
        // Like the normal MFC pump, wake for socket/window messages instead of
        // holding pending FD_READ notifications behind a coarse Sleep(1).
        // The timeout and all QUIC/recovery clocks remain real and unchanged.
        Require(MsgWaitForMultipleObjectsEx(0,nullptr,1,QS_ALLINPUT,MWMO_INPUTAVAILABLE)!=WAIT_FAILED,
            "pair message-aware wait");
        const auto afterSleep=Now(); sleepTotal+=afterSleep-beforeSleep;
        if(afterSleep-sampleStart>=5000) {
            Log(_T("QUIC_PAIR SCHEDULING role=%s window_ms=%I64u loops=%I64u wait_ms=%I64u work_ms=%I64u max_gap_ms=%I64u highres_requested=%u wait=message_or_timeout"),
                upload?_T("upload"):_T("download"),afterSleep-sampleStart,pumpCount,sleepTotal,workTotal,maxGap,
                static_cast<UINT>(thePrefs.GetHighresTimer()));
            theApp.HandleDebugLogQueue();
            sampleStart=afterSleep; pumpCount=sleepTotal=workTotal=maxGap=0;
        }
    };
    auto wait=[&](const CString& name,uint64 timeout=30000) {
        const auto until=Now()+timeout;
        while(GetFileAttributes(root+_T("\\")+name)==INVALID_FILE_ATTRIBUTES && Now()<until) pump();
        Require(GetFileAttributes(root+_T("\\")+name)!=INVALID_FILE_ATTRIBUTES,"pair rendezvous deadline");
    };
    std::array<BYTE,48> local{},peer{};
    memcpy(local.data(),eSELive::NodeIdentityPub(),32); memcpy(local.data()+32,thePrefs.GetUserHash(),16);
    publish(upload?_T("upload.identity"):_T("download.identity"),local.data(),static_cast<UINT>(local.size()));
    wait(upload?_T("download.identity"):_T("upload.identity"));
    { CFile disk(root+_T("\\")+(upload?_T("download.identity"):_T("upload.identity")),CFile::modeRead|CFile::shareDenyNone);
      Require(disk.GetLength()==peer.size() && disk.Read(peer.data(),static_cast<UINT>(peer.size()))==peer.size(),"pair exact peer enrollment"); }
    std::array<std::uint8_t,32> node{}; memcpy(node.data(),peer.data(),32);
    Require(node!=std::array<std::uint8_t,32>{} && !std::equal(node.begin(),node.end(),local.begin()),"pair independent identities");
    // Operator-enrolled pin, not TOFU or a HELLO trust decision.
    const CString trustDir=config+_T("peer_trust");
    Require(CreateDirectory(trustDir,nullptr)!=FALSE || GetLastError()==ERROR_ALREADY_EXISTS,"pair private trust directory");
    CString nodeHex; for(const auto byte:node) nodeHex.AppendFormat(_T("%02x"),byte);
    std::array<std::uint8_t,trust::RecordSize> pin{};
    Require(trust::Encode(trust::Record{node,1,trust::Kind::Pinned},pin),"pair explicit pin encoding");
    const CString pinPath=trustDir+_T("\\")+nodeHex+_T(".trust");
    HANDLE pinFile=CreateFile(pinPath,GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
    Require(pinFile!=INVALID_HANDLE_VALUE,"pair no overwrite existing pin"); DWORD written=0;
    const bool stored=WriteFile(pinFile,pin.data(),static_cast<DWORD>(pin.size()),&written,nullptr) && written==pin.size() && FlushFileBuffers(pinFile);
    const bool closed=CloseHandle(pinFile)!=FALSE; Require(stored && closed,"pair durable pin publication");
    udp::Endpoint endpoint; memcpy(endpoint.address.data(),&ip,4); endpoint.port=peerUdp;
    const UINT fixtureBytes=GetPrivateProfileInt(_T("Pair"),_T("FileBytes"),65537,ini);
    Require(fixtureBytes==65537 || fixtureBytes==1048576 || fixtureBytes==1073741824,"pair supported fixture size");
    const bool large=fixtureBytes==1073741824;
    Require(!recovery || large,"pair interruption requires real F1");
    Require(!manager.ConfigureIsolatedLanQuicPeer(node,endpoint,interfaceId,119999) &&
        !manager.ConfigureIsolatedLanQuicPeer(node,endpoint,interfaceId,1200001),"pair rejects unbounded lab authorization");
    Require(manager.ConfigureIsolatedLanQuicPeer(node,endpoint,interfaceId,large?1100000:120000),"pair exact assigned LAN authorization");
    auto wrongEndpoint=endpoint; ++wrongEndpoint.port;
    Require(!manager.IsIsolatedLanQuicPeer(node,wrongEndpoint),"pair other endpoint not authorized");
    auto wrongNode=node; wrongNode[0]^=1;
    Require(!manager.IsIsolatedLanQuicPeer(wrongNode,endpoint),"pair other node not authorized");
    const uint64 transferBudget=large?900000:60000;
    const CString fixtureName=fixtureBytes==65537?_T("pair-small.bin"):(large?_T("pair-f1.bin"):_T("pair-f2.bin"));
    const unsigned modulus=fixtureBytes==65537?251:256;
    std::vector<BYTE> chunk(65536);
    std::array<BYTE,16> md4{};
    auto* client=new CUpDownClient(static_cast<CPartFile*>(nullptr),peerTcp,ntohl(ip),0,0,false);
    pairClient=client;
    CNativeDirectSelfTestAccess::SeedPairClient(*client,peer,ip,peerUdp); theApp.clientlist->AddClient(client);
    const auto clientLifetime=client->GetDirectClientLifetime();
    pairLifetime=clientLifetime;
    std::unique_ptr<CKnownFile> source;
    CPartFile* download=nullptr;
    struct Cleanup {
        CDirectReachabilityManager& manager; CUpDownClient* client; std::unique_ptr<CKnownFile>& source;
        ~Cleanup() {
            manager.ShutdownDirectHost();
            if(theApp.clientlist->IsValidClient(client)) {
                theApp.uploadqueue->RemoveFromUploadQueue(client,_T("isolated pair end")); theApp.uploadqueue->RemoveFromWaitingQueue(client);
                client->SetDownloadState(DS_NONE); client->SetRequestFile(nullptr);
            }
            if(source) { theApp.sharedfiles->RemoveFile(source.get());
                if(InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&source->nInUse),0,0)>0) source.release(); }
        }
    } cleanup{manager,client,source};
    if(upload) {
        Require(!manager.HasPendingDirectUpload(client->GetDirectClientLifetime()),"pair no upload consent before queue admission");
        const CString name=fixtureName,directory=thePrefs.GetTempDir();
        { CFile disk(directory+_T("\\")+name,CFile::modeCreate|CFile::modeWrite|CFile::shareExclusive);
          for(uint64 offset=0;offset<fixtureBytes;) {
              const UINT count=static_cast<UINT>((std::min)(static_cast<uint64>(chunk.size()),static_cast<uint64>(fixtureBytes)-offset));
              for(UINT i=0;i<count;++i) chunk[i]=static_cast<BYTE>((offset+i)%modulus);
              disk.Write(chunk.data(),count); offset+=count;
          }
          disk.Flush(); }
        source=std::make_unique<CKnownFile>();
        Require(source->CreateFromFile(directory,name,nullptr) &&
            theApp.sharedfiles->SafeAddKFile(source.get(),true),"pair actual hashed shared source");
        memcpy(md4.data(),source->GetFileHash(),md4.size());
        publish(_T("upload.hash"),md4.data(),static_cast<UINT>(md4.size()));
        client->SetUploadFileID(source.get());
        theApp.uploadqueue->AddClientToQueue(client); // normal admission, queue checks and slot scheduler
        const auto grantUntil=Now()+4000;
        while(!manager.HasPendingDirectUpload(client->GetDirectClientLifetime()) && Now()<grantUntil) pump();
        Require(manager.HasPendingDirectUpload(client->GetDirectClientLifetime()),"pair normal upload bridge armed");
        const BYTE ready=1; publish(_T("upload.ready"),&ready,1);
        wait(_T("download.complete"),large?transferBudget:30000);
        Require(observedUpload>=fixtureBytes,"pair actual product uploader sent payload");
        if(recovery) {
            const auto record=CNativeDirectSelfTestAccess::PairSubscriber(manager,clientLifetime);
            const auto state=record && record->attempt ? manager.DirectConnections().Snapshot(*record->attempt) : std::nullopt;
            Require(uploadInterrupted && uploadBefore && record && record->token==uploadToken && state &&
                state->attempt_id==uploadBefore->attempt_id && state->handle.slot==uploadBefore->handle.slot &&
                state->handle.generation==uploadBefore->handle.generation &&
                (networkLossMs ? (state->epoch>=1 && state->epoch<=2) : state->epoch==2) && state->winner &&
                state->subscribers==uploadBefore->subscribers && theApp.uploadqueue->GetUploadQueueLength()==1,
                "pair recovered upload same session subscription single slot epoch2");
            if(networkLossMs) {
                Require(Now()-uploadLossStarted>=networkLossMs,"pair upload silent loss window elapsed");
                Log(_T("QUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=%u drops=%I64u epoch=%I64u slots=1"),networkLossMs,theApp.clientudp->PairUdpLossDrops(),state->epoch);
            } else Log(_T("QUIC_PAIR RECOVERY_UPLOAD PASS epoch=2 slots=1 same_attempt=1 same_subscriber=1"));
        }
        theApp.sharedfiles->RemoveFile(source.get()); manager.TickDirectConnections();
        Require(!manager.HasPendingDirectUpload(clientLifetime),"pair unshared file revokes upload authorization");
        publish(_T("upload.complete"),md4.data(),static_cast<UINT>(md4.size()));
    } else {
        wait(_T("upload.ready"),large?120000:30000);
        { CFile disk(root+_T("\\upload.hash"),CFile::modeRead|CFile::shareDenyNone);
          Require(disk.GetLength()==md4.size() && disk.Read(md4.data(),static_cast<UINT>(md4.size()))==md4.size(),"pair source ed2k hashset root"); }
        CString hash; for(const auto byte:md4) hash.AppendFormat(_T("%02X"),byte);
        CString link; link.Format(_T("ed2k://|file|%s|%u|%s|/"),(LPCTSTR)fixtureName,fixtureBytes,(LPCTSTR)hash);
        download=new CPartFile(link); theApp.downloadqueue->AddDownload(download,false);
        client->SetRequestFile(download); download->srclist.AddTail(client); client->SetDownloadState(DS_ONQUEUE);
        wait(_T("upload.ready"));
        Require(client->ProcessNativeDirectDownload() && client->GetNativeDirectDownloadSubscriber(),"pair normal downloader admission");
        const auto until=Now()+transferBudget; uint64 nextFlush=0;
        bool interrupted=false,recovered=false;
        uint64 lossStarted=0,lossFloor=0; bool lossPlateau=false;
        std::optional<reach::DirectCoordinatorSnapshot> before;
        const auto subscriber=client->GetNativeDirectDownloadSubscriber();
        auto* originalCredits=client->Credits(); uint64 completedBefore=0;
        std::vector<UINT> preservedParts;
        while(Now()<until && download->GetStatus()!=PS_COMPLETE) {
            pump();
            if(Now()>=nextFlush && (download->GetStatus()==PS_READY || download->GetStatus()==PS_EMPTY)) { download->FlushBuffer(); nextFlush=Now()+200; }
            if(recovery && !interrupted && download->GetCompletedSize()>=67108864) {
                download->FlushBuffer(); const auto flushUntil=Now()+8000;
                while(download->m_iWrites>0 && Now()<flushUntil) pump();
                Require(download->m_iWrites==0,"pair interruption IOCP drained");
                const auto record=manager.ResolveDirectSubscriber(subscriber);
                before=record && record->attempt ? manager.DirectConnections().Snapshot(*record->attempt) : std::nullopt;
                Require(before && before->epoch==1 && before->winner && before->useful_bytes>=67108864 && client->socket,
                    "pair interruption actual epoch1 progress");
                CNativeDirectSelfTestAccess::CheckNativeTimeoutDelegation(*client->socket);
                completedBefore=download->GetCompletedSize();
                originalCredits=client->Credits(); // identity/credits are established by the real HELLO, not admission
                for(UINT part=0;part<download->GetPartCount();++part) if(download->IsCompleteBD(part)) preservedParts.push_back(part);
                Require(!preservedParts.empty(),"pair interruption has complete persisted parts");
                const BYTE marker=1; publish(_T("interrupt.request"),&marker,1); wait(_T("interrupt.ack"));
                if(networkLossMs) {
                    Require(theApp.clientudp->ArmPairUdpLoss(node,endpoint,networkLossMs),"pair download exact endpoint silent UDP loss");
                    lossStarted=Now();
                } else {
                    auto* transport=client->socket ? manager.FindNativeQuicLab(CNativeDirectSelfTestAccess::DirectOwner(*client->socket)) : nullptr;
                    Require(transport!=nullptr,"pair interruption actual download QUIC transport");
                    transport->Close(reach::DirectReason::DirectUnreachable);
                    Require(transport->Snapshot().closed,"pair interruption download transport closed");
                }
                interrupted=true;
                if(networkLossMs) Log(_T("QUIC_PAIR NETWORK_LOSS download milliseconds=%u bytes=%I64u parts=%u no_close=1"),networkLossMs,before->useful_bytes,unsigned(preservedParts.size()));
                else Log(_T("QUIC_PAIR INTERRUPT download bytes=%I64u completed=%I64u parts=%u epoch=1"),before->useful_bytes,completedBefore,unsigned(preservedParts.size()));
            }
            // Completion legitimately detaches the active source before the
            // final rename/status message. Its oracle is the completed disk
            // file below, not the live-transfer pointer during PS_COMPLETING.
            if(interrupted && (download->GetStatus()==PS_READY || download->GetStatus()==PS_EMPTY)) {
                const auto record=manager.ResolveDirectSubscriber(subscriber);
                const auto state=record && record->attempt ? manager.DirectConnections().Snapshot(*record->attempt) : std::nullopt;
                Require(before && record && !record->terminal_reason && state && state->attempt_id==before->attempt_id &&
                    state->handle.slot==before->handle.slot && state->handle.generation==before->handle.generation &&
                    state->subscribers==before->subscribers && state->useful_bytes>=before->useful_bytes && state->useful_bytes<=fixtureBytes &&
                    client->GetNativeDirectDownloadSubscriber()==subscriber && client->GetDirectClientLifetime()==clientLifetime &&
                    client->Credits()==originalCredits && client->GetRequestFile()==download && download->GetCompletedSize()>=completedBefore,
                    "pair recovery preserves file identity accounting subscription and accepted bytes");
                for(const auto part:preservedParts) Require(download->IsCompleteBD(part),"pair recovery preserves completed parts");
                if(state->epoch==2 && state->winner) Require(CNativeDirectSelfTestAccess::PairRequestsExcludeParts(*client,preservedParts),
                    "pair recovered requests exclude already completed parts");
                if(networkLossMs && Now()-lossStarted>=1000 && Now()-lossStarted+100<networkLossMs) {
                    if(!lossPlateau) { lossFloor=state->useful_bytes; lossPlateau=true; }
                    Require(state->useful_bytes==lossFloor,"pair silent UDP outage has no useful delivery after in-flight drain");
                }
                const bool resumed=networkLossMs ? (Now()-lossStarted>=networkLossMs && state->epoch>=1 && state->epoch<=2 && state->useful_bytes>lossFloor)
                    : state->epoch==2;
                if(resumed && state->winner && state->useful_bytes>before->useful_bytes && !recovered) {
                    recovered=true;
                    if(networkLossMs) {
                        Require(networkLossMs<2100 || lossPlateau,"pair network outage plateau observed");
                        Log(_T("QUIC_PAIR NETWORK_LOSS_DOWNLOAD PASS milliseconds=%u epoch=%I64u preserved_parts=%u bytes_before=%I64u bytes_after=%I64u no_close=1 drops=%I64u"),
                            networkLossMs,state->epoch,unsigned(preservedParts.size()),before->useful_bytes,state->useful_bytes,theApp.clientudp->PairUdpLossDrops());
                    } else Log(_T("QUIC_PAIR RECOVERY_DOWNLOAD PASS epoch=2 same_attempt=1 same_subscriber=1 preserved_parts=%u bytes_before=%I64u bytes_after=%I64u"),
                        unsigned(preservedParts.size()),before->useful_bytes,state->useful_bytes);
                }
            }
        }
        Require(!recovery || (interrupted && recovered),"pair interruption and automatic recovery occurred");
        Require(download->GetStatus()==PS_COMPLETE,"pair product MD4 worker completed file");
        CFile disk(download->GetFilePath(),CFile::modeRead|CFile::shareDenyNone);
        Require(disk.GetLength()==fixtureBytes,"pair completed exact disk length");
        for(uint64 offset=0;offset<fixtureBytes;) {
            const UINT count=static_cast<UINT>((std::min)(static_cast<uint64>(chunk.size()),static_cast<uint64>(fixtureBytes)-offset));
            Require(disk.Read(chunk.data(),count)==count,"pair completed chunk read");
            for(UINT i=0;i<count;++i) Require(chunk[i]==static_cast<BYTE>((offset+i)%modulus),"pair completed disk byte for byte");
            offset+=count;
        }
        Require(!memcmp(download->GetFileHash(),md4.data(),md4.size()),"pair completed multipart ed2k root correct");
        publish(_T("download.complete"),md4.data(),static_cast<UINT>(md4.size()));
        wait(_T("upload.complete")); // sender accounting/revocation completes before either process exits
    }
    CString hash; for(const auto byte:md4) hash.AppendFormat(_T("%02X"),byte);
    Log(_T("QUIC_PAIR PASS role=%s bytes=%u MD4=%s two independent product processes exact SameLan pinned enrollment normal queue bootstrap AUTH HELLO file negotiation disk completion"),
        (LPCTSTR)theApp.m_strQuicPairSelfTestRole,fixtureBytes,(LPCTSTR)hash);
    return true;
}
} }
