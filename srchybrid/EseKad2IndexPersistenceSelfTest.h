#pragma once
#include "kademlia/kademlia/Indexed.h"
#include "kademlia/kademlia/Entry.h"
#include <memory>
namespace ese { namespace shared_socket_selftest {
// The actual legacy index and loader, in the already isolated diagnostic
// profile. No public Kad routing/traffic, accelerated clock or exit20 claim.
inline void RunKad2IndexPersistence(uint16 portNumber) {
    Require(theApp.m_bReachBindingSelfTest && !thePrefs.DoAutoConnect() &&
        !Kademlia::CKademlia::IsRunning(),"Kad2 persistence isolated stopped prerequisite");
    const CString config=thePrefs.GetMuleDirectory(EMULE_CONFIGDIR);
    Require(config.Left(7).CompareNoCase(_T("D:\\tmp\\"))==0,"Kad2 persistence private fixture directory");
    struct Restore {
        uint8 mask=thePrefs.GetKadNetworkMask();
        uint16 udp=thePrefs.GetUDPPort();
        ~Restore() {
            Kademlia::CKademlia::Stop(); thePrefs.SetKadNetworkMask(mask);
            thePrefs.SetUDPPort(udp); theApp.clientudp->Rebind();
            theApp.directreachability->SynchronizeLocalSocketBindings();
        }
    } restore;
    thePrefs.SetUDPPort(portNumber);
    Require(portNumber && theApp.clientudp->Rebind(),"Kad2 actual shared UDP activation");
    thePrefs.SetKadNetworkMask(KadNetworkPolicy::Kad2);
    auto pump=[]() {
        MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) {
            if(message.message==WM_TIMER) continue;
            TranslateMessage(&message); DispatchMessage(&message);
        }
        Sleep(1);
    };
    auto start=[&](ULONG readinessKey) {
        Kademlia::CKademlia::Start();
        Log(_T("KAD2_INDEX_SELFTEST activation: configured=%u effective=%u UDP=%u bound=%u"),
            unsigned(thePrefs.GetKadNetworkMask()),unsigned(thePrefs.GetEffectiveKadNetworkMask()),
            unsigned(thePrefs.GetUDPPort()),unsigned(theApp.clientudp->GetConnectedPort()));
        Require(Kademlia::CKademlia::IsKad2Running() && !Kademlia::CKademlia::IsKad6Running() &&
            Kademlia::CKademlia::GetIndexed(),"Kad2 actual legacy index activation");
        const auto deadline=Now()+5000;
        const Kademlia::CUInt128 key(readinessKey);
        while(!Kademlia::CKademlia::GetIndexed()->AddLoad(key,time(nullptr)+3600)) {
            Require(Now()<deadline,"Kad2 actual loader readiness deadline"); pump();
        }
    };
    start(900001);
    auto* index=Kademlia::CKademlia::GetIndexed();
    Require(index->m_uTotalIndexSource==0 && index->m_uTotalIndexKeyword==0,
        "Kad2 initially empty owned index, no overwrite of unrelated fixture state");
    for(ULONG i=1;i<=10000;++i) {
        const Kademlia::CUInt128 key(i),source(100000+i);
        std::unique_ptr<Kademlia::CEntry> entry(new Kademlia::CEntry());
        entry->m_uKeyID=key; entry->m_uSourceID=source; entry->m_bSource=true;
        entry->m_uIP=htonl(0x34010102); entry->m_uTCPPort=4662; entry->m_uUDPPort=4672;
        entry->m_tLifetime=time(nullptr)+3600;
        entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEIP,entry->m_uIP));
        entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEPORT,entry->m_uTCPPort));
        entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEUPORT,entry->m_uUDPPort));
        uint8 load=0;
        Require(index->AddSources(key,source,entry.get(),load),"Kad2 actual source index insertion");
        entry.release();
    }
    Require(index->m_uTotalIndexSource==10000,"Kad2 source count before stop");
    const auto before=Now(); Kademlia::CKademlia::Stop(); const auto elapsed=Now()-before;
    Require(elapsed<=30000,"Kad2 actual stop/write drain deadline");
    WIN32_FILE_ATTRIBUTE_DATA data{};
    Require(GetFileAttributesEx(config+_T("src_index.dat"),GetFileExInfoStandard,&data) &&
        !(data.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) &&
        (data.nFileSizeHigh || data.nFileSizeLow>100000),"Kad2 persisted nonempty regular source index");
    start(900002);
    Require(Kademlia::CKademlia::GetIndexed()->m_uTotalIndexSource==10000,
        "Kad2 real loader restores every persisted source");
    // Replace the same exact key/source/tuple: count must remain unchanged.
    std::unique_ptr<Kademlia::CEntry> replacement(new Kademlia::CEntry());
    replacement->m_uKeyID=Kademlia::CUInt128(1UL);
    replacement->m_uSourceID=Kademlia::CUInt128(100001UL);
    replacement->m_uIP=htonl(0x34010102); replacement->m_uTCPPort=4662;
    replacement->m_uUDPPort=4672; replacement->m_tLifetime=time(nullptr)+3600;
    replacement->m_bSource=true;
    replacement->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEIP,replacement->m_uIP));
    replacement->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEPORT,replacement->m_uTCPPort));
    replacement->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEUPORT,replacement->m_uUDPPort));
    uint8 load=0;
    Require(Kademlia::CKademlia::GetIndexed()->AddSources(Kademlia::CUInt128(1UL),
        Kademlia::CUInt128(100001UL),replacement.get(),load),"Kad2 restored tuple replacement");
    replacement.release();
    Require(Kademlia::CKademlia::GetIndexed()->m_uTotalIndexSource==10000,"Kad2 reload exact duplicate does not grow index");
    Log(_T("KAD2_INDEX_SELFTEST actual stop/write: entries=10000 elapsed_ms=%I64u"),elapsed);
    Log(_T("REACH_SELFTEST V174 PASS: actual legacy Kad2 index inserts10000 sources normal stop writes owned profile real restart loader recovers10000 exact duplicate stable drain under30s; no GUI responsiveness 2h20 soak or exit20 cause claim"));
}
}}
