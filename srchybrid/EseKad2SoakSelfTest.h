#pragma once
#ifdef ESE_NATIVE_QUIC_LAB_AVAILABLE
#include <dbghelp.h>
namespace ese { namespace kad2_soak {
inline bool Enabled() {
    TCHAR value[16]={};
    return theApp.m_bReachBindingSelfTest && GetEnvironmentVariable(_T("ESE_KAD2_SOAK"),value,16) &&
        (!_tcscmp(value,_T("seed")) || !_tcscmp(value,_T("reload")));
}
inline void Record(LPCTSTR phase) {
    CStdioFile file(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)+_T("soak-events.txt"),
        CFile::modeCreate|CFile::modeNoTruncate|CFile::modeWrite|CFile::typeText);
    file.SeekToEnd(); CString line;
    const auto* index=Kademlia::CKademlia::IsRunning() ? Kademlia::CKademlia::GetIndexed() : nullptr;
    line.Format(_T("%s tick=%I64u pid=%lu hwnd=%I64u sources=%u\n"),phase,
        ese::shared_socket_selftest::Now(),GetCurrentProcessId(),(ULONGLONG)(UINT_PTR)theApp.emuledlg->GetSafeHwnd(),
        index ? index->m_uTotalIndexSource : 0);
    file.WriteString(line); file.Flush();
}
inline LONG WINAPI Crash(EXCEPTION_POINTERS* exception) {
    const CString path=thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)+_T("soak-crash.dmp");
    HMODULE library=LoadLibraryEx(_T("dbghelp.dll"),nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(library) {
        typedef BOOL (WINAPI *Writer)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,
            PMINIDUMP_EXCEPTION_INFORMATION,PMINIDUMP_USER_STREAM_INFORMATION,PMINIDUMP_CALLBACK_INFORMATION);
        auto writer=reinterpret_cast<Writer>(GetProcAddress(library,"MiniDumpWriteDump"));
        HANDLE file=CreateFile(path,GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file!=INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION info={GetCurrentThreadId(),exception,FALSE};
            if(writer) writer(GetCurrentProcess(),GetCurrentProcessId(),file,MiniDumpNormal,&info,nullptr,nullptr);
            CloseHandle(file);
        }
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
inline void Start() {
    using ese::shared_socket_selftest::Require;
    Require(Enabled() && !thePrefs.DoAutoConnect() && !thePrefs.IsUPnPEnabled() &&
        thePrefs.GetMuleDirectory(EMULE_CONFIGDIR).Left(7).CompareNoCase(_T("D:\\tmp\\"))==0 &&
        thePrefs.GetBindAddrA() && !strcmp(thePrefs.GetBindAddrA(),"127.0.0.1"),"unsafe soak fixture");
    thePrefs.SetConfirmExit(false);
    SetUnhandledExceptionFilter(Crash); // Owned diagnostic profile; no registry or prompts.
    Require(theApp.clientudp->Rebind(),"soak UDP bind");
    thePrefs.SetKadNetworkMask(KadNetworkPolicy::Kad2);
    Kademlia::CKademlia::Start();
    Require(Kademlia::CKademlia::IsKad2Running(),"soak Kad2 activation");
    auto* index=Kademlia::CKademlia::GetIndexed();
    TCHAR mode[16]={}; GetEnvironmentVariable(_T("ESE_KAD2_SOAK"),mode,16);
    const bool seed=!_tcscmp(mode,_T("seed"));
    const auto deadline=ese::shared_socket_selftest::Now()+10000;
    while(!index->AddLoad(Kademlia::CUInt128(seed ? 990001UL : 990002UL),time(nullptr)+14400)) {
        Require(ese::shared_socket_selftest::Now()<deadline,"soak index loader deadline");
        Sleep(1);
    }
    if(seed) {
        Require(index->m_uTotalIndexSource==0,"soak fresh empty index");
        for(ULONG i=1;i<=10000;++i) {
            const Kademlia::CUInt128 key(i),source(100000+i);
            std::unique_ptr<Kademlia::CEntry> entry(new Kademlia::CEntry());
            entry->m_uKeyID=key; entry->m_uSourceID=source; entry->m_bSource=true;
            entry->m_uIP=htonl(INADDR_LOOPBACK); entry->m_uTCPPort=4662; entry->m_uUDPPort=4672;
            entry->m_tLifetime=time(nullptr)+14400;
            entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEIP,entry->m_uIP));
            entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEPORT,entry->m_uTCPPort));
            entry->AddTag(new Kademlia::CKadTagUInt32(TAG_SOURCEUPORT,entry->m_uUDPPort));
            uint8 load=0; Require(index->AddSources(key,source,entry.get(),load),"soak source insertion");
            entry.release();
        }
    }
    Require(index->m_uTotalIndexSource==10000,"soak count10000 seed/reload");
    theApp.m_app_state=APP_STATE_RUNNING;
    Record(!_tcscmp(mode,_T("seed")) ? _T("READY_SEED") : _T("READY_RELOAD"));
}
}}
#else
namespace ese { namespace kad2_soak {
inline bool Enabled() { return false; }
inline void Record(LPCTSTR) {}
inline void Start() {}
}}
#endif
