#pragma once
#include <initializer_list>
#include <memory>
#include "Packets.h"
#include "SafeFile.h"
#include "Server.h"
#include "ServerList.h"
#include "ServerConnect.h"
namespace ese { namespace shared_socket_selftest {
inline void RunServerCallbackHost(CDirectReachabilityManager& manager) {
    Require(theApp.m_bReachBindingSelfTest && manager.IsEnabled() &&
        !theApp.serverconnect->IsConnected() && !theApp.serverconnect->IsConnecting() &&
        theApp.serverlist->GetServerCount()==0, "callback isolated empty server list");
    struct Endpoint {
        SOCKET listener=INVALID_SOCKET,peer=INVALID_SOCKET;
        uint16 port=0; unsigned logins=0; bool closed=false;
        std::vector<unsigned char> input;
        std::vector<unsigned char> login;
        Endpoint() {
            listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            Require(listener!=INVALID_SOCKET,"callback mock server socket");
            sockaddr_in address{}; address.sin_family=AF_INET;
            address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            Require(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 &&
                listen(listener,2)==0,"callback mock server loopback bind");
            int length=sizeof(address);
            Require(getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0,"callback server assigned port");
            port=ntohs(address.sin_port); u_long nonblocking=1;
            Require(ioctlsocket(listener,FIONBIO,&nonblocking)==0,"callback listener nonblocking");
        }
        ~Endpoint() { if(peer!=INVALID_SOCKET) closesocket(peer); if(listener!=INVALID_SOCKET) closesocket(listener); }
        void Poll() {
            if(peer==INVALID_SOCKET) {
                peer=accept(listener,nullptr,nullptr);
                if(peer==INVALID_SOCKET) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"callback accept"); return; }
                u_long nonblocking=1; Require(ioctlsocket(peer,FIONBIO,&nonblocking)==0,"callback peer nonblocking");
            }
            if(closed) return;
            unsigned char buffer[4096];
            const int count=recv(peer,reinterpret_cast<char*>(buffer),sizeof(buffer),0);
            if(count==0) { closed=true; return; }
            if(count<0) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"callback receive"); return; }
            input.insert(input.end(),buffer,buffer+count);
            while(input.size()>=6) {
                const uint32 size=uint32(input[1])|(uint32(input[2])<<8)|(uint32(input[3])<<16)|(uint32(input[4])<<24);
                Require(input[0]==OP_EDONKEYPROT && size && size<=65536,"callback classic frame");
                if(input.size()<std::size_t(size)+5) break;
                if(input[5]==OP_LOGINREQUEST) {
                    ++logins;
                    login.assign(input.begin()+6,input.begin()+size+5);
                }
                input.erase(input.begin(),input.begin()+size+5);
            }
        }
        void CheckLoginTag(bool ipv6Enabled) {
            Require(login.size()>=26,"server login fixed fields");
            CSafeMemFile frame(login.data(),static_cast<UINT>(login.size()));
            frame.Seek(22,CFile::begin); // hash16, ID4, port2
            Require(frame.ReadUInt32()==(ipv6Enabled ? 5u : 4u),"server login tag count");
            const uint8 names[]={CT_NAME,CT_VERSION,CT_SERVER_FLAGS,CT_EMULE_VERSION};
            for(uint8 name:names) {
                CTag tag(frame,true);
                Require(tag.GetNameID()==name,"server login preserves classic tag order");
            }
            if(ipv6Enabled) {
                // uint32 TLV, reserved name 0xf0, only server IPv6 wire bit.
                const unsigned char fixture[]={0x03,0x01,0x00,0xf0,0x01,0x00,0x00,0x00};
                unsigned char actual[sizeof fixture]={};
                Require(frame.Read(actual,sizeof actual)==sizeof actual &&
                    memcmp(actual,fixture,sizeof fixture)==0,"private server login alias exact bytes");
            }
            Require(frame.GetPosition()==frame.GetLength(),"no extra server login tags");
        }
        void LowId(bool duplicate) {
            const unsigned char frame[20]={OP_EDONKEYPROT,5,0,0,0,OP_IDCHANGE,10,0,0,0,
                OP_EDONKEYPROT,5,0,0,0,OP_IDCHANGE,10,0,0,0};
            const int length=duplicate?20:10;
            Require(send(peer,reinterpret_cast<const char*>(frame),length,0)==length,"callback LowID wire");
        }
    } first,second,ipv6;
    struct Restore {
        uint16 firstPort,secondPort,ipv6Port;
        CPreferences::EIPv6Mode mode=thePrefs.GetIPv6Mode();
        bool smart=thePrefs.GetSmartIdCheck();
        bool enabled=thePrefs.GetEseNetLabEnabled();
        uint8 smartState=thePrefs.GetSmartIdState();
        ~Restore() {
            theApp.serverconnect->StopConnectionTry(); theApp.serverconnect->Disconnect();
            theApp.serverconnect->StopConnectionTry();
            for(uint16 port: {firstPort,secondPort,ipv6Port}) {
                CServer* own=theApp.serverlist->GetServerByAddress(_T("localhost"),port);
                if(own) theApp.serverlist->RemoveServer(own);
            }
            thePrefs.SetSmartIdCheck(smart);
            thePrefs.SetEseNetLabEnabled(enabled);
            thePrefs.SetSmartIdState(smartState);
            thePrefs.SetIPv6Mode(mode);
        }
    } restore{first.port,second.port,ipv6.port};
    for(uint16 port: {first.port,second.port,ipv6.port}) {
        std::unique_ptr<CServer> known(new CServer(port,_T("localhost")));
        known->SetIsStaticMember(true);
        Require(theApp.serverlist->AddServer(known.get()),"callback register owned known server"); known.release();
    }
    thePrefs.SetSmartIdCheck(true);
    auto pump=[&]() {
        MSG message;
        while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) {
            if(message.message==WM_TIMER) continue;
            TranslateMessage(&message); DispatchMessage(&message);
        }
        first.Poll(); second.Poll(); ipv6.Poll(); Sleep(1);
    };
    // Normal auto-connect path, plaintext classic server fixture, no private/public
    // endpoint authority, mapped reachability or HighID is inferred from this test.
    theApp.serverconnect->ConnectToAnyServer(0,false,true,true);
    auto until=Now()+3000;
    while(!first.logins && Now()<until) pump();
    Require(first.logins==1 && second.peer==INVALID_SOCKET,"callback one initial login");
    first.LowId(true);
    until=Now()+1000;
    while(!theApp.serverconnect->IsCallbackFallbackPending() && Now()<until) pump();
    Require(theApp.serverconnect->IsCallbackFallbackPending(),"callback failure reserves one fallback");
    theApp.serverconnect->CheckForTimeout();
    until=Now()+3000;
    while(!second.logins && Now()<until) pump();
    Require(first.closed && first.logins==1 && second.logins==1,"callback old socket closed before second login");
    second.LowId(true);
    until=Now()+500;
    while(Now()<until) { pump(); if(theApp.serverconnect->IsConnecting()) theApp.serverconnect->CheckForTimeout(); }
    Require(theApp.serverconnect->IsConnected() && theApp.serverconnect->IsLowID() &&
        theApp.serverconnect->GetCurrentServer()->GetPort()==second.port &&
        !theApp.serverconnect->IsCallbackFallbackPending() && first.logins==1 && second.logins==1,
        "callback second LowID retained without third login or fake HighID");
    for(auto* endpoint: {&first,&second}) {
        const SOCKET extra=accept(endpoint->listener,nullptr,nullptr);
        if(extra!=INVALID_SOCKET) closesocket(extra);
        Require(extra==INVALID_SOCKET && WSAGetLastError()==WSAEWOULDBLOCK,"callback no extra connections");
    }
    Log(_T("REACH_SELFTEST V172 PASS: normal automatic classic login failure selects second known server once after closing first; duplicate LowID no third login and no HighID; two loopback protocol fixtures not external servers"));
    thePrefs.SetSmartIdState(1); thePrefs.SetEseNetLabEnabled(false);
    second.LowId(true); until=Now()+100;
    while(Now()<until) pump();
    Require(thePrefs.GetSmartIdState()==0 && theApp.serverconnect->IsConnected() &&
        !theApp.serverconnect->IsCallbackFallbackPending() && second.logins==1,
        "callback feature disabled restores legacy SmartID handling");
    thePrefs.SetEseNetLabEnabled(restore.enabled);
    Log(_T("REACH_SELFTEST V173 PASS: disabling bounded callback fallback restores normal classic SmartID handling on duplicate LowID without another login; loopback fixture no HighID proof"));

    first.CheckLoginTag(false);
    second.CheckLoginTag(false);
    theApp.serverconnect->Disconnect();
    thePrefs.SetIPv6Mode(CPreferences::IPv6AutoMode);
    auto* owned=theApp.serverlist->GetServerByAddress(_T("localhost"),ipv6.port);
    Require(owned!=nullptr,"server login positive fixture owned endpoint");
    theApp.serverconnect->ConnectToServer(owned,false,true);
    until=Now()+3000;
    while(!ipv6.logins && Now()<until) pump();
    Require(ipv6.logins==1,"server login positive fixture capture");
    ipv6.CheckLoginTag(true);
    Log(_T("REACH_SELFTEST V175 PASS: loopback OP_LOGINREQUEST exact private 0xF0 UINT32 bit 0x01 and IPv6-off classic tag list"));
}
}}
