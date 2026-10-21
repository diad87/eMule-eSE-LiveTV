#include "../../srchybrid/EseNodeBindingCrypto.h"
#include "../../srchybrid/LiveCrypto.h"
#include "../../srchybrid/EsePeerTrust.h"
#include "../../srchybrid/EsePeerTrustStore.h"
#include <string>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
// NodeIdentity storage shim only. Ed25519 and SHA256 are real product primitives.
static std::uint8_t pub[32],priv[32];
static bool persistent=true;
namespace eSELive {
bool NodeIdentityIsPersistent() { return persistent; }
bool NodeIdentitySign(const std::uint8_t* p,std::size_t n,std::uint8_t sig[64]) {
    return SignMessage(priv,pub,p,n,sig);
}
}
using namespace ese::binding;
struct LabExporter : TlsExporter {
    bool PeerExporter(const std::array<std::uint8_t,32>& c,std::array<std::uint8_t,32>& out) noexcept override {
        out=c; return true;
    }
};
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) std::exit(1); }
static void TestStore(const Session& authenticated,const std::array<std::uint8_t,32>& key) {
    using namespace ese::trust;
    wchar_t base[MAX_PATH]{};
    Check(GetTempPathW(MAX_PATH,base)>0);
    const auto directory=std::wstring(base)+L"ese-peer-trust-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
    Check(CreateDirectoryW(directory.c_str(),nullptr)!=FALSE);
    const auto path=directory+L"/peer.trust",temporary=directory+L"/peer.new";
    Record loaded; loaded.node.fill(7); loaded.version=9;
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Missing && loaded.version==9);
    Hello local; local.node=key; local.attempt.fill(1); local.nonce.fill(2); local.caps=1;
    Session unverified(local,key,nullptr,true,true,100);
    FileCommitter committer(path,temporary);
    Check(committer.Commit(unverified,key)==CommitResult::PersistenceFailed);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),unverified,key)==SaveResult::Invalid);
    Check(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES);
    Check(PersistFirstUse(path.c_str(),path.c_str(),authenticated,key)==SaveResult::Invalid);
    // A pre-existing temporary file belongs to another operation, never delete it.
    HANDLE collision=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(collision!=INVALID_HANDLE_VALUE && CloseHandle(collision));
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::IoError);
    Check(GetFileAttributesW(temporary.c_str())!=INVALID_FILE_ATTRIBUTES);
    Check(DeleteFileW(temporary.c_str())!=FALSE);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::Created);
    Check(GetFileAttributesW(temporary.c_str())==INVALID_FILE_ATTRIBUTES);
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Loaded && loaded.node==key && loaded.version==1);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::AlreadyKnown);
    Check(committer.Commit(authenticated,key)==CommitResult::Stored);
    const auto racePath=directory+L"/race.trust",raceA=directory+L"/race-a.new",raceB=directory+L"/race-b.new";
    SaveResult resultA=SaveResult::Invalid,resultB=SaveResult::Invalid;
    std::thread first([&]{resultA=PersistFirstUse(racePath.c_str(),raceA.c_str(),authenticated,key);});
    std::thread second([&]{resultB=PersistFirstUse(racePath.c_str(),raceB.c_str(),authenticated,key);});
    first.join(); second.join();
    Check((resultA==SaveResult::Created && resultB==SaveResult::AlreadyKnown) ||
        (resultB==SaveResult::Created && resultA==SaveResult::AlreadyKnown));
    Check(LoadRecord(racePath.c_str(),loaded)==LoadResult::Loaded && loaded.node==key);
    Check(GetFileAttributesW(raceA.c_str())==INVALID_FILE_ATTRIBUTES && GetFileAttributesW(raceB.c_str())==INVALID_FILE_ATTRIBUTES);
    Check(DeleteFileW(racePath.c_str())!=FALSE);
    // Hold the destination exclusively: IO failure cannot erase prior trust.
    HANDLE held=CreateFileW(path.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(held!=INVALID_HANDLE_VALUE);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::IoError);
    Check(CloseHandle(held)!=FALSE);
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Loaded && loaded.node==key);
    // Write a different local trusted record to model a changed stored pin.
    auto changed=loaded; changed.node[0]^=1; changed.kind=Kind::Pinned; changed.version=8;
    std::array<std::uint8_t,RecordSize> bytes{}; Check(Encode(changed,bytes));
    HANDLE fixture=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    DWORD written=0;
    Check(fixture!=INVALID_HANDLE_VALUE && WriteFile(fixture,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr) && written==bytes.size());
    Check(CloseHandle(fixture)!=FALSE);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::Changed);
    Check(committer.Commit(authenticated,key)==CommitResult::PinChanged);
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Loaded && loaded.node==changed.node && loaded.version==8);
    fixture=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    LARGE_INTEGER end{}; const std::uint8_t extra=1;
    Check(fixture!=INVALID_HANDLE_VALUE && SetFilePointerEx(fixture,end,nullptr,FILE_END) &&
        WriteFile(fixture,&extra,1,&written,nullptr) && written==1);
    Check(CloseHandle(fixture)!=FALSE);
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Invalid && loaded.version==8);
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::Invalid);
    fixture=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(fixture!=INVALID_HANDLE_VALUE && CloseHandle(fixture));
    Check(PersistFirstUse(path.c_str(),temporary.c_str(),authenticated,key)==SaveResult::Invalid);
    Check(LoadRecord(path.c_str(),loaded)==LoadResult::Invalid && loaded.version==8);
    Check(DeleteFileW(path.c_str()) && RemoveDirectoryW(directory.c_str()));
}
int main() {
    Check(eSELive::GenerateBroadcasterKeypair(pub,priv));
    LabExporter tls; NodeCrypto crypto(tls);
    std::array<std::uint8_t,32> digest{},context{},exporter{},key{};
    Check(crypto.Hash(reinterpret_cast<const std::uint8_t*>("abc"),3,digest));
    const std::uint8_t expected[]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    Check(std::memcmp(digest.data(),expected,32)==0);
    std::copy_n(pub,32,key.begin()); context.fill(1); exporter.fill(2);
    auto message=AuthMessage(exporter,context,0); std::array<std::uint8_t,64> signature{};
    Check(crypto.Sign(message.data(),message.size(),signature));
    Check(crypto.Verify(key,message.data(),message.size(),signature.data()));
    for(std::size_t i=0;i<message.size();++i) {
        message[i]^=1; Check(!crypto.Verify(key,message.data(),message.size(),signature.data())); message[i]^=1;
    }
    for(std::size_t i=0;i<signature.size();++i) {
        signature[i]^=1; Check(!crypto.Verify(key,message.data(),message.size(),signature.data())); signature[i]^=1;
    }
    key[0]^=1; Check(!crypto.Verify(key,message.data(),message.size(),signature.data()));
    key[0]^=1;
    Hello local; local.node=key; local.attempt.fill(1); local.nonce.fill(2);
    local.topologyGeneration=1; local.caps=1;
    Hello remote=local; remote.role=1; remote.nonce.fill(3); remote.topologyGeneration=9;
    Session client(local,key,nullptr,true,true,100),server(remote,key,nullptr,true,true,100);
    std::optional<ese::trust::Record> known;
    Check(ese::trust::Check(known,key)==ese::trust::Match::Unknown);
    Check(!ese::trust::PrepareFirstUse(client,key,known));
    std::array<std::uint8_t,HelloSize> clientHello{},serverHello{};
    Check(client.LocalHello(clientHello) && server.LocalHello(serverHello));
    Check(client.RemoteHello(serverHello.data(),serverHello.size()) && server.RemoteHello(clientHello.data(),clientHello.size()));
    Check(!ese::trust::PrepareFirstUse(client,key,known)); // HELLO alone is insufficient.
    std::array<std::uint8_t,AuthSize> clientAuth{},serverAuth{};
    Check(client.LocalAuth(crypto,clientAuth) && server.LocalAuth(crypto,serverAuth));
    Check(client.AuthSent() && server.AuthSent());
    Check(client.RemoteAuth(crypto,serverAuth.data(),serverAuth.size()) && server.RemoteAuth(crypto,clientAuth.data(),clientAuth.size()));
    Check(client.Ready() && server.Ready() && client.BoundPeer()->topologyGeneration==9 &&
        server.BoundPeer()->topologyGeneration==1);
    for(const auto generation : {1ULL,10ULL,0xffffffffffffffffULL}) {
        auto changedHello=remote; changedHello.topologyGeneration=generation;
        std::array<std::uint8_t,HelloSize> changedWire{},ownWire{};
        Check(EncodeHello(changedHello,changedWire));
        Session changedTranscript(local,key,&key,true,true,100);
        Check(changedTranscript.LocalHello(ownWire));
        Check(changedTranscript.RemoteHello(changedWire.data(),changedWire.size()));
        std::array<std::uint8_t,AuthSize> ownAuth{};
        Check(changedTranscript.LocalAuth(crypto,ownAuth) && changedTranscript.AuthSent());
        Check(!changedTranscript.RemoteAuth(crypto,serverAuth.data(),serverAuth.size()) && !changedTranscript.Ready());
    }
    std::puts("Independent local1 remote9 generations signed binding PASS; altered remote generation rejects original AUTH (TLS exporter shim)");
    const auto prepared=ese::trust::PrepareFirstUse(client,key,known);
    Check(prepared && prepared->version==1 && prepared->kind==ese::trust::Kind::Tofu);
    known=prepared;
    Check(ese::trust::Check(known,key)==ese::trust::Match::Known);
    Check(!ese::trust::PrepareFirstUse(client,key,known));
    auto changed=key; changed[0]^=1;
    Check(ese::trust::Check(known,changed)==ese::trust::Match::Changed);
    Check(!ese::trust::PrepareFirstUse(client,changed,known) && known->node==key);
    Check(!ese::trust::PrepareFirstUse(client,changed,std::nullopt));
    Check(ese::trust::Check(known,{})==ese::trust::Match::Invalid);
    std::array<std::uint8_t,ese::trust::RecordSize> saved{};
    Check(ese::trust::Encode(*known,saved));
    ese::trust::Record loaded;
    Check(ese::trust::Decode(saved.data(),saved.size(),loaded) && loaded.node==key && loaded.version==1);
    const auto original=loaded;
    for(unsigned i=0;i<saved.size();++i) Check(!ese::trust::Decode(saved.data(),i,loaded) && loaded.node==original.node);
    Check(!ese::trust::Decode(nullptr,saved.size(),loaded));
    for(unsigned index : {0u,1u,2u,3u,5u,6u,7u}) {
        auto corrupt=saved; corrupt[index]^=1;
        Check(!ese::trust::Decode(corrupt.data(),corrupt.size(),loaded));
    }
    auto corrupt=saved; corrupt[4]=3;
    Check(!ese::trust::Decode(corrupt.data(),corrupt.size(),loaded));
    corrupt=saved; std::fill(corrupt.begin()+8,corrupt.begin()+16,std::uint8_t{0});
    Check(!ese::trust::Decode(corrupt.data(),corrupt.size(),loaded));
    corrupt=saved; std::fill(corrupt.begin()+16,corrupt.end(),std::uint8_t{0});
    Check(!ese::trust::Decode(corrupt.data(),corrupt.size(),loaded));
    TestStore(client,key);
    persistent=false; Check(!crypto.Sign(message.data(),message.size(),signature));
    Check(signature==std::array<std::uint8_t,64>{});
    std::printf("NodeCrypto/trust: %u checks PASS; actual Ed25519/SHA256 and trust disk IO; identity storage/TLS exporter shims\n",checks);
}
