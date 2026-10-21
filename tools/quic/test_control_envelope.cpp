#include "../../srchybrid/EseControlEnvelope.h"
#include "../../srchybrid/EseControlPendingRoutes.h"
#include "../../srchybrid/EseControlPacketBudget.h"
#include "../../srchybrid/EseControlBootstrap.h"
#include "../../srchybrid/EseControlCookie.h"
#include "../../srchybrid/EseControlChallengeLimit.h"
#include "../../srchybrid/EseControlSessions.h"
#include "../../srchybrid/EseReachDescriptor.h"
#include "../../srchybrid/EseDescriptorSerials.h"
#include "../../srchybrid/EseWitnessDescriptors.h"
#include "../../srchybrid/EseK6DirectSource.h"
#include <cstdio>
#include <cstdlib>
using namespace ese::control;
static unsigned checks=0;
static void Check(bool ok) { ++checks; if(!ok) { std::printf("FAIL %u\n",checks); std::exit(1); } }
int main() {
    {
        PacketBudget process;
        DescriptorGetLimit<> gets(process); ChallengeLimit challenges(process);
        std::array<std::uint8_t,32> identity{};
        ese::udp::Endpoint peer; peer.port=1;
        for(unsigned i=0;i<50;++i) {
            identity[0]=static_cast<std::uint8_t>(i+1);
            peer.address[0]=static_cast<std::uint8_t>(i+1);
            Check(gets.Allow(identity,0)); Check(challenges.Allow(peer,0));
        }
        identity[0]=99; peer.address[0]=99;
        Check(!gets.Allow(identity,0)); Check(!challenges.Allow(peer,0));
        Check(!process.Allow(999));
        Check(gets.Allow(identity,1000)); Check(challenges.Allow(peer,1000));
        // Global denials did not burn the prefix's four-token burst.
        Check(challenges.Allow(peer,1000)); Check(challenges.Allow(peer,1000));
        Check(challenges.Allow(peer,1000)); Check(!challenges.Allow(peer,1000));
        Check(gets.AllowPut(identity,1000)); Check(!gets.AllowPut(identity,1000));
        Check(!gets.Allow(identity,999)); Check(!challenges.Allow(peer,999));
    }
    {
        PacketBudget shared;
        auto& discovery=shared; auto& refresh=shared;
        for(unsigned i=0;i<50;++i) { Check(discovery.Allow(100)); Check(refresh.Allow(100)); }
        Check(!shared.Allow(100)); Check(!shared.Allow(1099));
        Check(!shared.Allow(99)); // backward clock cannot reopen capacity
        for(unsigned i=0;i<100;++i) Check(shared.Allow(1100));
        Check(!shared.Allow(1100));
        for(unsigned cycle=0;cycle<4;++cycle) {
            const auto now=2100+static_cast<std::uint64_t>(cycle)*1000;
            for(unsigned i=0;i<100;++i) Check(shared.Allow(now));
            Check(!shared.Allow(now+999));
        }
        PacketBudget staggered;
        for(unsigned i=0;i<100;++i) Check(staggered.Allow(i));
        Check(staggered.Allow(1000)); Check(!staggered.Allow(1000));
        Check(staggered.Allow(1001)); Check(!staggered.Allow(1001));
    }
    {
        PendingRoutes routes; Header request; request.type=24;
        request.attempt[0]=1; request.generation=2; request.sequence=3;
        ese::udp::Endpoint peer; peer.port=123; peer.address[0]=127;
        Check(routes.Add(request,25,peer,7,100,2100));
        Check(!routes.Add(request,25,peer,8,101,2100));
        auto reply=request; reply.type=25; Datagram packet;
        Check(Encode(reply,nullptr,0,packet)); std::uint64_t owner=0;
        Check(routes.Inspect(packet.bytes.data(),packet.size,peer,101,owner)==ese::udp::Match::Valid && owner==7);
        Check(routes.Inspect(packet.bytes.data(),packet.size,peer,102,owner)==ese::udp::Match::Valid);
        auto wrongPeer=peer; wrongPeer.port++;
        Check(routes.Inspect(packet.bytes.data(),packet.size,wrongPeer,102,owner)==ese::udp::Match::Invalid && !owner);
        Check(routes.Inspect(packet.bytes.data(),packet.size,peer,2100,owner)==ese::udp::Match::Invalid);
        Check(routes.Inspect(packet.bytes.data(),packet.size,peer,99,owner)==ese::udp::Match::Invalid);
        routes.Remove(7); Check(routes.Inspect(packet.bytes.data(),packet.size,peer,103,owner)==ese::udp::Match::Invalid);
        Check(routes.Advance(2100)); Check(!routes.Advance(2099));
        routes.Reset();
        for(unsigned i=1;i<=64;++i) { request.sequence=i; Check(routes.Add(request,25,peer,i,100,2100)); }
        request.sequence=65; Check(!routes.Add(request,25,peer,65,100,2100));
        Check(routes.Advance(2100)); Check(routes.Add(request,25,peer,65,2100,4100));
    }
    {
        PendingRoutes routes; std::array<std::uint8_t,32> local{},remote{}; local[0]=1; remote[0]=2;
        ese::udp::Endpoint endpoint; endpoint.port=123; endpoint.address[0]=127;
        Check(!routes.AddBootstrap({},remote,endpoint,1,100,2100));
        Check(!routes.AddBootstrap(local,local,endpoint,1,100,2100));
        Check(!routes.AddBootstrap(local,remote,endpoint,0,100,2100));
        Check(!routes.AddBootstrap(local,remote,endpoint,1,100,2101));
        Check(routes.AddBootstrap(local,remote,endpoint,1,100,2100));
        Check(!routes.AddBootstrap(local,remote,endpoint,2,100,2100));
        Probe probe; probe.node=remote; probe.peer=local; probe.nonce[0]=3;
        Header header; header.type=1; header.attempt[0]=4; header.generation=5; header.sequence=1;
        std::array<std::uint8_t,128> body{}; Datagram packet;
        Check(Encode(probe,body) && Encode(header,body.data(),body.size(),packet));
        std::uint64_t owner=0;
        Check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,101,owner)==ese::udp::Match::Valid && owner==1);
        for(std::size_t size=8;size<packet.size;++size)
            Check(routes.Inspect(packet.bytes.data(),size,endpoint,101,owner)==ese::udp::Match::Invalid && !owner);
        auto other=endpoint; ++other.port;
        Check(routes.Inspect(packet.bytes.data(),packet.size,other,101,owner)==ese::udp::Match::Invalid && !owner);
        auto wrong=packet; wrong.bytes[40]^=1;
        Check(routes.Inspect(wrong.bytes.data(),wrong.size,endpoint,101,owner)==ese::udp::Match::Invalid && !owner);
        wrong=packet; wrong.bytes[72]^=1;
        Check(routes.Inspect(wrong.bytes.data(),wrong.size,endpoint,101,owner)==ese::udp::Match::Invalid && !owner);
        Prove proof; proof.probe=probe; std::array<std::uint8_t,212> proveBody{};
        header.type=3; Check(Encode(proof,proveBody) && Encode(header,proveBody.data(),proveBody.size(),packet));
        // Even an all-zero cookie/signature is only routed, never authenticated.
        Check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,101,owner)==ese::udp::Match::Valid && owner==1);
        Check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,2100,owner)==ese::udp::Match::Invalid && !owner);
        routes.Remove(1); Check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,102,owner)==ese::udp::Match::Invalid);
        for(unsigned i=0;i<16;++i) { endpoint.port=static_cast<std::uint16_t>(i+1); Check(routes.AddBootstrap(local,remote,endpoint,i+1,102,2100)); }
        endpoint.port=17; Check(!routes.AddBootstrap(local,remote,endpoint,17,102,2100));
        Check(routes.Advance(2100) && routes.AddBootstrap(local,remote,endpoint,17,2100,4100));
        routes.Reset(); Check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,2100,owner)==ese::udp::Match::Invalid);
    }
    {
        std::array<std::uint8_t,40> packet{};
        std::memcpy(packet.data(),ese::wire::kEseWireControlMagic,8);
        Check(!Recognize(nullptr,40));
        for(std::size_t size=0;size<8;++size) Check(!Recognize(packet.data(),size));
        Check(Recognize(packet.data(),8)); Check(Recognize(packet.data(),40));
        Envelope invalid; Check(!ParseUntrusted(packet.data(),40,invalid));
        for(unsigned i=0;i<8;++i) {
            auto changed=packet; changed[i]^=1; Check(!Recognize(changed.data(),40));
        }
    }
    {
        using namespace ese::discovery;
        WitnessDescriptors<3> store; std::array<std::uint8_t,159> descriptor{};
        std::memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120; descriptor[29]=1;
        DirectSource source; source.node[0]=1; source.digest[0]=2; source.fileSize=123; source.generation=7; source.serial=1; source.ttl=120;
        ese::udp::Endpoint endpoint; endpoint.port=1; std::array<std::uint8_t,173> record{};
        Check(store.PutVerified(source.file,descriptor.data(),159,source.digest,endpoint,0,0)==StoreResult::Provisional);
        Check(EncodeSource(source,1000,record) && store.DirectSourceVerified(record.data(),173,1000,0)==SourceStoreResult::Stored);
        const auto oldDigest=source.digest; descriptor[24]=2; source.digest[0]=3; source.serial=2;
        Check(store.PutVerified(source.file,descriptor.data(),159,source.digest,endpoint,0,1000)==StoreResult::Provisional);
        Check(store.Get(source.file,source.node,oldDigest,1000).size==159 && !store.Get(source.file,source.node,source.digest,1000).bytes);
        FoundSources found; Check(store.Find(source.file,123,4,1000,found) && found.records[0]==record);
        Check(EncodeSource(source,1000,record)); auto wrong=record; wrong[57]^=1;
        Check(store.DirectSourceVerified(wrong.data(),173,1000,1000)==SourceStoreResult::Conflict);
        Check(store.Get(source.file,source.node,oldDigest,1000).size==159);
        Check(store.DirectSourceVerified(record.data(),173,1000,1000)==SourceStoreResult::Stored);
        Check(!store.Get(source.file,source.node,oldDigest,1000).bytes && store.Get(source.file,source.node,source.digest,1000).size==159);
        descriptor[24]=3; auto third=source.digest; third[0]=4;
        Check(store.PutVerified(source.file,descriptor.data(),159,third,endpoint,0,2000)==StoreResult::Provisional);
        Check(store.Get(source.file,source.node,source.digest,7000).size==159 && !store.Get(source.file,source.node,third,7000).bytes);
        Check(store.PutVerified(source.file,descriptor.data(),159,third,endpoint,0,7000)==StoreResult::Stale);
    }
    {
        DescriptorGetLimit<> shared; std::array<std::uint8_t,32> identity{}; identity[0]=1;
        Check(shared.AllowPut(identity,0)); Check(!shared.AllowPut(identity,999));
        for(unsigned i=0;i<4;++i) Check(shared.Allow(identity,999));
        Check(!shared.Allow(identity,999)); Check(shared.AllowPut(identity,1000));
        Check(!shared.AllowPut(identity,1999)); Check(shared.AllowPut(identity,2000));
        DescriptorGetLimit<> global;
        for(unsigned i=0;i<100;++i) {
            identity[0]=static_cast<std::uint8_t>(i+1);
            Check(i%2 ? global.AllowPut(identity,0) : global.Allow(identity,0));
        }
        identity[0]=101; Check(!global.AllowPut(identity,999) && !global.Allow(identity,999));
        Check(global.AllowPut(identity,1000));
        DescriptorGetLimit<1> one; identity[0]=1; Check(one.AllowPut(identity,0));
        identity[0]=2; Check(!one.Allow(identity,999));
        Check(one.Allow(identity,1000));
    }
    {
        using namespace ese::discovery;
        std::array<std::uint8_t,862> bytes{}; bytes[24]=123; bytes[25]=1; bytes[89]=4;
        DirectSource source; source.fileSize=123; source.generation=7; source.serial=1; source.ttl=120;
        for(unsigned i=0;i<4;++i) {
            source.node[0]=static_cast<std::uint8_t>(i+1); std::array<std::uint8_t,173> encoded{};
            Check(EncodeSource(source,1000,encoded)); std::memcpy(bytes.data()+90+177*i,encoded.data(),173);
            bytes[90+177*i+176]=119;
        }
        FindResultView result;
        Check(DecodeFindResult(bytes.data(),bytes.size(),1000,result) && result.count==4 && result.entries[3].remainingTtl==119);
        for(std::size_t n=0;n<bytes.size();++n) Check(!DecodeFindResult(bytes.data(),n,1000,result) && !result.signature);
        auto corrupt=bytes; corrupt[90+176]=121; Check(!DecodeFindResult(corrupt.data(),corrupt.size(),1000,result));
        corrupt=bytes; corrupt[90+177+25]=1; Check(!DecodeFindResult(corrupt.data(),corrupt.size(),1000,result));
        corrupt=bytes; corrupt[89]=3; Check(!DecodeFindResult(corrupt.data(),corrupt.size(),1000,result));
        bytes[0]=2; bytes[89]=0;
        Check(DecodeFindResult(bytes.data(),154,1000,result) && !result.count && result.kind==2);
        Check(!DecodeFindResult(bytes.data(),155,1000,result));
        bytes[0]=3; Check(!DecodeFindResult(bytes.data(),154,1000,result));
        bytes[0]=1; bytes[89]=1; bytes[90]=0; bytes[91]=1;
        Check(DecodeFindResult(bytes.data(),157,1000,result) && result.entries[0].size==1); // deliberately opaque; NOT a valid Kad6 record
        bytes[91]=2; Check(!DecodeFindResult(bytes.data(),157,1000,result));
        Check(!DecodeFindResult(nullptr,154,1000,result));
    }
    {
        using namespace ese::discovery;
        DirectFind query,decoded; query.requester[0]=1; query.fileSize=0x0102030405060708ULL; query.maximum=4;
        std::array<std::uint8_t,121> bytes{};
        constexpr auto maximum=(std::numeric_limits<std::uint64_t>::max)();
        Check(EncodeFind(query,maximum,bytes) && bytes[48]==1 && bytes[55]==8 && bytes[56]==4);
        Check(DecodeFind(bytes.data(),bytes.size(),maximum,decoded) && decoded.fileSize==query.fileSize);
        for(std::size_t n=0;n<121;++n) Check(!DecodeFind(bytes.data(),n,maximum,decoded) && decoded.maximum==0);
        Check(!DecodeFind(bytes.data(),122,maximum,decoded));
        Check(!DecodeFind(nullptr,121,maximum,decoded));
        Check(!DecodeFind(bytes.data(),121,query.fileSize-1,decoded));
        query.maximum=0; Check(!EncodeFind(query,maximum,bytes) && bytes==std::array<std::uint8_t,121>{});
    }
    {
        using namespace ese::discovery;
        WitnessDescriptors<2> store; std::array<std::uint8_t,159> descriptor{};
        std::memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3; descriptor[16]=7;
        descriptor[24]=1; descriptor[28]=120; descriptor[29]=1;
        DirectSource source; source.node[0]=1; source.digest[0]=2; source.generation=7;
        source.serial=1; source.fileSize=123; source.ttl=10;
        std::array<std::uint8_t,173> bytes{}; Check(EncodeSource(source,1000,bytes));
        Check(store.DirectSourceVerified(bytes.data(),bytes.size(),1000,1000)==SourceStoreResult::NeedDescriptor);
        ese::udp::Endpoint endpoint; endpoint.port=1;
        Check(store.PutVerified(source.file,descriptor.data(),descriptor.size(),source.digest,endpoint,0,1000)==StoreResult::Provisional);
        auto wrong=source; wrong.digest[1]=1; std::array<std::uint8_t,173> wrongBytes{};
        Check(EncodeSource(wrong,1000,wrongBytes));
        Check(store.DirectSourceVerified(wrongBytes.data(),wrongBytes.size(),1000,1000)==SourceStoreResult::Conflict);
        FoundSources found; Check(store.Find(source.file,123,4,1000,found) && found.count==0);
        Check(store.DirectSourceVerified(bytes.data(),bytes.size(),1000,2000)==SourceStoreResult::Stored);
        Check(store.Get(source.file,source.node,source.digest,2000).deadline==12000);
        Check(store.Find(source.file,123,4,2000,found) && found.count==1 && found.remainingTtl[0]==10 && found.records[0]==bytes);
        Check(store.DirectSourceVerified(bytes.data(),bytes.size(),1000,11999)==SourceStoreResult::Duplicate);
        Check(store.Get(source.file,source.node,source.digest,11999).deadline==12000);
        Check(store.Find(source.file,123,4,12000,found) && found.count==0);
        Check(!store.Get(source.file,source.node,source.digest,12000).bytes);
        Check(store.DirectSourceVerified(bytes.data(),bytes.size(),1000,12000)==SourceStoreResult::NeedDescriptor);
        Check(!store.Find(source.file,123,5,12000,found));
    }
    {
        using namespace ese::discovery;
        DirectSource source,decoded; source.node.fill(1); source.digest.fill(2);
        source.fileSize=0x0102030405060708ULL; source.generation=7; source.serial=9; source.ttl=120;
        std::array<std::uint8_t,173> bytes{}; constexpr auto maxFile=(std::numeric_limits<std::uint64_t>::max)();
        Check(EncodeSource(source,maxFile,bytes) && bytes[17]==1 && bytes[24]==8 && bytes[96]==7 && bytes[104]==9 && bytes[108]==120);
        Check(DecodeSource(bytes.data(),bytes.size(),maxFile,decoded) && decoded.fileSize==source.fileSize && decoded.node==source.node && decoded.serial==9);
        for(std::size_t n=0;n<173;++n) Check(!DecodeSource(bytes.data(),n,maxFile,decoded) && decoded.fileSize==0);
        Check(!DecodeSource(bytes.data(),174,maxFile,decoded));
        Check(!DecodeSource(nullptr,173,maxFile,decoded));
        Check(!DecodeSource(bytes.data(),173,source.fileSize-1,decoded));
        SourceSignatureInput input;
        Check(BuildSourceSignatureInput(bytes.data(),bytes.size(),maxFile,input) && input.bytes[sizeof(ese::wire::kEseWireK6DirectSourceDomain)-1]==0);
        auto unsignedPart=input; bytes[172]=1;
        Check(BuildSourceSignatureInput(bytes.data(),bytes.size(),maxFile,input) && input.bytes==unsignedPart.bytes);
        for(unsigned field=0;field<5;++field) {
            auto invalid=source;
            if(field==0) invalid.fileSize=0;
            if(field==1) invalid.generation=0;
            if(field==2) invalid.serial=0;
            if(field==3) invalid.ttl=121;
            if(field==4) invalid.node={};
            Check(!EncodeSource(invalid,maxFile,bytes) && bytes==std::array<std::uint8_t,173>{});
        }
    }
    {
        using namespace ese::discovery;
        WitnessDescriptors<20> store; std::array<std::uint8_t,159> bytes{};
        std::memcpy(bytes.data(),"ESD3",4); bytes[4]=3; bytes[16]=7; bytes[24]=1; bytes[28]=120; bytes[29]=1;
        std::array<std::uint8_t,16> file{}; std::array<std::uint8_t,32> node{},digest{}; node[0]=1; digest[0]=2;
        ese::udp::Endpoint source; source.port=1; source.address[0]=10;
        const auto baseline=store.ChargedBytes();
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,0,1000)==StoreResult::Provisional);
        Check(store.ChargedBytes()>baseline && !store.Get(file,node,digest,1000).bytes);
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,1000)==StoreResult::Duplicate && !store.Get(file,node,digest,1000).bytes);
        Check(store.SourceVerified(file,node,10,5999));
        auto found=store.Get(file,node,digest,5999);
        Check(found.size==159 && found.deadline==15999 && !std::memcmp(found.bytes,bytes.data(),159));
        Check(!store.Get(file,node,digest,15999).bytes && store.ChargedBytes()==baseline);
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,16000)==StoreResult::Stale);
        bytes[24]=2; digest[0]=3;
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,5,16000)==StoreResult::Stored);
        Check(store.Get(file,node,digest,16000).deadline==21000);
        auto conflict=digest; conflict[1]=1;
        Check(store.PutVerified(file,bytes.data(),bytes.size(),conflict,source,5,16000)==StoreResult::Conflict);
        Check(!store.Get(file,node,digest,15999).bytes);
        file[0]=1;
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,0,16000)==StoreResult::Provisional);
        file[0]=2;
        Check(store.PutVerified(file,bytes.data(),bytes.size(),digest,source,0,16000)==StoreResult::Limit);
        file[0]=1; Check(!store.SourceVerified(file,node,10,21000));
        Check(!store.Get(file,node,digest,21000).bytes);
        WitnessDescriptors<20> quota;
        file={}; bytes[24]=1; digest[0]=2;
        for(unsigned i=0;i<8;++i) {
            file[0]=static_cast<std::uint8_t>(i);
            Check(quota.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        }
        file[0]=8; Check(quota.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Limit);
        file[0]=0; bytes[24]=2; digest[0]=3;
        Check(quota.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        Check(quota.Get(file,node,digest,0).size==159);
        WitnessDescriptors<20> prefixes; file={}; bytes[24]=1;
        for(unsigned i=0;i<16;++i) {
            bytes[29]=static_cast<std::uint8_t>(i+1);
            Check(prefixes.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        }
        bytes[29]=17;
        Check(prefixes.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Limit);
        source.address[2]=1;
        Check(prefixes.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        WitnessDescriptors<1> full; bytes[29]=1; node[0]=1;
        Check(full.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        auto otherFile=file; otherFile[0]=1;
        Check(full.PutVerified(otherFile,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Limit);
        Check(full.Get(file,node,digest,0).size==159);
        WitnessDescriptors<1,1> tooSmall;
        Check(tooSmall.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Limit);
        WitnessDescriptors<1,sizeof(WitnessDescriptors<1>)+159> atomic;
        Check(atomic.PutVerified(file,bytes.data(),bytes.size(),digest,source,120,0)==StoreResult::Stored);
        std::array<std::uint8_t,187> larger{};
        std::memcpy(larger.data(),bytes.data(),95); larger[24]=2; larger[93]=1;
        larger[95]=2; larger[96]=4; larger[97]=4; larger[116]=1; larger[122]=60;
        auto newerDigest=digest; newerDigest[0]^=1;
        Check(atomic.PutVerified(file,larger.data(),larger.size(),newerDigest,source,120,0)==StoreResult::Limit);
        Check(atomic.Get(file,node,digest,0).size==159 && !atomic.Get(file,node,newerDigest,0).bytes);
    }
    {
        DescriptorGetLimit<> limit; std::array<std::uint8_t,32> key{};
        Check(!limit.Allow(key,900000)); key[0]=1;
        for(unsigned i=0;i<4;++i) Check(limit.Allow(key,100));
        Check(!limit.Allow(key,100) && !limit.Allow(key,1099));
        Check(limit.Allow(key,1100));
        Check(!limit.Allow(key,1099));
        DescriptorGetLimit<> global;
        for(unsigned i=0;i<100;++i) { key[0]=static_cast<std::uint8_t>(i+1); Check(global.Allow(key,0)); }
        key[0]=101; Check(!global.Allow(key,0) && !global.Allow(key,999));
        Check(global.Allow(key,1000));
        DescriptorGetLimit<1> bounded; key[0]=1; Check(bounded.Allow(key,0));
        key[0]=2; Check(!bounded.Allow(key,999));
        key[0]=1; Check(bounded.Allow(key,999)); // original identity not evicted
        key[0]=2; Check(!bounded.Allow(key,1000)); // newest original request still live
        Check(bounded.Allow(key,1999));
        DescriptorGetLimit<> staggered; key[0]=1;
        for(const auto now : {0,250,500,750}) Check(staggered.Allow(key,static_cast<std::uint64_t>(now)));
        Check(!staggered.Allow(key,999)); Check(staggered.Allow(key,1000));
        Check(!staggered.Allow(key,1001)); Check(staggered.Allow(key,1250));
    }
    {
        using namespace ese::discovery;
        std::array<std::uint8_t,1115> result{};
        result[81]=0; result[82]=159;
        auto* descriptor=result.data()+83;
        std::memcpy(descriptor,"ESD3",4); descriptor[4]=3; descriptor[28]=120;
        ResultView view;
        Check(DecodeResult(result.data(),306,view) && view.length==159 && view.signature==result.data()+242);
        for(std::size_t n=0;n<306;++n) Check(!DecodeResult(result.data(),n,view) && !view.signature);
        Check(!DecodeResult(result.data(),307,view));
        result[0]=1; Check(!DecodeResult(result.data(),306,view));
        result[82]=0;
        Check(DecodeResult(result.data(),147,view) && view.status==1 && !view.descriptor && view.length==0);
        result[0]=2; Check(DecodeResult(result.data(),147,view));
        result[0]=3; Check(!DecodeResult(result.data(),147,view));
        result[0]=0; Check(!DecodeResult(result.data(),147,view));
        std::array<std::uint8_t,1050> put{}; put[17]=159;
        std::memcpy(put.data()+18,descriptor,159); PutView publication;
        Check(DecodePut(put.data(),241,publication) && publication.length==159 && publication.signature==put.data()+177);
        for(std::size_t n=0;n<241;++n) Check(!DecodePut(put.data(),n,publication) && !publication.signature);
        Check(!DecodePut(put.data(),242,publication));
        GetView query; std::array<std::uint8_t,144> get{};
        Check(DecodeGet(get.data(),144,query) && query.signature==get.data()+80);
        for(std::size_t n=0;n<144;++n) Check(!DecodeGet(get.data(),n,query));
        Check(!DecodeGet(nullptr,144,query) && !DecodePut(nullptr,241,publication) && !DecodeResult(nullptr,147,view));
        result={}; result[82]=0xc8; result[81]=3; // 968 bytes
        descriptor=result.data()+83; std::memcpy(descriptor,"ESD3",4);
        descriptor[4]=3; descriptor[28]=120; descriptor[93]=8; descriptor[94]=3;
        for(unsigned i=0;i<8;++i) {
            auto* candidate=descriptor+95+28*i;
            candidate[0]=2; candidate[1]=4; candidate[2]=4; candidate[21]=1; candidate[27]=60;
        }
        for(unsigned i=0;i<3;++i) {
            auto* reservation=descriptor+95+8*28+195*i;
            reservation[0]=4; reservation[18]=1;
        }
        Check(DecodeResult(result.data(),result.size(),view) && view.length==968);
        Header header; header.type=ese::wire::kEseWireUdpDescriptorResult; Datagram datagram;
        Check(Encode(header,result.data(),result.size(),datagram) && datagram.size==1155 && datagram.size<=1200);
        put={}; put[16]=3; put[17]=0xc8; std::memcpy(put.data()+18,descriptor,968);
        Check(DecodePut(put.data(),put.size(),publication) && publication.length==968);
        header.type=ese::wire::kEseWireUdpDescriptorPut;
        Check(Encode(header,put.data(),put.size(),datagram) && datagram.size==1090);
    }
    {
        using namespace ese::discovery;
        Locator locator,decoded; locator.node.fill(0x31); locator.digest.fill(0xa2);
        locator.serial=0x0102030405060708ULL; locator.ttl=120;
        std::array<std::uint8_t,77> bytes{};
        Check(EncodeLocator(locator,bytes) && bytes[0]==1 && bytes[65]==1 && bytes[72]==8 && bytes[73]==0 && bytes[76]==120);
        Check(DecodeLocator(bytes.data(),bytes.size(),decoded) && decoded.node==locator.node && decoded.digest==locator.digest && decoded.serial==locator.serial && decoded.ttl==120);
        for(std::size_t n=0;n<77;++n) Check(!DecodeLocator(bytes.data(),n,decoded) && decoded.ttl==0 && decoded.node==std::array<std::uint8_t,32>{});
        Check(!DecodeLocator(bytes.data(),78,decoded));
        Check(!DecodeLocator(nullptr,77,decoded));
        bytes[0]=2; Check(!DecodeLocator(bytes.data(),77,decoded)); bytes[0]=1;
        bytes[76]=0; Check(!DecodeLocator(bytes.data(),77,decoded));
        bytes[76]=121; Check(!DecodeLocator(bytes.data(),77,decoded));
        locator.ttl=0; Check(!EncodeLocator(locator,bytes) && bytes==std::array<std::uint8_t,77>{});
        locator.ttl=121; Check(!EncodeLocator(locator,bytes));
    }
    {
        using namespace ese::discovery;
        DescriptorSerials<2> serials; DescriptorView descriptor;
        descriptor.node.fill(1); descriptor.generation=7; descriptor.serial=10; descriptor.ttl=120;
        std::array<std::uint8_t,32> digest{}; digest.fill(2); std::uint64_t deadline=0;
        Check(serials.AcceptVerified(descriptor,digest,10,1000,deadline)==SerialResult::Accepted && deadline==11000);
        Check(serials.AcceptVerified(descriptor,digest,120,10999,deadline)==SerialResult::Duplicate && deadline==11000);
        Check(serials.AcceptVerified(descriptor,digest,120,11000,deadline)==SerialResult::Expired && deadline==0);
        --descriptor.serial; Check(serials.AcceptVerified(descriptor,digest,120,11000,deadline)==SerialResult::Stale);
        ++descriptor.serial; auto wrong=digest; wrong[0]^=1;
        Check(serials.AcceptVerified(descriptor,wrong,120,11000,deadline)==SerialResult::Conflict);
        ++descriptor.serial; Check(serials.AcceptVerified(descriptor,wrong,120,11000,deadline)==SerialResult::Accepted && deadline==131000);
        Check(serials.AcceptVerified(descriptor,wrong,120,10999,deadline)==SerialResult::Invalid);
        ++descriptor.generation; descriptor.serial=0;
        Check(serials.AcceptVerified(descriptor,digest,1,11000,deadline)==SerialResult::Accepted && deadline==12000);
        ++descriptor.generation; Check(serials.AcceptVerified(descriptor,digest,1,11000,deadline)==SerialResult::Full);
        descriptor.generation=7; descriptor.serial=9;
        Check(serials.AcceptVerified(descriptor,digest,1,200000,deadline)==SerialResult::Stale); // expiry did not erase watermark
        DescriptorSerials<1> overflow;
        Check(overflow.AcceptVerified(descriptor,digest,1,UINT64_MAX,deadline)==SerialResult::Invalid && deadline==0);
    }
    {
        std::array<std::uint8_t,968> packet{};
        packet[0]='E'; packet[1]='S'; packet[2]='D'; packet[3]='3'; packet[4]=3;
        packet[5]=0x80; packet[8]=1; packet[16]=7; packet[24]=9; packet[28]=120;
        packet[29]=1; packet[93]=8; packet[94]=3;
        for(unsigned i=0;i<8;++i) {
            auto* candidate=packet.data()+95+28*i;
            candidate[0]=2; candidate[1]=4; candidate[2]=4; candidate[3]=3;
            candidate[4]=203; candidate[6]=113; candidate[7]=1;
            candidate[20]=0x12; candidate[21]=0x34; candidate[27]=60;
        }
        for(unsigned i=0;i<3;++i) {
            auto* reservation=packet.data()+95+224+195*i;
            reservation[0]=4; reservation[1]=203; reservation[3]=113; reservation[4]=1;
            reservation[17]=0x12; reservation[18]=0x34;
        }
        ese::discovery::DescriptorView descriptor;
        for(std::size_t size=0;size<=968;++size) Check(ese::discovery::ParseUntrusted(packet.data(),size,descriptor)==(size==968));
        Check(descriptor.caps==0x80000001 && descriptor.generation==7 && descriptor.serial==9 && descriptor.ttl==120);
        Check(descriptor.candidates==8 && descriptor.reservations==3 && descriptor.signature==packet.data()+904);
        ese::discovery::DescriptorSignatureInput signature;
        Check(ese::discovery::BuildSignatureInput(packet.data(),packet.size(),signature) && signature.size==signature.bytes.size());
        const char domain[]="ESE-REACH/3";
        Check(std::memcmp(signature.bytes.data(),domain,sizeof(domain))==0 && std::memcmp(signature.bytes.data()+sizeof(domain),packet.data(),904)==0);
        const auto original=signature;
        packet.back()^=1;
        Check(ese::discovery::BuildSignatureInput(packet.data(),packet.size(),signature) && signature.bytes==original.bytes);
        for(const auto offset : {4U,93U,94U,95U+1,95U+2,95U+3,95U+22,95U+23,95U+24}) {
            auto changed=packet; changed[offset]=255;
            Check(!ese::discovery::ParseUntrusted(changed.data(),changed.size(),descriptor) && descriptor.signature==nullptr);
        }
        auto wrongFamily=packet; wrongFamily[95]=1;
        Check(!ese::discovery::ParseUntrusted(wrongFamily.data(),wrongFamily.size(),descriptor));
        auto zeroTtl=packet; zeroTtl[95+27]=0;
        Check(!ese::discovery::ParseUntrusted(zeroTtl.data(),zeroTtl.size(),descriptor));
        packet[28]=0; Check(!ese::discovery::ParseUntrusted(packet.data(),packet.size(),descriptor));
        packet[28]=121; Check(!ese::discovery::ParseUntrusted(packet.data(),packet.size(),descriptor));
        Check(!ese::discovery::ParseUntrusted(packet.data(),969,descriptor));
        Check(!ese::discovery::ParseUntrusted(nullptr,968,descriptor));
        packet[28]=1; packet[93]=packet[94]=0;
        Check(ese::discovery::ParseUntrusted(packet.data(),159,descriptor) && descriptor.candidates==0 && descriptor.reservations==0);
    }
    {
        PendingBootstrapChallenge pending;
        Header request; request.type=ese::wire::kEseWireUdpProbe;
        request.attempt.fill(3); request.generation=4; request.sequence=5;
        Probe probe; probe.node.fill(1); probe.peer.fill(2); probe.nonce.fill(3); probe.mask=4;
        Challenge challenge; challenge.nonce=probe.nonce; challenge.cookie.fill(7); challenge.epoch=2;
        Prove proof; proof.probe=probe; proof.cookie=challenge.cookie; proof.epoch=challenge.epoch;
        auto reply=request; reply.type=ese::wire::kEseWireUdpProve;
        Check(!pending.Matches(reply,proof,32000));
        Check(pending.Remember(request,probe,challenge,32000,34000));
        Check(pending.Issued()==32000 && pending.Matches(reply,proof,32000));
        Check(pending.Matches(reply,proof,33999) && !pending.Matches(reply,proof,34000));
        Check(!pending.Matches(reply,proof,31999));
        for(unsigned field=0;field<10;++field) {
            auto changed=proof; auto context=reply;
            switch(field) {
            case 0: ++context.sequence; break;
            case 1: ++context.generation; break;
            case 2: context.attempt[0]^=1; break;
            case 3: changed.probe.node[0]^=1; break;
            case 4: changed.probe.peer[0]^=1; break;
            case 5: changed.probe.nonce[0]^=1; break;
            case 6: changed.probe.mask=2; break;
            case 7: changed.probe.padding[0]^=1; break;
            case 8: changed.cookie[0]^=1; break;
            case 9: --changed.epoch; break;
            }
            Check(!pending.Matches(context,changed,32001));
        }
        Check(!pending.Remember(request,probe,challenge,32000,34001));
        Check(pending.Matches(reply,proof,32001)); // invalid replacement preserves pending challenge
        auto next=challenge; next.cookie[0]^=1; ++request.sequence;
        Check(pending.Remember(request,probe,next,32001,34000));
        Check(!pending.Matches(reply,proof,32002));
        pending.Clear(); Check(!pending.Matches(reply,proof,32002));
    }
    Sessions sessions;
    std::array<std::uint8_t,32> sessionPeer{},digest{}; sessionPeer.fill(1); digest.fill(2);
    ese::udp::Endpoint sessionEndpoint; sessionEndpoint.port=1;
    Header sessionHeader; sessionHeader.attempt.fill(3); sessionHeader.generation=4; sessionHeader.sequence=5;
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,0)==Admission::Accepted);
    Check(sessions.Current(sessionPeer,sessionEndpoint,sessionHeader,1));
    Check(sessions.Current(sessionPeer,sessionEndpoint,sessionHeader,29999));
    Check(!sessions.Current(sessionPeer,sessionEndpoint,sessionHeader,30000));
    auto absentSessionEndpoint=sessionEndpoint; ++absentSessionEndpoint.port;
    Check(!sessions.Current(sessionPeer,absentSessionEndpoint,sessionHeader,1));
    auto absentSessionHeader=sessionHeader; ++absentSessionHeader.generation;
    Check(!sessions.Current(sessionPeer,sessionEndpoint,absentSessionHeader,1));
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,29999)==Admission::Duplicate);
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,30000)==Admission::Rejected);
    ++sessionHeader.sequence; Check(!sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,30000));
    --sessionHeader.sequence;
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,63999)==Admission::Rejected);
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,64000)==Admission::Accepted);
    auto conflicting=digest; conflicting[0]^=1;
    Check(sessions.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,conflicting,64000)==Admission::Rejected);
    auto wrongEndpoint=sessionEndpoint; ++wrongEndpoint.port;
    Check(sessions.AdmitVerified(sessionPeer,wrongEndpoint,sessionHeader,digest,64000)==Admission::Rejected);
    ++sessionHeader.sequence;
    Check(sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,65000));
    Check(!sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,65000));
    ++sessionHeader.sequence; Check(!sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,64999));
    Check(sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,94999));
    ++sessionHeader.sequence; Check(!sessions.ObserveVerified(sessionPeer,sessionEndpoint,sessionHeader,124999));
    // Recovery sequence allocation must not silently renew the idle lease.
    // These boundary cases expose why the owning download needs a separate
    // fresh-bootstrap path after expiry, not a relaxation of Current().
    for(const auto elapsed : {29999ULL,30000ULL,63999ULL,64000ULL}) {
        Sessions recovery;
        Header original; original.attempt.fill(3); original.generation=4; original.sequence=5;
        Check(recovery.AdmitVerified(sessionPeer,sessionEndpoint,original,digest,1000)==Admission::Accepted);
        Header reserved=original;
        const bool allocated=recovery.NextBootstrap(sessionPeer,sessionEndpoint,reserved,1000+elapsed,reserved);
        Check(allocated==(elapsed<30000));
        if(allocated) Check(reserved.sequence==6);
        else Check(reserved.sequence==0); // failure clears output, including alias
        Check(!recovery.Current(sessionPeer,sessionEndpoint,original,31000));
    }
    {
        Sessions recovery;
        Header original; original.attempt.fill(3); original.generation=4; original.sequence=5;
        Check(recovery.AdmitVerified(sessionPeer,sessionEndpoint,original,digest,1000)==Admission::Accepted);
        Header reserved=original;
        Check(recovery.NextBootstrap(sessionPeer,sessionEndpoint,reserved,30999,reserved));
        auto freshDigest=digest; freshDigest[0]^=1;
        Check(recovery.ReadmitVerified(sessionPeer,sessionEndpoint,reserved,freshDigest,31000)==Admission::Rejected);
        Check(!recovery.Current(sessionPeer,sessionEndpoint,original,31000));
    }
    {
        Sessions expired;
        Header initial; initial.attempt.fill(3); initial.generation=4; initial.sequence=5;
        Check(expired.AdmitVerified(sessionPeer,sessionEndpoint,initial,digest,1000)==Admission::Accepted);
        auto fresh=initial; ++fresh.sequence;
        auto freshDigest=digest; freshDigest[0]^=1;
        Check(!expired.Current(sessionPeer,sessionEndpoint,initial,31000));
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,1000,31000)==Admission::Rejected);
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,31001,31000)==Admission::Rejected);
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,29000,31000)==Admission::Rejected);
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,initial,freshDigest,31000,31000)==Admission::Rejected);
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,digest,31000,31000)==Admission::Rejected);
        auto badEndpoint=sessionEndpoint; ++badEndpoint.port;
        Check(expired.ReadmitFreshVerified(sessionPeer,badEndpoint,fresh,freshDigest,31000,31000)==Admission::Rejected);
        auto bad=fresh; ++bad.generation;
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,bad,freshDigest,31000,31000)==Admission::Rejected);
        bad=fresh; bad.attempt[0]^=1;
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,bad,freshDigest,31000,31000)==Admission::Rejected);
        Check(!expired.Current(sessionPeer,sessionEndpoint,initial,31000));
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,31000,31000)==Admission::Accepted);
        Check(expired.Current(sessionPeer,sessionEndpoint,fresh,31000));
        Check(!expired.Current(sessionPeer,sessionEndpoint,initial,31000));
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,31000,31001)==Admission::Rejected);
        Check(!expired.Current(sessionPeer,sessionEndpoint,fresh,61000));
        Sessions missing;
        Check(missing.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,31000,31000)==Admission::Rejected);
    }
    {
        Sessions expired;
        Header initial; initial.attempt.fill(3); initial.generation=4; initial.sequence=5;
        Check(expired.AdmitVerified(sessionPeer,sessionEndpoint,initial,digest,1000)==Admission::Accepted);
        Header reserved=initial;
        Check(!expired.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,30999,reserved) && reserved.sequence==0);
        reserved=initial;
        Check(expired.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,31000,reserved) && reserved.sequence==6);
        Check(!expired.Current(sessionPeer,sessionEndpoint,reserved,31000));
        Header newer=initial;
        Check(expired.NextExpiredBootstrap(sessionPeer,sessionEndpoint,newer,31001,newer) && newer.sequence==7);
        auto freshDigest=digest; freshDigest[0]^=1;
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,reserved,freshDigest,31000,31001)==Admission::Rejected);
        Check(expired.ReadmitFreshVerified(sessionPeer,sessionEndpoint,newer,freshDigest,31001,31001)==Admission::Accepted);
        Check(expired.Current(sessionPeer,sessionEndpoint,newer,31001));
        Sessions missing;
        reserved=initial;
        Check(!missing.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,64000,reserved) && reserved.sequence==0);
        Sessions exhausted;
        initial.sequence=UINT32_MAX;
        Check(exhausted.AdmitVerified(sessionPeer,sessionEndpoint,initial,digest,1000)==Admission::Accepted);
        reserved=initial;
        Check(!exhausted.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,31000,reserved) && reserved.sequence==0);
    }
    {
        Sessions retained;
        Header initial; initial.attempt.fill(3); initial.generation=4; initial.sequence=5;
        Check(retained.AdmitVerified(sessionPeer,sessionEndpoint,initial,digest,1000)==Admission::Accepted);
        Check(!retained.RetainDownload(sessionPeer,sessionEndpoint,initial,0,1000));
        Check(retained.RetainDownload(sessionPeer,sessionEndpoint,initial,17,1000));
        Check(retained.RetainDownload(sessionPeer,sessionEndpoint,initial,17,1001));
        Check(!retained.RetainDownload(sessionPeer,sessionEndpoint,initial,18,1001));
        Check(!retained.Current(sessionPeer,sessionEndpoint,initial,31000));
        auto fresh=initial; ++fresh.sequence;
        auto freshDigest=digest; freshDigest[0]^=1;
        Check(retained.AdmitVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,1000000)==Admission::Rejected);
        Check(!retained.Current(sessionPeer,sessionEndpoint,initial,1000000));
        Check(retained.NextExpiredBootstrap(sessionPeer,sessionEndpoint,initial,1000000,fresh) && fresh.sequence==6);
        Check(retained.ReadmitFreshVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,1000000,1000000)==Admission::Accepted);
        retained.ReleaseDownload(18); // unrelated owner cannot unretain
        Check(retained.AdmitVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,1064000)==Admission::Rejected);
        retained.ReleaseDownload(17);
        Check(retained.AdmitVerified(sessionPeer,sessionEndpoint,fresh,freshDigest,1064000)==Admission::Accepted);
    }
    {
        Sessions retainedFull;
        Header entry; entry.attempt.fill(3); entry.generation=4; entry.sequence=5;
        for(unsigned i=0;i<256;++i) {
            entry.attempt[0]=static_cast<std::uint8_t>(i);
            Check(retainedFull.AdmitVerified(sessionPeer,sessionEndpoint,entry,digest,1000)==Admission::Accepted);
            Check(retainedFull.RetainDownload(sessionPeer,sessionEndpoint,entry,i+1,1000));
        }
        auto extra=entry; extra.attempt[1]^=1;
        Check(retainedFull.AdmitVerified(sessionPeer,sessionEndpoint,extra,digest,1000000)==Admission::Full);
        entry.attempt[0]=0; Header reserved=entry;
        Check(retainedFull.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,1000000,reserved) && reserved.sequence==6);
        Check(!retainedFull.Current(sessionPeer,sessionEndpoint,entry,1000000));
        retainedFull.ReleaseDownload(1);
        Check(retainedFull.AdmitVerified(sessionPeer,sessionEndpoint,extra,digest,1000000)==Admission::Accepted);
        entry.attempt[0]=1; reserved=entry;
        Check(retainedFull.NextExpiredBootstrap(sessionPeer,sessionEndpoint,reserved,1000000,reserved) && reserved.sequence==6);
    }
    Sessions full;
    for(unsigned i=0;i<256;++i) { sessionHeader.attempt[0]=static_cast<std::uint8_t>(i); Check(full.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,0)==Admission::Accepted); }
    sessionHeader.attempt[1]^=1;
    Check(full.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,0)==Admission::Full);
    Check(full.AdmitVerified(sessionPeer,sessionEndpoint,sessionHeader,digest,64000)==Admission::Accepted);
    ChallengeLimit limit;
    ese::udp::Endpoint limited; limited.address[0]=203; limited.address[2]=113; limited.port=1;
    for(unsigned i=0;i<4;++i) Check(limit.Allow(limited,0));
    Check(!limit.Allow(limited,0));
    ++limited.address[3]; ++limited.port; Check(!limit.Allow(limited,499)); // same /24
    Check(limit.Allow(limited,500) && !limit.Allow(limited,500));
    Check(!limit.Allow(limited,499)); // rollback must not refill
    Check(limit.Allow(limited,1000));
    ChallengeLimit v6limit; limited.ipv6=true;
    for(unsigned i=0;i<4;++i) Check(v6limit.Allow(limited,10));
    ++limited.address[15]; Check(!v6limit.Allow(limited,10)); // same /64
    ++limited.address[7]; Check(v6limit.Allow(limited,10)); // different /64
    ChallengeLimit processLimit; limited={}; limited.port=1;
    for(unsigned i=0;i<100;++i) { limited.address[0]=static_cast<std::uint8_t>(i); Check(processLimit.Allow(limited,0)); }
    limited.address[0]=100;
    Check(!processLimit.Allow(limited,0) && !processLimit.Allow(limited,999));
    Check(processLimit.Allow(limited,1000));
    for(unsigned i=0;i<99;++i) { limited.address[0]=static_cast<std::uint8_t>(i); Check(processLimit.Allow(limited,1000)); }
    Check(!processLimit.Allow(limited,1000));
    Check(processLimit.Allow(limited,3000)); // bounded prefix expiry
    limited.port=0; Check(!processLimit.Allow(limited,3000));
    CookieProof proof; proof.attempt.fill(1); proof.generation=0x0102030405060708ULL;
    proof.nonce.fill(2); proof.cookie.fill(3); proof.epoch=0x91a2b3c4;
    std::array<std::uint8_t,76> proofBytes; Encode(proof,proofBytes);
    CookieProof parsedProof;
    for(std::size_t n=0;n<78;++n) Check(Decode(proofBytes.data(),n,parsedProof)==(n==76));
    Check(Decode(proofBytes.data(),76,parsedProof) && parsedProof.generation==proof.generation &&
        parsedProof.epoch==proof.epoch && parsedProof.cookie==proof.cookie && parsedProof.nonce==proof.nonce);
    ese::udp::Endpoint endpoint; endpoint.address[0]=203; endpoint.address[1]=0; endpoint.address[2]=113; endpoint.address[3]=8; endpoint.port=0x1234;
    std::array<std::uint8_t,32> signer{}; signer.fill(4); CookieInput cookieInput;
    Check(BuildCookieInput(endpoint,proof,signer,cookieInput));
    const std::uint8_t cookieDomain[]={'E','S','E','-','C','O','O','K','I','E','/','1',0};
    // Domain is 13 bytes including NUL: all subsequent offsets are exact.
    Check(std::memcmp(cookieInput.bytes.data(),cookieDomain,sizeof(cookieDomain))==0);
    Check(cookieInput.bytes[13]==4 && cookieInput.bytes[30]==0x12 && cookieInput.bytes[31]==0x34);
    const auto original=cookieInput;
    ++endpoint.port; Check(BuildCookieInput(endpoint,proof,signer,cookieInput) && cookieInput.bytes!=original.bytes);
    endpoint.port=0; Check(!BuildCookieInput(endpoint,proof,signer,cookieInput));
    endpoint.port=0x1234; endpoint.address[15]=1; Check(!BuildCookieInput(endpoint,proof,signer,cookieInput));
    endpoint.ipv6=true; Check(BuildCookieInput(endpoint,proof,signer,cookieInput) && cookieInput.bytes[13]==6);
    std::uint32_t epoch=99;
    Check(CurrentEpoch(15999,epoch) && epoch==0 && AcceptEpoch(0,0) && !AcceptEpoch(UINT32_MAX,0));
    Check(CurrentEpoch(16000,epoch) && epoch==1 && AcceptEpoch(0,1) && AcceptEpoch(1,1) && !AcceptEpoch(2,1));
    Check(CurrentEpoch(static_cast<std::uint64_t>(UINT32_MAX)*16000,epoch) && epoch==UINT32_MAX);
    Check(!CurrentEpoch((static_cast<std::uint64_t>(UINT32_MAX)+1)*16000,epoch));
    Check(EqualCookie(proof.cookie,proof.cookie));
    for(unsigned i=0;i<16;++i) { auto wrong=proof.cookie; wrong[i]^=1; Check(!EqualCookie(proof.cookie,wrong)); }
    Probe probe; probe.node.fill(1); probe.peer.fill(2); probe.nonce.fill(3); probe.padding.fill(4);
    Prove prove; prove.probe=probe; prove.cookie.fill(5); prove.epoch=0x01020304; prove.signature.fill(6);
    Challenge challenge; challenge.nonce=probe.nonce; challenge.cookie=prove.cookie; challenge.epoch=prove.epoch;
    Ack ack; ack.nonce=probe.nonce; ack.signature=prove.signature;
    std::array<std::uint8_t,128> probeBytes; std::array<std::uint8_t,212> proveBytes;
    std::array<std::uint8_t,52> challengeBytes; std::array<std::uint8_t,97> ackBytes;
    Check(Encode(probe,probeBytes) && Encode(prove,proveBytes) && Encode(challenge,challengeBytes) && Encode(ack,ackBytes));
    Check(proveBytes[144]==1 && proveBytes[145]==2 && proveBytes[146]==3 && proveBytes[147]==4);
    Check(challengeBytes[48]==1 && challengeBytes[49]==2 && challengeBytes[50]==3 && challengeBytes[51]==4);
    Check(std::memcmp(proveBytes.data(),probeBytes.data(),128)==0);
    Probe decodedProbe; Prove decodedProve; Challenge decodedChallenge; Ack decodedAck;
    Check(Decode(proveBytes.data(),212,decodedProve) && decodedProve.cookie==prove.cookie && decodedProve.epoch==prove.epoch && decodedProve.signature==prove.signature);
    Check(Decode(challengeBytes.data(),52,decodedChallenge) && decodedChallenge.nonce==challenge.nonce && decodedChallenge.cookie==challenge.cookie && decodedChallenge.epoch==challenge.epoch);
    for(std::size_t n=0;n<=213;++n) {
        Check(Decode(probeBytes.data(),n,decodedProbe)==(n==128));
        Check(Decode(proveBytes.data(),n,decodedProve)==(n==212));
        Check(Decode(challengeBytes.data(),n,decodedChallenge)==(n==52));
        Check(Decode(ackBytes.data(),n,decodedAck)==(n==97));
    }
    for(unsigned value=0;value<256;++value) {
        probe.mask=static_cast<std::uint8_t>(value); ack.selected=static_cast<std::uint8_t>(value);
        Check(Encode(probe,probeBytes)==(value<8));
        probeBytes[96]=probe.mask; Check(Decode(probeBytes.data(),128,decodedProbe)==(value<8));
        const bool valid=value==0 || value==2 || value==4;
        Check(Encode(ack,ackBytes)==valid); ackBytes[32]=ack.selected;
        Check(Decode(ackBytes.data(),97,decodedAck)==valid);
        if(!valid) Check(decodedAck.selected==0 && decodedAck.signature==std::array<std::uint8_t,64>{});
    }
    Check(!Decode(nullptr,128,decodedProbe) && !Decode(nullptr,212,decodedProve) &&
        !Decode(nullptr,52,decodedChallenge) && !Decode(nullptr,97,decodedAck));
    Header header; header.type=1; header.generation=0x0102030405060708ULL; header.sequence=0x91a2b3c4;
    for(unsigned i=0;i<16;++i) header.attempt[i]=static_cast<std::uint8_t>(i);
    const std::uint8_t payload[]={0x80,0,0xff}; Datagram encoded; Envelope view;
    const std::uint8_t golden[]={0,0x45,0x53,0x45,0x43,0x54,0x4c,0x31,1,1,0,3,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1,2,3,4,5,6,7,8,0x91,0xa2,0xb3,0xc4,0x80,0,0xff};
    Check(Encode(header,payload,3,encoded) && encoded.size==sizeof(golden));
    Check(std::memcmp(encoded.bytes.data(),golden,sizeof(golden))==0);
    Check(ParseUntrusted(golden,sizeof(golden),view));
    Check(view.header.generation==header.generation && view.header.sequence==header.sequence && view.header.attempt==header.attempt);
    Check(view.payloadSize==3 && std::memcmp(view.payload,payload,3)==0);
    for(std::size_t n=0;n<sizeof(golden);++n) {
        Check(!ParseUntrusted(golden,n,view)); Check(view.payload==nullptr && view.payloadSize==0 && view.header.type==0);
    }
    for(unsigned offset=0;offset<12;++offset) {
        auto bad=encoded; bad.bytes[offset]^=0x80;
        Check(!ParseUntrusted(bad.bytes.data(),bad.size,view));
    }
    auto trailing=encoded; ++trailing.size;
    Check(!ParseUntrusted(trailing.bytes.data(),trailing.size,view));
    Check(!ParseUntrusted(nullptr,43,view));
    std::array<std::uint8_t,1161> body{};
    for(unsigned type=1;type<=25;++type) {
        header.type=static_cast<std::uint8_t>(type);
        for(const auto length : {std::size_t(0),std::size_t(64),std::size_t(1160)}) {
            Check(Encode(header,body.data(),length,encoded));
            Check(ParseUntrusted(encoded.bytes.data(),encoded.size,view) && view.header.type==type && view.payloadSize==length);
            Check(Encode(header,view.payload,view.payloadSize,encoded)); // alias-safe
        }
    }
    Check(!Encode(header,body.data(),1161,encoded) && encoded.size==0);
    Check(!ParseUntrusted(body.data(),1201,view)); // bound check before dereference
    Check(!Encode(header,nullptr,1,encoded));
    SignatureInput input;
    header.type=3;
    body.fill(0x7b);
    Check(Encode(header,body.data(),67,encoded));
    Check(BuildSignatureInput(encoded.bytes.data(),encoded.size,input) && input.size==54);
    const std::uint8_t domain[]={'E','S','E','-','C','T','R','L','/','1',0};
    Check(std::memcmp(input.bytes.data(),domain,sizeof(domain))==0);
    Check(std::memcmp(input.bytes.data()+sizeof(domain),encoded.bytes.data(),43)==0);
    const auto before=input;
    encoded.bytes[encoded.size-1]^=1;
    Check(BuildSignatureInput(encoded.bytes.data(),encoded.size,input) && input.bytes==before.bytes);
    encoded.bytes[12]^=1;
    Check(BuildSignatureInput(encoded.bytes.data(),encoded.size,input) && input.bytes!=before.bytes);
    Check(Encode(header,body.data(),1160,encoded) && BuildSignatureInput(encoded.bytes.data(),encoded.size,input));
    Check(input.size==input.bytes.size());
    for(const auto type : {1,2,6,11,12,13,18,19}) {
        header.type=static_cast<std::uint8_t>(type);
        Check(Encode(header,body.data(),100,encoded));
        Check(!BuildSignatureInput(encoded.bytes.data(),encoded.size,input) && input.size==0);
    }
    header.type=14;
    Check(Encode(header,body.data(),63,encoded));
    Check(!BuildSignatureInput(encoded.bytes.data(),encoded.size,input));
    Check(!BuildSignatureInput(nullptr,1200,input) && input.size==0);
    for(const auto type : {0,26,255}) {
        header.type=static_cast<std::uint8_t>(type); Check(!Encode(header,nullptr,0,encoded));
    }
    std::printf("Control/1 envelope: %u checks PASS (structural only; no authentication or discovery credited)\n",checks);
}
