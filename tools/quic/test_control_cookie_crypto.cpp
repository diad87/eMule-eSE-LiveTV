#include "../../srchybrid/EseControlCookieCrypto.h"
#include "../../srchybrid/EseControlInitiator.h"
#include "../../srchybrid/EseControlInitiatorHost.h"
#include "../../srchybrid/LiveCrypto.h"
#include "../../cryptopp/sha.h"
#include <cstdio>
#include <cstdlib>
using namespace ese::control;
static unsigned checks=0;
static void Check(bool ok) { ++checks; if(!ok) { std::printf("FAIL %u\n",checks); std::exit(1); } }
struct LabSigner final : Signer {
    const std::array<std::uint8_t,32>& privateKey;
    const std::array<std::uint8_t,32>& publicKey;
    bool fail=false;
    LabSigner(const std::array<std::uint8_t,32>& secret,const std::array<std::uint8_t,32>& pub):privateKey(secret),publicKey(pub) {}
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        return !fail && eSELive::SignMessage(privateKey.data(),publicKey.data(),p,n,out.data());
    }
};
struct BootstrapHost final : ese::QuicSessionHost {
    Datagram sent; unsigned sends=0,removes=0; std::uint8_t expected=0;
    bool allow=true; ese::QuicUdpSendStatus sendStatus=ese::QuicUdpSendStatus::Sent;
    bool ExpectControlReply(const Header&,std::uint8_t type,const ese::udp::Endpoint&,std::uint64_t,std::uint64_t) override { expected=type; return allow; }
    void RemoveControlReplies(std::uint64_t) override { ++removes; expected=0; }
    ese::QuicUdpSendResult SendControl(const ese::udp::Endpoint&,reach::DirectByteView view) override {
        ++sends; sent.size=view.size; std::memcpy(sent.bytes.data(),view.data,view.size); return {sendStatus,0};
    }
    void Stop() override {} void Poll(std::uint64_t) override {}
    std::size_t RetireClosed() override { return 0; } bool Empty() const noexcept override { return true; }
    std::uint64_t Begin(ese::NativeQuicConfig,ese::QuicPeerConfig,reach::DirectHandle,const reach::DirectSessionRoute&) override { return 0; }
    ese::QuicTransport* Find(std::uint64_t) const override { return nullptr; }
    bool Release(std::uint64_t) override { return false; }
};
int main() {
    {
        Sessions requests; ese::udp::Endpoint peer; peer.port=123;
        std::array<std::uint8_t,32> key{},digest{}; key[0]=1; digest[0]=1;
        Header session; session.attempt[0]=1; session.generation=1; session.sequence=1;
        Check(requests.AdmitVerified(key,peer,session,digest,100)==Admission::Accepted);
        Header next;
        Check(requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpK6DirectFind,101,next) && next.sequence==2);
        auto explicitRequest=session; explicitRequest.sequence=8;
        Check(requests.RememberOutgoing(key,peer,explicitRequest,102));
        Check(requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpDescriptorGet,103,next) && next.sequence==9);
        auto wrong=peer; ++wrong.port;
        Check(!requests.NextRequest(key,wrong,session,ese::wire::kEseWireUdpDescriptorGet,104,next) && !next.sequence);
        Check(!requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpAck,104,next));
        Check(requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpK6ContactGet,104,next) && next.sequence==10);
        Check(!requests.NextRequest(key,wrong,session,ese::wire::kEseWireUdpK6ContactGet,104,next));
        Check(!requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpK6ContactGet,30100,next));
        Check(!requests.NextRequest(key,peer,session,ese::wire::kEseWireUdpDescriptorGet,30100,next));
    }
    std::array<std::uint8_t,32> publicKey{},privateKey{},otherPublic{},otherPrivate{};
    Check(eSELive::GenerateBroadcasterKeypair(publicKey.data(),privateKey.data()));
    Check(eSELive::GenerateBroadcasterKeypair(otherPublic.data(),otherPrivate.data()));
    {
        constexpr std::uint64_t maxFileSize=0x4000000000ULL;
        ese::discovery::DirectFind query,verified; query.requester=publicKey; query.fileSize=123; query.maximum=4;
        LabSigner signer(privateKey,publicKey),wrong(otherPrivate,otherPublic);
        Header header; header.type=ese::wire::kEseWireUdpK6DirectFind; header.attempt.fill(1); header.generation=7; header.sequence=2;
        Datagram packet; Header observed;
        Check(BuildDirectFind(header,query,maxFileSize,signer,packet) && packet.size==161);
        Check(VerifyDirectFind(publicKey,packet.bytes.data(),packet.size,maxFileSize,observed,verified) && verified.maximum==4 && verified.fileSize==123);
        std::array<std::uint8_t,32> requestDigest{};
        Check(DirectFindDigest(publicKey,packet.bytes.data(),packet.size,maxFileSize,requestDigest));
        std::array<std::uint8_t,331> responseBody{};
        responseBody[24]=123; std::memcpy(responseBody.data()+25,publicKey.data(),32);
        std::memcpy(responseBody.data()+57,requestDigest.data(),32); responseBody[89]=1;
        ese::discovery::DirectSource source; source.node=publicKey; source.fileSize=123; source.generation=7; source.serial=1; source.ttl=120;
        std::array<std::uint8_t,173> sourceBytes{};
        Check(BuildDirectSource(source,maxFileSize,signer,sourceBytes));
        std::memcpy(responseBody.data()+90,sourceBytes.data(),173); responseBody[266]=119;
        auto replyHeader=header; replyHeader.type=ese::wire::kEseWireUdpK6DirectFindResult;
        Datagram response; SignatureInput responseInput; std::array<std::uint8_t,64> responseSignature{};
        Check(Encode(replyHeader,responseBody.data(),responseBody.size(),response) && BuildSignatureInput(response.bytes.data(),response.size,responseInput));
        Check(wrong.Sign(responseInput.bytes.data(),responseInput.size,responseSignature));
        std::memcpy(response.bytes.data()+response.size-64,responseSignature.data(),64);
        ese::discovery::FindResultView result;
        Check(VerifyDirectFindResultSignature(otherPublic,header,query,requestDigest,response.bytes.data(),response.size,maxFileSize,result) && VerifyDirectFindSources(result,maxFileSize));
        ese::udp::Endpoint findEndpoint; findEndpoint.port=7; DirectFindRequest pendingFind;
        Check(pendingFind.Start(otherPublic,findEndpoint,header,query,requestDigest,maxFileSize,1000));
        auto wrongFindEndpoint=findEndpoint; ++wrongFindEndpoint.port;
        Check(!pendingFind.Receive(wrongFindEndpoint,response.bytes.data(),response.size,1000,result) && !result.signature);
        Check(pendingFind.Receive(findEndpoint,response.bytes.data(),response.size,2999,result) && result.count==1);
        Check(!pendingFind.Receive(findEndpoint,response.bytes.data(),response.size,2999,result) && !result.signature);
        DirectFindRequest lateFind; Check(lateFind.Start(otherPublic,findEndpoint,header,query,requestDigest,maxFileSize,1000));
        Check(!lateFind.Receive(findEndpoint,response.bytes.data(),response.size,3000,result) && lateFind.State()==DescriptorRequestState::Failed);
        DirectFindRequest rollbackFind; Check(rollbackFind.Start(otherPublic,findEndpoint,header,query,requestDigest,maxFileSize,1000));
        Check(!rollbackFind.Poll(999) && rollbackFind.State()==DescriptorRequestState::Failed);
        std::array<std::uint8_t,157> closer{}; std::memcpy(closer.data(),responseBody.data(),90);
        closer[0]=1; closer[89]=1; closer[91]=1; closer[92]=1; // invalid opaque Kad6 contact
        Datagram closerPacket; SignatureInput closerInput; std::array<std::uint8_t,64> closerSignature{};
        Check(Encode(replyHeader,closer.data(),closer.size(),closerPacket) && BuildSignatureInput(closerPacket.bytes.data(),closerPacket.size,closerInput) && wrong.Sign(closerInput.bytes.data(),closerInput.size,closerSignature));
        std::memcpy(closerPacket.bytes.data()+closerPacket.size-64,closerSignature.data(),64);
        DirectFindRequest noContacts; Check(noContacts.Start(otherPublic,findEndpoint,header,query,requestDigest,maxFileSize,1000));
        Check(!noContacts.Receive(findEndpoint,closerPacket.bytes.data(),closerPacket.size,1000,result) && !result.signature && noContacts.State()==DescriptorRequestState::Pending);
        std::array<ese::discovery::FindEntryView,4> entries{}; entries[0]={sourceBytes.data(),173,119};
        Datagram built;
        Check(BuildDirectFindSourcesResult(header,query,requestDigest,entries,1,maxFileSize,otherPublic,wrong,built) && built.size==response.size && !std::memcmp(built.bytes.data(),response.bytes.data(),response.size));
        Check(BuildDirectFindSourcesResult(header,query,requestDigest,entries,0,maxFileSize,otherPublic,wrong,built) && built.size==194);
        Check(VerifyDirectFindResultSignature(otherPublic,header,query,requestDigest,built.bytes.data(),built.size,maxFileSize,result) && result.kind==2 && !result.count);
        entries[0].remainingTtl=121;
        Check(!BuildDirectFindSourcesResult(header,query,requestDigest,entries,1,maxFileSize,otherPublic,wrong,built) && !built.size);
        entries[0].remainingTtl=119;
        Check(!BuildDirectFindSourcesResult(header,query,requestDigest,entries,5,maxFileSize,otherPublic,wrong,built));
        Check(!BuildDirectFindSourcesResult(header,query,requestDigest,entries,1,maxFileSize,publicKey,wrong,built));
        for(std::size_t i=0;i<response.size;++i) {
            auto changed=response; changed.bytes[i]^=1;
            Check(!VerifyDirectFindResultSignature(otherPublic,header,query,requestDigest,changed.bytes.data(),changed.size,maxFileSize,result) && !result.signature);
        }
        auto wrongDigest=requestDigest; wrongDigest[0]^=1;
        Check(!VerifyDirectFindResultSignature(otherPublic,header,query,wrongDigest,response.bytes.data(),response.size,maxFileSize,result));
        responseBody[90+109]^=1;
        Check(Encode(replyHeader,responseBody.data(),responseBody.size(),response) && BuildSignatureInput(response.bytes.data(),response.size,responseInput) && wrong.Sign(responseInput.bytes.data(),responseInput.size,responseSignature));
        std::memcpy(response.bytes.data()+response.size-64,responseSignature.data(),64);
        Check(VerifyDirectFindResultSignature(otherPublic,header,query,requestDigest,response.bytes.data(),response.size,maxFileSize,result));
        Check(!VerifyDirectFindSources(result,maxFileSize)); // W signature cannot legitimize bad B signature
        for(std::size_t i=0;i<packet.size;++i) {
            auto changed=packet; changed.bytes[i]^=1;
            Check(!VerifyDirectFind(publicKey,changed.bytes.data(),changed.size,maxFileSize,observed,verified) && verified.maximum==0);
        }
        Sessions sessions; DescriptorGetLimit<> limit; ese::udp::Endpoint endpoint; endpoint.port=1;
        Check(!AdmitDirectFind(sessions,limit,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        auto bootstrap=header; bootstrap.sequence=1; bootstrap.type=3;
        std::array<std::uint8_t,32> digest{}; digest[0]=1;
        Check(sessions.AdmitVerified(publicKey,endpoint,bootstrap,digest,1000)==Admission::Accepted);
        Check(AdmitDirectFind(sessions,limit,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        Check(!AdmitDirectFind(sessions,limit,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        Check(!BuildDirectFind(header,query,maxFileSize,wrong,packet) && !packet.size);
        query.maximum=5; Check(!BuildDirectFind(header,query,maxFileSize,signer,packet));
    }
    {
        constexpr std::uint64_t maxFileSize=0x4000000000ULL;
        ese::discovery::DirectSource record,verified;
        record.node=publicKey; record.fileSize=123456; record.generation=7; record.serial=1; record.ttl=120; record.digest.fill(3);
        LabSigner signer(privateKey,publicKey),wrongSigner(otherPrivate,otherPublic);
        std::array<std::uint8_t,173> bytes{};
        Check(BuildDirectSource(record,maxFileSize,signer,bytes));
        Check(VerifyDirectSource(publicKey,bytes.data(),bytes.size(),maxFileSize,verified) && verified.fileSize==123456);
        for(std::size_t i=0;i<bytes.size();++i) {
            auto changed=bytes; changed[i]^=1;
            Check(!VerifyDirectSource(publicKey,changed.data(),changed.size(),maxFileSize,verified) && verified.fileSize==0);
        }
        Check(!VerifyDirectSource(otherPublic,bytes.data(),bytes.size(),maxFileSize,verified));
        std::array<std::uint8_t,173> wrong{};
        Check(!BuildDirectSource(record,maxFileSize,wrongSigner,wrong) && wrong==std::array<std::uint8_t,173>{});
        Header header; header.type=ese::wire::kEseWireUdpK6DirectPut; header.attempt.fill(1); header.generation=7; header.sequence=2;
        Datagram packet; Header observed;
        Check(BuildDirectPut(header,bytes.data(),bytes.size(),maxFileSize,publicKey,signer,packet) && packet.size==277);
        Check(VerifyDirectPut(publicKey,packet.bytes.data(),packet.size,maxFileSize,observed,verified) && verified.serial==1);
        for(std::size_t i=0;i<packet.size;++i) {
            auto changed=packet; changed.bytes[i]^=1;
            Check(!VerifyDirectPut(publicKey,changed.bytes.data(),changed.size,maxFileSize,observed,verified) && verified.serial==0);
        }
        Sessions sessions; ese::udp::Endpoint endpoint; endpoint.port=1;
        Check(!AdmitDirectPut(sessions,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        auto bootstrap=header; bootstrap.sequence=1; bootstrap.type=3;
        Check(sessions.AdmitVerified(publicKey,endpoint,bootstrap,record.digest,1000)==Admission::Accepted);
        Check(AdmitDirectPut(sessions,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        Check(!AdmitDirectPut(sessions,endpoint,publicKey,packet.bytes.data(),packet.size,maxFileSize,1000,observed,verified));
        // Independently valid outer signature cannot authorize a false inner signature.
        packet.bytes[40+109]^=1; SignatureInput input; std::array<std::uint8_t,64> signature{};
        Check(BuildSignatureInput(packet.bytes.data(),packet.size,input) && signer.Sign(input.bytes.data(),input.size,signature));
        std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
        Check(VerifyEnvelopeSignature(publicKey,packet.bytes.data(),packet.size));
        Check(!VerifyDirectPut(publicKey,packet.bytes.data(),packet.size,maxFileSize,observed,verified));
        LabSigner witness(otherPrivate,otherPublic); Datagram response; std::uint8_t status=0;
        for(std::uint8_t expected=0;expected<4;++expected) {
            Check(BuildDirectPutResult(header,expected,record,maxFileSize,otherPublic,witness,response) && response.size==209);
            Check(VerifyDirectPutResult(otherPublic,header,record,maxFileSize,response.bytes.data(),response.size,status) && status==expected);
        }
        for(std::size_t i=0;i<response.size;++i) {
            auto changed=response; changed.bytes[i]^=1;
            Check(!VerifyDirectPutResult(otherPublic,header,record,maxFileSize,changed.bytes.data(),changed.size,status) && status==255);
        }
        auto wrongRecord=record; ++wrongRecord.fileSize;
        Check(!VerifyDirectPutResult(otherPublic,header,wrongRecord,maxFileSize,response.bytes.data(),response.size,status));
        auto wrongHeader=header; ++wrongHeader.sequence;
        Check(!VerifyDirectPutResult(otherPublic,wrongHeader,record,maxFileSize,response.bytes.data(),response.size,status));
        Check(!VerifyDirectPutResult(publicKey,header,record,maxFileSize,response.bytes.data(),response.size,status));
        Check(!BuildDirectPutResult(header,4,record,maxFileSize,otherPublic,witness,response) && !response.size);
        Check(BuildDirectPutResult(header,0,record,maxFileSize,otherPublic,witness,response));
        DirectPutRequest pending;
        Check(pending.Start(otherPublic,endpoint,header,record,maxFileSize,1000));
        auto wrongEndpoint=endpoint; ++wrongEndpoint.port;
        Check(!pending.Receive(wrongEndpoint,response.bytes.data(),response.size,1000,status) && status==255);
        auto corrupt=response; corrupt.bytes[corrupt.size-1]^=1;
        Check(!pending.Receive(endpoint,corrupt.bytes.data(),corrupt.size,1000,status) && pending.State()==DescriptorRequestState::Pending);
        Check(pending.Receive(endpoint,response.bytes.data(),response.size,2999,status) && status==0 && pending.State()==DescriptorRequestState::Complete);
        Check(!pending.Receive(endpoint,response.bytes.data(),response.size,2999,status) && status==255);
        Check(!pending.Start(otherPublic,endpoint,header,record,maxFileSize,3000));
        DirectPutRequest late;
        Check(late.Start(otherPublic,endpoint,header,record,maxFileSize,1000));
        Check(!late.Receive(endpoint,response.bytes.data(),response.size,3000,status) && late.State()==DescriptorRequestState::Failed);
        DirectPutRequest backwards;
        Check(backwards.Start(otherPublic,endpoint,header,record,maxFileSize,1000));
        Check(!backwards.Poll(999) && backwards.State()==DescriptorRequestState::Failed);
        DirectPutRequest cancelled;
        Check(cancelled.Start(otherPublic,endpoint,header,record,maxFileSize,1000));
        cancelled.Cancel(); Check(!cancelled.Receive(endpoint,response.bytes.data(),response.size,1000,status));
    }
    {
        std::array<std::uint8_t,159> descriptor{};
        std::memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3;
        descriptor[8]=1; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
        std::memcpy(descriptor.data()+29,publicKey.data(),32);
        ese::discovery::DescriptorSignatureInput input;
        Check(ese::discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),input));
        Check(eSELive::SignMessage(privateKey.data(),publicKey.data(),input.bytes.data(),input.size,descriptor.data()+95));
        std::array<std::uint8_t,32> digest{}; ese::discovery::DescriptorView view;
        Check(DescriptorDigest(descriptor.data(),descriptor.size(),digest));
        Check(VerifyDescriptor(publicKey,digest,descriptor.data(),descriptor.size(),view) && view.generation==7 && view.serial==1);
        Check(!VerifyDescriptor(otherPublic,digest,descriptor.data(),descriptor.size(),view));
        auto wrong=digest; wrong[0]^=1;
        Check(!VerifyDescriptor(publicKey,wrong,descriptor.data(),descriptor.size(),view) && view.signature==nullptr);
        for(unsigned i=0;i<descriptor.size();++i) {
            auto changed=descriptor; changed[i]^=1;
            Check(!VerifyDescriptor(publicKey,digest,changed.data(),changed.size(),view));
            // Even a newly supplied digest cannot legitimize modified signed fields.
            std::array<std::uint8_t,32> newDigest{};
            if(DescriptorDigest(changed.data(),changed.size(),newDigest)) Check(!VerifyDescriptor(publicKey,newDigest,changed.data(),changed.size(),view));
        }
        Check(!VerifyDescriptor(publicKey,digest,nullptr,159,view));
        ese::discovery::DescriptorSerials<1> serials;
        using Result=ese::discovery::SerialResult;
        std::uint64_t deadline=999;
        Check(AdmitDescriptor(serials,otherPublic,digest,descriptor.data(),descriptor.size(),10,900000,view,deadline)==Result::Invalid && !view.signature && deadline==0);
        auto corrupt=descriptor; corrupt[24]=200; // invalid signed high serial must not poison the watermark or clock
        std::array<std::uint8_t,32> corruptDigest{};
        Check(DescriptorDigest(corrupt.data(),corrupt.size(),corruptDigest));
        Check(AdmitDescriptor(serials,publicKey,corruptDigest,corrupt.data(),corrupt.size(),10,900000,view,deadline)==Result::Invalid && !view.signature && deadline==0);
        Check(AdmitDescriptor(serials,publicKey,digest,descriptor.data(),descriptor.size(),10,1000,view,deadline)==Result::Accepted && view.serial==1 && deadline==11000);
        Check(AdmitDescriptor(serials,publicKey,digest,descriptor.data(),descriptor.size(),120,10999,view,deadline)==Result::Duplicate && view.signature && deadline==11000);
        Check(AdmitDescriptor(serials,publicKey,digest,descriptor.data(),descriptor.size(),120,11000,view,deadline)==Result::Expired && !view.signature && deadline==0);
        descriptor[24]=2;
        Check(ese::discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),input));
        Check(eSELive::SignMessage(privateKey.data(),publicKey.data(),input.bytes.data(),input.size,descriptor.data()+95));
        Check(DescriptorDigest(descriptor.data(),descriptor.size(),digest));
        Check(AdmitDescriptor(serials,publicKey,digest,descriptor.data(),descriptor.size(),5,11000,view,deadline)==Result::Accepted && view.serial==2 && deadline==16000);
        ese::discovery::Locator locator; locator.node=publicKey; locator.digest=digest; locator.serial=1; locator.ttl=3;
        ese::discovery::DescriptorSerials<1> located;
        Check(AdmitLocatedDescriptor(located,locator,descriptor.data(),descriptor.size(),900000,view,deadline)==Result::Invalid && !view.signature && deadline==0);
        locator.serial=2;
        Check(AdmitLocatedDescriptor(located,locator,descriptor.data(),descriptor.size(),1000,view,deadline)==Result::Accepted && deadline==4000);
        std::array<std::uint8_t,306> response{}; response[82]=159;
        std::memcpy(response.data()+17,publicKey.data(),32);
        std::memcpy(response.data()+49,digest.data(),32);
        std::memcpy(response.data()+83,descriptor.data(),159);
        Header request; request.type=ese::wire::kEseWireUdpDescriptorGet;
        request.attempt.fill(1); request.generation=7; request.sequence=9;
        auto reply=request; reply.type=ese::wire::kEseWireUdpDescriptorResult;
        LabSigner requester(privateKey,publicKey),badRequester(otherPrivate,otherPublic);
        Datagram getPacket; ese::discovery::GetView query; Header queryHeader;
        Check(BuildDescriptorGet(request,{},locator,publicKey,requester,getPacket) && getPacket.size==184);
        Check(VerifyDescriptorGet(publicKey,getPacket.bytes.data(),getPacket.size,queryHeader,query) && query.node==publicKey && query.digest==digest && queryHeader.sequence==9);
        Sessions getSessions; DescriptorGetLimit<> getLimit; ese::udp::Endpoint getSource; getSource.port=99;
        Check(!AdmitDescriptorGet(getSessions,getLimit,getSource,publicKey,getPacket.bytes.data(),getPacket.size,1000,queryHeader,query));
        auto sessionHeader=request; sessionHeader.sequence=8; sessionHeader.type=ese::wire::kEseWireUdpProve;
        Check(getSessions.AdmitVerified(publicKey,getSource,sessionHeader,digest,1000)==Admission::Accepted);
        auto wrongSource=getSource; ++wrongSource.port;
        Check(!AdmitDescriptorGet(getSessions,getLimit,wrongSource,publicKey,getPacket.bytes.data(),getPacket.size,1000,queryHeader,query));
        Check(AdmitDescriptorGet(getSessions,getLimit,getSource,publicKey,getPacket.bytes.data(),getPacket.size,1000,queryHeader,query));
        Check(!AdmitDescriptorGet(getSessions,getLimit,getSource,publicKey,getPacket.bytes.data(),getPacket.size,1000,queryHeader,query) && !query.signature);
        for(unsigned sequence=10;sequence<=13;++sequence) {
            auto next=request; next.sequence=sequence;
            Datagram nextPacket;
            Check(BuildDescriptorGet(next,{},locator,publicKey,requester,nextPacket));
            Check(AdmitDescriptorGet(getSessions,getLimit,getSource,publicKey,nextPacket.bytes.data(),nextPacket.size,1000,queryHeader,query)==(sequence<13));
        }
        for(std::size_t i=0;i<getPacket.size;++i) {
            auto changed=getPacket; changed.bytes[i]^=1;
            Check(!VerifyDescriptorGet(publicKey,changed.bytes.data(),changed.size,queryHeader,query) && !query.signature && queryHeader.sequence==0);
        }
        Check(!BuildDescriptorGet(request,{},locator,publicKey,badRequester,getPacket) && !getPacket.size);
        requester.fail=true; Check(!BuildDescriptorGet(request,{},locator,publicKey,requester,getPacket)); requester.fail=false;
        auto emptyRequest=request; emptyRequest.attempt={};
        Check(!BuildDescriptorGet(emptyRequest,{},locator,publicKey,requester,getPacket));
        auto putHeader=request; putHeader.type=ese::wire::kEseWireUdpDescriptorPut;
        Datagram putPacket; ese::discovery::PutView publication; std::array<std::uint8_t,32> putDigest{};
        Check(BuildDescriptorPut(putHeader,{},descriptor.data(),descriptor.size(),publicKey,requester,putPacket) && putPacket.size==281);
        Check(VerifyDescriptorPut(publicKey,putPacket.bytes.data(),putPacket.size,queryHeader,publication,putDigest) && putDigest==digest && publication.length==159);
        for(std::size_t i=0;i<putPacket.size;++i) {
            auto changed=putPacket; changed.bytes[i]^=1;
            Check(!VerifyDescriptorPut(publicKey,changed.bytes.data(),changed.size,queryHeader,publication,putDigest) && !publication.signature && putDigest==std::array<std::uint8_t,32>{});
        }
        Sessions putSessions;
        Check(!AdmitDescriptorPut(putSessions,getSource,publicKey,putPacket.bytes.data(),putPacket.size,1000,queryHeader,publication,putDigest));
        Check(putSessions.AdmitVerified(publicKey,getSource,sessionHeader,digest,1000)==Admission::Accepted);
        Check(!AdmitDescriptorPut(putSessions,wrongSource,publicKey,putPacket.bytes.data(),putPacket.size,1000,queryHeader,publication,putDigest));
        Check(AdmitDescriptorPut(putSessions,getSource,publicKey,putPacket.bytes.data(),putPacket.size,1000,queryHeader,publication,putDigest));
        Check(!AdmitDescriptorPut(putSessions,getSource,publicKey,putPacket.bytes.data(),putPacket.size,1000,queryHeader,publication,putDigest));
        auto otherGeneration=putHeader; ++otherGeneration.generation;
        Check(!BuildDescriptorPut(otherGeneration,{},descriptor.data(),descriptor.size(),publicKey,requester,putPacket));
        Check(!BuildDescriptorPut(putHeader,{},descriptor.data(),descriptor.size(),otherPublic,badRequester,putPacket));
        Check(BuildDescriptorPut(putHeader,{},descriptor.data(),descriptor.size(),publicKey,requester,putPacket));
        putPacket.bytes[40+18+95]^=1;
        SignatureInput putInput; std::array<std::uint8_t,64> putSignature{};
        Check(BuildSignatureInput(putPacket.bytes.data(),putPacket.size,putInput) && requester.Sign(putInput.bytes.data(),putInput.size,putSignature));
        std::memcpy(putPacket.bytes.data()+putPacket.size-64,putSignature.data(),64);
        Check(VerifyEnvelopeSignature(publicKey,putPacket.bytes.data(),putPacket.size));
        Check(!VerifyDescriptorPut(publicKey,putPacket.bytes.data(),putPacket.size,queryHeader,publication,putDigest) && !publication.signature);
        Datagram packet; SignatureInput outer; ese::discovery::ResultView result;
        std::array<std::uint8_t,16> file{};
        LabSigner witnessSigner(otherPrivate,otherPublic);
        Datagram built;
        Check(BuildDescriptorResult(reply,0,file,locator,descriptor.data(),descriptor.size(),otherPublic,witnessSigner,built) && built.size==346);
        Check(VerifyDescriptorResult(otherPublic,request,file,locator,built.bytes.data(),built.size,result) && result.length==159);
        for(const auto status : {1,2}) {
            Check(BuildDescriptorResult(reply,static_cast<std::uint8_t>(status),file,locator,nullptr,0,otherPublic,witnessSigner,built) && built.size==187);
            Check(VerifyDescriptorResult(otherPublic,request,file,locator,built.bytes.data(),built.size,result) && result.status==status && !result.descriptor);
            Check(!BuildDescriptorResult(reply,static_cast<std::uint8_t>(status),file,locator,descriptor.data(),descriptor.size(),otherPublic,witnessSigner,built) && built.size==0);
        }
        Check(!BuildDescriptorResult(reply,3,file,locator,nullptr,0,otherPublic,witnessSigner,built));
        Check(!BuildDescriptorResult(reply,0,file,locator,nullptr,0,otherPublic,witnessSigner,built));
        Check(!BuildDescriptorResult(reply,0,file,locator,descriptor.data(),descriptor.size(),publicKey,witnessSigner,built));
        auto badLocator=locator; badLocator.digest[0]^=1;
        Check(!BuildDescriptorResult(reply,0,file,badLocator,descriptor.data(),descriptor.size(),otherPublic,witnessSigner,built));
        witnessSigner.fail=true;
        Check(!BuildDescriptorResult(reply,0,file,locator,descriptor.data(),descriptor.size(),otherPublic,witnessSigner,built));
        witnessSigner.fail=false;
        Check(Encode(reply,response.data(),response.size(),packet) && BuildSignatureInput(packet.bytes.data(),packet.size,outer));
        Check(eSELive::SignMessage(otherPrivate.data(),otherPublic.data(),outer.bytes.data(),outer.size,packet.bytes.data()+packet.size-64));
        Check(VerifyDescriptorResult(otherPublic,request,file,locator,packet.bytes.data(),packet.size,result) && result.status==0 && result.length==159);
        ese::udp::Endpoint endpoint; endpoint.port=123;
        DescriptorRequest pending; auto expected=reply;
        ese::discovery::DescriptorView coherent; Check(ese::discovery::ParseUntrusted(descriptor.data(),descriptor.size(),coherent));
        DescriptorRequest wrongGeneration;
        Check(wrongGeneration.Start(otherPublic,endpoint,expected,file,locator,1000,3000,coherent.generation+1));
        Check(!wrongGeneration.Receive(endpoint,packet.bytes.data(),packet.size,1001,result) && !result.descriptor &&
            wrongGeneration.State()==DescriptorRequestState::Pending);
        DescriptorRequest matchingGeneration;
        Check(matchingGeneration.Start(otherPublic,endpoint,expected,file,locator,1000,3000,coherent.generation));
        Check(matchingGeneration.Receive(endpoint,packet.bytes.data(),packet.size,1001,result));
        Check(pending.Start(otherPublic,endpoint,expected,file,locator,1000));
        auto wrongEndpoint=endpoint; ++wrongEndpoint.port;
        Check(!pending.Receive(wrongEndpoint,packet.bytes.data(),packet.size,1000,result) && !result.signature);
        auto invalidPacket=packet; invalidPacket.bytes[invalidPacket.size-1]^=1;
        Check(!pending.Receive(endpoint,invalidPacket.bytes.data(),invalidPacket.size,1000,result) && pending.State()==DescriptorRequestState::Pending);
        Check(pending.Receive(endpoint,packet.bytes.data(),packet.size,2999,result) && pending.State()==DescriptorRequestState::Complete);
        Check(!pending.Receive(endpoint,packet.bytes.data(),packet.size,2999,result) && !result.signature);
        Check(!pending.Start(otherPublic,endpoint,expected,file,locator,3000));
        DescriptorRequest late; Check(late.Start(otherPublic,endpoint,expected,file,locator,1000));
        Check(!late.Receive(endpoint,packet.bytes.data(),packet.size,3000,result) && late.State()==DescriptorRequestState::Failed);
        DescriptorRequest backwards; Check(backwards.Start(otherPublic,endpoint,expected,file,locator,1000));
        Check(!backwards.Poll(999) && backwards.State()==DescriptorRequestState::Failed);
        DescriptorRequest cancelled; Check(cancelled.Start(otherPublic,endpoint,expected,file,locator,1000));
        cancelled.Cancel(); Check(!cancelled.Receive(endpoint,packet.bytes.data(),packet.size,1000,result));
        DescriptorRequest overflow;
        Check(!overflow.Start(otherPublic,endpoint,expected,file,locator,std::numeric_limits<std::uint64_t>::max()-1999));
        for(std::size_t i=0;i<packet.size;++i) {
            auto changed=packet; changed.bytes[i]^=1;
            Check(!VerifyDescriptorResult(otherPublic,request,file,locator,changed.bytes.data(),changed.size,result) && !result.signature);
        }
        auto wrongRequest=request; ++wrongRequest.sequence;
        Check(!VerifyDescriptorResult(otherPublic,wrongRequest,file,locator,packet.bytes.data(),packet.size,result));
        auto wrongFile=file; wrongFile[0]=1;
        Check(!VerifyDescriptorResult(otherPublic,request,wrongFile,locator,packet.bytes.data(),packet.size,result));
        ++locator.serial; Check(!VerifyDescriptorResult(otherPublic,request,file,locator,packet.bytes.data(),packet.size,result)); --locator.serial;
        Check(!VerifyDescriptorResult(publicKey,request,file,locator,packet.bytes.data(),packet.size,result));
        // A valid W signature must not legitimize an invalid publisher signature.
        response[83+95]^=1;
        Check(DescriptorDigest(response.data()+83,159,locator.digest));
        std::memcpy(response.data()+49,locator.digest.data(),32);
        Check(Encode(reply,response.data(),response.size(),packet) && BuildSignatureInput(packet.bytes.data(),packet.size,outer));
        Check(eSELive::SignMessage(otherPrivate.data(),otherPublic.data(),outer.bytes.data(),outer.size,packet.bytes.data()+packet.size-64));
        Check(!VerifyDescriptorResult(otherPublic,request,file,locator,packet.bytes.data(),packet.size,result));
        for(const auto status : {1,2}) {
            response[0]=static_cast<std::uint8_t>(status); response[82]=0;
            Check(Encode(reply,response.data(),147,packet) && BuildSignatureInput(packet.bytes.data(),packet.size,outer));
            Check(eSELive::SignMessage(otherPrivate.data(),otherPublic.data(),outer.bytes.data(),outer.size,packet.bytes.data()+packet.size-64));
            Check(VerifyDescriptorResult(otherPublic,request,file,locator,packet.bytes.data(),packet.size,result) && result.status==status && !result.descriptor);
        }
        Check(!DescriptorDigest(nullptr,159,digest) && digest==std::array<std::uint8_t,32>{});
    }
    for(const std::uint8_t selected : {std::uint8_t{0},std::uint8_t{4}}) {
        Header header; header.type=1; header.attempt.fill(1); header.generation=7; header.sequence=1;
        Probe probe; probe.node=publicKey; probe.peer=otherPublic; probe.nonce.fill(2); probe.mask=selected;
        ese::udp::Endpoint local,remote; local.port=1; remote.port=2;
        Initiator initiator; Check(initiator.Start(header,probe,remote,100,10000));
        BootstrapHost host; InitiatorHost adapter(host);
        Check(!adapter.Start(1,header,probe,remote,100,2101));
        Check(adapter.Start(1,header,probe,remote,100,2100) && host.expected==2);
        host.sendStatus=ese::QuicUdpSendStatus::WouldBlock;
        adapter.Poll(100); adapter.Poll(101); Check(host.sends==2 && adapter.State()==InitiatorState::Probe);
        host.sendStatus=ese::QuicUdpSendStatus::Sent;
        adapter.Poll(102); adapter.Poll(103); Check(host.sends==3);
        CookieAuthority bridgeAuthority; ChallengeLimit bridgeLimit; Datagram bridgeReply;
        Check(bridgeAuthority.Initialize());
        Check(BuildChallenge(bridgeAuthority,bridgeLimit,local,otherPublic,publicKey,host.sent.bytes.data(),host.sent.size,102,bridgeReply));
        LabSigner bridgeSigner(privateKey,publicKey),bridgeResponder(otherPrivate,otherPublic);
        Check(!adapter.Receive(2,remote,bridgeReply.bytes.data(),bridgeReply.size,103,bridgeSigner));
        Check(adapter.Receive(1,remote,bridgeReply.bytes.data(),bridgeReply.size,103,bridgeSigner) && host.expected==4 && host.removes==1);
        adapter.Poll(103); Check(host.sent.size==252);
        Prove bridgeProof; Sessions bridgeSessions; Envelope bridgeEnvelope;
        Check(AdmitProve(bridgeAuthority,bridgeSessions,local,otherPublic,publicKey,host.sent.bytes.data(),host.sent.size,103,bridgeProof)==Admission::Accepted);
        Check(ParseUntrusted(host.sent.bytes.data(),host.sent.size,bridgeEnvelope));
        Check(BuildAck(bridgeProof,bridgeEnvelope.header,selected,otherPublic,bridgeResponder,bridgeReply));
        auto badAck=bridgeReply; badAck.bytes[badAck.size-1]^=1;
        Check(!adapter.Receive(1,remote,badAck.bytes.data(),badAck.size,104,bridgeSigner) && host.expected==4);
        Check(adapter.Receive(1,remote,bridgeReply.bytes.data(),bridgeReply.size,104,bridgeSigner));
        Check(adapter.State()==InitiatorState::Ready && host.removes==2 && adapter.Selected()==selected);
        adapter.Poll(105); Check(host.sends==4);
        adapter.Cancel();
        Check(adapter.State()==InitiatorState::Failed && adapter.Selected()==0 && host.removes==2);
        adapter.Cancel(); adapter.Poll(106);
        Check(adapter.State()==InitiatorState::Failed && host.removes==2 && host.sends==4);
        Check(!adapter.Receive(1,remote,bridgeReply.bytes.data(),bridgeReply.size,107,bridgeSigner));
        BootstrapHost failedHost; InitiatorHost failedAdapter(failedHost); failedHost.allow=false;
        Check(!failedAdapter.Start(2,header,probe,remote,100,2000) && failedAdapter.State()==InitiatorState::Failed && failedHost.removes==1);
        BootstrapHost timeoutHost; InitiatorHost timeoutAdapter(timeoutHost);
        Check(timeoutAdapter.Start(3,header,probe,remote,100,2000));
        timeoutAdapter.Poll(2000); Check(timeoutAdapter.State()==InitiatorState::Failed && timeoutHost.removes==1 && !timeoutHost.sends);
        const auto pending=initiator.Pending(100); Check(pending.size==168);
        Check(initiator.Pending(100).data==pending.data && initiator.Pending(100).size==168); // WOULD_BLOCK retained
        Check(initiator.Submitted(100) && !initiator.Submitted(100));
        Check(initiator.Pending(499).size==0 && initiator.Pending(500).size==168);
        Check(initiator.Submitted(500) && initiator.Pending(1299).size==0);
        Check(initiator.Pending(1300).size==168 && initiator.Submitted(1300) && initiator.Pending(1300).size==0);
        CookieAuthority authority; ChallengeLimit limit; Sessions sessions;
        Check(authority.Initialize()); Datagram response;
        Check(BuildChallenge(authority,limit,local,otherPublic,publicKey,pending.data,pending.size,1300,response));
        LabSigner signer(privateKey,publicKey),responder(otherPrivate,otherPublic);
        auto wrong=remote; ++wrong.port;
        Check(!initiator.ChallengeReceived(wrong,response.bytes.data(),response.size,1300,signer));
        Check(initiator.ChallengeReceived(remote,response.bytes.data(),response.size,1300,signer));
        Check(!initiator.ChallengeReceived(remote,response.bytes.data(),response.size,1300,signer));
        const auto provePacket=initiator.Pending(1300); Check(provePacket.size==252 && initiator.Submitted(1300));
        Check(initiator.Pending(1699).size==0 && initiator.Pending(1700).data==provePacket.data && initiator.Submitted(1700));
        Check(initiator.Pending(2499).size==0 && initiator.Pending(2500).data==provePacket.data && initiator.Submitted(2500));
        Check(initiator.Pending(2500).size==0 && !initiator.Submitted(2500));
        Prove proof; Check(AdmitProve(authority,sessions,local,otherPublic,publicKey,provePacket.data,provePacket.size,1300,proof)==Admission::Accepted);
        Envelope envelope; Check(ParseUntrusted(provePacket.data,provePacket.size,envelope));
        Check(BuildAck(proof,envelope.header,0,otherPublic,responder,response));
        Check(!initiator.AckReceived(wrong,response.bytes.data(),response.size,2500));
        Check(initiator.AckReceived(remote,response.bytes.data(),response.size,2500) && initiator.State()==InitiatorState::Ready && initiator.Selected()==0);
        Check(!initiator.AckReceived(remote,response.bytes.data(),response.size,2500) && initiator.Pending(2500).size==0);
        Initiator timeout; Check(timeout.Start(header,probe,remote,100,1301));
        Check(timeout.Pending(1301).size==0 && timeout.State()==InitiatorState::Failed);
        Initiator rollback; Check(rollback.Start(header,probe,remote,100,10000));
        Check(rollback.Pending(99).size==0 && rollback.State()==InitiatorState::Failed);
        initiator.Cancel(); Check(initiator.State()==InitiatorState::Failed);
    }
    for(const unsigned type : {3U,4U}) {
        Header header; header.type=static_cast<std::uint8_t>(type); header.attempt.fill(1);
        header.generation=7; header.sequence=8;
        std::array<std::uint8_t,212> payload{}; payload.fill(0x31);
        if(type==3) { std::memcpy(payload.data(),publicKey.data(),32); payload[96]=4; }
        else payload[32]=4;
        const auto length=type==3 ? 212U : 97U;
        Datagram packet; SignatureInput message;
        Check(Encode(header,payload.data(),length,packet) && BuildSignatureInput(packet.bytes.data(),packet.size,message));
        Check(eSELive::SignMessage(privateKey.data(),publicKey.data(),message.bytes.data(),message.size,packet.bytes.data()+packet.size-64));
        Check(VerifyEnvelopeSignature(publicKey,packet.bytes.data(),packet.size));
        Check(!VerifyEnvelopeSignature(otherPublic,packet.bytes.data(),packet.size));
        Check(!VerifyEnvelopeSignature({},packet.bytes.data(),packet.size));
        for(std::size_t i=0;i<packet.size;++i) {
            auto changed=packet; changed.bytes[i]^=1;
            Check(!VerifyEnvelopeSignature(publicKey,changed.bytes.data(),changed.size));
        }
        Check(!VerifyEnvelopeSignature(publicKey,packet.bytes.data(),packet.size-1));
        Check(!VerifyEnvelopeSignature(publicKey,nullptr,packet.size));
    }
    std::array<std::uint8_t,32> key{},signer{}; signer.fill(4);
    {
        CookieAuthority receiver; ChallengeLimit limiter;
        Check(receiver.Initialize());
        ese::udp::Endpoint source; source.address[0]=203; source.address[2]=113; source.address[3]=5; source.port=4665;
        Probe probe; probe.node=publicKey; probe.peer=otherPublic; probe.nonce.fill(0x25); probe.mask=0;
        Header header; header.type=1; header.attempt.fill(0x18); header.generation=9; header.sequence=1;
        std::array<std::uint8_t,128> probeBody; Datagram request,response;
        Check(Encode(probe,probeBody) && Encode(header,probeBody.data(),probeBody.size(),request));
        Check(BuildChallenge(receiver,limiter,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,response));
        Check(response.size==92 && response.size<request.size);
        Envelope envelope; Challenge challenge;
        Check(ParseUntrusted(response.bytes.data(),response.size,envelope) && envelope.header.type==2 &&
            envelope.header.attempt==header.attempt && Decode(envelope.payload,envelope.payloadSize,challenge));
        Prove prove; prove.probe=probe; prove.cookie=challenge.cookie; prove.epoch=challenge.epoch;
        std::array<std::uint8_t,212> proveBody; header.type=3;
        Check(Encode(prove,proveBody) && Encode(header,proveBody.data(),proveBody.size(),request));
        SignatureInput input; Check(BuildSignatureInput(request.bytes.data(),request.size,input));
        Check(eSELive::SignMessage(privateKey.data(),publicKey.data(),input.bytes.data(),input.size,request.bytes.data()+request.size-64));
        Prove verified;
        Check(VerifyProve(receiver,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified) && verified.probe.mask==0);
        Check(VerifyProve(receiver,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified)); // stateless primitive; replay gate still required
        Sessions sessions;
        Check(AdmitProve(receiver,sessions,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified)==Admission::Accepted);
        Check(AdmitProve(receiver,sessions,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified)==Admission::Duplicate);
        {
            // Real signed packets and HMAC cookies, synthetic monotonic idle.
            // No MFC/file/network recovery is claimed by this crypto fixture.
            const auto savedVerified=verified;
            const auto savedProbeBody=probeBody;
            const auto savedProveBody=proveBody;
            const auto savedInput=input;
            Sessions expired;
            Check(AdmitProve(receiver,expired,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified)==Admission::Accepted);
            Check(expired.RetainDownload(publicKey,source,header,19,32000));
            const auto oldPacket=request;
            Header fresh=header;
            Check(expired.NextExpiredBootstrap(publicKey,source,fresh,97000,fresh) && fresh.sequence==2);
            Check(!expired.Current(publicKey,source,header,97000));
            Probe newProbe=probe; newProbe.nonce[0]^=1; newProbe.mask=4;
            Datagram freshProbe,freshChallenge,freshProof;
            Check(Encode(newProbe,probeBody) && Encode(fresh,probeBody.data(),probeBody.size(),freshProbe));
            ChallengeLimit freshLimit;
            Check(BuildChallenge(receiver,freshLimit,source,otherPublic,publicKey,freshProbe.bytes.data(),freshProbe.size,97000,freshChallenge));
            Envelope issued; Challenge newChallenge;
            Check(ParseUntrusted(freshChallenge.bytes.data(),freshChallenge.size,issued) && Decode(issued.payload,issued.payloadSize,newChallenge));
            PendingBootstrapChallenge pending;
            Check(pending.Remember(fresh,newProbe,newChallenge,97000,99000));
            Prove newProof; newProof.probe=newProbe; newProof.cookie=newChallenge.cookie; newProof.epoch=newChallenge.epoch;
            fresh.type=ese::wire::kEseWireUdpProve;
            Check(Encode(newProof,proveBody) && Encode(fresh,proveBody.data(),proveBody.size(),freshProof));
            Check(BuildSignatureInput(freshProof.bytes.data(),freshProof.size,input));
            Check(eSELive::SignMessage(privateKey.data(),publicKey.data(),input.bytes.data(),input.size,freshProof.bytes.data()+freshProof.size-64));
            Envelope oldEnvelope; Prove oldProof;
            Check(ParseUntrusted(oldPacket.bytes.data(),oldPacket.size,oldEnvelope) && Decode(oldEnvelope.payload,oldEnvelope.payloadSize,oldProof));
            Check(!pending.Matches(oldEnvelope.header,oldProof,97000));
            Check(!VerifyProve(receiver,source,otherPublic,publicKey,oldPacket.bytes.data(),oldPacket.size,97000,verified));
            Check(pending.Matches(fresh,newProof,97000));
            auto damaged=freshProof; damaged.bytes[damaged.size-1]^=1;
            Check(!VerifyProve(receiver,source,otherPublic,publicKey,damaged.bytes.data(),damaged.size,97000,verified));
            Check(VerifyProve(receiver,source,otherPublic,publicKey,freshProof.bytes.data(),freshProof.size,97000,verified));
            std::array<std::uint8_t,32> freshDigest{};
            CryptoPP::SHA256 hash; hash.CalculateDigest(freshDigest.data(),freshProof.bytes.data(),freshProof.size);
            Check(expired.ReadmitFreshVerified(publicKey,source,fresh,freshDigest,pending.Issued(),97000)==Admission::Accepted);
            Check(expired.Current(publicKey,source,fresh,97000) && !expired.Current(publicKey,source,header,97000));
            Check(expired.ReadmitFreshVerified(publicKey,source,fresh,freshDigest,pending.Issued(),97001)==Admission::Rejected);
            LabSigner ackSigner(otherPrivate,otherPublic);
            Datagram oldAck,newAck; Ack checkedAck;
            Check(BuildAck(oldProof,header,0,otherPublic,ackSigner,oldAck));
            Check(BuildAck(newProof,fresh,4,otherPublic,ackSigner,newAck));
            Check(!VerifyAck(otherPublic,fresh,newProbe.nonce,4,oldAck.bytes.data(),oldAck.size,checkedAck));
            Check(!VerifyAck(otherPublic,fresh,probe.nonce,4,newAck.bytes.data(),newAck.size,checkedAck));
            auto damagedAck=newAck; damagedAck.bytes[damagedAck.size-1]^=1;
            Check(!VerifyAck(otherPublic,fresh,newProbe.nonce,4,damagedAck.bytes.data(),damagedAck.size,checkedAck));
            Check(VerifyAck(otherPublic,fresh,newProbe.nonce,4,newAck.bytes.data(),newAck.size,checkedAck) && checkedAck.selected==4);
            Sessions initiatorLedger;
            std::array<std::uint8_t,32> oldAckDigest{},newAckDigest{};
            hash.CalculateDigest(oldAckDigest.data(),oldAck.bytes.data(),oldAck.size);
            hash.CalculateDigest(newAckDigest.data(),newAck.bytes.data(),newAck.size);
            Check(initiatorLedger.AdmitVerified(otherPublic,source,header,oldAckDigest,32000)==Admission::Accepted);
            Check(initiatorLedger.RetainDownload(otherPublic,source,header,20,32000));
            auto outbound=header;
            Check(initiatorLedger.NextExpiredBootstrap(otherPublic,source,outbound,97000,outbound) && outbound.sequence==fresh.sequence);
            Check(!initiatorLedger.Current(otherPublic,source,outbound,97000));
            Check(initiatorLedger.ReadmitFreshVerified(otherPublic,source,outbound,newAckDigest,97000,97000)==Admission::Accepted);
            Check(initiatorLedger.Current(otherPublic,source,outbound,97000));
            Check(!expired.Current(publicKey,source,fresh,127000));
            std::puts("Expired Control/1 retained65s fresh HMAC/Ed25519 PROVE replay/corrupt rejection PASS (synthetic clock; no MFC download)");
            verified=savedVerified; probeBody=savedProbeBody; proveBody=savedProveBody; input=savedInput;
        }
        DescriptorGetLimit<> contactLimit; LabSigner contactSigner(privateKey,publicKey);
        auto contactHeader=header; contactHeader.type=ese::wire::kEseWireUdpK6ContactGet; contactHeader.sequence=2;
        Datagram contactPacket; Header admittedContact;
        Check(BuildContactGet(contactHeader,publicKey,contactSigner,contactPacket));
        Sessions absentSession;
        Check(!AdmitContactGet(absentSession,contactLimit,source,publicKey,contactPacket.bytes.data(),contactPacket.size,32000,admittedContact));
        auto wrongContactSource=source; ++wrongContactSource.port;
        Check(!AdmitContactGet(sessions,contactLimit,wrongContactSource,publicKey,contactPacket.bytes.data(),contactPacket.size,32000,admittedContact));
        Check(AdmitContactGet(sessions,contactLimit,source,publicKey,contactPacket.bytes.data(),contactPacket.size,32000,admittedContact));
        Check(!AdmitContactGet(sessions,contactLimit,source,publicKey,contactPacket.bytes.data(),contactPacket.size,32000,admittedContact));
        for(unsigned sequence=3;sequence<=6;++sequence) {
            contactHeader.sequence=sequence; Check(BuildContactGet(contactHeader,publicKey,contactSigner,contactPacket));
            Check(AdmitContactGet(sessions,contactLimit,source,publicKey,contactPacket.bytes.data(),contactPacket.size,32000,admittedContact)==(sequence<6));
        }
        ese::discovery::DirectFind limitedQuery,limitedResult; limitedQuery.requester=publicKey; limitedQuery.fileSize=123; limitedQuery.maximum=1;
        contactHeader.type=ese::wire::kEseWireUdpK6DirectFind; contactHeader.sequence=7;
        Check(BuildDirectFind(contactHeader,limitedQuery,1000,contactSigner,contactPacket));
        Check(!AdmitDirectFind(sessions,contactLimit,source,publicKey,contactPacket.bytes.data(),contactPacket.size,1000,32000,admittedContact,limitedResult));
        LabSigner responder(otherPrivate,otherPublic),wrongSigner(privateKey,publicKey);
        Datagram ackPacket; Ack receivedAck;
        Check(BuildAck(verified,header,0,otherPublic,responder,ackPacket) && ackPacket.size==137);
        Check(VerifyAck(otherPublic,header,probe.nonce,0,ackPacket.bytes.data(),ackPacket.size,receivedAck) && receivedAck.selected==0);
        auto wrongNonce=probe.nonce; wrongNonce[0]^=1;
        Check(!VerifyAck(otherPublic,header,wrongNonce,0,ackPacket.bytes.data(),ackPacket.size,receivedAck));
        for(unsigned field=0;field<3;++field) {
            auto wrongHeader=header;
            if(field==0) wrongHeader.attempt[0]^=1;
            if(field==1) ++wrongHeader.generation;
            if(field==2) ++wrongHeader.sequence;
            Check(!VerifyAck(otherPublic,wrongHeader,probe.nonce,0,ackPacket.bytes.data(),ackPacket.size,receivedAck));
        }
        Check(!VerifyAck(publicKey,header,probe.nonce,0,ackPacket.bytes.data(),ackPacket.size,receivedAck));
        Check(!BuildAck(verified,header,4,otherPublic,responder,ackPacket) && ackPacket.size==0);
        Check(!BuildAck(verified,header,0,otherPublic,wrongSigner,ackPacket));
        responder.fail=true; Check(!BuildAck(verified,header,0,otherPublic,responder,ackPacket));
        responder.fail=false;
        auto profile=verified; profile.probe.mask=6;
        for(const auto selected : {2,4}) {
            Check(BuildAck(profile,header,static_cast<std::uint8_t>(selected),otherPublic,responder,ackPacket));
            Check(VerifyAck(otherPublic,header,probe.nonce,6,ackPacket.bytes.data(),ackPacket.size,receivedAck) && receivedAck.selected==selected);
            Check(!VerifyAck(otherPublic,header,probe.nonce,0,ackPacket.bytes.data(),ackPacket.size,receivedAck));
        }
        for(const auto selected : {1,3,6,8,255}) Check(!BuildAck(profile,header,static_cast<std::uint8_t>(selected),otherPublic,responder,ackPacket));
        auto corrupt=request; corrupt.bytes[251]^=1;
        Sessions cleanSessions;
        Check(AdmitProve(receiver,cleanSessions,source,otherPublic,publicKey,corrupt.bytes.data(),corrupt.size,32000,verified)==Admission::Rejected);
        Check(verified.cookie==std::array<std::uint8_t,16>{});
        Check(AdmitProve(receiver,cleanSessions,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified)==Admission::Accepted);
        Check(AdmitProve(receiver,sessions,source,otherPublic,publicKey,request.bytes.data(),request.size,61999,verified)==Admission::Duplicate);
        Check(VerifyProve(receiver,source,otherPublic,publicKey,request.bytes.data(),request.size,62000,verified)); // cookie still live
        Check(AdmitProve(receiver,sessions,source,otherPublic,publicKey,request.bytes.data(),request.size,62000,verified)==Admission::Rejected); // idle tombstone blocks resurrection
        auto changed=source; ++changed.port;
        Check(!VerifyProve(receiver,changed,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified));
        Check(verified.cookie==std::array<std::uint8_t,16>{});
        Check(!VerifyProve(receiver,source,publicKey,publicKey,request.bytes.data(),request.size,32000,verified));
        Check(!VerifyProve(receiver,source,otherPublic,otherPublic,request.bytes.data(),request.size,32000,verified));
        Check(!VerifyProve(receiver,source,otherPublic,publicKey,request.bytes.data(),request.size,64000,verified));
        Check(!VerifyProve(receiver,source,otherPublic,publicKey,nullptr,252,32000,verified));
        request.bytes[251]^=1;
        Check(!VerifyProve(receiver,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,verified));
        header.type=1; Check(Encode(header,probeBody.data(),probeBody.size(),request));
        for(unsigned i=0;i<3;++i) Check(BuildChallenge(receiver,limiter,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,response));
        Check(!BuildChallenge(receiver,limiter,source,otherPublic,publicKey,request.bytes.data(),request.size,32000,response) && response.size==0);
    }
    for(unsigned i=0;i<32;++i) key[i]=static_cast<std::uint8_t>(i);
    ese::udp::Endpoint endpoint; endpoint.address[0]=203; endpoint.address[2]=113; endpoint.address[3]=8; endpoint.port=0x1234;
    CookieProof proof; proof.attempt.fill(1); proof.generation=0x0102030405060708ULL; proof.nonce.fill(2); proof.epoch=0x91a2b3c4;
    std::array<std::uint8_t,16> cookie{};
    const std::array<std::uint8_t,16> golden={0x8b,0xf1,0xef,0x14,0x8e,0xc9,0x8f,0x8c,0x44,0x1a,0xa0,0x3b,0x0c,0xee,0xec,0x06};
    Check(ComputeCookie(key,endpoint,proof,signer,cookie) && cookie==golden);
    CookieAuthority authority,other;
    Check(!authority.Issue(endpoint,proof,signer,32000) && !authority.Verify(endpoint,proof,signer,32000));
    Check(authority.Initialize() && authority.Initialize() && other.Initialize());
    Check(authority.Issue(endpoint,proof,signer,32000) && proof.epoch==2);
    Check(authority.Verify(endpoint,proof,signer,32000) && authority.Verify(endpoint,proof,signer,63999));
    Check(!authority.Verify(endpoint,proof,signer,64000) && !authority.Verify(endpoint,proof,signer,31999));
    Check(!other.Verify(endpoint,proof,signer,32000));
    auto changedEndpoint=endpoint; ++changedEndpoint.port;
    Check(!authority.Verify(changedEndpoint,proof,signer,32000));
    changedEndpoint=endpoint; ++changedEndpoint.address[3];
    Check(!authority.Verify(changedEndpoint,proof,signer,32000));
    for(unsigned field=0;field<5;++field) {
        auto changed=proof; auto wrongSigner=signer;
        if(field==0) changed.attempt[0]^=1;
        if(field==1) ++changed.generation;
        if(field==2) changed.nonce[0]^=1;
        if(field==3) --changed.epoch;
        if(field==4) wrongSigner[0]^=1;
        Check(!authority.Verify(endpoint,changed,wrongSigner,32000));
    }
    for(unsigned i=0;i<16;++i) { auto changed=proof; changed.cookie[i]^=1; Check(!authority.Verify(endpoint,changed,signer,32000)); }
    endpoint.port=0; Check(!authority.Issue(endpoint,proof,signer,32000) && proof.cookie==std::array<std::uint8_t,16>{});
    std::printf("Control/1 HMAC cookie: %u checks PASS (real Crypto++; endpoint/state machine integration pending)\n",checks);
}
