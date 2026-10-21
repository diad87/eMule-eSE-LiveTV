#include "../srchybrid/EseKad6IndexService.h"
#include "../srchybrid/EseKad6IndexBootstrap.h"
#include "../srchybrid/EseKad6PublicationAttempt.h"
#include "../srchybrid/EseKad6PublicationDescriptor.h"
#include "../srchybrid/EseKad6DiscoveryOutcome.h"
#include "../srchybrid/EseKad6NearestContacts.h"
#include "../srchybrid/LiveCrypto.h"
#include <cstdio>
#include <cstdlib>
using namespace ese;
static unsigned checks=0;
static void CheckAt(bool ok,unsigned line) { ++checks; if(!ok) { std::printf("FAIL check%u line%u\n",checks,line); std::exit(1); } }
#define Check(...) CheckAt((__VA_ARGS__),__LINE__)
struct Identity final : control::Signer {
    std::array<std::uint8_t,32> pub{},secret{};
    Identity() { Check(eSELive::GenerateBroadcasterKeypair(pub.data(),secret.data())); }
    ~Identity() { volatile std::uint8_t* p=secret.data(); for(unsigned i=0;i<secret.size();++i) p[i]=0; }
    bool Sign(const std::uint8_t* bytes,std::size_t size,std::array<std::uint8_t,64>& signature) noexcept override {
        return eSELive::SignMessage(secret.data(),pub.data(),bytes,size,signature.data());
    }
};
int main() {
    {
        std::array<unsigned char,16> target{},id{};
        std::array<unsigned char,32> node{};
        discovery::NearestContacts<3> nearest(target);
        for(unsigned value : {9U,5U,7U,2U}) { id[0]=static_cast<unsigned char>(value); node[0]=id[0]; Check(nearest.Add(id,node,value)); }
        Check(nearest.Count()==3 && nearest[0].ordinal==2 && nearest[1].ordinal==5 && nearest[2].ordinal==7);
        Check(!nearest.Add(id,node,99));
        target[0]=0x80; discovery::NearestContacts<1> xorNearest(target);
        id[0]=1; node[0]=1; Check(xorNearest.Add(id,node,1));
        id[0]=0x81; node[0]=2; Check(xorNearest.Add(id,node,2));
        Check(xorNearest[0].ordinal==2);
    }
    Identity publisher,requester,witness;
    {
        discovery::DiscoveryStatus status;
        Check(status.State()==discovery::DiscoveryOutcome::Idle);
        status.MissingBootstrap(); status.Cancelled();
        Check(status.State()==discovery::DiscoveryOutcome::BootstrapRequired);
        status.Started(); status.Expired(); status.Cancelled();
        Check(status.State()==discovery::DiscoveryOutcome::DiscoveryUnavailable);
        status.Started(); status.Resolved(); status.Expired();
        Check(status.State()==discovery::DiscoveryOutcome::SourceReady);
        status.Cancelled(); Check(status.State()==discovery::DiscoveryOutcome::Idle);
    }
    {
        control::PacketBudget quotaBudget;
        auto limited=std::make_unique<discovery::Kad6IndexService<1>>(quotaBudget);
        auto ledger=std::make_unique<control::Sessions>();
        udp::Endpoint endpoint; endpoint.address[0]=52; endpoint.port=4665;
        control::Header context; context.type=wire::kEseWireUdpProve; context.attempt[0]=5;
        context.generation=7; context.sequence=1; std::array<std::uint8_t,32> proof{}; proof[0]=1;
        Check(ledger->AdmitVerified(publisher.pub,endpoint,context,proof,100)==control::Admission::Accepted);
        std::array<std::uint8_t,16> hash{},user{},kad{};
        std::array<discovery::OwnedPublicationCandidate,2> routes{};
        std::array<std::uint8_t,discovery::DescriptorMax> descriptor{};
        std::array<std::uint8_t,173> sourceBytes{}; std::size_t length=0;
        for(unsigned file=1;file<=2;++file) {
            hash[0]=static_cast<std::uint8_t>(file);
            Check(discovery::BuildOwnedPublication(hash,123,7,8,publisher.pub,user,kad,routes,0,30,publisher,
                descriptor,length,sourceBytes,2000));
            control::Datagram request,response; context.type=wire::kEseWireUdpDescriptorPut; ++context.sequence;
            Check(control::BuildDescriptorPut(context,hash,descriptor.data(),length,publisher.pub,publisher,request));
            const auto now=100+1001*(file-1);
            Check(limited->Receive(*ledger,publisher.pub,endpoint,request.bytes.data(),request.size,2000,now,witness.pub,witness,response)
                ==discovery::IndexDispatch::Silent);
            context.type=wire::kEseWireUdpK6DirectPut; ++context.sequence;
            Check(control::BuildDirectPut(context,sourceBytes.data(),sourceBytes.size(),2000,publisher.pub,publisher,request));
            Check(limited->Receive(*ledger,publisher.pub,endpoint,request.bytes.data(),request.size,2000,now+1,witness.pub,witness,response)
                ==discovery::IndexDispatch::Reply);
            discovery::DirectSource source; std::uint8_t status=255;
            Check(control::VerifyDirectSource(publisher.pub,sourceBytes.data(),sourceBytes.size(),2000,source) &&
                control::VerifyDirectPutResult(witness.pub,context,source,2000,response.bytes.data(),response.size,status) &&
                status==(file==1 ? 0 : 2)); // capacity is LIMIT, never a bogus NEED_DESCRIPTOR loop
        }
        Check(limited->ChargedBytes()<=8*1024*1024);
    }
    {
        std::array<std::uint8_t,16> hash{},user{},kad{}; hash[0]=1; user[0]=2; kad[0]=3;
        std::array<discovery::OwnedPublicationCandidate,2> candidates{};
        candidates[0].endpoint.address[0]=52; candidates[0].endpoint.port=4662;
        candidates[0].transports=1; candidates[0].ttl=20;
        candidates[1].endpoint.address[0]=53; candidates[1].endpoint.port=4665;
        candidates[1].transports=4; candidates[1].ttl=15;
        std::array<std::uint8_t,discovery::DescriptorMax> descriptor{};
        std::array<std::uint8_t,173> source{}; std::size_t length=0;
        auto build=[&](unsigned count,std::uint64_t size=123) {
            return discovery::BuildOwnedPublication(hash,size,7,8,publisher.pub,user,kad,candidates,count,30,
                publisher,descriptor,length,source,2000);
        };
        Check(build(2));
        discovery::DirectSource record; discovery::DescriptorView view;
        Check(control::VerifyDirectSource(publisher.pub,source.data(),source.size(),2000,record) &&
            record.file==hash && record.fileSize==123 && record.generation==7 && record.serial==8 && record.ttl==30);
        Check(control::VerifyDescriptor(publisher.pub,record.digest,descriptor.data(),length,view));
        Check(build(0)); // metadata only is valid; never fabricate a reachable route
        candidates[0].endpoint.address[0]=10;
        Check(!build(1) && length==0);
        candidates[0].endpoint.address[0]=100; candidates[0].endpoint.address[1]=74;
        Check(!build(1));
        candidates[0].endpoint.address[0]=52; candidates[0].ttl=31;
        Check(!build(1)); candidates[0].ttl=20;
        Check(!build(3)); Check(!build(1,2001)); Check(!build(1,0));
    }
    {
        control::PacketBudget bootstrapBudget;
        auto bootstrap=std::make_unique<discovery::Kad6IndexBootstrap>(bootstrapBudget);
        auto ledger=std::make_unique<control::Sessions>();
        Check(bootstrap->Initialize());
        udp::Endpoint endpoint; endpoint.address[0]=52; endpoint.port=4665;
        control::Probe probe; probe.node=publisher.pub; probe.peer=witness.pub; probe.nonce.fill(4); probe.mask=4;
        control::Header context; context.type=wire::kEseWireUdpProbe; context.attempt.fill(7); context.generation=7; context.sequence=1;
        std::array<std::uint8_t,128> body{}; control::Datagram packet,response;
        Check(control::Encode(probe,body) && control::Encode(context,body.data(),body.size(),packet));
        std::array<std::uint8_t,32> peer{}; control::Header admitted;
        auto receive=[&](const udp::Endpoint& from,std::uint64_t now) {
            return bootstrap->Receive(*ledger,from,witness.pub,packet.bytes.data(),packet.size,now,witness,response,peer,admitted);
        };
        Check(receive(endpoint,100)==discovery::IndexBootstrapResult::Challenge && peer==std::array<std::uint8_t,32>{});
        const auto first=response;
        Check(receive(endpoint,101)==discovery::IndexBootstrapResult::Challenge &&
            response.size==first.size && !std::memcmp(response.bytes.data(),first.bytes.data(),first.size));
        control::Envelope envelope; control::Challenge challenge;
        Check(control::ParseUntrusted(response.bytes.data(),response.size,envelope) && control::Decode(envelope.payload,envelope.payloadSize,challenge));
        control::Prove proof; proof.probe=probe; proof.cookie=challenge.cookie; proof.epoch=challenge.epoch;
        std::array<std::uint8_t,212> proofBody{}; context.type=wire::kEseWireUdpProve;
        Check(control::Encode(proof,proofBody) && control::Encode(context,proofBody.data(),proofBody.size(),packet));
        control::SignatureInput input; std::array<std::uint8_t,64> signature{};
        Check(control::BuildSignatureInput(packet.bytes.data(),packet.size,input) && publisher.Sign(input.bytes.data(),input.size,signature));
        std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
        auto wrong=endpoint; wrong.port++;
        Check(receive(wrong,102)==discovery::IndexBootstrapResult::Rejected);
        packet.bytes[packet.size-1]^=1;
        Check(receive(endpoint,102)==discovery::IndexBootstrapResult::Rejected);
        packet.bytes[packet.size-1]^=1;
        Check(receive(endpoint,103)==discovery::IndexBootstrapResult::Accepted && peer==publisher.pub &&
            ledger->Current(publisher.pub,endpoint,admitted,103));
        control::Ack ack;
        Check(control::ParseUntrusted(response.bytes.data(),response.size,envelope) && control::Decode(envelope.payload,envelope.payloadSize,ack) && ack.selected==0);
        Check(receive(endpoint,104)==discovery::IndexBootstrapResult::Duplicate);
        Check(receive(endpoint,99)==discovery::IndexBootstrapResult::Rejected);
        Check(receive(endpoint,2100)==discovery::IndexBootstrapResult::Rejected); // retry did not renew 2s
    }
    control::PacketBudget budget;
    auto service=std::make_unique<discovery::Kad6IndexService<4>>(budget);
    auto sessions=std::make_unique<control::Sessions>();
    udp::Endpoint b,a; b.address[0]=52; b.address[1]=8; b.port=4665;
    a.address[0]=53; a.address[1]=9; a.port=4666;
    control::Header bh,ah; bh.type=ah.type=wire::kEseWireUdpProve;
    bh.attempt[0]=1; ah.attempt[0]=2; bh.generation=7; ah.generation=9; bh.sequence=ah.sequence=1;
    std::array<std::uint8_t,32> digest{}; digest[0]=1;
    // Explicit unit fixture admission only; no network return proof credited.
    Check(sessions->AdmitVerified(publisher.pub,b,bh,digest,100)==control::Admission::Accepted);
    Check(sessions->AdmitVerified(requester.pub,a,ah,digest,100)==control::Admission::Accepted);
    std::array<std::uint8_t,159> descriptor{};
    std::memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
    std::memcpy(descriptor.data()+29,publisher.pub.data(),32);
    discovery::DescriptorSignatureInput input; std::array<std::uint8_t,64> signature{};
    Check(discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),input) &&
        publisher.Sign(input.bytes.data(),input.size,signature));
    std::memcpy(descriptor.data()+95,signature.data(),64);
    discovery::DirectSource source; source.file[0]=1; source.fileSize=1234; source.node=publisher.pub;
    source.generation=7; source.serial=1; source.ttl=120;
    Check(control::DescriptorDigest(descriptor.data(),descriptor.size(),source.digest));
    std::array<std::uint8_t,173> signedSource{};
    Check(control::BuildDirectSource(source,2000,publisher,signedSource));
    {
        control::PacketBudget publicationBudget;
        auto receiver=std::make_unique<discovery::Kad6IndexService<4>>(publicationBudget);
        auto client=std::make_unique<control::Sessions>(); auto server=std::make_unique<control::Sessions>();
        auto context=bh; context.type=wire::kEseWireUdpProve; context.sequence=1;
        Check(client->AdmitVerified(witness.pub,a,context,digest,100)==control::Admission::Accepted);
        Check(server->AdmitVerified(publisher.pub,b,context,digest,100)==control::Admission::Accepted);
        discovery::PublicationAttempt publication;
        Check(publication.Start(*client,witness.pub,a,context,descriptor.data(),descriptor.size(),signedSource,2000,101,publisher));
        control::Datagram reply; std::uint8_t result=255;
        // Lose the descriptor; source must request one bounded restage.
        auto put=publication.SourcePacket();
        Check(receiver->Receive(*server,publisher.pub,b,put.bytes.data(),put.size,2000,102,witness.pub,witness,reply)==discovery::IndexDispatch::Reply);
        Check(publication.Receive(*client,a,reply.bytes.data(),reply.size,103,result) && result==1 &&
            publication.State()==discovery::PublicationState::Restage);
        Check(!publication.Restage(*client,1100,publisher));
        Check(!publication.Restage(*client,1102,publisher));
        Check(!publication.Restage(*client,1103,publisher));
        Check(publication.Restage(*client,1104,publisher));
        auto desc=publication.DescriptorPacket(); put=publication.SourcePacket();
        Check(receiver->Receive(*server,publisher.pub,b,desc.bytes.data(),desc.size,2000,1104,witness.pub,witness,reply)==discovery::IndexDispatch::Silent);
        Check(receiver->Receive(*server,publisher.pub,b,put.bytes.data(),put.size,2000,1105,witness.pub,witness,reply)==discovery::IndexDispatch::Reply);
        const auto saved=reply;
        auto wrong=a; wrong.port++;
        Check(!publication.Receive(*client,wrong,reply.bytes.data(),reply.size,1106,result));
        // Lose ACK then retransmit identical PUT: receiver returns exact ACK.
        Check(receiver->Receive(*server,publisher.pub,b,put.bytes.data(),put.size,2000,1106,witness.pub,witness,reply)==discovery::IndexDispatch::Reply &&
            reply.size==saved.size && !std::memcmp(reply.bytes.data(),saved.bytes.data(),saved.size));
        Check(publication.Receive(*client,a,reply.bytes.data(),reply.size,1107,result) && result==0 &&
            publication.State()==discovery::PublicationState::Stored);
        Check(!publication.Receive(*client,a,reply.bytes.data(),reply.size,1108,result));
        Check(!publication.Restage(*client,1108,publisher));
        discovery::PublicationAttempt expired;
        Check(expired.Start(*client,witness.pub,a,context,descriptor.data(),descriptor.size(),signedSource,2000,1110,publisher));
        Check(!expired.Current(*client,3110) && expired.State()==discovery::PublicationState::Failed);
    }
    control::Datagram packet,response;
    auto receive=[&](const Identity& identity,const udp::Endpoint& endpoint,std::uint64_t now) {
        return service->Receive(*sessions,identity.pub,endpoint,packet.bytes.data(),packet.size,2000,now,witness.pub,witness,response);
    };
    bh.type=wire::kEseWireUdpDescriptorPut; bh.sequence=2;
    Check(control::BuildDescriptorPut(bh,source.file,descriptor.data(),descriptor.size(),publisher.pub,publisher,packet));
    Check(receive(publisher,b,102)==discovery::IndexDispatch::Silent && !response.size);
    discovery::Locator locator; locator.node=source.node; locator.digest=source.digest; locator.serial=1; locator.ttl=120;
    ah.type=wire::kEseWireUdpDescriptorGet; ah.sequence=2;
    Check(control::BuildDescriptorGet(ah,source.file,locator,requester.pub,requester,packet));
    Check(receive(requester,a,103)==discovery::IndexDispatch::Reply);
    control::Envelope envelope; discovery::ResultView result;
    Check(control::VerifyEnvelopeSignature(witness.pub,response.bytes.data(),response.size) &&
        control::ParseUntrusted(response.bytes.data(),response.size,envelope) &&
        discovery::DecodeResult(envelope.payload,envelope.payloadSize,result) && result.status==1);
    bh.type=wire::kEseWireUdpK6DirectPut; bh.sequence=3;
    Check(control::BuildDirectPut(bh,signedSource.data(),signedSource.size(),2000,publisher.pub,publisher,packet));
    Check(receive(publisher,b,104)==discovery::IndexDispatch::Reply);
    std::uint8_t status=255;
    Check(control::VerifyDirectPutResult(witness.pub,bh,source,2000,response.bytes.data(),response.size,status) && status==0);
    const auto storedReply=response;
    control::Datagram deferredAck; udp::Endpoint deferredEndpoint;
    Check(service->PopSecondary(*sessions,104,deferredEndpoint,deferredAck) && deferredEndpoint==b &&
        control::VerifyEnvelopeSignature(witness.pub,deferredAck.bytes.data(),deferredAck.size) &&
        control::ParseUntrusted(deferredAck.bytes.data(),deferredAck.size,envelope) && envelope.header.sequence==2 &&
        discovery::DecodeResult(envelope.payload,envelope.payloadSize,result) && result.status==0 &&
        result.length==descriptor.size() && !std::memcmp(result.descriptor,descriptor.data(),descriptor.size()));
    Check(!service->PopSecondary(*sessions,104,deferredEndpoint,deferredAck));
    Check(receive(publisher,b,105)==discovery::IndexDispatch::Reply && response.size==storedReply.size &&
        !std::memcmp(response.bytes.data(),storedReply.bytes.data(),response.size));
    packet.bytes[packet.size-1]^=1;
    Check(receive(publisher,b,105)==discovery::IndexDispatch::Rejected && !response.size);
    packet.bytes[packet.size-1]^=1;
    auto wrongPort=b; wrongPort.port++;
    Check(receive(publisher,wrongPort,105)==discovery::IndexDispatch::Rejected);
    discovery::DirectFind query; query.file=source.file; query.fileSize=source.fileSize; query.requester=requester.pub; query.maximum=4;
    ah.type=wire::kEseWireUdpK6DirectFind; ah.sequence=3;
    std::array<std::uint8_t,32> findDigest{}; discovery::FindResultView found;
    Check(control::BuildDirectFind(ah,query,2000,requester,packet) &&
        control::DirectFindDigest(requester.pub,packet.bytes.data(),packet.size,2000,findDigest));
    Check(receive(requester,a,106)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectFindResultSignature(witness.pub,ah,query,findDigest,response.bytes.data(),response.size,2000,found) &&
        found.kind==0 && found.count==1 && control::VerifyDirectFindSources(found,2000));
    query.file[0]=2; ah.sequence=4;
    Check(control::BuildDirectFind(ah,query,2000,requester,packet) &&
        control::DirectFindDigest(requester.pub,packet.bytes.data(),packet.size,2000,findDigest));
    Check(receive(requester,a,107)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectFindResultSignature(witness.pub,ah,query,findDigest,response.bytes.data(),response.size,2000,found) && found.kind==2);
    ah.type=wire::kEseWireUdpDescriptorGet; ah.sequence=5;
    Check(control::BuildDescriptorGet(ah,source.file,locator,requester.pub,requester,packet));
    Check(receive(requester,a,108)==discovery::IndexDispatch::Reply &&
        control::ParseUntrusted(response.bytes.data(),response.size,envelope) &&
        discovery::DecodeResult(envelope.payload,envelope.payloadSize,result) && result.status==0 &&
        result.length==descriptor.size() && !std::memcmp(result.descriptor,descriptor.data(),descriptor.size()));
    ah.type=wire::kEseWireUdpK6DirectFind; ah.sequence=6; query.file=source.file;
    Check(control::BuildDirectFind(ah,query,2000,requester,packet));
    Check(receive(requester,a,109)==discovery::IndexDispatch::Rejected); // fifth GET/FIND in rolling second
    ah.sequence=7;
    Check(control::BuildDirectFind(ah,query,2000,requester,packet) &&
        control::DirectFindDigest(requester.pub,packet.bytes.data(),packet.size,2000,findDigest));
    Check(receive(requester,a,1110)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectFindResultSignature(witness.pub,ah,query,findDigest,response.bytes.data(),response.size,2000,found) &&
        found.entries[0].remainingTtl==118);
    bh.sequence=4;
    Check(control::BuildDirectPut(bh,signedSource.data(),signedSource.size(),2000,publisher.pub,publisher,packet));
    Check(receive(publisher,b,1111)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectPutResult(witness.pub,bh,source,2000,response.bytes.data(),response.size,status) && status==0);
    ah.type=wire::kEseWireUdpK6DirectFind; ah.sequence=8;
    Check(control::BuildDirectFind(ah,query,2000,requester,packet) &&
        control::DirectFindDigest(requester.pub,packet.bytes.data(),packet.size,2000,findDigest));
    Check(receive(requester,a,1112)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectFindResultSignature(witness.pub,ah,query,findDigest,response.bytes.data(),response.size,2000,found) &&
        found.entries[0].remainingTtl==118); // new PUT sequence does not renew duplicate source TTL
    source.file[0]=2;
    Check(control::BuildDirectSource(source,2000,publisher,signedSource));
    bh.sequence=5;
    Check(control::BuildDirectPut(bh,signedSource.data(),signedSource.size(),2000,publisher.pub,publisher,packet));
    Check(receive(publisher,b,2212)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectPutResult(witness.pub,bh,source,2000,response.bytes.data(),response.size,status) && status==1);
    bh.type=wire::kEseWireUdpDescriptorPut; bh.sequence=6;
    Check(control::BuildDescriptorPut(bh,source.file,descriptor.data(),descriptor.size(),publisher.pub,publisher,packet));
    Check(receive(publisher,b,2213)==discovery::IndexDispatch::Silent);
    bh.type=wire::kEseWireUdpK6DirectPut; bh.sequence=7;
    Check(control::BuildDirectPut(bh,signedSource.data(),signedSource.size(),2000,publisher.pub,publisher,packet));
    Check(receive(publisher,b,3213)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectPutResult(witness.pub,bh,source,2000,response.bytes.data(),response.size,status) && status==0);
    bh.sequence=8;
    Check(control::BuildDirectPut(bh,signedSource.data(),signedSource.size(),2000,publisher.pub,publisher,packet));
    Check(receive(publisher,b,3214)==discovery::IndexDispatch::Reply &&
        control::VerifyDirectPutResult(witness.pub,bh,source,2000,response.bytes.data(),response.size,status) && status==2);
    Check(service->ChargedBytes()<=8*1024*1024);
    Check(receive(publisher,b,3213)==discovery::IndexDispatch::Rejected); // clock regression
    ah.type=wire::kEseWireUdpProve; ah.attempt[0]=9; ah.sequence=1;
    Check(sessions->AdmitVerified(requester.pub,a,ah,digest,122214)==control::Admission::Accepted);
    ah.type=wire::kEseWireUdpDescriptorGet; ah.sequence=2;
    Check(control::BuildDescriptorGet(ah,source.file,locator,requester.pub,requester,packet));
    Check(receive(requester,a,122215)==discovery::IndexDispatch::Reply &&
        control::ParseUntrusted(response.bytes.data(),response.size,envelope) &&
        discovery::DecodeResult(envelope.payload,envelope.payloadSize,result) && result.status==1); // expired pair never answers GET
    std::printf("Kad6 index receiver: %u checks PASS (real signatures; fixture sessions; no service advertisement or data grant)\n",checks);
}
