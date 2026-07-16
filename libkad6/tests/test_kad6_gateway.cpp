// SPDX-License-Identifier: MIT
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_gateway.h"
#include "kad6/kad6_hints.h"
#include "kad6/kad6_vep.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;
static int g_pass=0,g_fail=0;
#define CHECK(c,m) do{if(c)++g_pass;else{++g_fail;std::printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);}}while(0)

static bool MockHmac(const Byte*k,std::size_t kn,const Byte*m,std::size_t mn,Byte out[32]){
    std::uint64_t h=1469598103934665603ull;for(std::size_t i=0;i<kn;++i){h^=k[i];h*=1099511628211ull;}for(std::size_t i=0;i<mn;++i){h^=m[i];h*=1099511628211ull;}for(int i=0;i<32;++i){h^=i+0x9e;h*=1099511628211ull;out[i]=static_cast<Byte>(h>>(8*(i%8)));}return true;
}
static void MockSignature(const Byte*m,std::size_t n,Byte out[64]){std::uint64_t h=0xcbf29ce484222325ull;for(std::size_t i=0;i<n;++i){h^=m[i];h*=0x100000001b3ull;}for(int i=0;i<64;++i){h^=static_cast<Byte>(i);h*=0x100000001b3ull;out[i]=static_cast<Byte>(h>>(8*(i%8)));}}
static bool MockSign(const Byte*,std::size_t,const Byte*m,std::size_t n,Byte out[64]){MockSignature(m,n,out);return true;}
static bool MockVerify(const Byte[32],const Byte*m,std::size_t n,const Byte sig[64]){Byte expected[64];MockSignature(m,n,expected);return Kad6CtEqual(expected,sig,64);}
static Kad6CryptoHooks Hooks(){Kad6CryptoHooks h;h.hmac_sha256=&MockHmac;h.ed25519_sign=&MockSign;h.ed25519_verify=&MockVerify;return h;}
static bool Allow(void*,Byte,const K6Endpoint&){return true;} static bool Consume(void*,const K6TargetTicket&){return true;}
static K6TargetPolicy Policy(){K6TargetPolicy p;p.allow_target=&Allow;p.consume_use=&Consume;return p;}
static K6Endpoint Endpoint(Byte a,Byte b,Byte c,Byte d,std::uint16_t port){K6Endpoint e;e.addr.family=Kad6Address::Family::IPv4;e.addr.addr={a,b,c,d};e.tcp_port=port;e.udp_port=port+10;e.transport_flags=kK6EpTcpEd2k;e.valid_until=2000;return e;}
static std::vector<Byte> Ticket(const K6Endpoint&e,K6Provenance provenance,std::uint64_t session,std::uint64_t stream,std::uint64_t seq,const Hash16&object,const Hash32&digest){K6TargetTicket t;t.service=static_cast<Byte>(K6TicketService::Ed2kTcp);t.lease_id=77;t.provenance_kind=static_cast<Byte>(provenance);t.provenance_session=session;t.provenance_stream=stream;t.provenance_seq=seq;t.provenance_digest=digest;t.target_endpoint=e;t.object_hash=object;t.issued_at=1000;t.expires_at=1200;t.max_bytes=1000000;t.max_connections=1;for(Byte i=0;i<16;++i)t.nonce[i]=i+1;std::vector<Byte>w;const Byte secret[]={1,2,3};CHECK(IssueK6TargetTicket(Hooks(),Policy(),secret,sizeof(secret),t,w)==Kad6Status::Ok,"issue fixture ticket");return w;}

static void TestTicketAndDial(){
    K6TargetTicketRequest q;q.source_request_id=9;q.service=2;q.requested_max_bytes=12345;for(Byte i=0;i<16;++i){q.result_id[i]=i;q.object_hash[i]=0xf0+i;}
    std::vector<Byte>w;CHECK(EncodeK6TargetTicketRequest(q,w)==Kad6Status::Ok,"ticket request encode");K6TargetTicketRequest qr;CHECK(DecodeK6TargetTicketRequest(w.data(),w.size(),qr)==Kad6Status::Ok&&qr.source_request_id==9&&qr.object_hash==q.object_hash,"ticket request round trip");
    Hash32 digest{};digest[0]=1;auto tw=Ticket(Endpoint(8,8,8,8,4662),K6Provenance::KadResult,1,2,3,q.object_hash,digest);
    K6TargetTicketResponse tr;tr.status=K6TargetTicketStatus::Ok;tr.ticket=tw;CHECK(EncodeK6TargetTicketResponse(tr,w)==Kad6Status::Ok,"ticket response encode");K6TargetTicketResponse td;CHECK(DecodeK6TargetTicketResponse(w.data(),w.size(),td)==Kad6Status::Ok&&td.ticket==tw,"ticket response round trip");
    K6Dial d;d.ticket=tw;d.initial_data={0xe3,1,0,0,0,1};CHECK(EncodeK6Dial(d,w)==Kad6Status::Ok,"dial encode");K6Dial dd;CHECK(DecodeK6Dial(w.data(),w.size(),dd)==Kad6Status::Ok&&dd.initial_data==d.initial_data,"dial round trip");
    d.initial_data.resize(kK6DialMaxInitialData+1);CHECK(EncodeK6Dial(d,w)==Kad6Status::BadValue,"dial initial cap");
    K6DialResult ok;ok.stream_id=44;ok.status=K6DialStatus::Ok;ok.apparent_local_endpoint=Endpoint(9,9,9,9,4662);ok.remote_endpoint=Endpoint(8,8,8,8,4662);ok.max_bytes=999;ok.idle_timeout_ms=60000;CHECK(EncodeK6DialResult(ok,w)==Kad6Status::Ok,"dial result encode");K6DialResult od;CHECK(DecodeK6DialResult(w.data(),w.size(),od)==Kad6Status::Ok&&od.stream_id==44&&od.remote_endpoint.tcp_port==4662,"dial result round trip");
}

static void TestStream(){
    K6StreamFlowState flow(5);K6StreamData d;d.stream_id=7;d.data={1,2,3};std::vector<Byte>w;CHECK(EncodeK6StreamData(d,w)==Kad6Status::Ok,"stream data encode");K6StreamData rd;CHECK(DecodeK6StreamData(w.data(),w.size(),rd)==Kad6Status::Ok&&rd.data==d.data,"stream data round trip");CHECK(flow.AcceptFrame(0,0,3)==Kad6Status::Ok,"flow metadata commit");CHECK(flow.Accept(rd)==Kad6Status::StaleEpoch,"flow replay");d.sequence=1;d.data={4,5};CHECK(flow.Accept(d)==Kad6Status::Ok,"flow exact next and quota");d.sequence=2;d.data={6};CHECK(flow.Accept(d)==Kad6Status::TooLarge,"flow quota cap");K6StreamData reverse;reverse.stream_id=7;reverse.direction=1;reverse.data={9};CHECK(flow.Accept(reverse)==Kad6Status::TooLarge,"flow quota is aggregate across directions");K6StreamHalfClose half;half.stream_id=7;half.last_sequence=1;CHECK(flow.HalfClose(half)==Kad6Status::Ok,"half close exact last seq");d.data.clear();CHECK(flow.Accept(d)==Kad6Status::StaleEpoch,"data after half close");K6StreamClose close;close.stream_id=7;close.last_tx_sequence=1;close.total_tx_bytes=5;CHECK(flow.Close(close)==Kad6Status::Ok,"close counters exact");CHECK(flow.Close(close)==Kad6Status::StaleEpoch,"close replay");
}

static void U16(std::vector<Byte>&v,std::uint16_t x){v.push_back(static_cast<Byte>(x));v.push_back(static_cast<Byte>(x>>8));}static void U32(std::vector<Byte>&v,std::uint32_t x){for(int i=0;i<4;++i)v.push_back(static_cast<Byte>(x>>(8*i)));}
static void TestPexHints(){
    Hash16 object{};for(Byte i=0;i<16;++i)object[i]=i+1;std::vector<Byte>p;p.push_back(4);p.insert(p.end(),object.begin(),object.end());U16(p,2);
    U32(p,0x08090a0b);U16(p,4662);U32(p,0);U16(p,0);for(Byte i=0;i<16;++i)p.push_back(0x20+i);p.push_back(3);
    U32(p,1);U16(p,4663);U32(p,0x01020304);U16(p,4661);for(Byte i=0;i<16;++i)p.push_back(0);p.push_back(0);
    K6ParsedPex parsed;CHECK(DecodeEd2kSourceExchange(kEd2kOpAnswerSources2,p.data(),p.size(),parsed)==Kad6Status::Ok,"SX2 v4 exact parse");CHECK(parsed.version==4&&parsed.sources.size()==2&&!parsed.sources[0].low_id&&parsed.sources[1].low_id,"PEX high/LowID classification");CHECK(parsed.sources[0].endpoint.addr.addr[0]==8&&parsed.sources[0].endpoint.addr.addr[1]==9&&parsed.sources[0].endpoint.addr.addr[2]==10&&parsed.sources[0].endpoint.addr.addr[3]==11,"PEX HybridID byte order");Hash16 firstUser{};if(!parsed.sources.empty())firstUser=parsed.sources[0].user_hash;auto bad=p;bad.push_back(0);CHECK(DecodeEd2kSourceExchange(kEd2kOpAnswerSources2,bad.data(),bad.size(),parsed)==Kad6Status::Malformed,"PEX trailing rejected");
    std::vector<Byte>sx1;sx1.insert(sx1.end(),object.begin(),object.end());U16(sx1,1);U32(sx1,1);U16(sx1,4662);U32(sx1,0x01020304);U16(sx1,4661);CHECK(DecodeEd2kSourceExchange(kEd2kOpAnswerSources,sx1.data(),sx1.size(),parsed)==Kad6Status::Ok&&parsed.sources.size()==1&&parsed.sources[0].low_id,"SX1 LowID stays non-routable");
    Hash32 digest{};for(Byte i=0;i<32;++i)digest[i]=0x40+i;K6SourceHints hints;hints.source_session_id=11;hints.source_stream_id=12;hints.source_message_seq=13;hints.pex_version=4;hints.object_hash=object;hints.exterior_message_hash=digest;K6SourceHint h;h.endpoint=Endpoint(8,8,8,8,4662);h.user_hash=firstUser;h.crypt_options=3;h.ticket=Ticket(h.endpoint,K6Provenance::Pex,11,12,13,object,digest);hints.sources.push_back(h);std::vector<Byte>w;CHECK(EncodeK6SourceHints(hints,w)==Kad6Status::Ok,"source hints encode");K6SourceHints hd;CHECK(DecodeK6SourceHints(w.data(),w.size(),hd)==Kad6Status::Ok&&hd.sources.size()==1&&hd.sources[0].ticket==h.ticket,"source hints exact round trip");w.back()^=1;CHECK(DecodeK6SourceHints(w.data(),w.size(),hd)==Kad6Status::Ok,"hint codec preserves opaque MAC tamper for verifier");
}

static void TestVep(){K6VirtualIdentityEndpoint v;v.apparent_source_ip.family=Kad6Address::Family::IPv4;v.apparent_source_ip.addr={8,8,4,4};v.apparent_tcp_port=4662;v.apparent_udp_port=4672;v.source_lease_id=77;v.valid_until=1100;for(Byte i=0;i<32;++i)v.exit_node_pub[i]=0x80+i;std::vector<Byte>w;CHECK(SignK6Vep(Hooks(),v,w)==Kad6Status::Ok,"VEP sign");K6VirtualIdentityEndpoint d;CHECK(DecodeK6Vep(w.data(),w.size(),d)==Kad6Status::Ok&&VerifyK6Vep(Hooks(),d,1000)==Kad6Status::Ok,"VEP decode verify");d.apparent_tcp_port^=1;CHECK(VerifyK6Vep(Hooks(),d,1000)==Kad6Status::AuthFailed,"VEP tamper rejected");CHECK(VerifyK6Vep(Hooks(),v,1100)==Kad6Status::Expired,"VEP expiry boundary");}

static void TestEd2kPolicy(){Byte hello[]={16};std::vector<Byte>w;CHECK(EncodeK6Ed2kFrame(kEd2kProtocolBase,0x01,hello,sizeof(hello),w)==Kad6Status::Ok,"ed2k frame encode");K6Ed2kFrameView f;CHECK(DecodeK6Ed2kFrame(w.data(),w.size(),f)==Kad6Status::Ok&&ClassifyK6Ed2kFrame(f.protocol,f.opcode)==K6Ed2kFrameClass::Hello,"ed2k frame/class round trip");CHECK(K6Ed2kPolicy(K6Ed2kDirection::OriginToRemote,K6Ed2kFrameClass::Hello)==K6Ed2kDisposition::RewriteEndpoint,"HELLO must rewrite");CHECK(K6Ed2kPolicy(K6Ed2kDirection::RemoteToOrigin,K6Ed2kFrameClass::SourceExchange)==K6Ed2kDisposition::ConvertToHints,"PEX must convert");CHECK(ClassifyK6Ed2kFrame(kEd2kProtocolBase,0x47)==K6Ed2kFrameClass::SafeControl,"download request allow-listed");CHECK(K6Ed2kPolicy(K6Ed2kDirection::OriginToRemote,ClassifyK6Ed2kFrame(kEd2kProtocolBase,0x4d))==K6Ed2kDisposition::Drop,"endpoint-bearing client id dropped");CHECK(K6Ed2kPolicy(K6Ed2kDirection::OriginToRemote,ClassifyK6Ed2kFrame(kEd2kProtocolEmule,0xc0))==K6Ed2kDisposition::Reject,"unknown extension fails closed");w.push_back(0);CHECK(DecodeK6Ed2kFrame(w.data(),w.size(),f)==Kad6Status::Malformed,"ed2k trailing reject");Kad6Address a;a.family=Kad6Address::Family::IPv4;a.addr={9,9,9,9};Byte oldIp[4]={1,2,3,4};CHECK(EncodeK6Ed2kFrame(kEd2kProtocolEmule,0x98,oldIp,4,w)==Kad6Status::Ok,"public ip fixture");CHECK(DecodeK6Ed2kFrame(w.data(),w.size(),f)==Kad6Status::Ok&&RewriteK6Ed2kPublicIpAnswer(f,a,w)==Kad6Status::Ok&&w[6]==9,"public IP rewritten to exit");}

int main(){TestTicketAndDial();TestStream();TestPexHints();TestVep();TestEd2kPolicy();std::printf("test_kad6_gateway: %d passed, %d failed\n",g_pass,g_fail);return g_fail?1:0;}
