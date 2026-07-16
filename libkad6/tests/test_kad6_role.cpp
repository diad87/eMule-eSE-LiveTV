// SPDX-License-Identifier: MIT
#include "kad6/kad6_role.h"

#include <cstdio>
#include <vector>

using namespace kad6;
static int pass=0,fail=0;
#define CHECK(c,m) do{if(c)++pass;else{++fail;std::printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);}}while(0)

static bool Sign(const Byte* key,std::size_t keyLen,const Byte* msg,std::size_t len,Byte sig[64]){
    if(!key||keyLen!=32)return false;for(std::size_t i=0;i<64;++i){Byte v=key[i%32]^static_cast<Byte>(i);
        for(std::size_t j=i;j<len;j+=64)v^=msg[j];sig[i]=v;}return true;}
static bool Verify(const Byte key[32],const Byte* msg,std::size_t len,const Byte sig[64]){
    Byte expected[64];return Sign(key,32,msg,len,expected)&&Kad6CtEqual(expected,sig,64);}
static Kad6CryptoHooks Hooks(){Kad6CryptoHooks h;h.ed25519_sign=&Sign;h.ed25519_verify=&Verify;return h;}

static K6RoleEvidence Native(std::uint64_t now){K6RoleEvidence e;e.access_kind=K6AccessKind::NativeIpv6;
    e.local_endpoint.family=Kad6Address::Family::IPv6;e.local_endpoint.addr={0x20,1,0xd,0xb8,1,0,0,0,0,0,0,0,0,0,0,1};
    e.endpoint_generation=4;e.observed_at=now-10;e.valid_until=now+300;
    e.outbound_authenticated_kad6=true;e.actual_public_endpoint=true;
    for(std::uint32_t asn:{64501u,64502u,64503u}){K6InboundProbe p;p.probe_asn=asn;
        p.endpoint_generation=4;p.udp_return_ok=p.tcp_return_ok=true;e.probes.push_back(p);}return e;}

int main(){const std::uint64_t now=1800000000;K6RoleEvidence native=Native(now);
    CHECK(ClassifyK6NodeRole(native,now)==K6NodeRole::Router,"native v6 plus three-AS UDP/TCP proof is Router");
    native.legacy_egress_ok=native.exit_service_policy_ok=true;
    CHECK(ClassifyK6NodeRole(native,now)==K6NodeRole::Exit,"Router plus egress and policy is Exit");
    K6RoleEvidence nat64=Native(now);nat64.access_kind=K6AccessKind::Nat64Dns64;
    K6Pref64 pref;pref.prefix_bits=96;pref.prefix={0,0x64,0xff,0x9b,0,0,0,0,0,0,0,0,0,0,0,0};pref.valid_until=now+60;
    nat64.local_endpoint.addr=pref.prefix;nat64.local_endpoint.addr[12]=8;nat64.local_endpoint.addr[13]=8;
    nat64.local_endpoint.addr[14]=8;nat64.local_endpoint.addr[15]=8;nat64.pref64.push_back(pref);
    CHECK(K6AddressMatchesPref64(nat64.local_endpoint,pref,now)&&
          ClassifyK6NodeRole(nat64,now)==K6NodeRole::OriginOnly,
          "NAT64 synthesized destination is never advertised");
    K6RoleEvidence xlat=Native(now);xlat.access_kind=K6AccessKind::Xlat464;xlat.actual_public_endpoint=false;
    CHECK(ClassifyK6NodeRole(xlat,now)==K6NodeRole::OriginOnly,"464XLAT remains OriginOnly");
    K6RoleEvidence churn=Native(now);churn.access_kind=K6AccessKind::PrefixChurn;
    for(auto& probe:churn.probes)probe.endpoint_generation=3;
    CHECK(ClassifyK6NodeRole(churn,now)==K6NodeRole::OriginOnly,"prefix churn invalidates old probes");
    K6RoleEvidence firewalled=Native(now);firewalled.access_kind=K6AccessKind::FirewalledGlobalIpv6;
    firewalled.probes.clear();CHECK(ClassifyK6NodeRole(firewalled,now)==K6NodeRole::OriginOnly,
          "firewalled global v6 is demand not router supply");
    K6RoleEvidence publicV4=Native(now);publicV4.access_kind=K6AccessKind::PublicIpv4;
    publicV4.local_endpoint.family=Kad6Address::Family::IPv4;
    publicV4.local_endpoint.addr={198,51,100,9};
    CHECK(ClassifyK6NodeRole(publicV4,now)==K6NodeRole::Router,
          "public IPv4 qualifies after the same three-AS UDP/TCP proof");
    K6RoleEvidence cgnat=publicV4;cgnat.access_kind=K6AccessKind::CgnatIpv4;
    cgnat.actual_public_endpoint=false;
    CHECK(ClassifyK6NodeRole(cgnat,now)==K6NodeRole::OriginOnly,
          "CGNAT outbound reachability never self-promotes router supply");

    K6EndpointSet endpointSet;for(Byte i=0;i<16;++i)endpointSet.kad_id[i]=i+1;
    for(Byte i=0;i<32;++i)endpointSet.node_pub[i]=0x40+i;endpointSet.epoch=7;
    endpointSet.caps=0x1234;endpointSet.valid_from=now-10;endpointSet.valid_until=now+600;
    K6Endpoint v6;v6.addr.family=Kad6Address::Family::IPv6;
    v6.addr.addr={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,7};v6.udp_port=4672;
    v6.transport_flags=kK6EpUdpKad6|kK6EpInboundVerified;v6.observed=1;
    v6.valid_until=endpointSet.valid_until;K6Endpoint v4=v6;
    v4.addr.family=Kad6Address::Family::IPv4;v4.addr.addr={198,51,100,7};v4.priority=1;
    endpointSet.endpoints={v6,v4};
    std::vector<Byte> endpointWire;
    CHECK(SignK6EndpointSet(Hooks(),endpointSet.node_pub.data(),32,endpointSet,endpointWire)==
          Kad6Status::Ok,"dual-stack EndpointSet signs");
    K6EndpointSet decodedSet;std::size_t endpointUsed=0;
    CHECK(DecodeK6EndpointSet(endpointWire.data(),endpointWire.size(),decodedSet,&endpointUsed)==
          Kad6Status::Ok&&endpointUsed==endpointWire.size()&&decodedSet.endpoints.size()==2&&
          VerifyK6EndpointSet(Hooks(),decodedSet,now)==Kad6Status::Ok,
          "EndpointSet binds one NodeIdentity/KadID to both families");
    std::vector<K6EndpointCandidateHealth> health(2);health[0].endpoint=v6;
    health[0].verified=true;health[0].last_success=now-1;health[1].endpoint=v4;
    health[1].verified=true;health[1].last_success=now-2;
    std::vector<K6EndpointAttempt> attempts;
    CHECK(BuildK6EndpointRace(decodedSet,health,now,kK6HappyEyeballsDefaultDelayMs,
          attempts)==Kad6Status::Ok&&attempts.size()==2&&
          attempts[0].endpoint.addr.family==Kad6Address::Family::IPv6&&
          attempts[0].start_after_ms==0&&attempts[1].start_after_ms==250,
          "bounded Happy Eyeballs prefers IPv6 and schedules IPv4 fallback");
    K6Endpoint winner;std::vector<std::size_t> cancelled;
    CHECK(SelectK6EndpointRaceWinner(attempts,1,winner,cancelled)==Kad6Status::Ok&&
          winner.addr.family==Kad6Address::Family::IPv4&&cancelled.size()==1&&
          cancelled[0]==0,"first authenticated success cancels the losing family");
    health[0].verified=false;
    CHECK(BuildK6EndpointRace(decodedSet,health,now,999,attempts)==Kad6Status::Ok&&
          attempts.size()==1&&attempts[0].endpoint.addr.family==Kad6Address::Family::IPv4&&
          attempts[0].start_after_ms==0,"family failure falls back without identity duplication");

    K6RendezvousDescriptor descriptor;for(Byte i=0;i<32;++i){descriptor.origin_node_pub[i]=0x20+i;
        descriptor.router_node_pub[i]=0x80+i;}for(Byte i=0;i<16;++i)descriptor.introduction_token[i]=i+1;
    descriptor.valid_from=now-1;descriptor.valid_until=now+300;std::vector<Byte> wire;
    CHECK(SignK6RendezvousDescriptor(Hooks(),descriptor.origin_node_pub.data(),32,descriptor,wire)==
          Kad6Status::Ok,"OriginOnly rendezvous descriptor signs");
    K6RendezvousDescriptor decoded;std::size_t used=0;
    CHECK(DecodeK6RendezvousDescriptor(wire.data(),wire.size(),decoded,&used)==Kad6Status::Ok&&
          used==wire.size()&&VerifyK6RendezvousDescriptor(Hooks(),decoded,now)==Kad6Status::Ok,
          "rendezvous exact decode and verify");
    decoded.introduction_token[0]^=1;CHECK(VerifyK6RendezvousDescriptor(Hooks(),decoded,now)==
          Kad6Status::AuthFailed,"rendezvous tamper rejected");
    CHECK(VerifyK6RendezvousDescriptor(Hooks(),descriptor,descriptor.valid_until)==
          Kad6Status::Expired,"rendezvous expiry exact");
    std::printf("test_kad6_role: %d passed, %d failed\n",pass,fail);return fail?1:0;}
