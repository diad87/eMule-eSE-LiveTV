// SPDX-License-Identifier: MIT
#include "kad6/kad6_lease.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;
static int g_pass = 0, g_fail = 0;
#define CHECK(c,m) do { if (c) ++g_pass; else { ++g_fail; std::printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__); } } while(0)

namespace {
bool Sha(const Byte* p, std::size_t n, Byte out[32]) {
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i=0;i<n;++i) { h ^= p[i]; h *= 1099511628211ull; }
    for (int i=0;i<32;++i) { h ^= static_cast<std::uint64_t>(i)+0x9e3779b97f4a7c15ull; h*=1099511628211ull; out[i]=static_cast<Byte>(h>>(8*(i%8))); }
    return true;
}
bool Sign(const Byte* sk, std::size_t skn, const Byte* msg, std::size_t n, Byte sig[64]) {
    if (!sk || skn != 32) return false;
    std::vector<Byte> v(sk,sk+skn); v.insert(v.end(),msg,msg+n);
    Sha(v.data(),v.size(),sig); v.push_back(0x5a); Sha(v.data(),v.size(),sig+32); return true;
}
bool Verify(const Byte pub[32], const Byte* msg, std::size_t n, const Byte sig[64]) {
    Byte expected[64]; return Sign(pub,32,msg,n,expected) && Kad6CtEqual(expected,sig,64);
}
Kad6CryptoHooks Hooks() { Kad6CryptoHooks h{}; h.sha256=&Sha; h.ed25519_sign=&Sign; h.ed25519_verify=&Verify; return h; }

K6SourceBind Bind(K6BindingMode mode=K6BindingMode::DedicatedVep) {
    K6SourceBind b;
    for (Byte i=0;i<16;++i) { b.file_hash[i]=i+1; b.compat_user_hash[i]=0x20+i; b.bind_nonce[i]=0x90+i; }
    b.file_size=123456789; b.desired_family=4; b.transport_mask=kK6TransportTcp|kK6TransportUdp;
    b.flags=kK6SourceAllowInbound|kK6SourceFile; b.requested_lifetime_s=3600;
    b.max_upload_bps=1024*1024; b.source_epoch=7; b.requested_mode=mode;
    if (mode==K6BindingMode::Cohort) { b.commitment_kind=K6CommitmentKind::Sha256Hashset; for(Byte i=0;i<32;++i)b.content_commitment[i]=i+3; }
    Byte pub[32]; for(Byte i=0;i<32;++i)pub[i]=0x40+i;
    CHECK(MakeK6CompatProofV1(Hooks(),pub,32,pub,b)==Kad6Status::Ok,"make compat proof");
    return b;
}
K6SourceBound Bound(const K6SourceBind& b, K6BindingMode mode=K6BindingMode::DedicatedVep) {
    K6SourceBound v; v.status=K6SourceBoundStatus::Ok; v.transport_mask=b.transport_mask; v.flags=b.flags;
    v.binding_mode=mode; v.identity_mode=mode==K6BindingMode::DedicatedVep?K6IdentityMode::OriginatorVep:K6IdentityMode::ExitTerminated;
    v.endpoint_slot=3; v.source_lease_id=99; v.lifetime_s=1800; v.refresh_after_s=900;
    v.commitment_kind=b.commitment_kind; v.content_commitment=b.content_commitment; v.bind_nonce=b.bind_nonce;
    if(mode==K6BindingMode::Cohort)for(Byte i=0;i<16;++i)v.cohort_id[i]=0x70+i;
    v.virtual_endpoint.addr.family=Kad6Address::Family::IPv4; v.virtual_endpoint.addr.addr={8,8,4,4};
    v.virtual_endpoint.tcp_port=4662; v.virtual_endpoint.udp_port=4672;
    v.virtual_endpoint.transport_flags=kK6EpTcpEd2k|kK6EpEd2kGateway; v.virtual_endpoint.valid_until=2800;
    v.exit_apparent_ip=v.virtual_endpoint.addr; for(Byte i=0;i<32;++i)v.exit_node_pub[i]=0x60+i;
    return v;
}
}

int main() {
    K6SourceBind b=Bind();
    CHECK(VerifyK6CompatProofV1(Hooks(),b)==Kad6Status::Ok,"verify compat proof");
    std::vector<Byte> wire; CHECK(EncodeK6SourceBind(b,wire)==Kad6Status::Ok,"encode bind");
    CHECK(wire.size()==kK6SourceBindFixedSize+kK6CompatProofV1Size,"exact bind size");
    K6SourceBind decoded; std::size_t used=0;
    CHECK(DecodeK6SourceBind(wire.data(),wire.size(),decoded,&used)==Kad6Status::Ok && used==wire.size(),"decode bind");
    CHECK(decoded.file_size==b.file_size && decoded.compat_proof==b.compat_proof,"bind round trip");
    for(std::size_t n=0;n<kK6SourceBindFixedSize;++n) CHECK(DecodeK6SourceBind(wire.data(),n,decoded)==Kad6Status::Truncated,"bind prefix truncation");
    auto bad=wire; bad[109]=1; CHECK(DecodeK6SourceBind(bad.data(),bad.size(),decoded)==Kad6Status::Malformed,"bind reserved rejected");
    b.compat_proof.back()^=1; CHECK(VerifyK6CompatProofV1(Hooks(),b)==Kad6Status::AuthFailed,"tampered proof rejected"); b.compat_proof.back()^=1;

    K6SourceBound bound=Bound(b); Byte exitKey[32]; std::memcpy(exitKey,bound.exit_node_pub.data(),32);
    CHECK(SignK6SourceBound(Hooks(),exitKey,32,b,bound,wire)==Kad6Status::Ok,"sign bound");
    CHECK(VerifyK6SourceBound(Hooks(),b,bound)==Kad6Status::Ok,"verify bound");
    K6SourceBound bd; used=0; CHECK(DecodeK6SourceBound(wire.data(),wire.size(),bd,&used)==Kad6Status::Ok && used==wire.size(),"decode bound");
    CHECK(bd.source_lease_id==99 && bd.virtual_endpoint.tcp_port==4662,"bound round trip");
    bd.lifetime_s++; CHECK(VerifyK6SourceBound(Hooks(),b,bd)==Kad6Status::AuthFailed,"bound limits signed");
    bd=bound; K6SourceBind changed=b; changed.source_epoch++; CHECK(VerifyK6SourceBound(Hooks(),changed,bd)==Kad6Status::AuthFailed,"bound epoch signed");
    K6SourceBind strict=Bind(K6BindingMode::Cohort);strict.requested_mode=K6BindingMode::DedicatedVep;
    K6SourceBound downgrade=Bound(strict,K6BindingMode::Cohort);
    CHECK(SignK6SourceBound(Hooks(),exitKey,32,strict,downgrade,wire)==Kad6Status::Ok &&
        VerifyK6SourceBound(Hooks(),strict,downgrade)==Kad6Status::BadValue,
        "signed binding-mode downgrade rejected");
    K6SourceBound extraTransport=bound;extraTransport.transport_mask|=kK6TransportUtp;
    CHECK(SignK6SourceBound(Hooks(),exitKey,32,b,extraTransport,wire)==Kad6Status::Ok &&
        VerifyK6SourceBound(Hooks(),b,extraTransport)==Kad6Status::BadValue,
        "signed transport expansion rejected");
    K6SourceBound wrongApparent=bound;wrongApparent.exit_apparent_ip.addr[0]^=1;
    CHECK(SignK6SourceBound(Hooks(),exitKey,32,b,wrongApparent,wire)==Kad6Status::Ok &&
        VerifyK6SourceBound(Hooks(),b,wrongApparent)==Kad6Status::BadValue,
        "signed apparent-address mismatch rejected");

    K6SourceUnbind u; u.source_lease_id=99;u.source_epoch=8;u.bind_nonce=b.bind_nonce;
    CHECK(EncodeK6SourceUnbind(u,wire)==Kad6Status::Ok && wire.size()==40,"encode unbind exact");
    K6SourceUnbind ud; CHECK(DecodeK6SourceUnbind(wire.data(),wire.size(),ud,&used)==Kad6Status::Ok && used==40,"decode unbind");
    bad=wire;bad[17]=1;CHECK(DecodeK6SourceUnbind(bad.data(),bad.size(),ud)==Kad6Status::Malformed,"unbind reserved rejected");

    Hash16 pseudo{};pseudo[0]=1;K6SourceLeaseTable table;
    CHECK(table.AddBound(7,pseudo,b,bound,1000)==Kad6Status::Ok,"add bound lease");
    CHECK(table.CanPublish(99) && !table.CanAccept(99),"bound can publish not accept");
    CHECK(table.MarkServing(99)==Kad6Status::BadValue,"publish-before-bound transition blocked");
    CHECK(table.MarkPublished(99)==Kad6Status::Ok && table.MarkServing(99)==Kad6Status::Ok,"publish and serving transitions");
    CHECK(table.CanAccept(99),"serving accepts");
    CHECK(table.DrainCircuit(7)==1 && !table.CanAccept(99),"dead circuit drains");
    CHECK(table.MarkPublished(99)==Kad6Status::BadValue,"draining cannot republish");

    K6SourceBind cohort=Bind(K6BindingMode::Cohort);K6SourceBound cb=Bound(cohort,K6BindingMode::Cohort);cb.source_lease_id=100;
    CHECK(table.AddBound(8,pseudo,cohort,cb,1000)==Kad6Status::Ok,"cohort lease accepted");
    CHECK(table.Find(100)->state==K6SourceLeaseState::JoinedCohortNotPublished,"cohort state fixed");
    K6SourceBind peer=Bind(K6BindingMode::Cohort); peer.bind_nonce[0]^=0x55; peer.source_epoch=8;
    K6SourceBound peerBound=Bound(peer,K6BindingMode::Cohort);peerBound.source_lease_id=101;
    CHECK(table.AddBound(9,pseudo,peer,peerBound,1000)==Kad6Status::Ok,"equivalent cohort peer accepted");
    K6SourceBind conflict=peer;conflict.bind_nonce[0]^=0x33;conflict.source_epoch=9;conflict.content_commitment[0]^=1;
    K6SourceBound conflictBound=Bound(conflict,K6BindingMode::Cohort);conflictBound.source_lease_id=102;
    CHECK(table.AddBound(10,pseudo,conflict,conflictBound,1000)==Kad6Status::BadValue,
        "same hash and front door reject conflicting cohort");
    peerBound.source_lease_id=103;peerBound.cohort_id[0]^=1;
    CHECK(table.AddBound(11,pseudo,peer,peerBound,1000)==Kad6Status::BadValue,
        "same hash and front door reject cohort-id switch");
    CHECK(table.Expire(2800)==3 && !table.CanAccept(100),"expiry closes all");
    CHECK(table.ActiveSize()==0&&table.Size()==3,"closed leases excluded from active count");
    CHECK(table.EraseClosed()==3&&table.Size()==0,"closed leases purged");

    std::printf("test_kad6_lease: %d passed, %d failed\n",g_pass,g_fail);
    return g_fail?1:0;
}
