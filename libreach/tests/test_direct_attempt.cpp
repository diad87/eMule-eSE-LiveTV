// SPDX-License-Identifier: MIT
#include "reach/direct_attempt.h"

#include <cstdio>
#include <algorithm>
#include <vector>

using namespace reach;
static int checks = 0;
static int failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #x); } } while (0)

static DirectPolicy Policy()
{
    DirectPolicy p;
    p.topology_generation = 1;
    p.now_monotonic_ms = 0; // zero is a valid injected monotonic-clock value
    p.required_interface_id = 7;
    p.allow_same_lan = true;
    p.local_interface_family = 4;
    p.local_interface_address[0]=192; p.local_interface_address[1]=168;
    p.local_interface_address[2]=1; p.local_interface_address[3]=1;
    p.local_prefix_length=24;
    return p;
}

static DirectCandidate V4(std::uint64_t id, std::uint8_t x=8, std::uint8_t y=8,
                          std::uint8_t z=8, std::uint8_t w=8)
{
    DirectCandidate c;
    c.id=id; c.kind=DirectKind::DirectV4; c.family=4;
    c.address[0]=x; c.address[1]=y; c.address[2]=z; c.address[3]=w;
    c.port=4662; c.transport_mask=DirectTcp;
    c.evidence=DirectEvidence::InboundVerified;
    c.topology_generation=1; c.expires_monotonic_ms=100;
    return c;
}

static DirectCandidate V6(std::uint64_t id)
{
    DirectCandidate c;
    c.id=id; c.kind=DirectKind::DirectV6; c.family=6;
    c.address[0]=0x20; c.address[1]=0x01; c.address[2]=0x48; c.address[3]=0x60;
    c.address[15]=1; c.port=4662; c.transport_mask=DirectTcp|DirectQuic;
    c.evidence=DirectEvidence::InboundVerified;
    c.topology_generation=1; c.expires_monotonic_ms=100;
    return c;
}

int main()
{
    auto p=Policy();
    auto v4=V4(2); auto v6=V6(1);
    auto plan=BuildDirectPlan(p,{v4,v6});
    CHECK(plan.status==DirectStatus::Ok && plan.routes.size()==2);
    CHECK(plan.routes[0].id==1 && plan.routes[1].id==2); // stable kind priority

    auto stale=v4; stale.topology_generation=0;
    auto expired=v4; expired.expires_monotonic_ms=0;
    auto unroutable=V4(4,127,0,0,1);
    auto multicast=V4(5,239,1,2,3);
    auto privateGlobal=V4(6,192,168,1,2);
    auto noPort=v4; noPort.port=0;
    auto badId=v4; badId.id=0;
    auto badTransport=v4; badTransport.transport_mask=0x80;
    auto badV4Tail=v4; badV4Tail.address[12]=1;
    auto advertisedDirect=v4; advertisedDirect.evidence=DirectEvidence::Advertised;
    plan=BuildDirectPlan(p,{stale,expired,unroutable,multicast,privateGlobal,
                            noPort,badId,badTransport,badV4Tail,advertisedDirect});
    CHECK(plan.status==DirectStatus::Ok && plan.routes.empty());

    auto lan=V4(10,192,168,1,9); lan.scope=DirectScope::SameLan; lan.interface_id=7;
    CHECK(BuildDirectPlan(p,{lan}).routes.size()==1);
    lan.interface_id=8;
    CHECK(BuildDirectPlan(p,{lan}).routes.empty());
    lan.interface_id=7; p.allow_same_lan=false;
    CHECK(BuildDirectPlan(p,{lan}).routes.empty());
    p.allow_same_lan=true;

    // An exact interface/prefix match is not permission to dial its directed
    // broadcast. /31 point-to-point and /32 host routes have no broadcast.
    auto broadcast=V4(31,192,168,1,255);
    broadcast.scope=DirectScope::SameLan; broadcast.interface_id=7;
    CHECK(BuildDirectPlan(p,{broadcast}).routes.empty());
    auto pointToPoint=p; pointToPoint.local_prefix_length=31;
    pointToPoint.local_interface_address[3]=254;
    CHECK(BuildDirectPlan(pointToPoint,{broadcast}).routes.size()==1);
    auto hostRoute=pointToPoint; hostRoute.local_prefix_length=32;
    hostRoute.local_interface_address[3]=255;
    CHECK(BuildDirectPlan(hostRoute,{broadcast}).routes.size()==1);

    auto loop6=V6(11); loop6.address={}; loop6.address[15]=1;
    auto multicast6=V6(12); multicast6.address={}; multicast6.address[0]=0xff;
    auto link6=V6(13); link6.address={}; link6.address[0]=0xfe; link6.address[1]=0x80; link6.address[15]=1;
    auto ula6=V6(14); ula6.address={}; ula6.address[0]=0xfd; ula6.address[15]=1;
    auto doc6=V6(15); doc6.address={0x20,0x01,0x0d,0xb8}; doc6.address[15]=1;
    plan=BuildDirectPlan(p,{loop6,multicast6,link6,ula6,doc6});
    CHECK(plan.routes.empty());
    auto p6=p; p6.local_interface_family=6; p6.local_interface_address={};
    p6.local_interface_address[0]=0xfe; p6.local_interface_address[1]=0x80;
    p6.local_interface_address[15]=2; p6.local_prefix_length=64;
    link6.scope=DirectScope::SameLan; link6.interface_id=7;
    CHECK(BuildDirectPlan(p6,{link6}).routes.size()==1);
    CHECK(BuildDirectPlan(p,{link6}).routes.empty()); // family/subnet mismatch
    auto ulaPolicy=p6; ulaPolicy.local_interface_address={};
    ulaPolicy.local_interface_address[0]=0xfd; ulaPolicy.local_interface_address[15]=2;
    ula6.scope=DirectScope::SameLan; ula6.interface_id=7;
    CHECK(BuildDirectPlan(ulaPolicy,{ula6}).routes.size()==1);
    CHECK(BuildDirectPlan(p6,{ula6}).routes.empty());

    auto mapped=V6(16); mapped.address={}; mapped.address[10]=0xff; mapped.address[11]=0xff;
    mapped.address[12]=8; mapped.address[13]=8; mapped.address[14]=8; mapped.address[15]=8;
    CHECK(BuildDirectPlan(p,{mapped}).routes.empty());

    auto mapping=V4(17); mapping.kind=DirectKind::VerifiedMapping;
    mapping.evidence=DirectEvidence::MappingVerified;
    auto badMapping=mapping; badMapping.evidence=DirectEvidence::Observed;
    CHECK(BuildDirectPlan(p,{mapping}).routes.size()==1);
    CHECK(BuildDirectPlan(p,{badMapping}).routes.empty());

    auto duplicate=v4; duplicate.id=18; duplicate.evidence=DirectEvidence::Observed;
    auto duplicateStrong=v4; duplicateStrong.id=19; duplicateStrong.rtt_ms=15;
    auto duplicateWeak=v4; duplicateWeak.id=20; duplicateWeak.evidence=DirectEvidence::Observed;
    plan=BuildDirectPlan(p,{duplicateWeak,duplicate,duplicateStrong});
    CHECK(plan.routes.size()==1 && plan.routes[0].id==19); // best evidence, then RTT
    duplicateWeak.expires_monotonic_ms=25;
    CHECK(BuildDirectPlan(p,{duplicateStrong,duplicateWeak}).routes[0].expires_monotonic_ms==25);
    CHECK(BuildDirectPlan(p,{duplicateWeak,duplicateStrong}).routes[0].expires_monotonic_ms==25);
    auto birthday=V4(21); birthday.kind=DirectKind::Birthday;
    birthday.evidence=DirectEvidence::Reserved;
    CHECK(BuildDirectPlan(p,{birthday}).routes.empty());
    p.allow_birthday=true;
    CHECK(BuildDirectPlan(p,{birthday}).routes.size()==1);

    p.topology_generation=0;
    CHECK(BuildDirectPlan(p,{v4}).status==DirectStatus::InvalidPolicy);
    p=Policy(); p.allow_same_lan=true; p.required_interface_id=0;
    CHECK(BuildDirectPlan(p,{v4}).status==DirectStatus::InvalidPolicy);
    p=Policy(); std::vector<DirectCandidate> many;
    for(std::uint64_t i=0;i<17;++i) many.push_back(V4(i+1,8,8,4,static_cast<std::uint8_t>(i+1)));
    CHECK(BuildDirectPlan(p,many).status==DirectStatus::TooManyCandidates);

    many.clear();
    for(std::uint64_t i=0;i<10;++i) many.push_back(V4(i+1,8,8,4,static_cast<std::uint8_t>(i+1)));
    plan=BuildDirectPlan(p,many);
    CHECK(plan.status==DirectStatus::Ok && plan.routes.size()==kDirectMaxRoutes);
    CHECK(plan.routes.front().id==1 && plan.routes.back().id==8);

    // Deterministic selection is an A1 requirement, not just a kind-order check.
    // The retained set is bounded independently of raw invalid observations.
    std::vector<DirectCandidate> permuted=many;
    permuted.insert(permuted.end(),{stale,expired,noPort,multicast,badV4Tail,advertisedDirect});
    const auto canonical=BuildDirectPlan(p,permuted);
    CHECK(canonical.status==DirectStatus::Ok && canonical.routes.size()==8);
    for(std::size_t rotation=0;rotation<permuted.size();++rotation) {
        std::rotate(permuted.begin(),permuted.begin()+1,permuted.end());
        for(unsigned direction=0;direction<2;++direction) {
            std::reverse(permuted.begin(),permuted.end());
            const auto reordered=BuildDirectPlan(p,permuted);
            CHECK(reordered.status==canonical.status && reordered.routes.size()==canonical.routes.size());
            if(reordered.routes.size()!=canonical.routes.size()) continue;
            for(std::size_t i=0;i<canonical.routes.size();++i) {
                const auto& actual=reordered.routes[i]; const auto& expected=canonical.routes[i];
                CHECK(actual.id==expected.id && actual.family==expected.family &&
                      actual.address==expected.address && actual.port==expected.port &&
                      actual.transport_mask==expected.transport_mask && actual.kind==expected.kind &&
                      actual.evidence==expected.evidence && actual.topology_generation==expected.topology_generation &&
                      actual.expires_monotonic_ms==expected.expires_monotonic_ms);
            }
        }
    }

    std::vector<DirectCandidate> full;
    for(std::uint64_t i=0;i<16;++i) full.push_back(V4(i+1,8,8,4,static_cast<std::uint8_t>(i+1)));
    full.insert(full.end(),{expired,noPort,multicast,stale});
    const auto fullCanonical=BuildDirectPlan(p,full);
    CHECK(fullCanonical.status==DirectStatus::Ok && fullCanonical.routes.size()==8);
    for(std::size_t i=0;i<full.size();++i) {
        std::rotate(full.begin(),full.begin()+1,full.end());
        const auto reordered=BuildDirectPlan(p,full);
        CHECK(reordered.status==DirectStatus::Ok && reordered.routes.size()==8);
        if(reordered.routes.size()==8) for(std::size_t j=0;j<8;++j)
            CHECK(reordered.routes[j].id==fullCanonical.routes[j].id);
    }
    full.assign(kDirectMaxCandidateInputs,V4(1));
    CHECK(BuildDirectPlan(p,full).status==DirectStatus::Ok && BuildDirectPlan(p,full).routes.size()==1);
    full.push_back(V4(1));
    CHECK(BuildDirectPlan(p,full).status==DirectStatus::TooManyCandidates);

    std::printf("test_direct_attempt: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
