#include "../srchybrid/EseKad6PublicContactProof.h"
#include <cstdio>
using namespace ese::discovery;
int main() {
    unsigned checks=0; auto check=[&](bool ok) { ++checks; return ok; };
    PublicUdpContact endpoint{{52,8,1,2},4665,54322,7,200000}; PublicContactProof proof;
    if(!check(!proof.Current(endpoint,100)) || !check(proof.Begin(1,endpoint,100)) ||
        !check(!proof.Begin(1,endpoint,100)) || !check(proof.Begin(2,endpoint,100)) ||
        !check(!proof.Begin(3,endpoint,100)) ||
        !check(!proof.Receive(3,54322,4665,endpoint,101)) ||
        !check(!proof.Receive(1,4665,4665,endpoint,101)) ||
        !check(!proof.Receive(1,54322,54322,endpoint,101))) return 1;
    auto changed=endpoint; changed.generation++;
    if(!check(!proof.Receive(1,54322,4665,changed,101))) return 2;
    changed=endpoint; changed.publicPort++;
    if(!check(!proof.Receive(1,54323,4665,changed,101))) return 3;
    if(!check(proof.Receive(1,54322,4665,endpoint,102)) ||
        !check(!proof.Receive(1,54322,4665,endpoint,103)) ||
        !check(proof.Current(endpoint,104)) || !check(proof.VerifiedUntil(endpoint,104)==60102) ||
        !check(!proof.Current(changed,104)) || !check(proof.VerifiedUntil(changed,104)==0) ||
        !check(proof.Current(endpoint,60101)) || !check(!proof.Current(endpoint,60102)) ||
        !check(!proof.Current(endpoint,101))) return 4;
    proof.Reset(); endpoint.until=200;
    if(!check(proof.Begin(1,endpoint,100)) || !check(proof.Receive(1,54322,4665,endpoint,102)) ||
        !check(proof.Current(endpoint,199)) || !check(!proof.Current(endpoint,200))) return 5;
    proof.Reset(); endpoint.address={100,74,178,81}; endpoint.until=200000;
    if(!check(!proof.Begin(1,endpoint,100))) return 6;
    endpoint.address={127,0,0,1}; if(!check(!proof.Begin(1,endpoint,100))) return 7;
    endpoint.address={198,18,0,1}; if(!check(!proof.Begin(1,endpoint,100))) return 7;
    endpoint.address={198,19,0,1}; if(!check(!proof.Begin(1,endpoint,100))) return 7;
    endpoint.address={52,8,1,2};
    if(!check(!proof.Begin(1,endpoint,(std::numeric_limits<std::uint64_t>::max)()))) return 8;
    proof.Reset();
    if(!check(proof.Begin(1,endpoint,100)) || !check(!proof.Receive(1,54322,4665,endpoint,99))) return 9;
    std::printf("Kad6 public UDP contact proof: %u checks PASS (fixture external-test admission; no TCP/HighID/identity grant)\n",checks);
}
