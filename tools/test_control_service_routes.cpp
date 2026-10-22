#include "../srchybrid/EseControlServiceRoutes.h"
#include <cstdio>
using namespace ese;
int main() {
    unsigned checks=0;
    auto check=[&](bool ok) { ++checks; return ok; };
    control::ServiceRoutes routes;
    std::array<std::uint8_t,32> local{},peer{},resolved{}; local[0]=1; peer[0]=2;
    udp::Endpoint endpoint; endpoint.address[0]=52; endpoint.address[1]=8; endpoint.port=4665;
    control::Header context; context.type=wire::kEseWireUdpProve;
    context.attempt[0]=1; context.generation=4; context.sequence=1;
    control::Datagram packet; std::uint64_t owner=999;
    if(!check(!routes.Activate({},9,7)) || !check(!routes.Activate(local,0,7)) ||
        !check(!routes.Activate(local,9,0)) || !check(routes.Activate(local,9,7)) ||
        !check(!routes.Activate(local,10,7)) || !check(!routes.Activate(local,9,8))) return 1;
    if(!check(control::Encode(context,nullptr,0,packet)) ||
        !check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,100,owner)==udp::Match::Invalid && !owner) ||
        !check(!routes.RegisterVerified(local,endpoint,context,100,200)) ||
        !check(!routes.RegisterVerified(peer,endpoint,context,100,60101)) ||
        !check(routes.RegisterVerified(peer,endpoint,context,100,200))) return 2;
    if(!check(routes.Resolve(endpoint,context,100,resolved) && resolved==peer)) return 3;
    auto wrongEndpoint=endpoint; wrongEndpoint.port++;
    auto wrongContext=context; wrongContext.generation++;
    if(!check(!routes.Resolve(wrongEndpoint,context,100,resolved) && resolved==std::array<std::uint8_t,32>{}) ||
        !check(!routes.Resolve(endpoint,wrongContext,100,resolved)) ||
        !check(!routes.RegisterVerified(local,endpoint,context,101,500)) ||
        !check(routes.RegisterVerified(peer,endpoint,context,101,500)) ||
        !check(!routes.Resolve(endpoint,context,200,resolved))) return 4; // duplicates don't renew
    control::Probe probe; probe.node=peer; probe.peer=local; probe.nonce[0]=1;
    std::array<std::uint8_t,128> body{}; context.type=wire::kEseWireUdpProbe;
    if(!check(control::Encode(probe,body) && control::Encode(context,body.data(),body.size(),packet)) ||
        !check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,102,owner)==udp::Match::Valid && owner==9)) return 5;
    packet.bytes[control::HeaderSize+32]^=1;
    if(!check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,102,owner)==udp::Match::Invalid && !owner)) return 6;
    context.type=wire::kEseWireUdpProve;
    for(std::uint8_t type=1;type<=25;++type) {
        auto request=context; request.type=type; request.sequence=2;
        if(!check(control::Encode(request,nullptr,0,packet))) return 7;
        const bool permitted=type==15 || type==16 || type==20 || type==22 || type==24;
        if(!check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,102,owner)==
            (permitted ? udp::Match::Valid : udp::Match::Invalid)) || !check(owner==(permitted ? 9u : 0u))) return 8;
    }
    routes.Reset();
    if(!check(!routes.Resolve(endpoint,context,100,resolved)) || !check(routes.Activate(local,10,8))) return 9;
    for(unsigned i=1;i<=64;++i) {
        context.attempt[0]=static_cast<std::uint8_t>(i);
        if(!check(routes.RegisterVerified(peer,endpoint,context,100,60100))) return 10;
    }
    context.attempt[0]=65;
    if(!check(!routes.RegisterVerified(peer,endpoint,context,100,60100)) ||
        !check(!routes.RegisterVerified(peer,endpoint,context,99,200)) ||
        !check(routes.RegisterVerified(peer,endpoint,context,60100,60200))) return 11;
    routes.Reset();
    if(!check(routes.Inspect(packet.bytes.data(),packet.size,endpoint,100,owner)==udp::Match::Invalid && !owner)) return 12;
    std::printf("Control service routing: %u checks PASS (bounded classification only; no authentication or data grant)\n",checks);
}
