#include "../srchybrid/EseClassicCallbackProof.h"
#include "../srchybrid/EseClassicCallbackPolicy.h"
#include "../srchybrid/EseServerCallbackRetry.h"
#include <cstdio>
using namespace ese::classic;
int main() {
    unsigned checks=0;
    auto check=[&](bool ok) { ++checks; return ok; };
    ServerCallbackRetry retry;
    if (!check(!retry.Reserve(0)) || !check(retry.Reserve(7)) ||
        !check(retry.Pending()) || !check(!retry.Reserve(7)) ||
        !check(!retry.Consume(8)) || !check(!retry.Pending()) ||
        !check(!retry.Reserve(8))) return 12;
    retry.Reset();
    if (!check(retry.Reserve(9)) || !check(retry.Consume(9)) ||
        !check(!retry.Consume(9)) || !check(!retry.Reserve(9))) return 13;
    retry.Reset();
    if (!check(retry.Reserve(10))) return 14;
    retry.CancelPending();
    if (!check(!retry.Consume(10)) || !check(retry.Used()) ||
        !check(!retry.Reserve(10))) return 15;
    CallbackTcpEndpoint endpoint{{52,8,1,2},4662,54321,7,200000};
    CallbackProof proof;
    if(!check(EvaluateCallback(true,false,true,true)==CallbackAvailability::NoRoute) ||
        !check(EvaluateCallback(false,false,true,true)==CallbackAvailability::Available) ||
        !check(EvaluateCallback(true,true,false,true)==CallbackAvailability::LegacyCallbackUnavailable) ||
        !check(EvaluateCallback(true,true,true,false)==CallbackAvailability::LegacyCallbackUnavailable) ||
        !check(EvaluateCallback(true,true,true,true)==CallbackAvailability::Available)) return 11;
    if(!check(!proof.Current(endpoint,100)) || !check(proof.Begin(11,endpoint,100)) ||
        !check(!proof.Begin(11,endpoint,101)) ||
        !check(!proof.Accept(12,endpoint,7,4662,102,103)) ||
        !check(!proof.Accept(11,endpoint,6,4662,102,103)) ||
        !check(!proof.Accept(11,endpoint,7,54321,102,103)) ||
        !check(!proof.Accept(11,endpoint,7,4662,99,103)) ||
        !check(!proof.Accept(11,endpoint,7,4662,104,103))) return 1;
    auto moved=endpoint; moved.publicPort++;
    if(!check(!proof.Accept(11,moved,7,4662,102,103)) ||
        !check(proof.Accept(11,endpoint,7,4662,102,103)) ||
        !check(proof.Current(endpoint,104)) || !check(!proof.Current(moved,104)) ||
        !check(!proof.Accept(11,endpoint,7,4662,105,105)) ||
        !check(proof.Current(endpoint,60102)) || !check(!proof.Current(endpoint,60103)) ||
        !check(!proof.Current(endpoint,102))) return 2;
    proof.Reset();
    auto expired=endpoint; expired.until=100;
    if(!check(!proof.Begin(11,expired,100)) || !check(!proof.Begin(0,endpoint,100))) return 3;
    for(unsigned i=1;i<=16;++i) if(!check(proof.Begin(i,endpoint,100))) return 4;
    if(!check(!proof.Begin(17,endpoint,100)) ||
        !check(!proof.Accept(1,endpoint,7,4662,101,180100)) ||
        !check(proof.Begin(17,endpoint,180100))) return 5;
    proof.Reset();
    auto shortLease=endpoint; shortLease.until=200;
    if(!check(proof.Begin(11,shortLease,100)) || !check(proof.Accept(11,shortLease,7,4662,101,102)) ||
        !check(proof.Current(shortLease,199)) || !check(!proof.Current(shortLease,200))) return 6;
    const std::array<std::array<std::uint8_t,4>,7> bad{{{{10,1,1,1}},{{127,0,0,1}},{{192,168,1,1}},
        {{100,74,178,81}},{{169,254,1,1}},{{224,0,0,1}},{{198,18,0,1}}}};
    for(const auto& ip:bad) {
        CallbackProof isolated; auto invalid=endpoint; invalid.address=ip;
        if(!check(!isolated.Begin(11,invalid,100))) return 7;
    }
    proof.Reset();
    if(!check(proof.Begin(11,endpoint,100)) || !check(!proof.AcceptRecorded(11,endpoint,101)) ||
        !check(!proof.RememberInbound(12,7,4662,102)) ||
        !check(!proof.RememberInbound(11,6,4662,102)) ||
        !check(!proof.RememberInbound(11,7,54321,102)) ||
        !check(proof.RememberInbound(11,7,4662,102)) ||
        !check(!proof.RememberInbound(11,7,4662,103)) ||
        !check(proof.AcceptRecorded(11,endpoint,104)) ||
        !check(!proof.AcceptRecorded(11,endpoint,105))) return 8;
    if(!check(proof.VerifiedUntil(endpoint,105)==60104) || !check(proof.VerifiedUntil(endpoint,60104)==0)) return 9;
    auto changedLease=endpoint; changedLease.until=150;
    if(!check(proof.VerifiedUntil(changedLease,105)==150)) return 10;
    std::printf("Classic callback proof: %u checks PASS (no server HighID or peer identity grant)\n",checks);
}
