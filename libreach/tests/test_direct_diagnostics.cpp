// SPDX-License-Identifier: MIT
#include "reach/direct_diagnostics.h"
#include <cstdio>
#include <thread>
using namespace reach;
static int checks=0,failures=0;
#define CHECK(x) do {++checks; if(!(x)){++failures; std::printf("FAIL line %d\n",__LINE__);}} while(0)
int main() {
    DirectDiagnosticPublisher publisher;
    CHECK(!publisher.Read());
    DirectCoordinatorSnapshot source;
    source.peer.identity.fill(0xab); source.attempt_id.fill(0xcd);
    auto value=ProjectDirectDiagnostic(source);
    CHECK(!value.authenticated && !value.transfer_verified);
    CHECK(publisher.Publish(value,0));
    auto initial=publisher.Read(); CHECK(initial->snapshot_sequence==1);
    CHECK(!publisher.Publish(value,1));
    value.accepted_unique_bytes=1;
    CHECK(!publisher.Publish(value,999));
    CHECK(publisher.Publish(value,1000));
    auto second=publisher.Read(); CHECK(second->snapshot_sequence==2 && initial->accepted_unique_bytes==0);
    for(unsigned i=0;i<20;++i) {
        value.state=i%2 ? DirectSessionState::Connecting : DirectSessionState::Recovering;
        CHECK(publisher.Publish(value,1001+i));
        CHECK(publisher.Read()->snapshot_sequence==3+i);
    }
    value.state=DirectSessionState::Failed; value.terminal_reason=DirectReason::Deadline;
    CHECK(publisher.Publish(value,1021));
    CHECK(publisher.Read()->terminal_reason==DirectReason::Deadline);
    CHECK(!publisher.Publish(value,1020));
    value.topology_generation=9007199254740993ull;
    value.session_epoch=(std::numeric_limits<std::uint64_t>::max)();
    auto json=DirectDiagnosticJson(value);
    CHECK(json.find("\"9007199254740993\"")!=std::string::npos);
    CHECK(json.find("\"18446744073709551615\"")!=std::string::npos);
    CHECK(json.find("\"fallback_count\":\"0\"")!=std::string::npos);
    CHECK(json.find("node")==std::string::npos && json.find("endpoint")==std::string::npos);
    std::shared_ptr<const DirectDiagnosticV2> api;
    std::thread reader([&]{api=publisher.Read();}); reader.join();
    CHECK(api==publisher.Read());
    source.winner=1; source.epoch=1; source.transfer_verified=true;
    source.state=DirectSessionState::Ready;
    CHECK(!ProjectDirectDiagnostic(source).authenticated);
    DirectSessionRoute route; route.id=1; route.transport=DirectQuic;
    route.candidate.kind=DirectKind::DirectV4;
    CHECK(ProjectDirectDiagnostic(source,{route}).authenticated && ProjectDirectDiagnostic(source,{route}).transfer_verified);
    value=ProjectDirectDiagnostic(source,{route}); value.session_id=23;
    CHECK(publisher.Publish(value,1022));
    json=DirectDiagnosticJson(*publisher.Read());
    CHECK(json.find("\"session_id\":\"d23\"")!=std::string::npos);
    CHECK(json.find("\"transport\":\"QUIC\"")!=std::string::npos);
    CHECK(json.find("\"limits\"")!=std::string::npos && json.find("\"progress_blocker\"")!=std::string::npos);
    const auto valid=publisher.Read();
    for(unsigned i=0;i<256;++i) {
        auto invalid=value; invalid.transport=static_cast<std::uint8_t>(i);
        if(i!=DirectTcp && i!=DirectUtp && i!=DirectQuic) {
            CHECK(!publisher.Publish(invalid,1023)); CHECK(publisher.Read()==valid);
        }
    }
    auto invalid=value; invalid.candidate_count=17;
    CHECK(!publisher.Publish(invalid,1023));
    invalid=value; invalid.state=static_cast<DirectSessionState>(255);
    CHECK(!publisher.Publish(invalid,1023));
    bool rejected=false; try { DirectDiagnosticJson(invalid); } catch(const std::invalid_argument&) {rejected=true;}
    CHECK(rejected);
    std::printf("test_direct_diagnostics: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
