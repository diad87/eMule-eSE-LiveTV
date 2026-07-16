// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_store.h"

namespace kad6_fuzz {
namespace {
kad6::K6Endpoint Endpoint(kad6::Byte host, std::uint16_t port, bool route) {
    kad6::K6Endpoint e; e.addr.family = kad6::Kad6Address::Family::IPv6;
    e.addr.addr = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,host};
    e.udp_port=port; e.tcp_port=port+1;
    e.transport_flags=route?kad6::kK6EpUdpKad6:(kad6::kK6EpUdpKad6|kad6::kK6EpTcpEd2k);
    e.valid_until=1700003600; return e;
}
kad6::K6RouteHeader Header() {
    kad6::K6RouteHeader h; h.txid=7; for(Byte i=0;i<16;++i)h.sender_id[i]=0x10+i;
    h.sender_caps=3; h.sender_epoch=9; h.sender_endpoint=Endpoint(1,4672,true);
    h.sender_record.kad_id=h.sender_id; for(Byte i=0;i<32;++i)h.sender_record.node_pub[i]=0x30+i;
    h.sender_record.epoch=h.sender_epoch; h.sender_record.caps=h.sender_caps;
    h.sender_record.valid_from=1700000000; h.sender_record.valid_until=1700003600;
    h.sender_record.endpoints.push_back(h.sender_endpoint); h.sender_record.signature[0]=1; return h;
}
kad6::K6SourceRecord Source() {
    kad6::K6SourceRecord s; for(Byte i=0;i<16;++i){s.object_hash[i]=i+1;s.source_pseudonym[i]=0x20+i;s.service_token[i]=0x40+i;}
    s.source_epoch=12;s.created_at=1700000000;s.expires_at=1700003600;
    for(Byte i=0;i<32;++i){s.metadata_hash[i]=0x60+i;s.pub_key[i]=0x80+i;}
    kad6::K6ExitDescriptor x;for(Byte i=0;i<32;++i)x.exit_node_pub[i]=0xa0+i;
    x.endpoint=Endpoint(2,5000,false);x.lease_hint=44;x.caps=2;x.exit_expires_at=1700003000;x.endpoint.valid_until=x.exit_expires_at;
    s.exits.push_back(x);s.signature[0]=1;return s;
}
}
bool FuzzStore(const Config& config, Report& report) {
    report.target = "store";
    kad6::K6StoreSourceRequest validRequest;validRequest.header=Header();validRequest.record=Source();validRequest.target_hash=validRequest.record.object_hash;
    std::vector<Byte> requestWire;kad6::EncodeK6StoreSourceRequest(validRequest,requestWire);
    kad6::K6StoreSourceResponse validResponse;validResponse.header=Header();validResponse.target_hash=validRequest.target_hash;validResponse.status=kad6::K6StoreStatus::Stored;validResponse.load=10;validResponse.accepted_epoch=12;
    std::vector<Byte> responseWire;kad6::EncodeK6StoreSourceResponse(validResponse,responseWire);
    const std::vector<std::vector<Byte>> corpus = {
        {}, {1}, std::vector<Byte>(74, 0), std::vector<Byte>(300, 0),
        std::vector<Byte>(kad6::kK6StoreMaxPayloadSize, 0xff),requestWire,responseWire
    };
    Rng rng(config.seed ^ 0x53544f5245ull);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        auto input = i==0?requestWire:(i==1?responseWire:Mutate(corpus, rng, i, kad6::kK6StoreMaxPayloadSize + 32));
        kad6::K6StoreSourceRequest request;
        kad6::K6StoreSourceResponse response;
        const kad6::Byte* data = DataOrNull(input);
        const kad6::Kad6Status a = kad6::DecodeK6StoreSourceRequest(
            data, input.size(), request);
        const kad6::Kad6Status b = kad6::DecodeK6StoreSourceResponse(
            data, input.size(), response);
        if (a == kad6::Kad6Status::Ok)
            Require(report, input.size() <= kad6::kK6StoreMaxPayloadSize,
                    "request input cap");
        if (b == kad6::Kad6Status::Ok)
            Require(report, response.load <= 100, "response load cap");
        report.max_input = (std::max)(report.max_input, input.size());
        report.max_output = (std::max)(report.max_output,
            request.record.compat_pub.size());
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}
}
