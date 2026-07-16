// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_routing.h"

namespace kad6_fuzz {

static kad6::K6RouteHeader Header() {
    kad6::K6RouteHeader header;
    header.txid = 1;
    header.sender_id[0] = 1;
    header.sender_caps = 1;
    header.sender_epoch = 1;
    header.sender_endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
    header.sender_endpoint.addr.addr = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1};
    header.sender_endpoint.udp_port = 4672;
    header.sender_endpoint.transport_flags = kad6::kK6EpUdpKad6;
    header.sender_endpoint.valid_until = 2000;
    header.sender_record.kad_id = header.sender_id;
    header.sender_record.node_pub[0] = 1;
    header.sender_record.epoch = header.sender_epoch;
    header.sender_record.caps = header.sender_caps;
    header.sender_record.valid_from = 1000;
    header.sender_record.valid_until = 2000;
    header.sender_record.endpoints.push_back(header.sender_endpoint);
    return header;
}

bool FuzzRouting(const Config& config, Report& report) {
    kad6::K6HelloRequest hello;
    hello.header = Header();
    std::vector<Byte> valid;
    (void)kad6::EncodeK6HelloRequest(hello, valid);
    const std::vector<std::vector<Byte>> corpus = {
        {}, valid, {1, 0, 0, 0}, std::vector<Byte>(2048, 0xff)};
    report.target = "routing";
    Rng rng(config.seed ^ 0x524f5554u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 4096);
        const Byte* data = DataOrNull(input);
        kad6::K6HelloRequest helloRequest;
        kad6::K6BootstrapResponse bootstrapResponse;
        kad6::K6FindNodeRequest findRequest;
        kad6::K6FindNodeResponse findResponse;
        std::vector<kad6::K6RouteSnapshotEntry> snapshot;
        (void)kad6::DecodeK6HelloRequest(data, input.size(), helloRequest);
        const kad6::Kad6Status bs = kad6::DecodeK6BootstrapResponse(
            data, input.size(), bootstrapResponse);
        const kad6::Kad6Status fr = kad6::DecodeK6FindNodeRequest(
            data, input.size(), findRequest);
        const kad6::Kad6Status fs = kad6::DecodeK6FindNodeResponse(
            data, input.size(), findResponse);
        const kad6::Kad6Status ss = kad6::DecodeK6RouteSnapshot(
            data, input.size(), snapshot);
        if (bs == kad6::Kad6Status::Ok)
            Require(report, bootstrapResponse.contacts.size() <=
                    kad6::kK6RouteMaxContacts, "bootstrap contact cap");
        if (fr == kad6::Kad6Status::Ok)
            Require(report, findRequest.max_results <=
                    kad6::kK6RouteMaxContacts, "find request cap");
        if (fs == kad6::Kad6Status::Ok)
            Require(report, findResponse.contacts.size() <=
                    kad6::kK6RouteMaxContacts, "find response cap");
        if (ss == kad6::Kad6Status::Ok)
            Require(report, snapshot.size() <= kad6::kK6RouteMaxStoredContacts,
                    "snapshot cap");
        report.max_input = std::max(report.max_input, input.size());
        report.max_output = std::max(report.max_output,
            (bootstrapResponse.contacts.size() + findResponse.contacts.size()) *
                sizeof(kad6::K6RouteContact) +
            snapshot.size() * sizeof(kad6::K6RouteSnapshotEntry));
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
