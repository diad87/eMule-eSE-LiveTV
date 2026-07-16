// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_records.h"

namespace kad6_fuzz {

static std::vector<std::vector<Byte>> RecordCorpus() {
    kad6::K6NodeBind bind;
    kad6::K6Rotate rotate;
    kad6::K6RouterRecord router;
    kad6::K6SourceRecord source;
    for (std::size_t i = 0; i < bind.kad_id.size(); ++i) {
        bind.kad_id[i] = static_cast<Byte>(i);
        rotate.kad_id[i] = static_cast<Byte>(i);
    }
    for (std::size_t i = 0; i < bind.node_pub.size(); ++i) {
        bind.node_pub[i] = static_cast<Byte>(0x20 + i);
        rotate.old_pub[i] = static_cast<Byte>(0x20 + i);
        rotate.new_pub[i] = static_cast<Byte>(0x40 + i);
    }
    bind.epoch = 1;
    rotate.rotation_epoch = 2;
    rotate.not_after = 1000;
    router.kad_id = bind.kad_id;
    router.node_pub = bind.node_pub;
    router.epoch = 1;
    router.valid_from = 1000;
    router.valid_until = 1300;
    kad6::K6Endpoint endpoint;
    endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr = {8, 8, 8, 8};
    endpoint.udp_port = 4672;
    endpoint.tcp_port = 4662;
    endpoint.valid_until = 1300;
    router.endpoints.push_back(endpoint);

    source.source_epoch = 1;
    source.created_at = 1000;
    source.expires_at = 1300;
    source.pub_key = bind.node_pub;
    kad6::K6ExitDescriptor exit;
    exit.exit_node_pub = bind.node_pub;
    exit.endpoint = endpoint;
    exit.lease_hint = 1;
    exit.exit_expires_at = 1300;
    source.exits.push_back(exit);

    std::vector<Byte> bindWire, rotateWire, routerWire, sourceWire;
    (void)kad6::EncodeK6NodeBind(bind, bindWire);
    (void)kad6::EncodeK6Rotate(rotate, rotateWire);
    (void)kad6::EncodeK6RouterRecord(router, routerWire);
    (void)kad6::EncodeK6SourceRecord(source, sourceWire);
    return {{}, bindWire, rotateWire, routerWire, sourceWire,
            {1, 0, 0, 0}, std::vector<Byte>(1024, 0xff)};
}

bool FuzzRecords(const Config& config, Report& report) {
    const std::vector<std::vector<Byte>> corpus = RecordCorpus();
    report.target = "records";
    Rng rng(config.seed ^ 0x52454353u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 4096);
        const Byte* data = DataOrNull(input);
        std::size_t consumed = 0;
        kad6::K6NodeBind bind;
        kad6::K6Rotate rotate;
        kad6::K6RouterRecord router;
        kad6::K6SourceRecord source;
        const kad6::Kad6Status sb = kad6::DecodeK6NodeBind(data, input.size(), bind, &consumed);
        if (sb == kad6::Kad6Status::Ok)
            Require(report, consumed == input.size(), "node-bind consumes exact input");
        consumed = 0;
        const kad6::Kad6Status sr = kad6::DecodeK6Rotate(data, input.size(), rotate, &consumed);
        if (sr == kad6::Kad6Status::Ok)
            Require(report, consumed == input.size(), "rotation consumes exact input");
        consumed = 0;
        const kad6::Kad6Status srr = kad6::DecodeK6RouterRecord(data, input.size(), router, &consumed);
        if (srr == kad6::Kad6Status::Ok) {
            Require(report, router.endpoints.size() <= kad6::kK6RouterMaxEndpoints,
                    "router endpoint cap");
            Require(report, consumed == input.size(), "router consumes exact input");
        }
        consumed = 0;
        const kad6::Kad6Status ss = kad6::DecodeK6SourceRecord(data, input.size(), source, &consumed);
        if (ss == kad6::Kad6Status::Ok) {
            Require(report, source.exits.size() <= kad6::kK6SourceMaxExits, "source exit cap");
            Require(report, source.compat_pub.size() <= kad6::kK6SourceMaxCompatPubLen,
                    "source compatibility blob cap");
            Require(report, consumed == input.size(), "source consumes exact input");
        }
        report.max_input = std::max(report.max_input, input.size());
        report.max_output = std::max(report.max_output,
            router.endpoints.size() * sizeof(kad6::K6Endpoint) +
            source.exits.size() * sizeof(kad6::K6ExitDescriptor) + source.compat_pub.size());
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
