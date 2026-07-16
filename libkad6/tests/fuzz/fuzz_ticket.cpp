// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_ticket.h"

namespace kad6_fuzz {

static std::vector<Byte> TicketSeed() {
    kad6::K6TargetTicket ticket;
    ticket.lease_id = 1;
    ticket.provenance_session = 2;
    ticket.provenance_stream = 3;
    ticket.provenance_seq = 4;
    ticket.target_endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    ticket.target_endpoint.addr.addr = {8, 8, 8, 8};
    ticket.target_endpoint.udp_port = 4672;
    ticket.target_endpoint.tcp_port = 4662;
    ticket.target_endpoint.valid_until = 2000;
    ticket.issued_at = 1000;
    ticket.expires_at = 1300;
    ticket.max_bytes = 1;
    ticket.max_connections = 1;
    std::vector<Byte> wire;
    (void)kad6::EncodeK6TargetTicket(ticket, wire);
    return wire;
}

bool FuzzTicket(const Config& config, Report& report) {
    const std::vector<std::vector<Byte>> corpus = {
        {}, TicketSeed(), {1}, {2, 1, 0, 0}, std::vector<Byte>(512, 0xff)
    };
    report.target = "ticket";
    Rng rng(config.seed ^ 0x5449434bu);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 1024);
        kad6::K6TargetTicket out;
        std::size_t consumed = 0;
        const kad6::Kad6Status status = kad6::DecodeK6TargetTicket(
            DataOrNull(input), input.size(), out, &consumed);
        report.max_input = std::max(report.max_input, input.size());
        if (status == kad6::Kad6Status::Ok) {
            Require(report, consumed <= input.size(), "consumed is bounded by input");
            Require(report, consumed <= 512, "ticket wire remains bounded");
            report.max_output = std::max(report.max_output, consumed);
        } else {
            Require(report, consumed == 0, "failure consumes no bytes");
        }
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
