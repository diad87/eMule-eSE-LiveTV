// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_asn.h"

namespace kad6_fuzz {

bool FuzzAsn(const Config& config, Report& report) {
    kad6::K6AsnPrefix prefix;
    prefix.prefix.family = kad6::Kad6Address::Family::IPv6;
    prefix.prefix.addr = {0x20, 0x01, 0x0d, 0xb8};
    prefix.prefix_length = 32;
    prefix.asn = 64500;
    std::vector<Byte> valid;
    (void)kad6::EncodeK6AsnSnapshot(1, {prefix}, valid);
    const std::vector<std::vector<Byte>> corpus = {
        {}, valid, {static_cast<Byte>('K'), static_cast<Byte>('6')},
        std::vector<Byte>(1024, 0xff)};
    report.target = "asn";
    Rng rng(config.seed ^ 0x41534e36u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 8192);
        std::uint64_t sequence = 0;
        std::vector<kad6::K6AsnPrefix> entries;
        const kad6::Kad6Status status = kad6::DecodeK6AsnSnapshot(
            DataOrNull(input), input.size(), sequence, entries);
        if (status == kad6::Kad6Status::Ok) {
            Require(report, sequence != 0, "ASN sequence nonzero");
            Require(report, entries.size() <= kad6::kK6AsnMaxEntries,
                    "ASN entry cap");
        }
        report.max_input = std::max(report.max_input, input.size());
        report.max_output = std::max(report.max_output,
            entries.size() * sizeof(kad6::K6AsnPrefix));
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
