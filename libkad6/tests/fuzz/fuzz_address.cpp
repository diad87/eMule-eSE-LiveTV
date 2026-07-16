// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_address.h"

namespace kad6_fuzz {

bool FuzzAddress(const Config& config, Report& report) {
    report.target = "address";
    const std::vector<std::vector<Byte>> corpus = {
        {}, {0, 0}, {4, 4, 8, 8, 8, 8},
        {6, 16, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        {4, 16}, {6, 4}, {5, 0}
    };
    Rng rng(config.seed ^ 0x41444452u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 64);
        kad6::Kad6Address out;
        std::size_t consumed = 0;
        const kad6::Kad6Status status = kad6::DecodeKad6Address(
            DataOrNull(input), input.size(), out, &consumed);
        report.max_input = std::max(report.max_input, input.size());
        if (status == kad6::Kad6Status::Ok) {
            Require(report, consumed == 2 || consumed == 6 || consumed == 18,
                    "successful decode has a canonical wire size");
            Require(report, consumed <= input.size(), "consumed is bounded by input");
        } else {
            Require(report, consumed == 0, "failure consumes no bytes");
        }
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
