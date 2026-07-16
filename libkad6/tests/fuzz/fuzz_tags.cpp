// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_tags.h"

namespace kad6_fuzz {

bool FuzzTags(const Config& config, Report& report) {
    // One canonical numeric-u8 tag: name 0x10, value 0x42.
    const std::vector<Byte> golden = {
        1, 1, 0, 16, 0, 0, 0, 0, 1, 0x10, 0, 1, 0, 0, 0, 0x42
    };
    const std::vector<std::vector<Byte>> corpus = {
        {}, golden, {1, 0xff, 0xff, 7, 0, 0, 0},
        {1, 0, 0, 0xff, 0xff, 0xff, 0x7f}
    };
    report.target = "tags";
    Rng rng(config.seed ^ 0x54414753u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 4096);
        kad6::K6TagList out;
        std::size_t consumed = 0;
        const kad6::Kad6Status status = kad6::DecodeK6TagList(
            DataOrNull(input), input.size(), out, &consumed);
        report.max_input = std::max(report.max_input, input.size());
        std::size_t aggregate = 0;
        for (const kad6::K6Tag& tag : out)
            aggregate += tag.name.size() + tag.value.size();
        if (status == kad6::Kad6Status::Ok) {
            Require(report, out.size() <= kad6::kK6MaxTags, "tag count cap");
            Require(report, aggregate <= kad6::kK6MaxTagListBytes,
                    "aggregate tag allocation cap");
            Require(report, consumed <= input.size(), "consumed is bounded by input");
            report.max_output = std::max(report.max_output, aggregate);
        } else {
            Require(report, out.empty(), "failed decode exposes no partial tag list");
        }
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
