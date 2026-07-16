// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_frame.h"

namespace kad6_fuzz {

bool FuzzFrame(const Config& config, Report& report) {
    std::vector<Byte> minimal(kad6::kK6FrameHeaderSize, 0);
    minimal[0] = 1;
    std::vector<Byte> tooLarge = minimal;
    const std::uint32_t claimed = static_cast<std::uint32_t>(kad6::kK6FrameMaxBody + 1);
    for (std::size_t n = 0; n < 4; ++n)
        tooLarge[16 + n] = static_cast<Byte>(claimed >> (8 * n));
    std::vector<Byte> withBody = minimal;
    withBody[16] = 4;
    withBody.insert(withBody.end(), {0xde, 0xad, 0xbe, 0xef});
    const std::vector<std::vector<Byte>> corpus = {
        {}, minimal, withBody, tooLarge, {2, 0, 0, 0}, {1, 0, 0, 0, 0, 0, 0, 0}
    };
    report.target = "frame";
    Rng rng(config.seed ^ 0x4652414du);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 4096);
        kad6::K6Frame out;
        std::size_t consumed = 0;
        const kad6::Kad6Status status = kad6::DecodeK6Frame(
            DataOrNull(input), input.size(), out, &consumed);
        report.max_input = std::max(report.max_input, input.size());
        if (status == kad6::Kad6Status::Ok) {
            Require(report, out.body.size() <= kad6::kK6FrameMaxBody,
                    "body allocation respects the 1 MiB cap");
            Require(report, consumed == input.size(), "frame consumes exact input");
            report.max_output = std::max(report.max_output, out.body.size());
        } else {
            Require(report, out.body.empty(), "failed decode exposes no body");
        }
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
