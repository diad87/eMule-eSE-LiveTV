// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_shaped_bulk.h"

namespace kad6_fuzz {

static std::vector<Byte> PlainSeed() {
    std::vector<Byte> wire(kad6::kK6ShapedPlainSize, 0);
    wire[0] = 1;
    wire[1] = static_cast<Byte>(kad6::K6BulkKind::Data);
    return wire;
}

static std::vector<Byte> CarrierSeed() {
    std::vector<Byte> wire(kad6::kK6ShapedTotal, 0x5a);
    wire[0] = wire[1] = wire[2] = wire[3] = 0;
    wire[4] = kad6::kK6ShapedBcmd;
    wire[5] = 1;
    for (std::size_t i = 6; i <= 12; ++i) wire[i] = 0;
    const std::uint32_t length = kad6::kK6ShapedLengthField;
    for (std::size_t i = 0; i < 4; ++i)
        wire[13 + i] = static_cast<Byte>(length >> (8 * i));
    return wire;
}

bool FuzzShaped(const Config& config, Report& report) {
    const std::vector<std::vector<Byte>> corpus = {
        {}, PlainSeed(), CarrierSeed(), {1, 1, 0, 0}, std::vector<Byte>(17001, 0)
    };
    report.target = "shaped";
    Rng rng(config.seed ^ 0x53485044u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        // Full arbitrary generation is capped; exact-size valid seeds still
        // exercise the two large fixed-size paths on most corpus cycles.
        std::vector<Byte> input = Mutate(corpus, rng, i, 20000);
        const Byte* data = DataOrNull(input);
        kad6::K6ShapedBulkPlainV1 plain;
        const kad6::Kad6Status sp = kad6::DecodeK6ShapedPlain(data, input.size(), plain);
        if (sp == kad6::Kad6Status::Ok) {
            Require(report, plain.inner.size() <= kad6::kK6ShapedInnerMax,
                    "plaintext inner cap");
            report.max_output = std::max(report.max_output, plain.inner.size());
        }
        kad6::K6ShapedHeader header;
        (void)kad6::PeekK6ShapedHeader(data, input.size(), header);
        const int layers = static_cast<int>(rng.Range(5));
        std::vector<Byte> prefix;
        const kad6::Kad6Status se = kad6::ExtractK6ShapedPrefix(
            data, input.size(), layers, prefix, &header);
        if (se == kad6::Kad6Status::Ok) {
            Require(report, layers >= 1 && layers <= 3, "accepted depth is in range");
            Require(report, prefix.size() == kad6::K6ShapedPrefixLen(layers),
                    "opaque-prefix allocation has exact bounded size");
            Require(report, prefix.size() <= kad6::K6ShapedPrefixLen(3),
                    "opaque-prefix allocation cap");
            report.max_output = std::max(report.max_output, prefix.size());
        } else {
            Require(report, prefix.empty(), "failed extraction exposes no partial prefix");
        }
        report.max_input = std::max(report.max_input, input.size());
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
