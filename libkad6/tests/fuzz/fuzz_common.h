// SPDX-License-Identifier: MIT
#pragma once

#include "kad6/kad6_types.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace kad6_fuzz {

using kad6::Byte;

struct Config {
    std::uint64_t seed = 0x4b4144365f463030ull; // "KAD6_F00"
    std::size_t iterations = 100000;
};

struct Report {
    const char* target = "";
    std::size_t iterations = 0;
    std::size_t checks = 0;
    std::size_t failures = 0;
    std::size_t max_input = 0;
    std::size_t max_output = 0;
};

class Rng {
public:
    explicit Rng(std::uint64_t seed) : state_(seed ? seed : 1) {}

    std::uint64_t Next() noexcept {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 7;
        state_ ^= state_ << 17;
        return state_;
    }

    std::size_t Range(std::size_t upper) noexcept {
        return upper == 0 ? 0 : static_cast<std::size_t>(Next() % upper);
    }

private:
    std::uint64_t state_;
};

inline void Require(Report& report, bool condition, const char* what) {
    ++report.checks;
    if (!condition) {
        ++report.failures;
        if (report.failures <= 8)
            std::printf("  FAIL[%s]: %s\n", report.target, what);
    }
}

inline const Byte* DataOrNull(const std::vector<Byte>& input) noexcept {
    return input.empty() ? nullptr : input.data();
}

// Deterministic corpus mutation. Most iterations are tiny mutations of a seed;
// every 257th iteration is a fully generated buffer. This keeps the 100k gate
// fast while still covering arbitrary lengths and bytes reproducibly.
inline std::vector<Byte> Mutate(const std::vector<std::vector<Byte>>& corpus,
                                Rng& rng, std::size_t iteration,
                                std::size_t randomMax) {
    std::vector<Byte> out;
    if (iteration % 257 == 0) {
        const std::size_t n = rng.Range(randomMax + 1);
        out.resize(n);
        for (Byte& b : out)
            b = static_cast<Byte>(rng.Next() >> 24);
        return out;
    }

    out = corpus[rng.Range(corpus.size())];
    switch (rng.Range(5)) {
        case 0:
            if (!out.empty()) out.resize(rng.Range(out.size() + 1));
            break;
        case 1: {
            const std::size_t extra = rng.Range(33);
            const std::size_t old = out.size();
            out.resize(std::min(randomMax, old + extra));
            for (std::size_t i = old; i < out.size(); ++i)
                out[i] = static_cast<Byte>(rng.Next() >> 32);
            break;
        }
        default: {
            const std::size_t mutations = 1 + rng.Range(8);
            for (std::size_t i = 0; i < mutations && !out.empty(); ++i)
                out[rng.Range(out.size())] ^= static_cast<Byte>(1u << rng.Range(8));
            break;
        }
    }
    return out;
}

bool FuzzAddress(const Config&, Report&);
bool FuzzAsn(const Config&, Report&);
bool FuzzBootstrap(const Config&, Report&);
bool FuzzFrame(const Config&, Report&);
bool FuzzGateway(const Config&, Report&);
bool FuzzLease(const Config&, Report&);
bool FuzzPublish(const Config&, Report&);
bool FuzzStore(const Config&, Report&);
bool FuzzTags(const Config&, Report&);
bool FuzzTicket(const Config&, Report&);
bool FuzzRecords(const Config&, Report&);
bool FuzzRouting(const Config&, Report&);
bool FuzzShaped(const Config&, Report&);

} // namespace kad6_fuzz
