// this file is part of eMule eSE — Cover traffic Poisson generator (F4)
//
// Cap 5 §5.5.7 thesis. Each active hop emits CELL_PADDING cells at a
// Poisson-distributed rate. Default μ=50/s, high-risk μ=200/s,
// low-bandwidth μ=10/s.
#pragma once

namespace eSELive {

class CLiveCoverTraffic {
public:
    static CLiveCoverTraffic& Get();

    enum Profile : uint8_t {
        ProfileLowBw   = 10,
        ProfileDefault = 50,
        ProfileHighRisk = 200
    };

    // Compute milliseconds until the NEXT padding cell, given μ (cells/sec).
    // Exponential distribution: dt = -ln(U) / μ. Returns clamped int [1, 60000].
    uint32_t NextPaddingDelayMs(uint32_t mu) const;

    // Set profile per-circuit. Default for new circuits = ProfileDefault.
    void SetProfile(Profile p) { m_profile = p; }
    Profile GetProfile() const { return m_profile; }

    // Sample a cell-payload's random length for a CELL_PADDING cell.
    // Returns a value in [0, CELL_PAYLOAD_MAX] uniformly so length-based
    // analysis can't distinguish real vs fake cells trivially.
    uint16_t SampleFakeLength() const;

private:
    CLiveCoverTraffic() : m_profile(ProfileDefault) {}
    CLiveCoverTraffic(const CLiveCoverTraffic&) = delete;
    CLiveCoverTraffic& operator=(const CLiveCoverTraffic&) = delete;

    Profile m_profile;
};

}  // namespace eSELive
