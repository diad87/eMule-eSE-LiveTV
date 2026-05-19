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

    // v0.71 P0.A — rates reduced from the original thesis values
    // (10/50/200 cells/s) which were per-stream-of-multiple-circuits.
    // With our current 1 Hz tick + per-originator-circuit emission,
    // the cap is effectively 1 cell/sec from the tick rate. We use
    // lower mu so most ticks DON'T emit (preserving Poisson burstiness).
    // 2/s default ≈ one padding every 500ms on average across all
    // circuits, which is enough to mask bursts without saturating
    // bandwidth.
    enum Profile : uint8_t {
        ProfileLowBw    = 1,
        ProfileDefault  = 2,
        ProfileHighRisk = 8
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
