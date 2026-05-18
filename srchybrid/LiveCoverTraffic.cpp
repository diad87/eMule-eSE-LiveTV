// this file is part of eMule eSE — Cover traffic Poisson generator impl (F4)
#include "stdafx.h"
#include "LiveCoverTraffic.h"
#include "LiveCellQueue.h"
#include "LiveOnionCrypto.h"
#include <math.h>

namespace eSELive {

CLiveCoverTraffic& CLiveCoverTraffic::Get()
{
    static CLiveCoverTraffic s_instance;
    return s_instance;
}

uint32_t CLiveCoverTraffic::NextPaddingDelayMs(uint32_t mu) const
{
    if (mu == 0) return 60000;
    // Sample U ~ uniform(0,1) from secure RNG, then dt = -ln(U)/μ seconds.
    uint8_t r[8];
    SecureRandomBytes(r, 8);
    uint64_t u64 = 0;
    for (int i = 0; i < 8; ++i) u64 |= ((uint64_t)r[i]) << (i * 8);
    // Avoid log(0): clamp lower bound.
    double u = ((double)(u64 | 1ULL)) / (double)UINT64_MAX;
    if (u <= 0.0) u = 1e-12;
    if (u >= 1.0) u = 1.0 - 1e-12;
    const double dt_s = -log(u) / (double)mu;
    int64_t dt_ms = (int64_t)(dt_s * 1000.0);
    if (dt_ms < 1)     dt_ms = 1;
    if (dt_ms > 60000) dt_ms = 60000;
    return (uint32_t)dt_ms;
}

uint16_t CLiveCoverTraffic::SampleFakeLength() const
{
    uint8_t r[2];
    SecureRandomBytes(r, 2);
    const uint16_t v = (uint16_t)r[0] | ((uint16_t)r[1] << 8);
    return (uint16_t)(v % (uint16_t)(CELL_PAYLOAD_MAX + 1));
}

}  // namespace eSELive
