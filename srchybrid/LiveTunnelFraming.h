// Pure tunnel framing primitives.
//
// This header deliberately has no MFC or Windows dependency so the exact
// production wire implementation can be compiled by the standalone tests.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace eSELive {

constexpr std::size_t CELL_TOTAL_BYTES  = 512;
constexpr std::size_t CELL_HEADER_BYTES = 7;
constexpr std::size_t CELL_PAYLOAD_MAX  = CELL_TOTAL_BYTES - CELL_HEADER_BYTES;

constexpr std::size_t SUB_HEADER_BYTES     = 7;
constexpr std::size_t FRAG_HEADER_BYTES    = 8;
constexpr std::uint8_t TUN_MULTICELL_OP_MIN = 0x40;

constexpr std::size_t TUN_MSG_MAX_BYTES       = 65536;
constexpr std::uint32_t TUN_REASSEMBLY_TTL_MS = 8000;
constexpr std::uint32_t TUN_REQUEST_HARD_TTL_MS = 60000;
constexpr int TUN_SEND_RETRIES = 2;
constexpr std::uint16_t TUN_MSG_MAX_FRAGS = 256;

void PackSubHeader(std::uint8_t sub_cmd, std::uint32_t req_id,
                   std::uint16_t bodyLen,
                   std::uint8_t out[SUB_HEADER_BYTES]);

bool ParseSubHeader(const std::uint8_t* plain, std::size_t len,
                    std::uint8_t& outSubCmd, std::uint32_t& outReqId,
                    std::uint16_t& outBodyLen,
                    const std::uint8_t*& outBody);

void PackFragHeader(std::uint16_t fragIndex, std::uint16_t fragCount,
                    std::uint32_t msgTotal,
                    std::uint8_t out[FRAG_HEADER_BYTES]);

bool ParseFragHeader(const std::uint8_t* body, std::size_t bodyLen,
                     std::uint16_t& outFragIndex,
                     std::uint16_t& outFragCount,
                     std::uint32_t& outMsgTotal,
                     const std::uint8_t*& outFragData,
                     std::size_t& outFragDataLen);

bool SplitIntoCells(std::uint8_t sub_cmd, std::uint32_t req_id,
                    const std::uint8_t* message, std::size_t messageLen,
                    std::size_t fragDataMax,
                    std::vector<std::vector<std::uint8_t>>& outCells);

enum class ReassemblyResult : std::uint8_t {
    Incomplete = 0,
    Complete   = 1,
    Error      = 2,
};

struct ReassemblyEntry {
    std::uint32_t expected_total = 0;
    std::uint16_t frag_count = 0;
    std::uint16_t got_count = 0;
    bool started = false;
    std::uint32_t first_seen_tick = 0;
    std::vector<std::vector<std::uint8_t>> frags;
    std::vector<bool> got;
    std::vector<std::uint8_t> message;
};

ReassemblyResult ReassemblyIngest(ReassemblyEntry& entry,
                                  std::uint16_t fragIndex,
                                  std::uint16_t fragCount,
                                  std::uint32_t msgTotal,
                                  const std::uint8_t* fragData,
                                  std::size_t fragDataLen);

} // namespace eSELive
