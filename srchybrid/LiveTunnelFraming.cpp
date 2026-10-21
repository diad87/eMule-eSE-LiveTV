#include "LiveTunnelFraming.h"

#include <cstring>
#include <utility>

namespace eSELive {

void PackSubHeader(std::uint8_t sub_cmd, std::uint32_t req_id,
                   std::uint16_t bodyLen,
                   std::uint8_t out[SUB_HEADER_BYTES])
{
    out[0] = sub_cmd;
    out[1] = static_cast<std::uint8_t>(req_id & 0xFF);
    out[2] = static_cast<std::uint8_t>((req_id >> 8) & 0xFF);
    out[3] = static_cast<std::uint8_t>((req_id >> 16) & 0xFF);
    out[4] = static_cast<std::uint8_t>((req_id >> 24) & 0xFF);
    out[5] = static_cast<std::uint8_t>(bodyLen & 0xFF);
    out[6] = static_cast<std::uint8_t>((bodyLen >> 8) & 0xFF);
}

bool ParseSubHeader(const std::uint8_t* plain, std::size_t len,
                    std::uint8_t& outSubCmd, std::uint32_t& outReqId,
                    std::uint16_t& outBodyLen,
                    const std::uint8_t*& outBody)
{
    if (!plain || len < SUB_HEADER_BYTES)
        return false;

    outSubCmd = plain[0];
    outReqId = static_cast<std::uint32_t>(plain[1])
             | (static_cast<std::uint32_t>(plain[2]) << 8)
             | (static_cast<std::uint32_t>(plain[3]) << 16)
             | (static_cast<std::uint32_t>(plain[4]) << 24);
    outBodyLen = static_cast<std::uint16_t>(plain[5])
               | (static_cast<std::uint16_t>(plain[6]) << 8);
    if (SUB_HEADER_BYTES + static_cast<std::size_t>(outBodyLen) > len)
        return false;

    outBody = plain + SUB_HEADER_BYTES;
    return true;
}

void PackFragHeader(std::uint16_t fragIndex, std::uint16_t fragCount,
                    std::uint32_t msgTotal,
                    std::uint8_t out[FRAG_HEADER_BYTES])
{
    out[0] = static_cast<std::uint8_t>(fragIndex & 0xFF);
    out[1] = static_cast<std::uint8_t>((fragIndex >> 8) & 0xFF);
    out[2] = static_cast<std::uint8_t>(fragCount & 0xFF);
    out[3] = static_cast<std::uint8_t>((fragCount >> 8) & 0xFF);
    out[4] = static_cast<std::uint8_t>(msgTotal & 0xFF);
    out[5] = static_cast<std::uint8_t>((msgTotal >> 8) & 0xFF);
    out[6] = static_cast<std::uint8_t>((msgTotal >> 16) & 0xFF);
    out[7] = static_cast<std::uint8_t>((msgTotal >> 24) & 0xFF);
}

bool ParseFragHeader(const std::uint8_t* body, std::size_t bodyLen,
                     std::uint16_t& outFragIndex,
                     std::uint16_t& outFragCount,
                     std::uint32_t& outMsgTotal,
                     const std::uint8_t*& outFragData,
                     std::size_t& outFragDataLen)
{
    if (!body || bodyLen < FRAG_HEADER_BYTES)
        return false;

    outFragIndex = static_cast<std::uint16_t>(body[0])
                 | (static_cast<std::uint16_t>(body[1]) << 8);
    outFragCount = static_cast<std::uint16_t>(body[2])
                 | (static_cast<std::uint16_t>(body[3]) << 8);
    outMsgTotal = static_cast<std::uint32_t>(body[4])
                | (static_cast<std::uint32_t>(body[5]) << 8)
                | (static_cast<std::uint32_t>(body[6]) << 16)
                | (static_cast<std::uint32_t>(body[7]) << 24);
    outFragData = body + FRAG_HEADER_BYTES;
    outFragDataLen = bodyLen - FRAG_HEADER_BYTES;
    return true;
}

bool SplitIntoCells(std::uint8_t sub_cmd, std::uint32_t req_id,
                    const std::uint8_t* message, std::size_t messageLen,
                    std::size_t fragDataMax,
                    std::vector<std::vector<std::uint8_t>>& outCells)
{
    outCells.clear();
    if (fragDataMax == 0 || fragDataMax > CELL_PAYLOAD_MAX)
        return false;
    if (messageLen > TUN_MSG_MAX_BYTES || (messageLen > 0 && !message))
        return false;

    const std::size_t fragCount =
        messageLen == 0 ? 1 : (messageLen + fragDataMax - 1) / fragDataMax;
    if (fragCount > TUN_MSG_MAX_FRAGS)
        return false;

    outCells.reserve(fragCount);
    for (std::size_t idx = 0; idx < fragCount; ++idx) {
        const std::size_t offset = idx * fragDataMax;
        const std::size_t chunk =
            messageLen - offset < fragDataMax ? messageLen - offset : fragDataMax;
        std::vector<std::uint8_t> cell(
            SUB_HEADER_BYTES + FRAG_HEADER_BYTES + chunk);
        PackSubHeader(sub_cmd, req_id,
                      static_cast<std::uint16_t>(FRAG_HEADER_BYTES + chunk),
                      cell.data());
        PackFragHeader(static_cast<std::uint16_t>(idx),
                       static_cast<std::uint16_t>(fragCount),
                       static_cast<std::uint32_t>(messageLen),
                       cell.data() + SUB_HEADER_BYTES);
        if (chunk > 0) {
            std::memcpy(cell.data() + SUB_HEADER_BYTES + FRAG_HEADER_BYTES,
                        message + offset, chunk);
        }
        outCells.push_back(std::move(cell));
    }
    return true;
}

ReassemblyResult ReassemblyIngest(ReassemblyEntry& entry,
                                  std::uint16_t fragIndex,
                                  std::uint16_t fragCount,
                                  std::uint32_t msgTotal,
                                  const std::uint8_t* fragData,
                                  std::size_t fragDataLen)
{
    if (fragCount == 0 || fragCount > TUN_MSG_MAX_FRAGS
        || msgTotal > TUN_MSG_MAX_BYTES
        || fragDataLen > TUN_MSG_MAX_BYTES
        || fragIndex >= fragCount
        || (fragDataLen > 0 && !fragData)) {
        return ReassemblyResult::Error;
    }

    if (!entry.started) {
        entry.expected_total = msgTotal;
        entry.frag_count = fragCount;
        entry.got_count = 0;
        entry.frags.assign(fragCount, std::vector<std::uint8_t>());
        entry.got.assign(fragCount, false);
        entry.started = true;
    } else if (fragCount != entry.frag_count
               || msgTotal != entry.expected_total) {
        return ReassemblyResult::Error;
    }

    if (!entry.got[fragIndex]) {
        if (fragDataLen == 0)
            entry.frags[fragIndex].clear();
        else
            entry.frags[fragIndex].assign(fragData, fragData + fragDataLen);
        entry.got[fragIndex] = true;
        ++entry.got_count;
    }
    if (entry.got_count < entry.frag_count)
        return ReassemblyResult::Incomplete;

    std::size_t total = 0;
    for (const auto& fragment : entry.frags)
        total += fragment.size();
    if (total != entry.expected_total)
        return ReassemblyResult::Error;

    entry.message.clear();
    entry.message.reserve(total);
    for (const auto& fragment : entry.frags)
        entry.message.insert(entry.message.end(),
                             fragment.begin(), fragment.end());
    return ReassemblyResult::Complete;
}

} // namespace eSELive
