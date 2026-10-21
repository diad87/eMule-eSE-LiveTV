#include "../LiveTunnelFraming.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* label)
{
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

} // namespace

int main()
{
    using namespace eSELive;

    std::array<std::uint8_t, SUB_HEADER_BYTES> sub{};
    PackSubHeader(0x40, 0x12345678, 3, sub.data());
    const std::array<std::uint8_t, SUB_HEADER_BYTES> expectedSub{
        0x40, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00};
    Check(sub == expectedSub, "sub-header pinned little-endian vector");

    const std::array<std::uint8_t, 3> body{0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> plain(sub.begin(), sub.end());
    plain.insert(plain.end(), body.begin(), body.end());
    std::uint8_t subCmd = 0;
    std::uint32_t requestId = 0;
    std::uint16_t bodyLen = 0;
    const std::uint8_t* parsedBody = nullptr;
    Check(ParseSubHeader(plain.data(), plain.size(), subCmd, requestId,
                         bodyLen, parsedBody),
          "parse valid sub-header");
    Check(subCmd == 0x40 && requestId == 0x12345678 && bodyLen == 3,
          "sub-header values round-trip");
    Check(std::equal(body.begin(), body.end(), parsedBody),
          "sub-header body points at payload");
    Check(!ParseSubHeader(plain.data(), plain.size() - 1, subCmd, requestId,
                          bodyLen, parsedBody),
          "reject declared body overrun");
    Check(!ParseSubHeader(nullptr, 0, subCmd, requestId, bodyLen, parsedBody),
          "reject null sub-header");

    std::array<std::uint8_t, FRAG_HEADER_BYTES> fragment{};
    PackFragHeader(2, 5, 0x01020304, fragment.data());
    const std::array<std::uint8_t, FRAG_HEADER_BYTES> expectedFragment{
        0x02, 0x00, 0x05, 0x00, 0x04, 0x03, 0x02, 0x01};
    Check(fragment == expectedFragment,
          "fragment-header pinned little-endian vector");

    std::uint16_t fragmentIndex = 0;
    std::uint16_t fragmentCount = 0;
    std::uint32_t messageTotal = 0;
    const std::uint8_t* fragmentData = nullptr;
    std::size_t fragmentDataLen = 0;
    Check(ParseFragHeader(fragment.data(), fragment.size(), fragmentIndex,
                          fragmentCount, messageTotal, fragmentData,
                          fragmentDataLen),
          "parse valid fragment header");
    Check(fragmentIndex == 2 && fragmentCount == 5
              && messageTotal == 0x01020304 && fragmentDataLen == 0,
          "fragment-header values round-trip");
    Check(!ParseFragHeader(fragment.data(), fragment.size() - 1,
                           fragmentIndex, fragmentCount, messageTotal,
                           fragmentData, fragmentDataLen),
          "reject short fragment header");

    std::vector<std::uint8_t> message(1000);
    for (std::size_t i = 0; i < message.size(); ++i)
        message[i] = static_cast<std::uint8_t>((i * 37) & 0xFF);

    std::vector<std::vector<std::uint8_t>> cells;
    Check(SplitIntoCells(0x40, 77, message.data(), message.size(), 458, cells),
          "split valid message");
    Check(cells.size() == 3, "split produces expected fragment count");

    ReassemblyEntry entry;
    const std::array<std::size_t, 3> order{2, 0, 1};
    ReassemblyResult result = ReassemblyResult::Incomplete;
    for (std::size_t cellIndex : order) {
        Check(ParseSubHeader(cells[cellIndex].data(), cells[cellIndex].size(),
                             subCmd, requestId, bodyLen, parsedBody),
              "parse split sub-header");
        Check(ParseFragHeader(parsedBody, bodyLen, fragmentIndex,
                              fragmentCount, messageTotal, fragmentData,
                              fragmentDataLen),
              "parse split fragment-header");
        result = ReassemblyIngest(entry, fragmentIndex, fragmentCount,
                                  messageTotal, fragmentData, fragmentDataLen);
    }
    Check(result == ReassemblyResult::Complete,
          "out-of-order reassembly completes");
    Check(entry.message == message, "reassembled message is byte-exact");

    Check(ReassemblyIngest(entry, 0, 4, messageTotal, nullptr, 0)
              == ReassemblyResult::Error,
          "reject inconsistent fragment count");
    Check(!SplitIntoCells(0x40, 1, message.data(), message.size(), 0, cells),
          "reject zero fragment capacity");
    Check(!SplitIntoCells(0x40, 1, message.data(), message.size(),
                          CELL_PAYLOAD_MAX + 1, cells),
          "reject oversized fragment capacity");

    Check(SplitIntoCells(0x40, 88, nullptr, 0, 458, cells)
              && cells.size() == 1,
          "zero-byte message uses one fragment");
    ReassemblyEntry emptyEntry;
    Check(ParseSubHeader(cells[0].data(), cells[0].size(), subCmd, requestId,
                         bodyLen, parsedBody)
              && ParseFragHeader(parsedBody, bodyLen, fragmentIndex,
                                 fragmentCount, messageTotal, fragmentData,
                                 fragmentDataLen)
              && ReassemblyIngest(emptyEntry, fragmentIndex, fragmentCount,
                                  messageTotal, fragmentData, fragmentDataLen)
                     == ReassemblyResult::Complete
              && emptyEntry.message.empty(),
          "zero-byte message reassembles safely");

    if (failures != 0)
        return 1;
    std::cout << "Live tunnel production framing: PASS\n";
    return 0;
}
