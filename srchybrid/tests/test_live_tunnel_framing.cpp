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

struct ParsedFragment {
    std::uint8_t sub_cmd = 0;
    std::uint32_t request_id = 0;
    std::uint16_t body_len = 0;
    std::uint16_t index = 0;
    std::uint16_t count = 0;
    std::uint32_t total = 0;
    const std::uint8_t* data = nullptr;
    std::size_t data_len = 0;
};

bool ParseCell(const std::vector<std::uint8_t>& cell, ParsedFragment& parsed)
{
    const std::uint8_t* body = nullptr;
    return eSELive::ParseSubHeader(
               cell.data(), cell.size(), parsed.sub_cmd, parsed.request_id,
               parsed.body_len, body)
        && eSELive::ParseFragHeader(
               body, parsed.body_len, parsed.index, parsed.count, parsed.total,
               parsed.data, parsed.data_len);
}

void TestSubHeaderGolden()
{
    using namespace eSELive;
    std::array<std::uint8_t, SUB_HEADER_BYTES> header{};
    PackSubHeader(0x40, 0xAABBCCDD, 0x1234, header.data());
    const std::array<std::uint8_t, SUB_HEADER_BYTES> expected{
        0x40, 0xDD, 0xCC, 0xBB, 0xAA, 0x34, 0x12,
    };
    Check(header == expected, "sub-header byte golden");

    std::vector<std::uint8_t> plain(header.begin(), header.end());
    plain.resize(plain.size() + 0x1234, 0xA5);
    std::uint8_t sub_cmd = 0;
    std::uint32_t request_id = 0;
    std::uint16_t body_len = 0;
    const std::uint8_t* body = nullptr;
    Check(ParseSubHeader(
              plain.data(), plain.size(), sub_cmd, request_id, body_len, body),
          "parse exact sub-header body");
    Check(
        sub_cmd == 0x40 && request_id == 0xAABBCCDD && body_len == 0x1234,
        "sub-header fields round-trip");
    Check(body == plain.data() + SUB_HEADER_BYTES,
          "sub-header body aliases input");

    for (std::size_t length = 0; length < SUB_HEADER_BYTES; ++length) {
        Check(!ParseSubHeader(
                  header.data(), length, sub_cmd, request_id, body_len, body),
              "reject short sub-header");
    }
    Check(!ParseSubHeader(
              nullptr, 0, sub_cmd, request_id, body_len, body),
          "reject null sub-header");

    PackSubHeader(0x40, 7, 6, header.data());
    std::vector<std::uint8_t> overrun(header.begin(), header.end());
    overrun.resize(overrun.size() + 5, 0);
    Check(!ParseSubHeader(
              overrun.data(), overrun.size(), sub_cmd, request_id, body_len,
              body),
          "reject declared sub-header overrun");
}

void TestFragmentHeaderGolden()
{
    using namespace eSELive;
    std::array<std::uint8_t, FRAG_HEADER_BYTES> header{};
    PackFragHeader(0x0102, 0x0304, 0xAABBCCDD, header.data());
    const std::array<std::uint8_t, FRAG_HEADER_BYTES> expected{
        0x02, 0x01, 0x04, 0x03, 0xDD, 0xCC, 0xBB, 0xAA,
    };
    Check(header == expected, "fragment-header byte golden");

    std::uint16_t index = 0;
    std::uint16_t count = 0;
    std::uint32_t total = 0;
    const std::uint8_t* data = nullptr;
    std::size_t data_len = 0;
    Check(ParseFragHeader(
              header.data(), header.size(), index, count, total, data,
              data_len),
          "parse exact fragment header");
    Check(
        index == 0x0102 && count == 0x0304 && total == 0xAABBCCDD
            && data_len == 0,
        "fragment-header fields round-trip");

    for (std::size_t length = 0; length < FRAG_HEADER_BYTES; ++length) {
        Check(!ParseFragHeader(
                  header.data(), length, index, count, total, data, data_len),
              "reject short fragment header");
    }
    Check(!ParseFragHeader(
              nullptr, 0, index, count, total, data, data_len),
          "reject null fragment header");
}

void TestSplitAndReassemblyGoldens()
{
    using namespace eSELive;
    std::vector<std::uint8_t> message(1000);
    for (std::size_t index = 0; index < message.size(); ++index)
        message[index] = static_cast<std::uint8_t>((index * 37) & 0xFF);

    std::vector<std::vector<std::uint8_t>> cells;
    Check(SplitIntoCells(
              0x40, 77, message.data(), message.size(), 458, cells),
          "split valid multi-cell message");
    Check(cells.size() == 3, "split produces three cells");

    std::array<ParsedFragment, 3> parsed{};
    for (std::size_t index = 0; index < parsed.size(); ++index) {
        Check(ParseCell(cells[index], parsed[index]), "parse split cell");
        Check(
            parsed[index].sub_cmd == 0x40
                && parsed[index].request_id == 77
                && parsed[index].index == index
                && parsed[index].count == 3
                && parsed[index].total == message.size(),
            "split cell metadata golden");
    }

    ReassemblyEntry entry;
    const std::array<std::size_t, 3> order{2, 0, 1};
    ReassemblyResult result = ReassemblyResult::Incomplete;
    for (const std::size_t index : order) {
        result = ReassemblyIngest(
            entry, parsed[index].index, parsed[index].count,
            parsed[index].total, parsed[index].data, parsed[index].data_len);
    }
    Check(result == ReassemblyResult::Complete,
          "out-of-order reassembly completes");
    Check(entry.message == message, "reassembled message is byte-exact");

    ReassemblyEntry duplicate;
    result = ReassemblyIngest(
        duplicate, parsed[0].index, parsed[0].count, parsed[0].total,
        parsed[0].data, parsed[0].data_len);
    Check(result == ReassemblyResult::Incomplete && duplicate.got_count == 1,
          "first fragment is incomplete");
    result = ReassemblyIngest(
        duplicate, parsed[0].index, parsed[0].count, parsed[0].total,
        parsed[0].data, parsed[0].data_len);
    Check(result == ReassemblyResult::Incomplete && duplicate.got_count == 1,
          "duplicate fragment is idempotent");
    for (std::size_t index = 1; index < parsed.size(); ++index) {
        result = ReassemblyIngest(
            duplicate, parsed[index].index, parsed[index].count,
            parsed[index].total, parsed[index].data, parsed[index].data_len);
    }
    Check(result == ReassemblyResult::Complete
              && duplicate.message == message,
          "duplicate does not change final message");

    std::vector<std::vector<std::uint8_t>> empty_cells;
    Check(SplitIntoCells(0x40, 88, nullptr, 0, 458, empty_cells)
              && empty_cells.size() == 1,
          "zero-byte message uses one fragment");
    ParsedFragment empty{};
    Check(ParseCell(empty_cells[0], empty), "parse zero-byte message");
    ReassemblyEntry empty_entry;
    Check(ReassemblyIngest(
              empty_entry, empty.index, empty.count, empty.total, empty.data,
              empty.data_len) == ReassemblyResult::Complete
              && empty_entry.message.empty(),
          "zero-byte message reassembles safely");
}

void TestBoundsAndMalformedInputs()
{
    using namespace eSELive;
    const std::array<std::uint8_t, 4> data{1, 2, 3, 4};
    std::vector<std::vector<std::uint8_t>> cells;
    Check(!SplitIntoCells(0x40, 1, data.data(), data.size(), 0, cells),
          "reject zero fragment capacity");
    Check(!SplitIntoCells(
              0x40, 1, data.data(), data.size(), CELL_PAYLOAD_MAX + 1, cells),
          "reject oversized fragment capacity");
    Check(!SplitIntoCells(0x40, 1, nullptr, 1, 1, cells),
          "reject null non-empty message");

    std::vector<std::uint8_t> oversized(TUN_MSG_MAX_BYTES + 1, 0);
    Check(!SplitIntoCells(
              0x40, 1, oversized.data(), oversized.size(), 458, cells),
          "reject message above hard cap");

    ReassemblyEntry bad;
    Check(ReassemblyIngest(bad, 0, 0, 1, data.data(), 1)
              == ReassemblyResult::Error,
          "reject zero fragment count");
    Check(ReassemblyIngest(
              bad, 0, static_cast<std::uint16_t>(TUN_MSG_MAX_FRAGS + 1), 1,
              data.data(), 1) == ReassemblyResult::Error,
          "reject fragment count above cap");
    Check(ReassemblyIngest(bad, 2, 2, 1, data.data(), 1)
              == ReassemblyResult::Error,
          "reject fragment index outside count");
    Check(ReassemblyIngest(
              bad, 0, 1, static_cast<std::uint32_t>(TUN_MSG_MAX_BYTES + 1),
              data.data(), 1) == ReassemblyResult::Error,
          "reject declared message above cap");
    Check(ReassemblyIngest(
              bad, 0, 1, 1, data.data(), TUN_MSG_MAX_BYTES + 1)
              == ReassemblyResult::Error,
          "reject fragment payload above cap");
    Check(ReassemblyIngest(bad, 0, 1, 1, nullptr, 1)
              == ReassemblyResult::Error,
          "reject null non-empty fragment");

    ReassemblyEntry inconsistent_count;
    Check(ReassemblyIngest(
              inconsistent_count, 0, 2, 2, data.data(), 1)
              == ReassemblyResult::Incomplete,
          "seed count-consistency fixture");
    Check(ReassemblyIngest(
              inconsistent_count, 1, 3, 2, data.data(), 1)
              == ReassemblyResult::Error,
          "reject inconsistent fragment count");

    ReassemblyEntry inconsistent_total;
    Check(ReassemblyIngest(
              inconsistent_total, 0, 2, 2, data.data(), 1)
              == ReassemblyResult::Incomplete,
          "seed total-consistency fixture");
    Check(ReassemblyIngest(
              inconsistent_total, 1, 2, 3, data.data(), 1)
              == ReassemblyResult::Error,
          "reject inconsistent declared total");

    ReassemblyEntry size_mismatch;
    Check(ReassemblyIngest(size_mismatch, 0, 2, 3, data.data(), 1)
              == ReassemblyResult::Incomplete,
          "seed declared-size fixture");
    Check(ReassemblyIngest(size_mismatch, 1, 2, 3, data.data() + 1, 1)
              == ReassemblyResult::Error,
          "reject completed message with wrong total size");
}

}  // namespace

int main()
{
    TestSubHeaderGolden();
    TestFragmentHeaderGolden();
    TestSplitAndReassemblyGoldens();
    TestBoundsAndMalformedInputs();
    Check(
        eSELive::RunFramingCharacterizationSelfTest()
            == eSELive::FramingSelfTestResult::Ok,
        "production characterization helper");

    if (failures != 0)
        return 1;
    std::cout << "Live tunnel production framing: PASS\n";
    return 0;
}
