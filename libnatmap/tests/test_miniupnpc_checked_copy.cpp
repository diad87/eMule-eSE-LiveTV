#include "../../miniupnpc/src/checked_copy.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void TestExactValuesFit() {
    char client[16] = {};
    CHECK(copyCheckedValue(client, sizeof(client), "192.168.100.100"));
    CHECK(std::strcmp(client, "192.168.100.100") == 0);

    char port[6] = {};
    CHECK(copyCheckedValue(port, sizeof(port), "46620"));
    CHECK(std::strcmp(port, "46620") == 0);

    char description[24] = {};
    CHECK(copyCheckedValue(
        description, sizeof(description),
        "eMuleT-0123456789ABCDEF"));
    CHECK(std::strcmp(
        description, "eMuleT-0123456789ABCDEF") == 0);
}

void TestOverlongValuesNeverCollapseToExact() {
    char client[16] = "old";
    CHECK(!copyCheckedValue(
        client, sizeof(client), "192.168.100.100X"));
    CHECK(client[0] == 0);

    char port[6] = "old";
    CHECK(!copyCheckedValue(
        port, sizeof(port), "46620junk"));
    CHECK(port[0] == 0);

    char description[24] = "old";
    CHECK(!copyCheckedValue(
        description, sizeof(description),
        "eMuleT-0123456789ABCDEFSUFFIX"));
    CHECK(description[0] == 0);
}

void TestInvalidArgumentsFailClosed() {
    char value[4] = "old";
    CHECK(!copyCheckedValue(value, 0, "1"));
    CHECK(std::strcmp(value, "old") == 0);
    CHECK(!copyCheckedValue(value, sizeof(value), nullptr));
    CHECK(value[0] == 0);
    CHECK(copyCheckedValue(nullptr, 0, "optional"));
}

void TestMalformedPayloadDominatesReportedSuccess() {
    CHECK(checkedResponseResult(
        UPNPCOMMAND_SUCCESS, 1) == UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(checkedResponseResult(
        718, 1) == UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(checkedResponseResult(
        UPNPCOMMAND_SUCCESS, 0) == UPNPCOMMAND_SUCCESS);
}

} // namespace

int main() {
    TestExactValuesFit();
    TestOverlongValuesNeverCollapseToExact();
    TestInvalidArgumentsFailClosed();
    TestMalformedPayloadDominatesReportedSuccess();
    std::printf("test_miniupnpc_checked_copy: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
