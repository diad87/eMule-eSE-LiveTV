#include "../../miniupnpc/include/miniupnpc.h"
#include "../../miniupnpc/src/checked_copy.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
const char* soapResponse = nullptr;
}

// Stand in for the HTTP transport while exercising the real C SOAP parser.
extern "C" char* simpleUPnPcommand(const char*, const char*, const char* action,
                                  const UPNParg*, int* size) {
    if (soapResponse == nullptr ||
        std::strcmp(action, "GetSpecificPortMappingEntry") != 0)
        return nullptr;
    const std::size_t bytes = std::strlen(soapResponse);
    auto* copy = static_cast<char*>(std::malloc(bytes + 1));
    if (copy == nullptr)
        return nullptr;
    std::memcpy(copy, soapResponse, bytes + 1);
    *size = static_cast<int>(bytes);
    return copy;
}

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

int ReadMapping(const char* response) {
    soapResponse = response;
    char client[40] = {};
    char port[8] = {};
    char description[80] = {};
    char enabled[8] = {};
    char lifetime[16] = {};
    return UPNP_GetSpecificPortMappingEntryChecked(
        "fake-url", "WANIPConnection", "4662", "TCP", nullptr,
        client, sizeof(client), port, sizeof(port),
        description, sizeof(description), enabled, sizeof(enabled),
        lifetime, sizeof(lifetime));
}

void TestSpecificMappingAbsenceFault() {
    const char faultStart[] =
        "<s:Envelope><s:Body><s:Fault><faultcode>s:Client</faultcode>"
        "<detail><UPnPError><errorCode>";
    const char faultEnd[] =
        "</UPnPError></detail></s:Fault></s:Body></s:Envelope>";
    const char mappingFields[] =
        "<NewInternalClient>192.168.1.15</NewInternalClient>"
        "<NewInternalPort>4662</NewInternalPort>"
        "<NewPortMappingDescription>eT0123456789123</NewPortMappingDescription>"
        "<NewEnabled>1</NewEnabled>";
    char xml[1024] = {};
    const auto fault = [&](const char* code, const char* fields) {
        std::snprintf(xml, sizeof(xml), "%s%s</errorCode>%s%s",
                      faultStart, code, fields, faultEnd);
        return ReadMapping(xml);
    };

    CHECK(fault("714", "") == 714);
    CHECK(fault("714", "<NewInternalPort>4662</NewInternalPort>") ==
          UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(fault("714", mappingFields) == UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(fault("714junk", "") == UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(ReadMapping("<response><errorCode>714</errorCode></response>") ==
          UPNPCOMMAND_INVALID_RESPONSE);
    CHECK(ReadMapping("<response><errorCode>0</errorCode></response>") ==
          UPNPCOMMAND_INVALID_RESPONSE);
    std::snprintf(xml, sizeof(xml), "<response>%s</response>", mappingFields);
    CHECK(ReadMapping(xml) == UPNPCOMMAND_SUCCESS);
}

} // namespace

int main() {
    TestExactValuesFit();
    TestOverlongValuesNeverCollapseToExact();
    TestInvalidArgumentsFailClosed();
    TestMalformedPayloadDominatesReportedSuccess();
    TestSpecificMappingAbsenceFault();
    std::printf("test_miniupnpc_checked_copy: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
