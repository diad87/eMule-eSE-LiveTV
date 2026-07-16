// SPDX-License-Identifier: MIT
#include "relay/relay_core.h"

#include <cstdio>
#include <cstring>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, message) \
    do { \
        if (condition) { \
            ++g_pass; \
        } else { \
            ++g_fail; \
            std::printf("  FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        } \
    } while (0)

} // namespace

static_assert(relay::kNodeIdSize == 32,
              "NodeID must keep the canonical Ed25519 public-key size");
static_assert(relay::kSessionIdSize == 16,
              "SessionID must remain an ephemeral 128-bit identifier");
static_assert(sizeof(relay::NodeId) == relay::kNodeIdSize,
              "NodeId storage must not truncate the public key");
static_assert(sizeof(relay::SessionId) == relay::kSessionIdSize,
              "SessionId storage must be exact");

int main() {
    const relay::RelayCoreBuildInfo& info = relay::GetRelayCoreBuildInfo();
    CHECK(info.version_major == 1 && info.version_minor == 0, "KRP design version is explicit");
    CHECK(!info.wire_enabled, "KRP wire remains disabled through P1");
    CHECK(!info.public_mode_enabled, "public mode remains disabled through P1");
    CHECK(!relay::RelayCoreCanOpenNetwork(), "core fails closed for network authorization");

    CHECK(std::strcmp(relay::RelayStatusName(relay::RelayStatus::TargetForbidden),
                      "TargetForbidden") == 0,
          "diagnostic status names are stable");
    CHECK(std::strcmp(relay::RelayStatusName(static_cast<relay::RelayStatus>(255)),
                      "Unknown") == 0,
          "unknown diagnostic status is bounded");

    std::printf("test_relay_core: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
