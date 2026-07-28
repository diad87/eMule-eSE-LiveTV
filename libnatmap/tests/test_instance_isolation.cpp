#include "natmap/instance_isolation.h"

#include <cstdio>
#include <cstring>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

constexpr std::uint64_t kProfileA = 0x1111222233334444ull;
constexpr std::uint64_t kProfileB = 0x5555666677778888ull;

FirewallRuleProof Proof(std::uint64_t profile, Transport transport,
                        std::uint16_t port) {
    FirewallRuleProof proof{};
    proof.profile_owner_token = profile;
    proof.transport = transport;
    proof.local_port = port;
    proof.rule_name = BuildOwnedFirewallRuleName(profile, transport);
    return proof;
}

void TestProfileAndRuleIdentity() {
    const auto tcpA =
        BuildOwnedFirewallRuleName(kProfileA, Transport::Tcp);
    const auto udpA =
        BuildOwnedFirewallRuleName(kProfileA, Transport::Udp);
    const auto tcpB =
        BuildOwnedFirewallRuleName(kProfileB, Transport::Tcp);
    CHECK(std::strncmp(tcpA.data(), "eSE-fw-T-", 9) == 0);
    CHECK(std::strncmp(udpA.data(), "eSE-fw-U-", 9) == 0);
    CHECK(std::strcmp(tcpA.data(), tcpB.data()) != 0);
    CHECK(std::strlen(tcpA.data()) == 25);
    CHECK(BuildOwnedFirewallRuleName(0, Transport::Tcp)[0] == 0);
    CHECK(IsOwnedFirewallRuleName(
        kProfileA, Transport::Tcp, tcpA));
    CHECK(!IsOwnedFirewallRuleName(
        kProfileA, Transport::Tcp, tcpB));
}

void TestFirewallCleanupIsExactAndPerInstance() {
    const FirewallRuleProof tcpA =
        Proof(kProfileA, Transport::Tcp, 4662);
    const FirewallRuleProof tcpB =
        Proof(kProfileB, Transport::Tcp, 4662);
    CHECK(tcpA.IsStructurallyValid());
    CHECK(tcpB.IsStructurallyValid());
    CHECK(EvaluateFirewallCleanup(
        tcpA, kProfileA, Transport::Tcp, 4662, tcpA.rule_name) ==
        FirewallCleanupDecision::Owned);

    // Closing A cannot remove B even when the requested port is identical.
    CHECK(EvaluateFirewallCleanup(
        tcpA, kProfileA, Transport::Tcp, 4662, tcpB.rule_name) ==
        FirewallCleanupDecision::NameMismatch);
    CHECK(EvaluateFirewallCleanup(
        tcpB, kProfileA, Transport::Tcp, 4662, tcpB.rule_name) ==
        FirewallCleanupDecision::ProfileMismatch);
    CHECK(EvaluateFirewallCleanup(
        tcpA, kProfileA, Transport::Udp, 4662, tcpA.rule_name) ==
        FirewallCleanupDecision::TransportMismatch);
    CHECK(EvaluateFirewallCleanup(
        tcpA, kProfileA, Transport::Tcp, 4663, tcpA.rule_name) ==
        FirewallCleanupDecision::PortMismatch);

    FirewallRuleProof forged = tcpA;
    forged.rule_name = tcpB.rule_name;
    CHECK(!forged.IsStructurallyValid());
    CHECK(EvaluateFirewallCleanup(
        forged, kProfileA, Transport::Tcp, 4662, tcpB.rule_name) ==
        FirewallCleanupDecision::InvalidProof);
}

void TestCollisionUsesAlternativeOrFailsExplicitly() {
    CHECK(ResolveInstancePortCollision(
        kProfileA, 0, 4662, false, SecureAlternativePort{}) ==
        PortCollisionDecision::RequestedPort);
    CHECK(ResolveInstancePortCollision(
        kProfileA, kProfileA, 4662, true, SecureAlternativePort{}) ==
        PortCollisionDecision::RequestedPort);

    SecureAlternativePort secure{};
    secure.port = 54001;
    secure.entropy_from_os = true;
    CHECK(ResolveInstancePortCollision(
        kProfileB, kProfileA, 4662, true, secure) ==
        PortCollisionDecision::AlternativePort);

    secure.entropy_from_os = false;
    CHECK(ResolveInstancePortCollision(
        kProfileB, kProfileA, 4662, true, secure) ==
        PortCollisionDecision::ExplicitFailure);
    secure.entropy_from_os = true;
    secure.port = 4662;
    CHECK(ResolveInstancePortCollision(
        kProfileB, kProfileA, 4662, true, secure) ==
        PortCollisionDecision::ExplicitFailure);
    CHECK(ResolveInstancePortCollision(
        0, kProfileA, 4662, true, secure) ==
        PortCollisionDecision::ExplicitFailure);
}

} // namespace

int main() {
    TestProfileAndRuleIdentity();
    TestFirewallCleanupIsExactAndPerInstance();
    TestCollisionUsesAlternativeOrFailsExplicitly();
    std::printf("instance isolation: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
