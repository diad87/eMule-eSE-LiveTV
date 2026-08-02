#include "natmap/instance_isolation.h"
#include "natmap/natpmp_pair_transaction.h"
#include "natmap/ownership_ledger.h"
#include "natmap/pcp_mapping_identity.h"

#include <array>
#include <cstdio>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

constexpr std::uint64_t kProfileA = 0x1111222233334444ull;
constexpr std::uint64_t kProfileB = 0x5555666677778888ull;
constexpr std::uint64_t kGateway1 = 0x1234567890abcdefull;
constexpr std::uint64_t kGateway2 = 0xfedcba0987654321ull;

ObservedUpnpMapping Observe(const UpnpOwnershipRecord& record);

struct LabRule {
    std::uint64_t profile = 0;
    MapperKind mapper = MapperKind::None;
    std::uint16_t requested_port = 0;
    std::uint16_t granted_port = 0;
    std::uint64_t session = 0;
    std::uint64_t gateway = 0;
    UpnpOwnershipRecord upnp{};
    FirewallRuleProof firewall{};
    bool active = false;
};

struct SimulatedT8 {
    std::array<LabRule, 8> rules{};
    std::size_t count = 0;
    std::uint64_t gateway = kGateway1;
    std::uint64_t sessionA = 1;
    std::uint64_t sessionB = 1;

    std::uint64_t CurrentSession(std::uint64_t profile) const {
        return profile == kProfileA ? sessionA : sessionB;
    }

    bool IsOccupied(std::uint16_t port,
                    std::uint64_t& owner) const {
        owner = 0;
        for (std::size_t i = 0; i < count; ++i) {
            if (rules[i].active && rules[i].granted_port == port) {
                owner = rules[i].profile;
                return true;
            }
        }
        return false;
    }

    PortCollisionDecision Start(
        std::uint64_t profile,
        MapperKind mapper,
        std::uint16_t requested,
        const SecureAlternativePort& alternative,
        LabRule*& created) {
        created = nullptr;
        std::uint64_t owner = 0;
        const bool occupied = IsOccupied(requested, owner);
        const PortCollisionDecision decision =
            ResolveInstancePortCollision(
                profile, owner, requested, occupied, alternative);
        if (decision == PortCollisionDecision::ExplicitFailure ||
            count == rules.size())
            return decision;

        const std::uint16_t granted =
            decision == PortCollisionDecision::AlternativePort
                ? alternative.port : requested;
        LabRule& rule = rules[count++];
        rule.profile = profile;
        rule.mapper = mapper;
        rule.requested_port = requested;
        rule.granted_port = granted;
        rule.session = CurrentSession(profile);
        rule.gateway = gateway;
        rule.active = true;
        rule.firewall.profile_owner_token = profile;
        rule.firewall.transport = Transport::Tcp;
        rule.firewall.local_port = granted;
        rule.firewall.rule_name =
            BuildOwnedFirewallRuleName(profile, Transport::Tcp);
        if (mapper == MapperKind::UpnpIgd) {
            rule.upnp.owner_token = profile;
            rule.upnp.gateway_fingerprint = gateway;
            rule.upnp.transport = Transport::Tcp;
            rule.upnp.local_address =
                IpAddress::V4(192, 168, 1,
                    profile == kProfileA ? 10 : 11);
            rule.upnp.local_port = requested;
            rule.upnp.external_port = granted;
            rule.upnp.lifetime_seconds = 3600;
            rule.upnp.acquired_unix_seconds = 1000;
            rule.upnp.generation = 1;
            rule.upnp.description =
                BuildOwnershipDescription(profile, Transport::Tcp);
        }
        created = &rule;
        return decision;
    }

    std::size_t Close(std::uint64_t profile) {
        std::size_t removed = 0;
        for (std::size_t i = 0; i < count; ++i) {
            LabRule& rule = rules[i];
            if (!rule.active)
                continue;
            if (EvaluateFirewallCleanup(
                    rule.firewall, profile, Transport::Tcp,
                    rule.granted_port, rule.firewall.rule_name) ==
                FirewallCleanupDecision::Owned)
            {
                rule.active = false;
                ++removed;
            }
        }
        return removed;
    }

    std::size_t ActiveFor(std::uint64_t profile) const {
        std::size_t active = 0;
        for (std::size_t i = 0; i < count; ++i)
            if (rules[i].active && rules[i].profile == profile)
                ++active;
        return active;
    }

    std::size_t Crash(std::uint64_t profile) {
        const std::size_t preserved = ActiveFor(profile);
        if (profile == kProfileA)
            ++sessionA;
        else
            ++sessionB;
        return preserved;
    }

    std::size_t Refresh(std::uint64_t profile) const {
        std::size_t refreshed = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const LabRule& rule = rules[i];
            if (!rule.active || rule.profile != profile ||
                rule.session != CurrentSession(profile))
                continue;
            if (EvaluateFirewallCleanup(
                    rule.firewall, profile, Transport::Tcp,
                    rule.granted_port, rule.firewall.rule_name) ==
                FirewallCleanupDecision::Owned)
                ++refreshed;
        }
        return refreshed;
    }

    std::size_t RestartProfile(std::uint64_t profile) const {
        std::size_t reconciled = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const LabRule& rule = rules[i];
            if (!rule.active || rule.profile != profile ||
                rule.mapper != MapperKind::UpnpIgd)
                continue;
            if (IsUpnpCleanupAuthorized(
                    rule.upnp, gateway, Observe(rule.upnp)))
                ++reconciled;
        }
        return reconciled;
    }

    void RestartGateway(std::uint64_t replacement) {
        gateway = replacement;
    }
};

ObservedUpnpMapping Observe(const UpnpOwnershipRecord& record) {
    ObservedUpnpMapping observed{};
    observed.transport = record.transport;
    observed.local_address = record.local_address;
    observed.local_port = record.local_port;
    observed.external_port = record.external_port;
    observed.description = record.description;
    return observed;
}

void TestSamePortAndDistinctPorts() {
    SimulatedT8 lab;
    SecureAlternativePort secure{54001, true};
    LabRule* a = nullptr;
    LabRule* b = nullptr;
    CHECK(lab.Start(kProfileA, MapperKind::UpnpIgd, 4662,
                    secure, a) ==
          PortCollisionDecision::RequestedPort);
    CHECK(a != nullptr && a->granted_port == 4662);
    CHECK(lab.Start(kProfileB, MapperKind::UpnpIgd, 4662,
                    secure, b) ==
          PortCollisionDecision::AlternativePort);
    CHECK(b != nullptr && b->granted_port == 54001);
    CHECK(a->profile != b->profile);
    CHECK(a->upnp.description != b->upnp.description);
    CHECK(a->firewall.rule_name != b->firewall.rule_name);

    LabRule* bUdp = nullptr;
    secure.port = 54002;
    CHECK(lab.Start(kProfileB, MapperKind::NatPmp, 4672,
                    secure, bUdp) ==
          PortCollisionDecision::RequestedPort);
    CHECK(bUdp != nullptr && bUdp->granted_port == 4672);
}

void TestMapperEqualAndDifferentFailClosed() {
    SimulatedT8 lab;
    SecureAlternativePort secure{55001, true};
    LabRule* a = nullptr;
    LabRule* b = nullptr;
    CHECK(lab.Start(kProfileA, MapperKind::Pcp, 4662,
                    secure, a) ==
          PortCollisionDecision::RequestedPort);
    CHECK(lab.Start(kProfileB, MapperKind::Pcp, 4662,
                    secure, b) ==
          PortCollisionDecision::AlternativePort);
    CHECK(a->mapper == b->mapper);

    secure.port = 0;
    secure.entropy_from_os = false;
    LabRule* failed = nullptr;
    CHECK(lab.Start(kProfileB, MapperKind::NatPmp, 4662,
                    secure, failed) ==
          PortCollisionDecision::ExplicitFailure);
    CHECK(failed == nullptr);

    secure = SecureAlternativePort{55002, true};
    CHECK(lab.Start(kProfileB, MapperKind::NatPmp, 4662,
                    secure, failed) ==
          PortCollisionDecision::AlternativePort);
    CHECK(failed != nullptr &&
          failed->mapper != a->mapper);
}

void TestCloseCrashRestartRefreshAndGatewayRestart() {
    SimulatedT8 lab;
    SecureAlternativePort secure{56001, true};
    LabRule* a = nullptr;
    LabRule* b = nullptr;
    CHECK(lab.Start(kProfileA, MapperKind::UpnpIgd, 4662,
                    secure, a) ==
          PortCollisionDecision::RequestedPort);
    CHECK(lab.Start(kProfileB, MapperKind::UpnpIgd, 4672,
                    secure, b) ==
          PortCollisionDecision::RequestedPort);

    // Clean close A removes only A.
    CHECK(lab.Close(kProfileA) == 1);
    CHECK(lab.ActiveFor(kProfileA) == 0);
    CHECK(lab.ActiveFor(kProfileB) == 1);

    // A crashes after recreating a rule: no cleanup runs, B refresh survives.
    LabRule* crashedA = nullptr;
    CHECK(lab.Start(kProfileA, MapperKind::UpnpIgd, 4662,
                    secure, crashedA) ==
          PortCollisionDecision::RequestedPort);
    CHECK(lab.Crash(kProfileA) == 1);
    CHECK(lab.ActiveFor(kProfileB) == 1);
    CHECK(lab.Refresh(kProfileB) == 1);

    // Restart A can reconcile its durable UPnP proof, never B's proof.
    CHECK(lab.RestartProfile(kProfileA) == 1);
    CHECK(lab.RestartProfile(kProfileB) == 1);
    CHECK(!IsUpnpCleanupAuthorized(
        crashedA->upnp, kGateway1, Observe(b->upnp)));

    // A gateway restart invalidates all old deletion authority.
    lab.RestartGateway(kGateway2);
    CHECK(lab.RestartProfile(kProfileA) == 0);
    CHECK(lab.RestartProfile(kProfileB) == 0);
    CHECK(!IsUpnpCleanupAuthorized(
        crashedA->upnp, lab.gateway, Observe(crashedA->upnp)));
    CHECK(!IsUpnpCleanupAuthorized(
        b->upnp, lab.gateway, Observe(b->upnp)));
}

void TestInheritedMappingCannotBeClaimed() {
    SimulatedT8 lab;
    SecureAlternativePort secure{57001, true};
    LabRule* inherited = nullptr;
    CHECK(lab.Start(kProfileA, MapperKind::UpnpIgd, 4662,
                    secure, inherited) ==
          PortCollisionDecision::RequestedPort);

    // Profile B sees an inherited/foreign mapping: alternative or failure,
    // never adoption of A's requested port.
    LabRule* b = nullptr;
    CHECK(lab.Start(kProfileB, MapperKind::UpnpIgd, 4662,
                    secure, b) ==
          PortCollisionDecision::AlternativePort);
    CHECK(b != nullptr && b->granted_port == 57001);
    CHECK(!IsUpnpCleanupAuthorized(
        inherited->upnp, kGateway1, Observe(b->upnp)));

    SecureAlternativePort unavailable{};
    LabRule* failed = nullptr;
    CHECK(lab.Start(kProfileB, MapperKind::Pcp, 4662,
                    unavailable, failed) ==
          PortCollisionDecision::ExplicitFailure);
    CHECK(failed == nullptr);
}

void TestSessionScopedMapperProofsStaySeparate() {
    std::array<std::uint8_t, 12> nonceA{};
    std::array<std::uint8_t, 12> nonceB{};
    nonceA.fill(0x11);
    nonceB.fill(0x22);
    PcpMappingIdentity pcpA{};
    PcpMappingIdentity pcpB{};
    CHECK(InitializePcpMappingIdentity(
        pcpA, Transport::Tcp, 4662, nonceA) ==
        PcpIdentityStatus::Valid);
    CHECK(InitializePcpMappingIdentity(
        pcpB, Transport::Tcp, 4662, nonceB) ==
        PcpIdentityStatus::Valid);
    CHECK(pcpA.nonce != pcpB.nonce);

    NatPmpCleanupProof proofA{};
    proofA.gateway_address = {192, 168, 1, 1};
    proofA.interface_index = 7;
    proofA.generation = 11;
    proofA.expires_monotonic_seconds = 1000;
    proofA.mapping_count = 1;
    proofA.in_process_proof = true;
    proofA.mappings[0].transport = NatPmpTransport::Tcp;
    proofA.mappings[0].internal_port = 4662;
    proofA.mappings[0].external_port = 4662;
    CHECK(proofA.IsValid());

    // B cannot consume A's route/generation proof.
    NatPmpCleanupProof foreignAttempt = proofA;
    NatPmpCleanupContext bContext{};
    bContext.gateway_address = proofA.gateway_address;
    bContext.interface_index = 8;
    bContext.generation = 12;
    bContext.observed_monotonic_seconds = 900;
    CHECK(TakeNatPmpCleanupPlan(
        foreignAttempt, bContext).IsEmpty());
    CHECK(!foreignAttempt.IsValid());

    NatPmpCleanupContext aContext{};
    aContext.gateway_address = proofA.gateway_address;
    aContext.interface_index = 7;
    aContext.generation = 11;
    aContext.observed_monotonic_seconds = 900;
    const NatPmpCleanupPlan aPlan =
        TakeNatPmpCleanupPlan(proofA, aContext);
    CHECK(aPlan.mapping_count == 1);
    CHECK(!proofA.IsValid());

    // Crash/restart has no in-process proof and therefore no cleanup plan.
    NatPmpCleanupProof afterCrash{};
    CHECK(TakeNatPmpCleanupPlan(
        afterCrash, aContext).IsEmpty());
}

} // namespace

int main() {
    TestSamePortAndDistinctPorts();
    TestMapperEqualAndDifferentFailClosed();
    TestCloseCrashRestartRefreshAndGatewayRestart();
    TestInheritedMappingCannotBeClaimed();
    TestSessionScopedMapperProofsStaySeparate();
    std::printf("two-instance T8: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
