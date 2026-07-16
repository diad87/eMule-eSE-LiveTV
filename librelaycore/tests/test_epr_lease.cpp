// SPDX-License-Identifier: MIT
#include "relay/epr_lease.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, message) \
    do { \
        if (condition) { ++g_pass; } \
        else { ++g_fail; std::printf("  FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); } \
    } while (0)

template <typename Array>
void Fill(Array& value, relay::Byte seed) {
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<relay::Byte>(seed + i);
}

relay::KrpSessionBinding MakeBinding() {
    relay::KrpSessionBinding binding;
    Fill(binding.session_id, 1);
    Fill(binding.node_id, 0x21);
    Fill(binding.owner_edge_id, 0x51);
    Fill(binding.fencing_token, 0x71);
    binding.session_epoch = 7;
    binding.route_generation = 41;
    return binding;
}

relay::KrpSession MakeActiveSession() {
    relay::KrpSession session;
    (void)session.BeginAuthentication();
    (void)session.ActivateNew(MakeBinding());
    return session;
}

relay::EprLeaseRequest MakeRequest(const relay::KrpSession& session,
                                   std::uint64_t lease_id = 100) {
    relay::EprLeaseRequest request;
    request.lease_id = lease_id;
    request.generation = 1;
    request.session_id = session.binding().session_id;
    request.node_id = session.binding().node_id;
    request.lease_class = relay::EprLeaseClass::PeerShared;
    request.request_tcp = true;
    request.issued_at = 1000;
    request.expires_at = 1900;
    request.grace_expires_at = 1960;
    return request;
}

relay::EprPublicAddress PublicV4() {
    relay::EprPublicAddress address;
    address.family = relay::EprAddressFamily::IPv4;
    address.bytes[0] = 8;
    address.bytes[1] = 8;
    address.bytes[2] = 8;
    address.bytes[3] = 8;
    return address;
}

relay::EprLease MakeActiveLease(const relay::KrpSession& session,
                                std::uint64_t lease_id = 100) {
    relay::EprLease lease;
    (void)lease.Initialize(MakeRequest(session, lease_id),
                           session,
                           relay::KrpTransportPhase::Confirmed1Rtt);
    (void)lease.Allocate(1, PublicV4(), 4662, 0);
    (void)lease.MarkBound();
    relay::EprProbeNonce nonce;
    Fill(nonce, 0xA0);
    (void)lease.BeginProbe(nonce);
    (void)lease.CompleteProbe(nonce, true);
    return lease;
}

void TestAllocationProbeAndOptionalResources() {
    relay::KrpSession session = MakeActiveSession();
    relay::EprLeaseRequest request = MakeRequest(session);
    relay::EprLease lease;
    CHECK(lease.Initialize(request,
                           session,
                           relay::KrpTransportPhase::EarlyData0Rtt) ==
              relay::RelayStatus::OneRttRequired && !lease.initialized(),
          "0-RTT cannot allocate scarce endpoint resources");

    relay::EprLeaseRequest wrong = request;
    wrong.node_id[0] ^= 1;
    CHECK(lease.Initialize(wrong,
                           session,
                           relay::KrpTransportPhase::Confirmed1Rtt) ==
              relay::RelayStatus::AuthFailed,
          "lease identity must equal authenticated session NodeID");
    CHECK(lease.Initialize(request,
                           session,
                           relay::KrpTransportPhase::Confirmed1Rtt) ==
              relay::RelayStatus::Ok &&
              lease.record().state == relay::EprLeaseState::Requested,
          "authenticated 1-RTT request enters REQUESTED");

    relay::EprPublicAddress private_address = PublicV4();
    private_address.bytes[0] = 10;
    CHECK(lease.Allocate(1, private_address, 4662, 0) ==
              relay::RelayStatus::InvalidArgument,
          "private address cannot be exposed as public EPR");
    CHECK(lease.Allocate(0, PublicV4(), 4662, 0) ==
              relay::RelayStatus::StaleGeneration,
          "allocator is fenced by lease generation");
    CHECK(lease.Allocate(1, PublicV4(), 4662, 4672) ==
              relay::RelayStatus::InvalidArgument,
          "allocator cannot add an unrequested UDP resource");
    CHECK(lease.Allocate(1, PublicV4(), 4662, 0) == relay::RelayStatus::Ok &&
              lease.MarkBound() == relay::RelayStatus::Ok,
          "requested TCP-only resource allocates and binds");
    CHECK(!lease.CanAcceptNewTraffic(),
          "BOUND endpoint is not announced before external probe");

    relay::EprProbeNonce zero{};
    CHECK(lease.BeginProbe(zero) == relay::RelayStatus::InvalidArgument,
          "probe requires unpredictable non-zero nonce");
    relay::EprProbeNonce nonce;
    Fill(nonce, 0xA0);
    CHECK(lease.BeginProbe(nonce) == relay::RelayStatus::Ok,
          "BOUND begins challenge probe");
    relay::EprProbeNonce wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    CHECK(lease.CompleteProbe(wrong_nonce, true) == relay::RelayStatus::AuthFailed &&
              lease.record().state == relay::EprLeaseState::Probing,
          "spoofed probe response cannot activate endpoint");
    CHECK(lease.CompleteProbe(nonce, true) == relay::RelayStatus::Ok &&
              lease.CanAcceptNewTraffic() &&
              std::strcmp(relay::EprLeaseStateName(lease.record().state), "ACTIVE") == 0,
          "matching end-to-end probe activates endpoint");

    relay::EprLeaseRequest both = MakeRequest(session, 101);
    both.request_udp = true;
    relay::EprLease dual;
    CHECK(dual.Initialize(both,
                          session,
                          relay::KrpTransportPhase::Confirmed1Rtt) == relay::RelayStatus::Ok &&
              dual.Allocate(1, PublicV4(), 4662, 4672) == relay::RelayStatus::Ok,
          "TCP and UDP are optional and do not require equal port numbers");
}

void TestRenewMigrationGraceAndExpiry() {
    relay::KrpSession session = MakeActiveSession();
    relay::EprLease lease = MakeActiveLease(session);
    CHECK(lease.Renew(1,
                      2,
                      1500,
                      2400,
                      2460,
                      session,
                      relay::KrpTransportPhase::EarlyData0Rtt) ==
              relay::RelayStatus::OneRttRequired &&
              lease.record().request.generation == 1,
          "0-RTT replay cannot renew or extend lease");
    CHECK(lease.Renew(0,
                      2,
                      1500,
                      2400,
                      2460,
                      session,
                      relay::KrpTransportPhase::Confirmed1Rtt) ==
              relay::RelayStatus::StaleGeneration,
          "stale lease generation cannot renew");

    relay::OwnerEdgeId owner;
    relay::FencingToken fencing;
    Fill(owner, 0xC0);
    Fill(fencing, 0xD0);
    CHECK(session.BeginMigration() == relay::RelayStatus::Ok &&
              session.CommitMigration(41, 42, owner, fencing) == relay::RelayStatus::Ok,
          "session route migrates under new fencing token");
    CHECK(lease.Renew(1,
                      2,
                      1500,
                      2400,
                      2460,
                      session,
                      relay::KrpTransportPhase::Confirmed1Rtt) == relay::RelayStatus::Ok &&
              lease.record().request.generation == 2 &&
              lease.record().route_generation == 42,
          "1-RTT renewal advances lease generation and current route");

    CHECK(lease.EnterGrace() == relay::RelayStatus::Ok &&
              !lease.CanAcceptNewTraffic(),
          "disconnected ACTIVE lease enters GRACE without accepting new traffic");
    CHECK(lease.ResumeFromGrace(2,
                                1600,
                                session,
                                relay::KrpTransportPhase::EarlyData0Rtt) ==
              relay::RelayStatus::OneRttRequired,
          "0-RTT cannot recover lease from GRACE");
    CHECK(lease.ResumeFromGrace(2,
                                1600,
                                session,
                                relay::KrpTransportPhase::Confirmed1Rtt) ==
              relay::RelayStatus::Ok && lease.CanAcceptNewTraffic(),
          "current 1-RTT owner can recover same lease generation");
    CHECK(lease.AdvanceTime(2400) == relay::RelayStatus::Ok &&
              lease.record().state == relay::EprLeaseState::Grace,
          "expiry enters bounded GRACE window");
    CHECK(lease.AdvanceTime(2460) == relay::RelayStatus::Expired &&
              lease.record().state == relay::EprLeaseState::Expired &&
              !lease.CanAcceptNewTraffic(),
          "grace deadline irreversibly expires endpoint");
}

void TestFailureAndTerminalStates() {
    relay::KrpSession session = MakeActiveSession();
    relay::EprLease failed;
    CHECK(failed.Initialize(MakeRequest(session, 200),
                            session,
                            relay::KrpTransportPhase::Confirmed1Rtt) == relay::RelayStatus::Ok &&
              failed.Allocate(1, PublicV4(), 4662, 0) == relay::RelayStatus::Ok &&
              failed.MarkBound() == relay::RelayStatus::Ok,
          "failure fixture reaches BOUND");
    relay::EprProbeNonce nonce;
    Fill(nonce, 0xB0);
    CHECK(failed.BeginProbe(nonce) == relay::RelayStatus::Ok &&
              failed.CompleteProbe(nonce, false) == relay::RelayStatus::TargetForbidden &&
              failed.record().state == relay::EprLeaseState::Failed,
          "failed external probe is terminal and never ACTIVE");
    CHECK(failed.Release() == relay::RelayStatus::InvalidState,
          "terminal lease cannot change terminal reason");

    relay::EprLease revoked = MakeActiveLease(session, 201);
    CHECK(revoked.Revoke() == relay::RelayStatus::Ok &&
              revoked.record().state == relay::EprLeaseState::Revoked &&
              !revoked.CanAcceptNewTraffic(),
          "revocation immediately disables new traffic");
    relay::EprLease released = MakeActiveLease(session, 202);
    CHECK(released.BeginDrain() == relay::RelayStatus::Ok &&
              released.Release() == relay::RelayStatus::Ok &&
              released.record().state == relay::EprLeaseState::Released,
          "normal drain can release resources");
}

std::uint64_t NextRandom(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

void TestDeterministicLeaseFuzz() {
    std::uint64_t random = 0x4C454153455F5031ull;
    relay::KrpSession session = MakeActiveSession();
    std::size_t actions = 0;
    for (std::size_t scenario = 0; scenario < 10000; ++scenario) {
        relay::EprLease lease = MakeActiveLease(session, 1000 + scenario);
        for (std::size_t step = 0; step < 10; ++step) {
            const std::uint64_t generation = lease.record().request.generation;
            const std::uint64_t now = 1500 + step * 10;
            switch (NextRandom(random) % 7u) {
                case 0: (void)lease.EnterGrace(); break;
                case 1:
                    (void)lease.ResumeFromGrace(
                        generation,
                        now,
                        session,
                        relay::KrpTransportPhase::Confirmed1Rtt);
                    break;
                case 2:
                    (void)lease.Renew(
                        generation,
                        generation + 1,
                        now,
                        now + 900,
                        now + 960,
                        session,
                        relay::KrpTransportPhase::Confirmed1Rtt);
                    break;
                case 3: (void)lease.BeginDrain(); break;
                case 4: (void)lease.Revoke(); break;
                case 5: (void)lease.Release(); break;
                case 6: (void)lease.AdvanceTime(1000 + NextRandom(random) % 1600u); break;
            }
            ++actions;
            CHECK(lease.record().request.generation != 0 &&
                      lease.record().session_epoch == session.binding().session_epoch,
                  "fuzz lease retains non-zero generation and session epoch");
            CHECK(lease.CanAcceptNewTraffic() ==
                      (lease.record().state == relay::EprLeaseState::Active),
                  "fuzz only ACTIVE lease accepts new traffic");
            CHECK(lease.record().tcp_port == 4662 && lease.record().udp_port == 0,
                  "fuzz lifecycle never changes allocated resources");
        }
    }
    std::printf("  deterministic lease fuzz: %zu actions\n", actions);
}

} // namespace

static_assert(sizeof(relay::EprLease) < 512, "EPR lease state must remain compact");

int main() {
    TestAllocationProbeAndOptionalResources();
    TestRenewMigrationGraceAndExpiry();
    TestFailureAndTerminalStates();
    TestDeterministicLeaseFuzz();
    std::printf("test_epr_lease: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
