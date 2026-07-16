#pragma once

#include "natmap/natmap_types.h"

namespace natmap::test {

struct MapResult {
    bool success = false;
    PortLease lease{};
    ReasonCode reason = ReasonCode::None;
};

class FakeGateway {
public:
    MapperKind mapper = MapperKind::None;
    Endpoint gateway{};
    IpAddress external_address{};
    std::uint16_t forced_external_port = 0;
    std::uint32_t lifetime_seconds = 3600;
    ReasonCode failure = ReasonCode::None;

    MapResult Map(const PortIntent& intent, std::uint64_t generation) const noexcept {
        MapResult result{};
        if (!intent.IsValid() || generation == 0) {
            result.reason = ReasonCode::InvalidResponse;
            return result;
        }
        if (mapper == MapperKind::None) {
            result.reason = ReasonCode::NoMappingProtocol;
            return result;
        }
        if (failure != ReasonCode::None) {
            result.reason = failure;
            return result;
        }

        std::uint16_t requested = intent.local.port;
        if (intent.candidate_count != 0)
            requested = intent.external_candidates[0];
        const std::uint16_t granted = forced_external_port != 0
            ? forced_external_port : requested;
        if (granted == 0 || (!intent.allow_any_external_port && granted != requested)) {
            result.reason = ReasonCode::MappingConflict;
            return result;
        }

        result.success = true;
        result.lease.mapper = mapper;
        result.lease.transport = intent.transport;
        result.lease.gateway = gateway;
        result.lease.local = intent.local;
        result.lease.public_endpoint = Endpoint{
            external_address, granted,
            mapper == MapperKind::Pcp ? EndpointSource::PcpMap :
            mapper == MapperKind::NatPmp ? EndpointSource::NatPmpPublicAddress :
                                           EndpointSource::UpnpExternalAddress};
        result.lease.requested_external_port = requested;
        result.lease.granted_external_port = granted;
        result.lease.lifetime_seconds = lifetime_seconds;
        result.lease.generation = generation;
        result.lease.owned_by_us = true;
        return result;
    }
};

struct LoginResult {
    std::uint32_t client_id = 0;
    bool high_id = false;
    Evidence server_evidence{};
    Evidence inbound_evidence{};
};

class FakeEd2kServer {
public:
    LoginResult Login(const Endpoint& advertised, bool callback_reached,
                      std::uint64_t generation) const noexcept {
        LoginResult result{};
        result.client_id = callback_reached ? 0x580B1604u : 0x00119752u;
        result.high_id = callback_reached && advertised.IsUsable();
        if (result.high_id) {
            result.server_evidence = Evidence{
                EvidenceKind::ServerHighId, advertised, generation, 1000};
            result.inbound_evidence = Evidence{
                EvidenceKind::InboundTcpAccept, advertised, generation, 1001};
        }
        return result;
    }
};

} // namespace natmap::test
