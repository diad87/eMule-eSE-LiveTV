// this file is part of eMule eSE - neutral LT8 search ownership port
#pragma once
#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_live_search.h"
#include <cstdint>
#include <string>
#include <vector>
namespace eSELive {
struct LiveTunnelSearchJob {
    std::uint32_t circ_id=0,req_id=0;std::string keyword;
    bool canonicalK6=false,kadReachable=false,lookupStarted=false,kad2LookupStarted=false,kad6LookupStarted=false;
    std::uint8_t networkMask=0;std::uint16_t maxResults=100;
    std::uint8_t searchKind=kad6::kK6SearchKindLive;kad6::Hash16 targetHash{};
    struct SourceCandidate {
        kad6::Hash16 userHash{};kad6::K6Endpoint endpoint;
        std::uint8_t sourceType=0,cryptOptions=0;std::uint16_t reachCaps=0;
        std::uint8_t networkOrigin=kad6::kK6NetOriginKad2;
        kad6::K6Provenance provenance=kad6::K6Provenance::KadResult;
        kad6::Hash32 provenanceDigest{};std::uint32_t score=0;
    };
    std::vector<SourceCandidate> sourceCandidates;
    bool firstSourceMetric=false,fiveSourceMetric=false;
    DWORD started=0,deadline=0;std::vector<std::uint32_t> kadSearchIds;
};
struct LiveTunnelSearchReplyAggregate {
    std::vector<std::uint8_t> legacy;std::uint16_t count=0;DWORD started=0;
};
bool RunLiveTunnelSearchServiceCharacterizationSelfTest();
} // namespace eSELive
