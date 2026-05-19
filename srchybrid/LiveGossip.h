// this file is part of eMule eSE — Channel gossip protocol (F3)
//
// Cap 5 §5.3.3 thesis. Each P2P connection exchanges a ChannelGossip
// payload periodically (every 10 min on long-lived connections, or once
// post-handshake on short ones).
//
// Wire format (after OP_LIVE_CHANNEL_GOSSIP opcode byte):
//   version          uint8 = 1
//   mySubsCount      uint16 LE
//   mySubsCount * [pubkey 32]
//   freshCount       uint16 LE
//   freshCount * [pubkey 32 | last_seen_unix uint32 LE | was_live uint8]
//
// Receivers MAY add anything they don't know to a "known channels" set
// for later refresh. They MUST NOT auto-refresh anything from mySubs
// (those are private subs of the sender; respecting privacy means we
// don't add the sender's preferences to our gossip mix unless we already
// know them via other channels).
#pragma once

#include <vector>

class CUpDownClient;

namespace eSELive {

struct ChannelGossipMySub {
    uint8_t pubkey[32];
};
struct ChannelGossipFresh {
    uint8_t pubkey[32];
    uint32_t last_seen_unix;
    bool was_live;
};
struct ChannelGossip {
    uint8_t version;
    std::vector<ChannelGossipMySub> my_subs;
    std::vector<ChannelGossipFresh> fresh;
};

// Serialise to flat bytes. Returns true on success.
bool ChannelGossipSerialize(const ChannelGossip& g, std::vector<uint8_t>& out);

// Parse incoming gossip. Returns false on malformed input.
bool ChannelGossipParse(const uint8_t* in, size_t inLen, ChannelGossip& out);

// === Send/receive helpers ===
// Schedule the next gossip send to `peer`. Called from CClientList tick
// or similar; cadence handled internally by LiveGossipManager (every 10 min).
void LiveGossipMaybeSend(CUpDownClient* peer);

// Receive callback: validates, parses, and feeds the known-channels cache.
void LiveGossipOnReceived(CUpDownClient* peer, const uint8_t* payload, size_t payloadLen);

}  // namespace eSELive
