// this file is part of eMule eSE — Kad Search v2 (F1 unified plan)
//
// Central constants for Kad Search v2 mechanisms. Header-only.
// Spec source: docs/thesis/kad-search-v2/04-diseno-kad-v2.md (M0-M6).
//
// F1 implements M3 + M5 + M6 in Modo Direct. The Tunneled mode of each
// mechanism is added in F4b together with PST. Direct mode is enabled by
// default (TAG_ESE_CAPS bit lit when the feature passes its phase exit).
#pragma once

#include "kademlia/utils/UInt128.h"

namespace Kademlia
{

// === KadV2Mode (Cap 6 §6.3 monograph) ====================================
// Direct  — no tunneling, behaves like Kad v1 (legacy + new eSE clients).
// Tunneled— route every RPC through the privacy onion tunnel (F4 onward).
// Adaptive— per-query decision based on the rules in Cap 6 §6.3 Modo C.
// F1 callers always pass Direct. F4b wires Tunneled. F5 UI exposes the
// dropdown that lets the user pick Adaptive (default).
enum class CKadV2Mode : uint8 {
    Direct   = 0,
    Tunneled = 1,
    Adaptive = 2
};

// === M3 — Sharding adaptativo ============================================
// Cap 4 §4.4 monograph. A keyword becomes "hot" when a single custodian
// observes >T_hot entries for it; the custodian announces a shard degree
// s ∈ [0, s_max], and clients re-route publishes/queries across 2^s shards.
static const uint32 KADV2_T_HOT_ENTRIES        = 50000u;
static const uint8  KADV2_S_MAX                = 6;        // 64 shards
static const uint8  KADV2_S_MIN_FOR_ANNOUNCE   = 1;        // emit if s >= 1
static const uint32 KADV2_SHARD_ANNOUNCE_TTL_S = 6u * 60u * 60u;  // 6 hours
static const uint32 KADV2_SHARD_COOLDOWN_S     = 7u * 24u * 60u * 60u;  // 7 days off-threshold to deactivate

// Wire-format separator byte for shard key derivation:
//   shard_key(kw, i) = MD4(kw || "\x1E" || uint8(i))
// 0x1E (Record Separator) does not appear in canon UTF-8 keyword tokens.
static const uint8  KADV2_SHARD_SEPARATOR_BYTE = 0x1E;

// === M5 — Bloom gossip ===================================================
// Cap 4 §4.6 monograph.
static const size_t KADV2_BLOOM_SIZE_BYTES         = 32u * 1024u;        // 32 KB per node
static const uint8  KADV2_BLOOM_NUM_HASHES         = 4;
static const uint32 KADV2_BLOOM_EXPECTED_ITEMS     = 50000u;
static const uint32 KADV2_BLOOM_REBUILD_INTERVAL_S = 30u * 60u;          // 30 min
static const uint32 KADV2_BLOOM_GOSSIP_INTERVAL_S  = 60u * 60u;          // push to a neighbour at most once per hour
static const uint32 KADV2_BLOOM_INBOUND_QUOTA_B    = 1u * 1024u * 1024u; // 1 MB/hour received from any neighbour

// === M6 — k adaptativo ===================================================
// Cap 4 §4.7 monograph.
//   k_effective(kw) = clamp(10 * max(1, log2(load_ratio)+1), 4, 24)
static const uint8  KADV2_K_BASE   = 10;
static const uint8  KADV2_K_MIN    = 4;
static const uint8  KADV2_K_MAX    = 24;
static const uint8  KADV2_K_HYST   = 2;            // ignore updates smaller than this
static const uint32 KADV2_K_UPDATE_INTERVAL_S = 60u * 60u;  // recompute hourly

// === M0 — Namespace isolation (already in code via plan H, doc-only here) ==
// See Search.h ESE_LIVE_KEYWORD_PREFIX. F1 confirms M0 is orthogonal to
// M3/M5/M6: every hash that M3 shards or M5 indexes can be either the
// legacy MD4(kw) target or the dedicated MD4("\x00eSE\x00" || kw) target.

// === Tunnel-readiness placeholder ========================================
// In F1, every operation passes CKadV2Mode::Direct. The Tunneled path is
// implemented in F4b together with PST. The Adaptive mode selector lives
// in F4b's KadV2ModeSelector module. Until then, treating Tunneled or
// Adaptive as Direct is a safe fallback (degrades to legacy behaviour).
inline CKadV2Mode KadV2EffectiveMode(CKadV2Mode requested)
{
    // F1: collapse any non-Direct request to Direct.
    // F4b will override this with the real selector.
    (void)requested;
    return CKadV2Mode::Direct;
}

}  // namespace Kademlia
