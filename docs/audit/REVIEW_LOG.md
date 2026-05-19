# Security review log

V1 release gated on every row below being PASS with a reviewer signature.
See `CODE_REVIEW_SCOPE.md` for what each module covers.

| Module | Reviewer | Date | ProVerif passed? | Result | Critical findings |
|---|---|---|---|---|---|
| LiveCrypto.cpp/h | _pending_ | _pending_ | (see proverif/REVIEW.md) | _pending_ | — |
| LiveOnionCrypto.cpp/h | _pending_ | _pending_ | (see proverif/REVIEW.md) | _pending_ | — |
| LiveTunnel.cpp/h | _pending_ | _pending_ | (see proverif/REVIEW.md) | _pending_ | — |
| LiveCircuit.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| LiveCellQueue.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| LiveChannel.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| LiveSubscriptionStore.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| LiveBootstrap.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| LiveGossip.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2BloomFilter.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2Sharding.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2KEffective.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2SubscriberPin.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2TunnelPool.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| KadV2ModeSelector.cpp/h | _pending_ | _pending_ | n/a | _pending_ | — |
| Plan H (already in production) | _re-review_ | _pending_ | n/a | _pending_ | — |

## Fuzzing log

| Parser | Target | AFL++ hours | Crashes found | Resolved |
|---|---|---|---|---|
| ChannelRecordParse | LiveChannel.cpp | 0 | n/a | n/a |
| CellUnpack | LiveCellQueue.cpp | 0 | n/a | n/a |
| PeerInviteParse | LiveBootstrap.cpp | 0 | n/a | n/a |
| ChannelGossipParse | LiveGossip.cpp | 0 | n/a | n/a |
| ParseAnnounce (M3) | KadV2Sharding.cpp | 0 | n/a | n/a |

Target: ≥24h per parser before V1.
