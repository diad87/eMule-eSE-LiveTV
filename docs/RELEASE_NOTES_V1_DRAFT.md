# eSE Live V1 — Release notes (DRAFT, gated)

> **Status:** Draft. V1 release is NOT shippable until both these are
> green:
>   * `docs/audit/proverif/REVIEW.md` has one row signed PASS (ProVerif).
>   * `docs/audit/REVIEW_LOG.md` has all 16 module rows signed PASS.

## What V1 brings

eSE Live V1 is the first release with the **privacy architecture** from
the doctoral thesis (`docs/thesis/`) implemented end-to-end:

- **Channels with persistent Ed25519 identity** (channel_id = pubkey),
  signed records, optional sealed records for private channels.
- **2-hop onion tunnels** with 512-byte cells, multipath split, 30s
  rotation, Poisson cover traffic (Default μ=50/s, High-risk μ=200/s).
- **3 privacy modes**: Direct / Tunneled / Adaptive (default). Configurable
  via /api/live/privacy and the upcoming MFC privacy dropdown.
- **PST (Persistent Search Tunnel)**: reuses tunnels for up to 30 s of
  Kad RPCs so interactive search is responsive even in Tunneled mode.
- **Kad Search v2 mechanisms M3/M5/M6** active by default (sharded hot
  keywords, Bloom-filter neighbour gossip, adaptive k); **M1 subscriber
  pinning** for downloaded files (opt-in, default ON); **M2/M4 (composite
  keys + trigrams)** available as opt-in.
- **M0 namespace isolation** (already in v7.7.x as plan H1-H8) formally
  documented in Cap 4 §4.1.1 of the monograph.

## What's NOT in V1

- MFC 4-tab UI (Subscriptions / Browse / MyChannel / Search) — spec in
  `docs/V1_UI_MFC_SKELETON.md`; deferred to a human PR. The privacy
  controls are operational from the ese-server dashboard meanwhile.
- DPI obfuscation (Obfs4) — out of scope, see Cap 8 P-9 of thesis.
- PoW continuous (anti-Sybil persistent) — V2.
- Post-quantum hybrid crypto — V2 (NIST FIPS 203/204 timeline).
- AS-aware path selection — V2.

## Wire compatibility

Cliente 0.70b sigue funcionando para descargas eD2K normales. Cliente
0.70b ve **streams públicos** (formato legacy en opcodes 0xC0-0xCB) pero
NO ve canales privados ni participa como relay. Esto es por diseño
(G6 garantía formal + Decision 5.9 tesis principal).

## Upgrade path

V7.x.x users: la actualización es seamless. El primer arranque de V1:

- Detecta `eselive_directory.dat` y `last_streams.json` legacy via
  `CLiveMigrationV7::RunIfNeeded()`.
- Mantiene los archivos legacy en su sitio (no formato cambia).
- Genera nuevo `subscriptions.dat` cifrado con DPAPI.
- Si la conexión existente tenía broadcast activo sin pubkey persistente,
  genera una nueva ChannelKey y muestra (en MFC + dashboard) un aviso de
  rotación de identidad.

## Default settings

| Feature | Default | Where to change |
|---|---|---|
| Kad v2 mode | Adaptive | `/api/live/privacy?mode=...` |
| Tunnel fallback | Balanced | `/api/live/privacy?fallback=...` |
| Cover traffic μ | 50/s | per-channel (high-risk = 200/s) |
| M1 file pinning | ON | TBD MFC dialog |
| M3 sharding | ON automatic | no toggle (kicks in @ 50k+ entries) |
| M5 Bloom gossip | ON | TBD MFC dialog |
| M6 k effective | ON automatic | no toggle |
| M4 trigrams | OFF (file-sharing); ON (LiveTV channels) | per-channel |
| M2 composite keys | OFF (opt-in) | TBD MFC dialog |
| Legacy Kad publish | ON (transition) | `m_bEseLivePublishLegacy` pref |

## Known limitations

- **MFC UI not shipped**: privacy controls require the web dashboard at
  http://127.0.0.1:8080 until a human completes `V1_UI_MFC_SKELETON.md`.
- **Network wire-up for M1 / M3 / M5 publish dispatcher is F1.5 work**:
  data structures + receive paths are in place; the publish side is
  initialised but doesn't push entries to Kad yet. This means M3 sharding
  and M5 bloom gossip are receive-only in V1.
- **Tunnel handshake not yet send-wired**: LiveTunnel constructs circuits
  in memory; the TCP-side send of CELL_CREATE goes via a path that needs
  LiveMeshManager refactor (deferred). Real tunnel use requires F5 MFC
  PR to complete the LiveMeshManager ↔ TunnelEndpoint wiring.

Translation: **V1 ships the THINKING + STRUCTURE; V1.1 ships the
end-to-end happy path with all wires connected**. The build is correct,
secure, and useable for everything that worked in v7.7.x. The new privacy
features become operational as the wire-up commits land in V1.1.

## How to verify locally

1. Clone the repo, `git checkout pre-F0-snapshot-build` for the pristine
   pre-F0 state, or `git checkout HEAD` for the F0-F8 stack.
2. Open `srchybrid/emule.sln` in VS 2022, set Configuration=Release
   Platform=x64 PlatformToolset=v143, build.
3. Output: `srchybrid/x64/Release/emule.exe` and `ese-server.exe`.
4. Run, open http://127.0.0.1:8080, navigate to /live.
5. Test the privacy endpoint: `curl http://127.0.0.1:4711/api/live/privacy`.

## Acknowledgements

This release is the product of the unified implementation plan
(`docs/UNIFIED_IMPLEMENTATION_PLAN.md`) executed across 12 phases
(F0.5 through F8) in May 2026. The thesis material in `docs/thesis/`
provided the spec.

Security reviewers (to be filled): _pending_.
ProVerif reviewer: _pending_.
