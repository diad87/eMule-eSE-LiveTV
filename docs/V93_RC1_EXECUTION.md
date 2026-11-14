# eSE 9.3.0-rc.1 execution plan

**Draft, 14 November 2026. R1 qualification pending.**

The expected tag is `v0.70b-eSE9.3.0-rc.1`. The candidate commit, executable
hashes, package hash and release receipt are pending. The integration base is
`9f105835` on `codex/v93-integrate`. Working builds passed the standard x64
and native QUIC x64/Win32 loopback reachability tests. The x64 pair also
transferred 1 MiB with the product timer and verified the file hash for
periodic and high-entropy input. [Execution status](V9.3_EXECUTION_STATE.md)
On the same host, the x64 laboratory build completed the 1 GiB fixture with
15 seconds of UDP discard, preserved six verified parts and kept one upload
slot. Both processes ran on private Windows desktops. The x64 distribution
dependency recipe passed its nine ABI and transport tests with the signed
sources and packages. [Dependency notices](../third_party/quic/DISTRIBUTION.md)

The clean x64 build at `a134acb0` passed Core, Integration, ZIP integrity,
dashboard and FFmpeg smoke. The extracted binary passed portable self-test,
reachability, and the 1 GiB transfer with 15 seconds of UDP discard.
The signed dependency data is pinned by the same manifest used by the build
and packaged next to the executable. This is a local qualification package.
Subsequent runtime changes are qualified against their own executable hashes.

## Pending exit checks

| Area | Evidence required for the candidate |
| --- | --- |
| Build and package | Build from the selected revision. The native, dashboard, installer and guide versions pass the metadata preflight. Link and test the signed QUIC/TLS dependency set, include its DLLs, license notices and corresponding sources, and record build and package hashes. Test a fresh install, launch and shutdown. |
| QUIC transfer and continuity | Explicit opt-in with durable peer pins passed the local activation, rebinding and revocation tests. Transfer eD2K files in both directions between two physical clients, including F1 (1 GiB). Check hashes, loss and interruption recovery, TCP fallback when QUIC is blocked before or during a session, and no duplicate slot, session or accounting. |
| Physical interoperability | Exercise normal and real NAT routes, mobility and cancellation, including `H93-16`. Verify Kad6-only discovery with collaborator changes and zero payload through collaborators. Check classic eMule/Kad2 and the applicable LowID callback controls. |
| Security and product | Verify identity before data, replay and unauthorized endpoints, parser bounds and focused fuzzing. Exercise the reference server, including login, sources, callback, RendezvousV2 and TLS/QUIC. Validate persistence, migration from a copied 9.2 profile, rollback, bulk cancellation, UI smoke and the specified benchmarks. |
| Final campaign | Complete the integrated 24-hour run under D6 on the selected build. Record the disposition of A–F and list the enabled features, experimental opt-ins and verified network limits. |

The publication decision follows R1 in [the release plan](V9.3_PLUS_RELEASE_TRAIN.md#17-salida-de-una-sola-release-con-validación-proporcional) and the [implementation specification](V9.3_IMPLEMENTATION_SPECIFICATION.md#empaquetado-y-rollback-entregables-concretos).
