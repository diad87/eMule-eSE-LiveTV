# eSE 9.3.0-rc.1 execution plan

**Draft, 15 November 2026. Focused R1 qualification pending under D21.**

The expected tag is `v0.70b-eSE9.3.0-rc.1`. Local package qualification is
recorded against `deddf0ea`; the publication decision and release receipt are
pending. The integration base is `9f105835` on `codex/v93-integrate`.
Working builds passed the standard x64 and native QUIC x64/Win32 loopback
reachability tests. [Execution status](V9.3_EXECUTION_STATE.md)
On the same host, the x64 laboratory build completed the 1 GiB fixture with
15 seconds of UDP discard, preserved six verified parts and kept one upload
slot. Both processes ran on private Windows desktops. The x64 distribution
dependency recipe passed its nine ABI and transport tests with the signed
sources and packages. [Dependency notices](../third_party/quic/DISTRIBUTION.md)

The clean `deddf0ea` x64 build passed Core, Integration, ZIP integrity,
dashboard and FFmpeg smoke. The extracted binary passed portable self-test
and native reachability. The same executable completed 1 GiB after 15 seconds
of UDP discard and passed the 1 GiB observed-TCP fallback fixture. The longer
stall ended with a typed no-progress result and six complete parts on disk.
On this revision a new bootstrap expired after rehash. The later `b4fa26e7`
build verified the consent rollover correction with a delayed authenticated
response and completed the restart case. It rehashed six parts totaling
67,768,320 bytes, requested missing ranges, and matched the original 1 GiB
SHA-256 `2C06ADE942EE3F17A048DD1064B2FAB046A4BB95386D8BB41B68DC6711AC2AF3`.
The upload and download processes both exited successfully in private desktops.

| Artifact | SHA-256 |
| --- | --- |
| `deddf0ea` eMule x64 | `BC47A6302BF6A25DCC288F6F4E2876A0CE01D4089DE200F78D69A43A655046C2` |
| Local portable x64 ZIP | `1D7769738A26AE3DCA2FDF759943FB438D069A7A18DBCD1A91516AD1450BE1D5` |

The same `deddf0ea` binary completed classic eD2K/TCP transfers from the
unmodified eMule 0.70b x64 binary and the archived eSE 9.2.0-rc.2 x64 binary.
Both tests used a private local eD2K server and a 1 MiB fixture with SHA-256
`FBBAB289F7F94B25736C58BE46A994C441FD02552CC6022352E3D86D2FAB7C83`.
All four client launches closed successfully. Kad2 and the physical control
cases are still required.

The Win32 dependency build verified the signed MSYS2 inventories and ngtcp2
source, rebuilt GnuTLS without hardware acceleration, checked the architecture
and import closure of 20 DLLs, and passed the ABI test and eight loopback
cases. Independent GnuTLS rebuilds produced the same SHA-256
`E964569804BBF514069D027BD99BBDA62CDE4C7029D3DEB6A1B3C809A32C883C`.
[Win32 dependency notices](../third_party/quic/DISTRIBUTION-Win32.md)

The x64 and Win32 dependency manifests now reproduce across independent
directories with the pinned toolchains. Win32 hashes stable test receipts
and retains the timed probe logs in the dependency work directory.

| Qualification case | Local result |
| --- | --- |
| F1, high-entropy data and 15 seconds of UDP discard | 1,073,741,824 bytes, six verified parts retained, one upload slot and the original transfer epoch. Both client exits were zero. Source and destination SHA-256 `6728F0CBB20D5794050D5D752FCBC0EDF6ED8B87E9E66F9E4BA9EEA70C826837`. |
| NC-Q06, application-data stall | `c5c23f9d` on two product processes stopped accepting file data after 8 MiB. Transport ACK and authenticated PONG continued. The downloader reported `QuicNoProgress` at 30,852 ms and retained the accepted disk ranges byte for byte. The uploader held one slot. This case had no authorized alternate route. |
| AICH recovery and parser bounds | `0d1aa33d` passed on x64 and Win32. Each run exercised 10,000 trees, 2,491 truncations, 512 malformed cases and the `known2.met` compaction lock. Both returned to the original live allocation count and closed from private desktops. |
| `.part.met` replacement and recovery | `5ab9abd7` held the staging file open to force a replacement failure. The committed metadata and backup remained byte-identical. Startup chose valid committed metadata, recovered `.bak` and legacy `.backup` as applicable, and ignored an unfinished `.tmp`. |

## Pending exit checks

| Area | Evidence required for the candidate |
| --- | --- |
| Build and package | Build x64 and Win32 from the selected revision. Link and test the release QUIC/TLS dependencies for each architecture, include the DLLs, notices and corresponding sources, and record hashes. Exercise startup, upgrade and shutdown. |
| QUIC transfer and continuity | Explicit opt-in with durable peer pins passed the local activation, rebinding and revocation tests. Transfer eD2K files in both directions between two physical clients, including F1 (1 GiB). Check hashes, loss and interruption recovery, TCP fallback when QUIC is blocked before or during a session, and no duplicate slot, session or accounting. |
| Physical interoperability | Exercise regular routes, mobility and cancellation, including `H93-16` and each supported NAT profile. Check classic eMule/Kad2, the previous eSE and applicable LowID callback controls. |
| Security and product | Verify identity before data, replay and unauthorized endpoints, parser bounds and focused MD4/AICH fuzzing. Verify retired KRP/R.3 values, `.part.met` and configuration recovery, profile migration and rollback, and the web/UI routes affected by the change. |
| Final campaign | Run the relevant combined x64/Win32 checks on the selected revision. Measure stability for the risks identified by the transfer and recovery tests. Record the enabled features, experimental opt-ins and verified network limits. |

The publication decision follows [D21](V9_RELEASE_ROADMAP.md) and [focused R1](V9.3_PLUS_RELEASE_TRAIN.md#17-salida-de-v93-y-validación-proporcional).
