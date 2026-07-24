# eMule eSE tests

The repository combines Python checks, Node.js tests, standalone C++ tests and
library-specific suites.

## Prerequisites

- Windows 10 or 11 x64.
- Visual Studio 2022 C++ tools.
- Node.js 22 and npm.
- Python 3.
- Initialized submodules.

```powershell
git submodule update --init --recursive
```

## Main test entry point

Run every local suite:

```powershell
.\tools\run_alpha_tests.ps1 -Suite All
```

Or run one group:

```powershell
.\tools\run_alpha_tests.ps1 -Suite Core
.\tools\run_alpha_tests.ps1 -Suite Integration
```

### Core

The core group runs:

- protocol registry consistency;
- direct-port ownership checks;
- address wire-format tests;
- tunnel framing tests;
- `libreach`;
- `libnatmap`;
- Crypto++ build dependency verification;
- `libkad6`;
- Node.js regression tests and dependency audit.

### Integration

The integration group runs:

- standalone native LiveTV/reachability tests;
- eMule 0.70b hashing, part-file I/O, transfer-state, Kad publishing and Kad response regressions;
- `librelaycore` Release and ASan;
- `relayedge` Release and ASan;
- `librelayclient` Release and ASan.

## Focused checks

Protocol registry:

```powershell
python tools\check_protocol_registry.py
```

Address and tunnel framing:

```powershell
python tests\test_address_wire.py
python tests\test_foundsources_v6_wire.py
python tests\test_callback_v6_wire.py
python tests\test_ipv6_transport_wire.py
python tests\test_tunnel_framing.py
```

Dashboard:

```powershell
Set-Location srchybrid\eSE
npm ci
npm test
npm audit --audit-level=high
```

Dashboard/package parity:

```powershell
.\tools\verify_eSE.ps1 -SkipBuild
```

## Executable self-test

A packaged `emule.exe` can run the local media and signed-chunk self-test:

```powershell
.\emule.exe --portable --selftest
```

It starts a controlled source, waits for real HLS output, verifies signed
ingest, duplicate rejection and tamper rejection, and returns a non-zero exit
code on failure.

The self-test does not validate remote discovery, real NAT behavior, relay
routing or multi-hour operation.

## Manual release checks

Hardware and network checks require real machines and are intentionally not
simulated by the hosted CI runner. Before publishing a release, maintainers
verify:

- a clean Release x64 build;
- startup from the extracted portable package;
- eD2K/Kad connectivity and transfer;
- LiveTV broadcast/view across separate machines;
- supported hardware encoders with CPU fallback;
- safe fresh-profile defaults;
- upgrade and rollback using a copied profile.

Store private logs and packet captures outside the source repository.
