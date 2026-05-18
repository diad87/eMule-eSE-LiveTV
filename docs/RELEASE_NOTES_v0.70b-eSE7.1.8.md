# eMule eSE LiveTV v0.70b-eSE7.1.8 — 2026-05-18

Fixes the use-after-free crash that killed `emule.exe` whenever a
LiveTV viewer disconnected abruptly. Identified directly from a saved
crash dump via WinDbg — not a guess this time.

`ese-server.exe` is unchanged from v7.1.7. Only `emule.exe` changed.

---

## The bug

### Symptom
Broadcaster running cleanly, viewer connects, sees the stream for a
few seconds, then `emule.exe` on the broadcaster vanishes (no dialog,
WER drops a `.dmp` into `%LOCALAPPDATA%\CrashDumps\`). On
CGN/4G/aggressive-NAT viewers, this happened within minutes of every
broadcast start. Apparent random crashes that I had been blaming on a
pre-existing upstream `CMap<CPartFile*>::Serialize` bug for the whole
session — **wrong diagnosis**.

### Root cause (from WinDbg analysis of the actual dump)
```
EXCEPTION_RECORD:
  ExceptionAddress: emule!CUpDownClient::SendPacket+0x23
  ExceptionCode:    0xC0000005 (access violation)
  Read address:     0x0000279400000250  (garbage pointer)

IP_IN_PAGED_CODE:
  emule!CUpDownClient::SendPacket+23
  mov rax, qword ptr [rcx]        ← reads vtable from 'this'

STACK_TEXT:
  emule!CUpDownClient::SendPacket+0x23
  emule!CLiveStreamManager::SendBitmapToAll::<lambda>+0x48
  emule!CLiveStreamManager::SendBitmapToAll+0x47f
  emule!CLiveStreamManager::Process+0x76
  emule!CLiveStreamDlg::OnTimer+0x65
```

`CLiveStreamManager` keeps **raw `CUpDownClient*`** in four containers:
`m_broadcastPeers`, `m_viewPeers`, `m_peerTrust`, `m_peerBitmaps`. The
only scrubber is `OnPeerDisconnected(peer)` — but until now it was
only wired into **two** LIVE-protocol packet handlers in
`ListenSocket.cpp` (`OP_LIVE_UNSUBSCRIBE` and stream-end). Any other
destruction path for `CUpDownClient` — TCP RST, CGN keep-alive
timeout, socket-close on the connecting side, ClientList cleanup —
left the peer pointer dangling. On the next `Process()` tick (every
~1 s), `SendBitmapToAll` iterated the list, called
`peer->SendPacket(pkt)` on the freed object, and dereferenced a
freed vtable → crash.

The crash address `0x0000279400000250` was diagnostic: the low 0x250
bits are noise (allocator quantum), and the high `0x2794` was leftover
heap metadata where the freed `CUpDownClient` used to live. Classic
use-after-free signature.

### Fix
One line in [`CUpDownClient::~CUpDownClient()`](srchybrid/BaseClient.cpp#L327):

```cpp
if (theApp.liveStreamManager != NULL)
    theApp.liveStreamManager->OnPeerDisconnected(this);
```

Plus the matching `#include "LiveStreamManager.h"` at the top.

Called from the destructor, this fires for **every** destruction path,
not just the two LIVE-protocol handlers. `OnPeerDisconnected` was
already correct and idempotent — Find returns NULL if the peer was
never in the list, RemoveKey is silent if the key isn't present —
so adding this call is safe for non-LIVE clients (the 99% case in
normal eMule operation).

### Verified against the existing dump
Crash dump `emule.exe.36568.dmp` (PID 36568, 18/05/2026 11:30:44) shows
this exact stack. The v7.1.6/v7.1.7 binaries triggered it; v7.1.8 will
not because the peer is removed from `m_broadcastPeers` **before** its
memory is freed.

---

## Why we missed this for so long

`CMap<CPartFile*>::Serialize` was a misread. The faulting offset
`0xe23xx` happens to land near both that function AND
`CUpDownClient::SendPacket` in the emule.exe build. Without symbols
loaded (which we only got working today), the offset-only error in the
Application event log pointed at the wrong place. Once we had the .pdb
and ran `!analyze -v`, the stack told the truth in 1 second.

Lesson for future crash triage: **enable WER LocalDumps + cdb +
`!analyze -v` before guessing**. The
[`tools/enable_crash_dumps.ps1`](tools/enable_crash_dumps.ps1) helper
from v7.1.5 was the right move; pity I didn't pair it with a debugger
session sooner.

---

## Upgrading from v7.1.7

Hot-swap supported. Only `emule.exe` changed.

1. Close eMule (or kill via Task Manager / PowerShell)
2. Download
   [`emule.exe`](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE7.1.8/emule.exe)
   (11.12 MB, SHA256 `98633C85EADEDD8F3C69D14C57C9BFB5910FB5FDA3FF7581C0916584D089C199`)
3. Replace `emule.exe` in your install folder
4. Reopen eMule

`ese-server.exe` stays at v7.1.7. Configuration unchanged.

---

## Carried over

- v7.1.7 — SyntaxError fix at /live + Cache-Control headers
- v7.1.6 — bitrate parameter drives ABR variant selection + muted autoplay
- v7.1.5 — orphan ffmpeg reap on broadcast start
- v7.1.4 — /player → /live/watch/local direct-link redirect
- v7.1.3 — preflight badges SyntaxError + cosmetic upload label
- v7.1.2 — Kad publish TAG_SOURCEIP for cross-PC discovery
- v7.1.1 — IPv4 localhost fix for login

---

GPL-2.0-only.
