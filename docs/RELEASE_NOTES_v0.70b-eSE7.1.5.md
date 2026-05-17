# eMule eSE LiveTV v0.70b-eSE7.1.5 — 2026-05-17

Fifth point release of the day. Fixes the "I broadcast Titanic but my
viewers see test pattern" bug — the symptom the cross-ISP test from PC1
(home fiber, HighID, Titanic) ↔ PC2 (4G LowID CGN) hit after the v7.1.4
direct-link fix unblocked discovery.

Also adds a one-shot helper to enable auto-saved crash dumps for the
underlying `BaseClient.obj` use-after-free we've been seeing daily but
couldn't reproduce on demand.

---

## The main fix — stream-mix on PC1

### Symptom
- PC1 broadcasts a movie file (e.g. Titanic) → emule shows `1 viewer`,
  chunks flow, the .m3u8 returns 200 to PC2's browser.
- PC2 sees the **test pattern** anyway. Not corrupted video, not a
  decoder error — actual color bars from FFmpeg's `testsrc2` filter.

### Root cause
When eMule crashes (and it does — see the dump helper below),
`ffmpeg.exe` is **not** killed with it. It survives as an orphan,
holding the same `%TEMP%\eMule_RTMP\` directory and continuing to write
`seg_*.ts` segments at whatever filename FFmpeg picks next (`seg_00000`,
`seg_00001`, …).

When the user re-opens eMule and starts a new broadcast (file, screen,
or test pattern), a NEW `ffmpeg.exe` spawns and writes the SAME segment
filenames into the SAME directory. Two processes racing the same
`seg_NNNNN.ts`. The `WatcherThread` reads whichever bytes happened to
land last, hands them to `FeedSegment()`, which pushes them into
`m_chunkBuffer` tagged with the NEW broadcast's `streamKey`.

The receiving peer's `OnChunkReceived` filters by streamKey
(`memcmp(m_streamInfo.streamKey, streamKey, 16)`), and the streamKey IS
the new one — so the chunks pass the filter and get written to
`%TEMP%\eMule_RTMP\<new_key>\seg_*.ts` on the viewer's disk. The viewer
plays whatever bytes the broadcaster's WatcherThread happened to grab —
which, since the orphan FFmpeg is steadily overwriting, is overwhelmingly
test-pattern bytes.

### Fix
`RTMPKillOrphanFFmpegs("eMule_RTMP")` already existed and was already
called at the top of `Start()` (RTMP-listen mode). The other three start
paths inherited the orphans silently:

- [`CRTMPIngest::StartTestPattern`](srchybrid/RTMPIngest.cpp#L907) — no reap
- [`CRTMPIngest::StartScreenCapture`](srchybrid/RTMPIngest.cpp#L459) — no reap
- [`CRTMPIngest::StartMediaFile`](srchybrid/RTMPIngest.cpp#L542)   — no reap

All three now reap orphans before spawning their own FFmpeg, identical
to what RTMP-listen mode already did. No more cross-broadcast bleed.

### How this looks in the log
After upgrade, the next broadcast you start after a previous crash will
show one of these lines in the debug log:

```
RTMP: TestPattern: reaped 1 orphan ffmpeg.exe(s) from prior session
RTMP: Media:       reaped 1 orphan ffmpeg.exe(s) from prior session
RTMP: Screen:      reaped 1 orphan ffmpeg.exe(s) from prior session
```

If you see "reaped 0", the orphan path didn't trigger — you're starting
clean. That's expected when there was no prior crash.

---

## Bonus — auto-save crash dumps

Five-plus eMule crashes happened during today's testing, all silent
(Windows briefly shows "save to disk?" then disappears). Without a
saved dump we've been guessing at the `BaseClient.obj +0xe23b3`
offset — a pre-existing upstream `CMap<CPartFile*>::Serialize`
use-after-free that's been in 0.70b for years.

[`tools/enable_crash_dumps.ps1`](tools/enable_crash_dumps.ps1) sets the
Windows Error Reporting `LocalDumps` registry keys for `emule.exe`. Run
ONCE as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\enable_crash_dumps.ps1
```

After that, every crash auto-saves a full minidump to
`%LOCALAPPDATA%\CrashDumps\emule.exe.<PID>.dmp`. Send that file +
the matching `emule.pdb` and we can finally see the real call stack
in WinDbg.

---

## Upgrading from v7.1.4

Hot-swap supported. This release only changes `emule.exe`.
`ese-server.exe` is unchanged from v7.1.4.

1. **Re-download the ZIP** and extract over your v7.1.4 install.
2. **Hot-swap `emule.exe`**: download it from this release's assets and
   replace yours. Close eMule first; reopen after.

You probably want to **also run the crash-dump helper** before resuming
testing — that way the next crash leaves us something to actually
investigate.

---

## Carried over

- v7.1.4 — `/player` → `/live/watch/local` direct-link redirect fix.
- v7.1.3 — preflight badges SyntaxError + cosmetic upload label.
- v7.1.2 — Kad publish TAG_SOURCEIP for cross-PC discovery.
- v7.1.1 — IPv4 localhost fix for login.

---

GPL-2.0-only.
