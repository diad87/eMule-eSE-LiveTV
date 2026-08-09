# ADR: UPnP cooperative worker lifecycle helpers v1

Status: approved contractual boundary for the v9.2 cooperative-shutdown delta.

## Decision

`srchybrid/UPnPWorkerLifecycle.h` and
`srchybrid/UPnPDeferredReaperCore.h` are the only two governed productive
non-module, header-only helpers consumed by the existing UPnP wrapper/MiniLib
lifecycle. They do
not own reachability or mapper domain state, wire formats, preferences,
configuration, logging, callbacks, UI, or MFC objects.

The worker helper is limited to 40 physical lines and exactly the direct
headers `Windows.h` and `atomic`. The reaper helper is limited to 150 physical
lines and exactly the direct headers `Windows.h`, `array`, and `cstddef`.
Neither helper may gain a companion `.cpp`. Capacity is fixed and overflow
must fail closed without deleting an active object. A third lifecycle helper
requires a new governance decision; it is not implicitly allowlisted here.

`srchybrid/tests/test_upnp_worker_lifecycle.cpp` is the single test-only
companion. It is limited to 300 physical lines and exact direct includes
`../UPnPWorkerLifecycle.h`, `../UPnPDeferredReaperCore.h`, `atomic`, and
`cstdio`. Those relative includes must resolve to the two productive entries.
The test is compiled with `/W4 /WX /std:c++17` and executed only by
`srchybrid/tests/make.bat`; it is absent from `emule.vcxproj` and no productive
source may include it. MOD-0.2 may bind these sources only through its critical
source identity; it does not compile or execute the test a second way.

The helpers may coordinate local Win32 handles, atomics, a fixed array and
destruction only after a worker is signalled. They must not include a
coordinator header or a concrete domain/module header, and they do not relax
MOD-0.3 ownership, MOD-0.4 discovery, MOD-5.1 include/SCC, or M2A card limits.
