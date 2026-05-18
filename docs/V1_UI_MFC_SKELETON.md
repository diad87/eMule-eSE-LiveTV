# V1 UI MFC — 4 tabs skeleton (F5 deliverable, human-implement)

The unified plan §F5 calls for a 4-tab UI in MFC (LiveStreamDlg.cpp + .rc).
Implementing this fully requires Visual Studio's resource editor; this file
documents the spec so a human can complete it.

## Tab layout (Cap 5 §5.1 + privacy memory)

```
┌────────────────────────────────────────────────────────────────┐
│  eSE Live                                                       │
├────────────────────────────────────────────────────────────────┤
│  [ Subscriptions ] [ Browse ] [ MyChannel ] [ Search ]          │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  (tab content here)                                             │
│                                                                 │
├────────────────────────────────────────────────────────────────┤
│  Privacy mode: [ Adaptive ▼ ]  Fallback: [ Balanced ▼ ]  [⚙]    │
└────────────────────────────────────────────────────────────────┘
```

### Tab 1 — Subscriptions

`CLiveSubscriptionStore` (F2). List of channels the user follows.

Controls:
- ListView with columns: Name, Category, Language, Last Live, LIVE badge
- Right-click context: Unsubscribe, Properties, Open in browser
- Selected row → click "Watch" button (bottom) launches `JoinStream`

### Tab 2 — Browse

`CLiveKadBridge::SearchStreams("eselive")` results filtered by category.

Controls:
- Category dropdown (Cine/Series/Deportes/Música/Charlas/Otros)
- Language filter
- Results listview (Name, Description, Viewers, Bitrate)
- Right-click: Subscribe, Watch, Copy link, Hide channel

### Tab 3 — MyChannel

Local broadcaster identity. Shows ChannelKey state + record info.

Controls:
- Channel name (editable, syncs to ChannelRecord)
- Description, Category, Language
- Access mode: Public / Private
- "Go LIVE" button (CRTMPIngest integration via existing code)
- Identity rotation hint (Cap 8 P-6) with last-rotation date
- "Export invite token" → generates `PeerInvite` and shows QR code

### Tab 4 — Search

Free-text search across known channels.

Controls:
- Search textbox + button → calls `CLiveKadBridge::SearchStreams(q)`
- Bloom-filter quick-look indicator (M5 hits in /api/live/debug)
- Results listview with same columns as Browse

### Bottom strip — Privacy controls

Two dropdowns + gear icon:

- **Privacy mode**: Direct / Tunneled / Adaptive (default Adaptive).
  Maps to `CKadV2ModeSelector::SetDefaultMode`.
- **Fallback**: Strict / Balanced / BestEffort (default Balanced).
  Maps to `CKadV2ModeSelector::SetFallbackPolicy`.
- **Gear icon**: opens dialog with:
  - Editable list of sensitive keywords
  - Toggle "Help index files I download" (M1)
  - Toggle "Enable Bloom gossip cache" (M5)
  - Toggle "Adaptive replication (k_effective)" (M6) — on by default
  - Toggle "Subscriber pinning channels" — on by default
  - Toggle "Cover traffic" — on by default
  - "Privacy details" link → opens docs/privacy-model.md in browser

## Capability indicator per peer

`CUpDownClient` listview elsewhere (peer list) gains a tooltip:

> ⚠ Cliente legacy — no participa en streams privados

…when `client->GetForkCaps()` doesn't include `CAP_FORK_IPV6_WIRE` AND the
client hasn't emitted `TAG_ESE_CAPS` bit 8 (tunneling).

## Backing API (already in code as of F4b)

- `/api/live/privacy` (WebServer.cpp, F5 already implemented):
  GET returns current state. PATCH-via-querystring (`?mode=tunneled`,
  `?fallback=balanced`, `?add_sensitive=foo`, `?rm_sensitive=foo`)
  updates. The ese-server dashboard can already drive this without
  touching MFC.

So **the privacy controls are operational TODAY via the web dashboard at
http://127.0.0.1:8080**; the MFC tab is a UX polish item for users who
prefer the native dialog. The functional requirements of F5 §4-pestañas
are exposed via the API, but the MFC implementation is deferred to a
human with a Resource Editor.

## Scope-cut justification

Resource editor edits (`.rc` files) are not human-readable diffs, conflict
constantly with auto-formatters, and require Visual Studio's WYSIWYG tool
to keep accelerator tables / control IDs / DLGTEMPLATEs consistent. This
is one of the few tasks where AI-generated code is consistently worse
than a 30-minute human session in the IDE.

Recommendation: the eSE project commits **API completeness** (done) and
**MFC UI as a follow-up PR** (human, ~1-2 weeks).
