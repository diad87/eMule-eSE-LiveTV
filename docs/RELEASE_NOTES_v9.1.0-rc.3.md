# eMule eSE 9.1.0-rc.3

`rc.3` succeeds `rc.2` after physical `V91-I05` qualification exposed a
direct-link scheduling defect. It does not broaden the v9.1 feature set.

## Why rc.2 was superseded

The exact `rc.2` candidate could accept an explicit source endpoint from an
eD2K link, but the download scheduler would not dial that source while both
eD2K server discovery and Kad were disconnected. The part file and source were
created correctly, yet the transfer remained inert.

That behavior blocked the direct-link-only physical transfer required by
`V91-I05`. The RC.2 package and its ledger remain immutable historical
evidence; they are not relabeled as RC.3 results.

## Delta in rc.3

- Sources explicitly supplied in an eD2K link retain `SF_LINK` provenance
  instead of being mislabeled as source-exchange discoveries.
- A direct HighID link source may be dialed even when eD2K and Kad discovery
  are both disconnected.
- LowID sources keep the existing callback and discovery requirements.
- Ordinary server, Kad and source-exchange scheduling behavior is unchanged.
- A focused 64 MiB regression runs with both discovery networks disabled,
  injects one literal IPv4 source link and requires a complete hash-matching
  transfer.
- The unattended `V91-I05` harness reports a failure to the source host before
  removing its nonce-scoped control firewall rule, then records the final local
  cleanup outcome.
- Laboratory control reachability and the physical transfer topology are
  configured independently, so an overlay control path cannot be mistaken for
  the data path under test.

## Safety and compatibility

The direct-link exception is deliberately narrow: it applies only to a
user-supplied HighID route. It does not enable automatic remote access, expose
the dashboard, change Kad6 consent, bypass IP filtering, or claim traversal of
CGNAT and arbitrary firewalls.

Dashboard, API and received-HLS access remain loopback-only. Automatic updates
remain disabled, and the portable package contains no updater or installer.

## Backup, update and rollback

Before updating, stop eMule and back up the active `%APPDATA%\eMule` and
`%APPDATA%\eSE` profiles, or the portable `config` directory, together with
configured incoming and temporary directories containing `.part` or
`.part.met` files.

Install RC.3 into a new empty directory. Do not merge executable or web assets
from an older package. Confirm that `BUILD_INFO.txt` reports `9.1.0-rc.3` and
verify the published SHA-256 before starting it.

To roll back, stop RC.3 and restore the previous application directory and its
matching profile/download snapshot. Never open the same profile or partial
download concurrently with two versions.

## Qualification status

RC.3 starts a new exact-candidate qualification identity. Existing unaffected
RC.2 results may be used as regression context, but promotion claims require
evidence tied to the clean RC.3 commit and package hashes. In particular,
`V91-I05` must complete its two-physical-host 4 GiB direct transfer with the
required socket, transport, payload and cleanup evidence.

The physical `V91-I05` rerun is now PASS. The exact candidate transferred the
canonical 4 GiB fixture between two physical Windows hosts over one on-link
IPv4 tuple, with matching SHA-256 and ED2K, zero IPv6/third-party peer packets,
valid large-file framing and complete cleanup. The corrected post-capture
adjudicator rebuilt the compact evidence bundle from the retained raw capture,
and the full H1 validator accepted all 11 compact entries and 12 raw records.

The RC.3 ledger now records **12 PASS, 0 FAIL and 15 BLOCKED**. RC.3 therefore
remains a release candidate and not the final v9.1 release.
