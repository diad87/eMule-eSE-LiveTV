# eSE 9.2.0-rc.1 execution plan

## 1. Candidate identity

The candidate is frozen through the governed sequence
`H32 -> G -> A -> M -> H -> optional S -> R`.

- `G` defines the closed paths, budgets, reviews and stop conditions.
- `A` contains the mapper hotfix and exact rc.1 metadata.
- `M` records the clean Release build receipt and MOD02 runtime reseal.
- `H` contains independent Terra and Sol approvals plus the offline summary.
- `S`, when used, is one NON_RELEASE physical preflight.
- `R` is the only phase that may archive formal eight-hour PASS evidence.

Every phase has one parent. Intermediate or merge commits invalidate the
candidate. The exact commit, tree and artifact hashes are derived from Git and
recorded by the later carriers rather than predicted in this document.

## 2. Clean build and local gates

Build `v0.70b-eSE9.2.0-rc.1` from the clean detached `A` worktree with the
official pipeline and Node 22. The build must run without `AllowDirty`, skipped
gates or a dry run.

Required local evidence includes:

1. the complete Node gateway suite and formal controller focal suite;
2. Windows PowerShell 5.1 parsing and the product/session/RPC/runner mocks;
3. PCP and NAT-PMP ownership, hostile corpus, double-NAT and upstream gates;
4. the complete native `libnatmap` suite;
5. Core and Integration suites;
6. a clean Release x64 rebuild and package smoke;
7. a Release receipt bound to `A`, its full source fingerprint and `emule.exe`;
8. MOD02 verification and production selftest against that same executable;
9. `git diff --check` and the hotfix governance verifier.

Any failed gate stops the sequence before physical mutation.

## 3. Physical preflight

At most one short preflight may run after `H`. It remains NON_RELEASE even when
successful. Before mutation it must prove the VM is off, checkpoints disabled,
no snapshots, one original NIC, one base disk, no child disk, no T8 switch/NAT
or owned firewall rules, and an unchanged protected eMule process inventory.

The preflight must observe one coherent TCP/UDP candidate generation through
PCP or NAT-PMP, exercise cleanup, close eMule naturally, restore the profile
byte-for-byte and return VM, disk, NIC, firewall and T8 state to the exact
baseline. Forced cleanup makes the verdict FAIL.

## 4. Formal V92-O01 campaign

Only after local gates and preflight readiness may the formal runner start.
The campaign has no duration override, resume or skip-cleanup option.

PASS requires all of the following:

- exactly 28,800,000 monotonic milliseconds;
- one accredited eMule process identity for the whole run;
- 2,880 ten-second observations and 960 thirty-second fault slots;
- 480 available product samples and 95 intermediate checkpoints;
- all ten frozen fault outcomes consumed through real gateway traffic;
- atomic TCP/UDP publication, monotonic generations and bounded recovery;
- no resource-limit or slope violation;
- natural product and daemon shutdown;
- zero owned mappings, the foreign fixture preserved, empty journal/timers;
- byte-exact profile restore and exact host/VM/T8 baseline restoration;
- an independently reconstructed checkpoint chain and validator PASS.

The executable SHA-256 in the formal result must equal the executable sealed by
the Release receipt and MOD02 manifest in `M`.

## 5. Decision

`rc.1` remains `NO_GO` when any required gate is missing, blocked, failed or
belongs to another commit/package. A safety cleanup may protect the machine but
cannot turn a failed run into PASS.

Only an `R` commit containing the exact 95 checkpoints, controller result,
formal run result and independent validation can change V92-O01 to PASS. The
broader v9.2 exit decision must still reconcile the remaining required physical
cases without borrowing evidence from earlier candidates.
