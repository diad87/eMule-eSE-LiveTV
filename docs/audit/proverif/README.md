# ProVerif handshake model — F4a deliverable

This directory contains the formal model of the eSE Live tunnel handshake
in the applied-pi calculus, as required by Decision 8.1 (thesis main Cap 8)
and Decision 9.2 (Cap 9): **bloqueante para V1 release**.

## Files

- `handshake.pv` — main model. ntor-style 2-hop construction.
- `REVIEW.md` — sign-off log (filled by the human reviewer).

## Status: BLOQUEANTE_HUMANO

The model has been written by the eSE project but **not executed**.
Code already in `srchybrid/LiveCircuit.cpp` follows the same abstract
structure (X25519 ECDH per hop, HKDF for K_send/K_recv, AEAD per layer).

A human with ProVerif experience must:

1. Install ProVerif 2.04+ from https://bblanche.gitlabpages.inria.fr/proverif/
2. Run:
   ```
   proverif handshake.pv
   ```
3. Confirm all three RESULT lines are `true`:
   - `not attacker(secret_payload[])`
   - `event(V_finished_with(x,y)) ==> event(A_finished_with(x,y))`
   - `inj-event(V_finished_with(x,y)) ==> inj-event(A_finished_with(x,y))`
4. If any property fails:
   - Save the attack trace to `attack-traces/<date>.txt`.
   - Open a design issue.
   - The handshake must be redesigned and `LiveCircuit.cpp` re-implemented
     before V1.
5. Fill `REVIEW.md` with timestamp + reviewer + ProVerif version + result.

## What this model proves (when it passes)

- **G1 — Forward secrecy.** A passive attacker who later compromises
  the long-term key of either hop A or B cannot decrypt past traffic.
  Modelled by leaving `sk_A_long` / `sk_B_long` private but the protocol
  proper using ephemeral X25519 scalars; the AEAD key is derived from
  the ephemeral DH, never from the long-term keys.
- **G2 — Unilateral authentication.** V verifies it is talking to the
  intended A and B (their public keys are known a priori from the swarm
  peer list); A and B do not learn V's identity.
- **No replay.** The `inj-event` correspondence asserts that each
  V-side handshake completion corresponds to a UNIQUE A-side
  handshake — replaying a CREATE/CREATED transcript cannot fool V
  into reusing K_send/K_recv.

## What this model does NOT cover (out of scope F4a)

- Rotation every 30 s + jitter: orthogonal to the static handshake.
- Multipath split across 3-5 circuits: independent property
  (correlation-resistance, P-7 thesis Cap 8).
- Cover traffic: traffic-analysis defence, not protocol correctness.
- DESTROY cells / circuit teardown: no security property at stake.

These belong in a separate model (`destroy.pv`, `cover.pv`) for V2 or
a thesis extension.

## Project policy

Without a green RESULT log signed in `REVIEW.md`, the V1 release is
gated. This is the same policy Tor and Signal apply for their handshake
verifications and reflects the project priority order: seguridad first.
