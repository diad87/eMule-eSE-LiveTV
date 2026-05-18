# ProVerif handshake — review sign-off

| Date | Reviewer | ProVerif version | Result | Notes |
|---|---|---|---|---|
| _pending_ | _pending_ | _pending_ | _pending_ | F4a deliverable produced 2026-05-18; review pending. |

## Procedure

1. Install ProVerif 2.04+ (Linux/macOS recommended; Windows via WSL).
2. From this directory:
   ```
   proverif handshake.pv
   ```
3. Copy the RESULT lines into the row above. If any line is not `true`,
   write `FAILED` in the Result column and append the attack trace to
   `attack-traces/`.
4. Sign the row with date, your name/handle, and ProVerif version.

V1 release is BLOQUEANTE on this table having at least one row with
Result = `PASS` and a reviewer signature.
