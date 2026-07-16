# Pinned Kad bootstrap snapshot

`nodes.dat.b64` is the deterministic bootstrap snapshot carried by release
packages. It was recovered from the locally built 2026-05-19 package, has 199
Kad v2 contacts and is pinned by `nodes.dat.sha256`.

Packaging decodes it only after checking the encoded artifact, validating the
nodes.dat structure and verifying the decoded SHA-256. Runtime eSE does not
refresh it automatically. A future refresh must be reviewed explicitly and
must update both files together.
