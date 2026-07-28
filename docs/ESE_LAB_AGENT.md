# eSE Lab Agent

`eSE Lab Agent` is the reusable unattended Windows test node for eMule/eSE
development. It is independent from a particular release plan. V91-I05 is
the first consumer, but later v9.x, v10, LiveTV, IPv4/IPv6, NAT and regression
campaigns use the same installed agent.

## Installation and lifetime

- `INSTALL-ESE-LAB-AGENT.cmd` is the only interactive installation step.
- The kit is copied to `C:\ProgramData\eSE-Lab-Agent`.
- Windows Task Scheduler runs it as `SYSTEM`, at boot, with highest privileges.
- Windows restarts it after an unexpected exit (up to 999 retries, one minute
  apart).
- Test failures are child-process failures and do not terminate the agent.
- `UNINSTALL-ESE-LAB-AGENT.cmd` removes the task and firewall rule but preserves
  collected evidence.

## Remote contract

The agent listens on the physical lab LAN and its firewall rule accepts only
the registered H1 address. Every request also needs the kit's random 256-bit
control token.

The token is installation configuration, never source code. Set
`ESE_LAB_AGENT_TOKEN` (or pass `-Token`) on the installer, controller and
repair tool. A repository or release package must not contain a live token.

The controller can:

- read agent and job status;
- deploy small authenticated test/code updates with byte count and
  SHA-256 verification;
- stream large candidates or fixtures from the registered H1 HTTP endpoint,
  with an exact size and SHA-256 contract;
- run injected PowerShell test jobs as isolated child processes;
- start the built-in V91-I05 physical campaign;
- stop a job without stopping the agent;
- enumerate and download only allowlisted result/evidence paths;
- update the agent itself and request a supervised restart.

Deployment and read paths are fail-closed allowlists. The protocol does not
provide a general interactive shell, filesystem browser or access to user
documents.

## Separation of concerns

The installed agent is infrastructure. Version-specific behavior belongs in
an injected job directory:

`injected/<32hex-job-id>/`

Each job has an immutable request document and writes status, stdout and
stderr under:

`jobs/<32hex-job-id>/`

This keeps future release tests separate from the agent lifecycle and lets the
same physical Windows node be reused without another interactive setup.
