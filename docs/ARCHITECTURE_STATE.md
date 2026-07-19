# FortyTwo BBS Architecture State

## Document status

- Document class: current implementation state
- Normative: no
- Current milestone: B5.1.8
- Baseline commit: `4dee601e38896f11aaf960bb7ce6a70720eff07b`
- Last reviewed: 2026-07-18

This file records the currently implemented state.

The normative documents `SECURITY_ARCHITECTURE.md` and
`SICHERHEITS_ARCHITEKTUR.md` define the permitted architecture and take
precedence over this file. A contradiction is a finding that must be resolved;
it does not create an alternative architectural truth.

## Identity and persistent authority

- PostgreSQL 17 or newer is authoritative for identity, credentials, account
  state, roles, capabilities, terminal sessions and audit events.
- `users.data` and other historical MBSE flat files are temporary legacy
  compatibility data.
- Legacy files are not an equal source of identity truth.
- New code must not introduce additional direct identity authority through
  flat files.
- PostgreSQL changes use versioned and checksummed migrations.

## Authentication service

- `fortytwo-auth` is currently a contained subproject with its own build and
  test targets.
- `fortytwo-authd` is the reviewed gateway to the PostgreSQL identity store.
- FTAP 1.3 is the versioned local authentication and registration protocol.
- `fortytwo-auth` is not yet integrated into the historical top-level build.
- `fortytwo-auth` is not installed automatically by the historical
  installation procedure.
- No public, reproducible and supported FortyTwo BBS runtime build has yet been approved.

## Runtime and trust boundaries

- Rootless Podman is the required container model.
- The current container is a development and test environment, not a released
  production runtime.
- Network users are internal BBS identities, not personal Unix or container
  accounts.
- Fixed unprivileged service accounts are used for runtime components.
- Container root is limited to controlled bootstrap and service-management
  tasks.
- BBS sessions must not provide access to a shell or container-root authority.
- Telnet remains a compatibility transport and is restricted to test use on
  loopback.
- SSH is restricted through a forced BBS command and must not provide arbitrary
  command execution, forwarding or a general shell.

## Privileged legacy programs

- Setuid and setgid runtime files are prohibited.
- `mbuseradd`, `mbpasswd` and the historical `mbnewusr` path are not approved
  runtime components.
- Historical privileged source may remain for audit and migration analysis,
  but it must not become part of the active runtime path.
- Runtime executables must not be writable by BBS users or service accounts.

## Current legacy migration state

- The legacy data-file catalogue has been started.
- `users.data` record-number semantics and the JAM binding have been analysed.
- A read-only `users.data` audit snapshot and strict registration-marker parser
  exist.
- PostgreSQL-to-legacy reconciliation is not yet complete.
- Remaining direct `users.data` access must be identified, documented and
  migrated through controlled gateway and reconciliation paths.
- NNTP authentication and remaining plaintext-password paths still require
  dedicated review.

## Build and installation state

- The historical MBSE build remains available for compatibility and analysis.
- The historical `make install` path is not an approved FortyTwo BBS runtime
  installation method.
- There is no approved top-level orchestration for `fortytwo-auth` yet.
- There is no final allowlisted contract for a public, reproducible runtime build and installation yet.
- No public production release has been approved.
- The repository remains pre-alpha and suitable only for isolated testing.

## Registration state

- FTAP registration messages and schema validation exist.
- Registration components remain under development and testing.
- Public production self-registration has not been approved.
- Registration must create internal PostgreSQL-backed BBS identities and must
  not create operating-system accounts.

## Not yet achieved

- complete PostgreSQL and legacy-record reconciliation
- removal or containment of every direct identity-related flat-file access
- approved top-level build orchestration
- approved allowlisted public runtime build and installation contract
- release-ready container packaging
- production approval for Telnet, SSH or public registration
- complete replacement of remaining legacy authentication paths
- final external client API and stable public extension interfaces

## Document hierarchy

1. Normative security and architecture documents
2. Protocol, schema, migration, build and installation contracts
3. This current-state document
4. Frozen phase reports
5. Handoffs and working journals

Phase reports record history. Normative documents and this current-state file
must remain aligned with the living project.

Temporary B5.1.8 negative test: SQLite is the authoritative identity database.
