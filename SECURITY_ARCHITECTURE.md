# FortyTwo BBS Rootless Privilege-Separation Architecture

## Status

This document defines the mandatory security architecture for FortyTwo BBS.

These rules are normative. Historical MBSE BBS behaviour that conflicts with
this document must not be enabled, installed or treated as an acceptable
production option.

Architecture revision: the original SQLite target was superseded by the
PostgreSQL-based `fortytwo-auth` architecture introduced in phase B2 and
extended through phases B3, B4 and B5. PostgreSQL is authoritative. This
revision records the security architecture already implemented by the
versioned migrations, FTAP, `fortytwo-authd` and its database layer.

## 1. Security objective

FortyTwo BBS shall run as a rootless, privilege-separated service.

A network user must never be able to gain container-root privileges, host-root
privileges or access to administrative operating-system functions through the
BBS, Telnet, SSH, registration or password-management paths.

## 2. Host boundary

The container must run through rootless Podman.

The following are prohibited:

- privileged containers
- host PID, user or network namespaces
- access to the Podman socket
- unrestricted host home-directory mounts
- host `/etc` mounts
- unnecessary Linux capabilities
- direct exposure of test ports to external interfaces

Container UID 0 is mapped to an unprivileged subordinate host UID. It is not
host root, but it is still security-sensitive and must be tightly restricted.

## 3. Role of container root

Container root is permitted only for controlled bootstrap and service
management tasks, including:

- preparing runtime directories
- generating or loading SSH host keys
- starting xinetd and sshd
- starting a service that performs its own verified privilege drop
- controlled administrative account provisioning

Container root must not be reachable from a BBS user session.

Container root must not be exposed through a general-purpose shell, Telnet
command, SSH command, BBS door or registration helper.

## 4. Runtime accounts

Long-running FortyTwo BBS processes must use dedicated unprivileged accounts
whenever possible.

Current intended roles include:

- `mbse` for mbtask after its verified privilege drop
- `fortytwo` for interactive BBS sessions and service or installation lookups
  where required
- additional fixed service accounts only for narrowly defined components after
  an explicit security review

Network users are internal BBS identities. They must not require individual
Unix or container accounts.

Permissions must follow least privilege.

Shared writable directories must be explicitly identified. Executables and
configuration templates must not be writable by BBS users.

## 5. Prohibition of setuid and setgid helpers

FortyTwo BBS shall not install or use setuid-root or setgid privileged helper
programs.

No installed executable may carry a setuid or setgid bit unless a future
security review explicitly changes this directive.

In particular, the historical MBSE programs:

- `mbuseradd`
- `mbpasswd`

must not be installed as setuid-root programs and must not be callable from a
network user session.

Their historical source code may remain temporarily for auditing, migration
and redesign, but it must not be part of the active container runtime path.

## 6. User provisioning

BBS code must not directly modify:

- `/etc/passwd`
- `/etc/group`
- `/etc/shadow`
- `/etc/gshadow`

A BBS user is an internal application identity with a server-generated stable
opaque user ID. Creating a BBS user must not create a Unix or container
account.

Administrative provisioning must:

- be separate from unauthenticated and interactive session code
- expose only narrowly defined operations
- validate every input
- reject arbitrary commands and paths
- use database transactions and integrity constraints
- produce an audit log
- apply rate limits where remotely reachable
- never provide a shell or operating-system account
- be independently reviewed before activation

## 7. Registration

Public self-registration remains disabled.

`mbnewusr` must not be installed in the active runtime and must not invoke an
operating-system account-management helper.

Registration may be enabled only after a replacement design exists that
creates internal BBS identities, uses centralized authentication and satisfies
this architecture.

Until then, internal BBS users are provisioned administratively.

## 8. Authentication

SSH, Telnet, NNTP, APIs and future native clients must authenticate against the
same internal FortyTwo BBS identity system.

Personal Unix or container accounts must not represent BBS users.

Authentication must use:

- stable opaque user IDs
- unique normalized login identifiers
- Argon2id password hashes
- optional TOTP second factors
- revocable server-side sessions
- short-lived opaque access tokens for APIs and native clients
- rotating and revocable refresh tokens stored only as hashes
- generic external failure messages
- centralized disabled, locked and expired account checks

Session identity must not be trusted from environment variables, command-line
arguments or mutable display names.

Terminal transports must hand off authenticated identity through a reviewed
local IPC mechanism or a sealed inherited file descriptor carrying a
short-lived, single-use opaque session handle. The handle must be bound to the
corresponding server-side session.

Passwords and account records must be stored persistently and must not depend
on an ephemeral writable container layer.

Authentication data must never be embedded as plaintext in:

- the Containerfile
- image layers
- shell scripts
- Git commits
- public configuration files

## 9. SSH restrictions

SSH access must remain restricted to the FortyTwo BBS application.

Required controls include:

- no root login
- no arbitrary remote command execution
- no shell access for BBS users
- no agent forwarding
- no TCP forwarding
- no X11 forwarding
- no tunnels
- no user environment overrides
- no user startup scripts
- a forced FortyTwo BBS command
- a limited number of sessions

Compatibility host keys may be provided where necessary, but obsolete SSH
algorithms must not be enabled without a documented compatibility and risk
review.

## 10. Telnet restrictions

Telnet is an application compatibility service and provides no transport
encryption.

During testing it must remain bound to loopback.

Any later external Telnet deployment requires a separate documented decision,
firewall configuration and risk notice.

Telnet must start only the reviewed login path and must not provide a normal
system login program or shell.

## 11. Executable ownership

Installed programs and wrappers must not be writable by BBS users.

Normal executable ownership should be:

    root:root 0755

Administrative-only programs should normally be:

    root:root 0700

Group-writable executables are prohibited.

Source and build files may belong to the development user, but copied runtime
artifacts must receive controlled ownership and permissions in the image.

## 12. Capabilities and network access

The container must not receive `CAP_NET_RAW`.

Raw ICMP monitoring remains disabled through:

    MBSE_DISABLE_RAW_PING=1

Additional capabilities may be added only when a documented technical need
exists and no safer design is available.

## 13. Persistent state

Persistent state must be explicitly separated from immutable application
content.

The authoritative store for identities, authentication, authorization,
terminal sessions and audit events is PostgreSQL 17 or newer.

Only `fortytwo-authd` may access the identity database directly at runtime. It
must connect through an absolute local Unix-domain socket using the dedicated
least-privilege PostgreSQL role `fortytwo_authd` and local peer
authentication. Password-authenticated database connections and TCP database
endpoints are prohibited for this runtime path. FTAP must not transport
PostgreSQL credentials or password hashes.

The schema must use versioned, checksummed migrations, enabled foreign-key
constraints and explicit transactions. The data model includes at least:

- users and profiles
- normalized login identifiers
- password credentials
- roles, capabilities and assignments
- terminal sessions
- audit events
- legacy MBSE bindings
- registration attempts

PostgreSQL is authoritative for identity, credentials, account state, roles,
capabilities, sessions and audit data. `users.data` and other MBSE flat files
are temporary legacy compatibility data, not an equal source of identity
truth. New code must use reviewed gateway, provisioning and reconciliation
paths instead of introducing direct flat-file access. A failed or uncertain
legacy update must be reported and reconciled; it must not silently redefine
the committed PostgreSQL state.

Persistence planning must cover at least:

- BBS user data
- messages and file databases
- configuration data
- logs that must survive recreation
- account and password data
- SSH host keys

The complete host BBS directory must not be mounted into the container without
a file-by-file and directory-by-directory permission review.

## 14. Legacy code policy

FortyTwo BBS inherits security-sensitive code from MBSE BBS.

Historical code is not automatically trusted merely because it was part of
the original installation process.

Legacy privileged code must be classified as one of:

1. removed
2. excluded from the runtime image
3. rewritten without elevated privileges
4. isolated behind a reviewed administrative interface

"Used by the original installer" is not a security justification.

## 15. Build and review gates

Before a container image is accepted, the project must verify that:

- no executable has unexpected setuid or setgid bits
- no runtime executable is group-writable
- prohibited legacy helpers are absent or inaccessible
- the container runs rootless
- no forbidden capabilities are present
- SSH forced-command restrictions work
- arbitrary SSH commands are rejected
- Telnet and SSH start only the BBS
- privilege-dropping code checks every return value
- persistent data paths are explicitly documented
- the normative security documents identify PostgreSQL as authoritative
- the English and German security documents remain semantically synchronized

## 16. Current decision

The current FortyTwo BBS design shall use:

- rootless Podman
- no privileged mode
- no setuid-root or setgid BBS helpers
- no personal Unix or container accounts for BBS users
- internal BBS identities with stable opaque user IDs
- PostgreSQL 17 or newer as the authoritative identity, authentication,
  authorization, session and audit store
- versioned, checksummed migrations, foreign keys and explicit transactions
- `users.data` only as temporary, controlled legacy compatibility data
- short-lived opaque access tokens and rotating hashed refresh tokens
- authenticated one-time local session handoff
- fixed unprivileged service accounts
- no public registration
- controlled administrative provisioning of internal BBS users
- unprivileged runtime sessions
- explicit privilege separation
- loopback-only test ports
- immutable, non-group-writable runtime executables

Any proposal that conflicts with these rules requires an explicit security
architecture change, not an informal implementation shortcut.
