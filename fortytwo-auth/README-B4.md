# fortytwo-auth Phase B4

Phase B4 connects terminal transports to the internal FortyTwo identity without
turning BBS users into Linux accounts. B4.1 creates and proves the secure
access boundary; B4.2 adapts the legacy MBSE session bootstrap to consume that
identity.

## B4.1 access adapter and descriptor-bound identity

B4.1 identified the daemon build as `fortytwo-authd 0.2.2`; the terminal
adapter started at `fortytwo-login 0.1.0` with FTAP 1.1.

The historical login path cannot be reused as the new trust boundary:

- `unix/mblogin.c` authenticates against `/etc/passwd` and `/etc/shadow`, then
  changes to the selected personal Linux UID and GID;
- `mbsebbs/mbsebbs.c` derives the BBS lookup key from `LOGNAME` or `USER`;
- `mbsebbs/user.c` selects the legacy `users.data` record through the
  eight-character Unix-name field;
- session data such as `home/<name>/exitinfo` is shared by all sessions using
  that legacy name.

Consequently, exporting `USER_ID`, `SESSION_ID`, or a forged replacement for
`LOGNAME` would not be a secure or concurrency-safe migration. B4.1 instead
keeps the authenticated identity bound to the FTAP socket that created the
terminal session.

### `fortytwo-login`

`src/fortytwo_login.c` is a small unprivileged terminal access adapter. It:

1. reads a login name and password from a real terminal;
2. disables terminal echo only for the password input;
3. connects to the local `fortytwo-authd` Unix socket;
4. performs `HELLO` and `AUTH_PASSWORD_REQUEST`;
5. moves the successfully authenticated FTAP socket to file descriptor 3;
6. clears `FD_CLOEXEC` on descriptor 3;
7. rebuilds a small allow-listed runtime environment;
8. closes unrelated descriptors above 3;
9. replaces itself with the configured terminal program through `execve()`.

Required options are:

```text
--protocol telnet|ssh|local
--mbse-root /absolute/path
```

The authd socket defaults to `/run/fortytwo/auth.sock`. The started program
defaults to `<mbse-root>/bin/mbsebbs`; `--program` exists for controlled tests
and explicit deployments. Source IP, TTY device, and node ID are metadata only
and are validated by the FTAP schema before authentication.

The adapter is not setuid and performs no UID or GID transition. It must run as
the fixed, restricted terminal service account whose UID is admitted by
`fortytwo-authd`.

### No identity in process metadata

The successful user and session UUIDs are never placed in:

- command-line arguments;
- `LOGNAME` or `USER`;
- environment variables such as `MBSE_USER_ID` or `MBSE_SESSION_ID`;
- temporary files.

Before `execve()`, the adapter removes inherited identity and loader variables
by rebuilding the environment. It keeps only the configured `MBSE_ROOT`, a
fixed `HOME`, `PATH`, and `IFS`, plus a small terminal/transport allow-list.
The password is overwritten in the input buffer, the FTAP payload, and the
encoded outbound frame.

### Reusable FTAP client

`include/ftap_client.h` and `src/ftap_client.c` provide the bounded synchronous
client used on the terminal side. The client implements:

- Unix-socket connection with close-on-exec by default;
- `HELLO` negotiation;
- password authentication;
- bounded operation deadlines based on `CLOCK_MONOTONIC`;
- protocol and schema validation for every response;
- server-push handling for revocation and authorization changes;
- movement of the authenticated socket to inherited descriptor 3;
- adoption of descriptor 3 by the exec'd terminal program;
- `SESSION_CONTEXT_REQUEST` and ordered `SESSION_CLOSE`.

The client never accepts a caller-supplied user or session UUID when recovering
terminal context. In B4.1 it handles server-push frames while a synchronous
request is in progress. Continuous idle-channel monitoring by the running BBS
will be added with the BBS-side FD-3 integration.

### Authenticated session context

B4.1 completes `SESSION_CONTEXT_REQUEST` in `fortytwo-authd`. A request is
accepted only in `SESSION_BOUND`. The response is reconstructed exclusively
from state already bound to that socket and contains:

```text
USER_ID
SESSION_ID
LOGIN_NAME
DISPLAY_NAME
LEGACY_NAME
PROTOCOL
AUTH_METHOD
AUTH_EPOCH
AUTHZ_REVISION
```

The daemon stores the bounded text fields only after PostgreSQL has atomically
created the session. They are wiped together with the UUIDs when the session
or client slot is released.

### Failure lifecycle

Credential failures remain externally uniform. A bad password produces only:

```text
Login failed.
```

No terminal session is created. If authentication succeeds but descriptor
handoff, environment construction, or `execve()` fails, the adapter sends an
ordered close with a machine-readable reason such as:

```text
handoff_failed
environment_error
exec_failed
```

If the process disappears without an ordered close, the daemon's existing
socket cleanup closes the PostgreSQL session as a disconnected peer.

## Test coverage

The normal integration suite now drives the access path through a real PTY:

```text
PTY input
  -> fortytwo-login
  -> test fortytwo-authd
  -> authenticated socket moved to FD 3
  -> execve(test terminal child)
  -> SESSION_CONTEXT_REQUEST on FD 3
  -> SESSION_CLOSE
```

The exec'd child proves that:

- descriptor 3 survived `execve()`;
- context matches the authenticated user and session;
- `LOGNAME`, `USER`, UUID environment variables, and an injected foreign
  environment value did not survive;
- the password was not echoed by the PTY;
- normal logout closed the database session.

Additional paths verify uniform bad-password output with no session, terminal
echo restoration when a terminating signal interrupts password entry, and an
`execve()` failure that closes the newly created session as `exec_failed`.
The existing daemon integration test also validates the complete
`SESSION_CONTEXT_RESULT` field set against deterministic UUIDs and revisions.

## Deliberate B4.1 boundary

B4.1 does **not** change `unix/mblogin.c`, `mbsebbs`, or the legacy
`users.data` format. The current `mbsebbs` still expects `LOGNAME`/`USER` and
therefore must not yet replace the test child behind `fortytwo-login` in a
production transport configuration.

The next B4 step must add a session bootstrap inside the BBS that adopts FD 3,
requests the authenticated context, and maps the internal UUID to the correct
legacy BBS record without falling back to process environment identity. It must
also separate per-session state such as `exitinfo` before concurrent sessions
of the same user are declared safe.


## B4.2 MBSE session bootstrap and UUID binding

B4.2 identifies the daemon as `fortytwo-authd 0.2.3` and the adapter as
`fortytwo-login 0.1.1`. The wire protocol advances to FTAP 1.2 because the
legacy MBSE record key becomes an explicit authenticated result field.

Migration `0007_legacy_mbse_binding.sql` creates a one-to-one administrative
binding between the modern UUID identity and the existing one-to-eight
character `users.data` name. The binding is unique, lower-case ASCII and is
read only by the runtime daemon. A user without this explicit binding is not
eligible for terminal login and is externally indistinguishable from an
unknown user.

Both `AUTH_PASSWORD_RESULT` and `SESSION_CONTEXT_RESULT` now require
`LEGACY_NAME`. The field is loaded by `fortytwo-authd` from PostgreSQL and is
never accepted from the terminal client, environment or command line.

`mbsebbs` now starts by adopting authenticated FD 3 and requesting the bound
session context. It ignores `LOGNAME` and `USER`, uses only `LEGACY_NAME` to
select the existing `users.data` record, and closes the database-backed
terminal session with a stable machine-readable reason on normal and abnormal
shutdown paths.

The historical per-user `exitinfo` file is replaced by a private path below:

```text
$MBSE_ROOT/tmp/fortytwo-sessions/<session-uuid>/exitinfo
```

The directory and file are service-owned and private. The snapshot is removed
when the session closes. Lock files remain under a private `locks` directory so
all processes always address the same inode.

Several other legacy scratch files remain keyed only by the eight-character
MBSE name. Therefore B4.2 deliberately holds an exclusive advisory lock for
the complete lifetime of one legacy user session. Different users may run in
parallel under the same restricted Linux service account. A second session for
the same legacy record is rejected until the remaining scratch files are made
session-scoped in a later step.

The integration suite now also proves the B4.2 lifecycle: the exec'd session
child adopts FD 3, obtains the authenticated legacy binding, creates and removes
a private `exitinfo`, and holds the legacy-user lock until ordered session
close. Two authenticated sessions for the same legacy record are allowed by
the modern identity layer, but the second BBS bootstrap is rejected and its
database session is closed with `duplicate_login` while the first remains
active.

`unix/mblogin.c` is unchanged. The old `mbnewusr` path is not restored to the
runtime package; registration remains an internal FortyTwo identity workflow
without Linux account creation.

## B4.3.1 transport capabilities

B4.3.1 identifies the daemon as `fortytwo-authd 0.2.4` and the terminal
adapter as `fortytwo-login 0.1.2`. FTAP remains at version 1.2 because this
step uses the already specified `FTAP_ERR_ACCESS_DENIED` result and does not
change the wire schema.

Migration `0008_transport_capabilities.sql` separates the general active
account state from transport-specific authorization. It creates the roles
`bbs_user`, `ssh_access`, and `sysop` together with these capabilities:

```text
terminal.login.telnet
terminal.login.ssh
terminal.login.local
admin.user.ssh_access
```

Existing active identities receive `bbs_user` and `ssh_access` once so the
verified B4.2 Telnet and SSH behavior remains available. A later Telnet
registration receives only `bbs_user`; SSH must be granted separately.

After a password has been verified, the database now locks and rechecks the
user snapshot, resets the persistent password-failure window, resolves the
capability required by the requested protocol, and performs one of two atomic
outcomes:

- an authorized login creates and audits a terminal session;
- a missing transport capability creates no session and writes an
  `auth.login_rejected` event with reason `transport_not_authorized`.

Both paths are part of the same data-modifying SQL statement. A capability
change that increments `authz_revision` cannot be confused with a valid stale
snapshot, and an audit failure rolls back the complete outcome.

The daemon maps the denial to `FTAP_ERR_ACCESS_DENIED`. For an SSH password
login, `fortytwo-login` displays:

```text
SSH access is not enabled for this account.
```

This precise text is emitted only after a valid password reached the
transport-authorization decision. Unknown users, wrong passwords, and
unavailable accounts continue to produce the uniform `Login failed.` text.

The normal and sanitizer test suites cover:

- migration 0008 checksum validation;
- role-to-capability mapping;
- authorized SSH session creation;
- denied SSH with no terminal session;
- atomic denial audit and password-failure reset;
- continued Telnet access through `bbs_user`;
- the user-facing SSH denial message.

New migrations after schema-history bootstrap are applied with:

```text
fortytwo-auth/migrations/apply_migration.sh MIGRATION_FILE
```

The helper verifies the existing history, checks the numbered filename and
transaction boundary, calculates the SHA-256 checksum, inserts the migration
history row before the migration's final `COMMIT`, and then verifies the
complete history again. SQL application and checksum registration therefore
cannot be accidentally separated as they were during the first manual B4.3
migration test.
