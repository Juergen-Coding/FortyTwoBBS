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


## B4.3.2 FTAP 1.3 registration foundation

B4.3.2 raises the local protocol to FTAP 1.3 and identifies the development
binaries as `fortytwo-authd 0.3.0` and `fortytwo-login 0.1.3`.

Self-registration remains disabled by default. The daemon configuration now
contains bounded values for:

```text
registration_enabled               false
registration_min_password_bytes    12
registration_timeout_seconds       600
registration_max_pending           16
registration_ip_attempts           3
registration_ip_window_seconds     900
```

The production service does not enable registration in this subsection. A
later B4.3.2 server handler will enforce these settings before submitting an
Argon2id generation job or opening a PostgreSQL registration transaction.

The per-source-IP prefilter uses a fixed table of 1024 canonical IPv4 or IPv6
addresses. Expired windows are reclaimed. If every entry is active, an unknown
address fails closed with a retry delay instead of evicting a live counter and
weakening the limit. This table is an in-memory defensive filter; PostgreSQL
remains authoritative for the global pending-registration limit and durable
registration state.

The existing bounded password worker pool now accepts typed verification and
hash-generation jobs through one shared thread and queue limit. Generated
Argon2id PHC strings are returned only in value completions, never through a
client pointer, and must be cleared explicitly after the event loop has used
them. Queue rejection, shutdown, stale completions and unclaimed completions
wipe both passwords and generated hashes.

### Migration 0009 registration lifecycle

Migration `0009_telnet_registration.sql` introduces the durable PostgreSQL
side of the two-phase Telnet registration.  A row in
`bbs_registration_attempts` binds one server-generated registration UUID to
one pending FortyTwo user UUID, one reserved legacy MBSE key and one canonical
source address.  Its constrained lifecycle is:

```text
pending_legacy -> completed
pending_legacy -> aborted
pending_legacy -> failed
```

Pending attempts expire explicitly and cannot represent an active account.
Aborted identities remain as logically deleted UUID rows for audit history,
while their credential, profile and legacy binding may be removed by the
daemon.  The login-name uniqueness rule therefore now covers only identities
whose `deleted_at` value is NULL, allowing a later independent registration to
reuse a name abandoned before activation.

The migration grants no broad schema rights.  `fortytwo_authd` receives only
`SELECT`, `INSERT` and `UPDATE` on the new lifecycle table, the precise write
rights required to reserve or release the legacy binding, and `DELETE` only on
profile and password rows needed by an abort.  Registration history itself is
never deleted by the runtime daemon.

### Registration database API

The PostgreSQL runtime layer now exposes four registration-specific operations:

```text
authd_database_begin_registration
authd_database_commit_registration
authd_database_abort_registration
authd_database_expire_registrations
```

`begin_registration` serializes the global pending limit with a transaction-
scoped advisory lock.  It then creates the pending identity, profile, Argon2id
credential, legacy-name reservation, lifecycle row, and
`auth.registration_started` audit in one explicit transaction.  A login-name
or legacy-name conflict rolls the complete transaction back and has its own
result code; neither case can leave a partial pending identity behind.

`commit_registration` locks the complete attempt and identity context and
rechecks the registration UUID, user UUID, login name, display name, legacy
name, source address, optional terminal binding, account state, expiry,
authentication epoch, authorization revision, and absence of pre-existing
roles.  It grants only `bbs_user`, activates the identity, increments
`authz_revision`, completes the attempt, creates the first Telnet/password
session, and writes both `auth.registration_completed` and
`auth.login_succeeded` before committing.  The SQL path never selects or
inserts `ssh_access`.

`abort_registration` keeps the user UUID and durable attempt history but marks
the identity deleted, increments `auth_epoch`, releases the profile,
credential, legacy binding and any accidental role assignment, and appends an
`auth.registration_aborted` audit.  The login name and legacy key are therefore
available to a later independent registration only after the abort transaction
has committed.

`expire_registrations` processes a bounded batch of expired pending attempts
with `FOR UPDATE ... SKIP LOCKED`.  Each selected identity becomes logically
deleted, authentication-bearing child rows are removed, the attempt becomes
`failed` with reason `registration_timeout`, and an
`auth.registration_failed` event is written atomically.

The dedicated libpq-wrapper suite validates the transaction boundaries,
conflict mappings, exact context binding, Telnet-only session creation,
absence of an SSH role grant, abort cleanup, bounded expiry, and stable public
result names.  This subsection still does not connect the database API to the
FTAP server state machine; registration remains disabled in the production
service configuration.

A separate real-PostgreSQL target validates the same lifecycle against schema
9, including actual SQL syntax, constraint behavior, grants, role assignment,
logical deletion, name reuse, the global pending limit, expiry cleanup,
sessions, and audits:

```sh
make database-registration-integration-test
```

The runner creates only conspicuously named test identities, refuses to start
while another pending registration exists, executes the binary as the
`fortytwo_authd` runtime role, verifies the resulting rows as the database
administrator, and removes the fixture even when the test fails.

### FTAP server registration state machine

The local FTAP server now connects the FTAP 1.3 registration messages to the
bounded worker pool and the schema-9 PostgreSQL lifecycle.  Registration still
starts only when `registration_enabled` is explicitly set; the production
default remains disabled until the visible NEW dialog and the legacy
`users.data` writer are implemented.

`REGISTRATION_BEGIN_REQUEST` is accepted only after HELLO on an otherwise idle
connection.  The daemon validates the Telnet/password metadata, records the
per-source-IP prefilter attempt, enforces the configured minimum password
length, and submits one typed Argon2id generation job.  The cleartext password
is wiped by the worker submission boundary.  No database identity exists while
the hash is pending, so a socket loss or stale worker completion at this stage
cannot leave a pending registration behind.

After hash generation, the daemon first tries a canonical login name of at most
eight characters as the legacy key.  A collision switches to an unbiased,
cryptographically random eight-character compatibility key and retries at most
16 times.  A successful PostgreSQL Begin snapshot is stored only in the client
slot that owns the exact connection generation, request ID and worker job ID.
The resulting registration UUID and pending identity are therefore bound to
one live FTAP socket.

In `REGISTERING`, Commit and Abort must contain the byte-identical bound
registration UUID.  Commit delegates the full recheck and Telnet-only
activation to PostgreSQL, binds the returned session, and changes the
connection to `SESSION_BOUND`.  Confirmed Abort removes the pending identity
through the database API, returns `REGISTRATION_ABORT_RESULT`, and moves the
same connection back to `HELLO_COMPLETE` so another Begin may be attempted.

Every reset after a successful Begin performs a best-effort database Abort.
This covers peer disconnects, protocol errors, failed response writes, daemon
shutdown and fatal daemon failure.  The local registration deadline is part of
the poll timeout; on expiry the daemon aborts the bound attempt and closes the
socket.  If that immediate cleanup fails, the database row remains bound and
the periodic schema-9 expiry operation is the fail-closed fallback.  Startup
and every database-health interval also process a bounded expiry batch with the
same PostgreSQL API.

The test-only database now models the registration lifecycle and records Begin,
Commit, Abort and legacy-collision events.  A dedicated end-to-end test starts
the real event-loop daemon with deterministic workers and covers:

- administrative disablement and password-policy rejection;
- successful Begin, Commit, session context and session close;
- direct legacy names and random collision retry;
- confirmed Abort followed by another Begin on the same socket;
- the per-source-IP attempt limit;
- disconnect, daemon-shutdown and database-failure cleanup after a durable Begin;
- disconnect while Argon2id generation is still pending;
- login-name, database, global-limit and stale-Commit result mappings.

The test is part of both `make test` and `make sanitize-test`.  The latter runs
the daemon and the complete registration state machine under ASan and UBSan.

### FTAP registration client lifecycle

The synchronous FTAP client now exposes the three operations required by the
visible Telnet registration flow:

```text
ftap_client_registration_begin
ftap_client_registration_commit
ftap_client_registration_abort
```

Begin transmits the canonical registration inputs and Telnet metadata, wipes
both the request payload and the encoded frame, changes the client to
`REGISTERING` before validating the server response, and retains the exact
registration UUID, user UUID, canonical login name, display name and legacy
key returned by PostgreSQL Begin.

Commit and Abort accept only that retained snapshot.  Their result parsers
compare the returned registration and user identities byte-for-byte with the
pending context; Commit additionally verifies the login, display and legacy
names before exposing the new terminal session.  A successful Commit changes
the client to `SESSION_BOUND`; a confirmed Abort returns the same socket to
`HELLO_COMPLETE`.

Only `client_cancelled` and `legacy_write_failed` can be sent by this client as
registration-abort reasons.  Server-only lifecycle reasons remain unavailable
to callers.

`ftap_client_error_t` distinguishes a validated FTAP `ERROR` response from a
transport or response-validation failure.  For Commit and Abort, the latter is
reported as `outcome_unknown` once the complete request has been sent.  The
caller must therefore not assume that a timed-out Commit failed and must retain
its legacy provisioning marker for reconciliation instead of blindly removing
the new record.

The dedicated socket-pair test covers successful Begin/Commit, successful
Begin/Abort, server-side password-policy rejection, exact pending-identity
binding, invalid client abort reasons, state changes, and the unknown-outcome
classification for an inconsistent Commit response.  It runs in both
`make test` and `make sanitize-test`.

### Read-only legacy users.data gateway

The first `users.data` replacement boundary is now a read-only gateway rather
than another direct `fopen()` call in `fortytwo-login`.  The public
`legacy_userdb` module opens the trusted MBSE root, `etc` directory and
`users.data` one component at a time with `O_NOFOLLOW`, validates the file
owner, group, exact permission mode and link count, and takes a shared advisory
open-file-description lock before reading any bytes.  These Linux OFD locks
also serialize independent threads in one process and do not disappear when an
unrelated descriptor for the same file is closed.

The gateway contains compile-time assertions for the active packed MBSE ABI:

```text
header size       8 bytes
user record     598 bytes
legacy name      offset 36
visible handle  offset 510
clear password  offset 563
```

A scan fails closed when the stored header does not match that exact build,
the file ends with a partial record, the configured record limit is exceeded,
a searched text field lacks a NUL terminator, two records contain the same
legacy name under deterministic ASCII case folding, or the file metadata
changes during the scan.  It can report collisions for the server-reserved
legacy key and for the proposed display name against both `sUserName` and
`sHandle`.  Non-ASCII display-name bytes remain byte-exact during this
temporary collision check; ASCII letters are compared case-insensitively.

The module is still deliberately read-only.  It does not append a record,
create a user directory, or alter PostgreSQL.  Those operations will build on
this validated boundary in the next provisioning section.

A dedicated fixture suite covers the real 8/598 layout, header and length
corruption, symlink and directory substitution, owner/group/mode/link policy,
unterminated legacy fields, duplicate names, display and handle collisions,
record limits, input validation, and a competing write lock.  The supplied
606-byte runtime fixture was also accepted as one valid record without logging
any user contents.

`make test` and `make sanitize-test` now also run a direct-access baseline
check.  Every literal `users.data` or `users.temp` reference outside the
central gateway must match the reviewed allowlist exactly.  Removing a legacy
access therefore reduces the recorded count; adding a new direct access fails
the build until the access register and allowlist are deliberately reviewed.

### Controlled local legacy provisioning

The legacy gateway now has a separate append-only provisioning path.  It is
still not connected to the FTAP client or the visible NEW dialog.  Its purpose
is to prove the complete local filesystem transaction in isolation before a
PostgreSQL Commit can depend on it.

`legacy_userdb_prepare_registration()` accepts only an already validated
registration snapshot: binary registration and user UUIDs, the server-selected
one-to-eight character legacy key, the display name, registration time, and the
small set of explicit MBSE defaults needed for the first session.  The function
never accepts or stores a password.

The constructed 598-byte record is zero-initialized and sets only reviewed
fields.  Provisioning is compiled only for the reviewed little-endian 8-bit-byte
ABI, and it checks the raw option-bit bytes so a compiler with incompatible C
bit-field allocation fails before any append.  In particular:

```text
Name             server-selected legacy key
sUserName        validated display name
sHandle          empty
Password         15 NUL bytes
xPassword        0
Security          explicit new-user security tuple
ExpirySec         same tuple
sExpiryDate       00-00-0000
tFirstLoginDate   registration time
tLastLoginDate    0
tLastPwdChange    registration time
iLastFileArea     1
iLastMsgArea      1
GraphMode         enabled
HotKeys           enabled
Cls / More        enabled
ieASCII8 / ieNEWS enabled
```

The registration UUID is rendered without hyphens into the record comment as
`FT42REG:<32 lowercase hex characters>`.  This is a reconciliation marker, not
an authentication token.

Before touching the database file, the provisioner acquires an exclusive Linux
OFD `fcntl()` lock at:

```text
$MBSE_ROOT/tmp/fortytwo-registration/users-data.lock
```

Independent threads and independent processes therefore serialize on the same
runtime lock.  It then opens the configured users directory component by
component from `/`
with `O_DIRECTORY|O_NOFOLLOW`, checks its owner, group and exact mode, opens
`users.data` for read/write under an exclusive advisory lock, repeats the full
8/598 validation and collision scan, and records the storage identities and
owner/group/mode metadata.  Both the proposed legacy key and display name are
checked against all three historical identifier fields (`Name`, `sUserName`
and non-empty `sHandle`).  A record carrying the same `FT42REG` registration
marker is treated as retained state requiring reconciliation rather than as a
new registration attempt.

The local transaction is:

```text
create private .ft42reg-<registration-id> staging directory
create Maildir/{cur,new,tmp}
write and fsync .fortytwo-registration mode 0600
fsync the staging tree and users directory
append exactly one 598-byte record
fdatasync users.data
read the appended bytes back and compare them byte-for-byte
repeat the full identifier, marker, duplicate-name and record validation
recheck active MBSE/users paths, metadata and exact file length
promote the private staging directory from 0700 to final mode 0770
rename the staging directory with RENAME_NOREPLACE to <legacy-name>
fsync the users directory
repeat active-path, metadata, exact-length and full-record-set checks
```

The unpublished staging directory is mode `0700`; the final user directory is
mode `0770`.  `Maildir` and its three children remain mode `0700`.  The marker
file contains only format version, registration UUID, user UUID, legacy key,
record number and `state=prepared`.  Before rollback can delete anything, the
complete marked tree must still contain exactly the marker plus `Maildir`, and
`Maildir` must contain exactly the three empty `cur`, `new` and `tmp`
directories.

`legacy_userdb_rollback_precommit()` is deliberately limited to the period
before any FTAP Commit request begins.  Its context retains the original file
length, storage device/inode identities, the exact appended record bytes, and
the two UUIDs.  Rollback proceeds only when the database is still the same
inode, the record is still the exact final record, and the directory marker is
byte-identical.  The final directory is first moved back to its private staging
name, then the database is truncated and synchronized, and finally the known
bounded directory tree is removed.  Unexpected files, marker changes, a later
record append, a configured-path replacement, an inode replacement or any
other ambiguity cause a fail-closed
`rollback_unsafe` result with `repair_required` instead of destructive guessing.

The provisioning fixture suite covers the successful record and directory
layout, exact password absence, explicit rollback, name and target collisions,
directory-policy rejection, global lock serialization, partial record writes,
record-sync failure, readback mismatch, marker-write failure, rename failure,
post-rename directory-sync failure, marker tampering, record tampering and a
later file-length change.  It also verifies same-process thread-style OFD lock
conflicts and rejects replacement of either active storage path.  Cross-field
identifier collisions, duplicate registration markers, storage metadata
changes, corrupted rollback contexts, malformed databases, a post-append collision and
unexpected directory entries are also covered.  The supplied real 606-byte
legacy file was exercised through prepare and rollback on an isolated copy.
Every injected pre-commit failure either restores
the original file length and removes the staging tree or reports a retained
state that requires reconciliation.  The suite runs under both the normal and
ASan/UBSan targets.
