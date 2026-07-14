# fortytwo-authd Phase B3

Phase B3 adds internal password authentication without Linux user accounts,
`/etc/passwd`, `/etc/shadow`, or SUID helpers.

## B3.1 password module

The first B3 step is deliberately isolated from the FTAP server and PostgreSQL
login flow. It provides a bounded Argon2id module in:

- `include/authd_password.h`
- `src/authd_password.c`
- `tests/authd_password_test.c`

Build dependency on Ubuntu and Debian:

```text
libsodium-dev
```

Current pre-alpha policy:

- Argon2id version 1.3 (`v=19`)
- 3 operations
- 256 MiB memory
- parallelism `p=1`
- password length 1 to 1024 bytes
- verification refuses hashes above the configured CPU, memory, or
  parallelism limits before calling the expensive verifier

The policy is represented by `authd_password_policy_t` so command-line or
configuration-file settings can be connected without changing the password
API.

`authd_password_generate()` and `authd_password_verify()` consume a mutable
password buffer and overwrite its entire declared capacity on every return
path. They attempt to lock the buffer with `sodium_mlock()`; if locking is not
available, the buffer is still overwritten with `sodium_memzero()`.

B3.7 now calls the password module only through the bounded worker pool. The
socket event loop never performs Argon2id itself and receives completed jobs
through the pool's `eventfd`.

## B3.2 canonical identity and PostgreSQL login snapshot

The second B3 step adds two isolated building blocks without connecting them to
FTAP yet:

- `authd_login_name_canonicalize()` accepts the conservative pre-alpha ASCII
  syntax, converts ASCII uppercase letters to lowercase, and rejects embedded
  NUL bytes, non-ASCII input, leading punctuation, and names longer than 32
  bytes.
- `authd_database_lookup_login()` uses exactly one `PQexecParams()` parameter;
  the login name is never concatenated into SQL.

The lookup returns a bounded snapshot containing:

- binary 16-byte user UUID
- canonical login name and display name
- account state and deletion marker
- active throttle state and bounded retry delay
- `auth_epoch`
- Argon2id hash
- `must_change`, `failed_count`, and optional `last_failed_at`

Profile and password rows are loaded with `LEFT JOIN`. A user that exists but
has no profile or password credential is therefore reported internally as an
invalid record rather than being confused with an unknown login.

`authd_login_record_availability()` performs no I/O and classifies the snapshot
as available, pending, disabled, locked, deleted, throttled, password-change
required, or invalid. Administrative `locked` remains separate from temporary
`throttled_until` protection.

An unknown login is deliberately still distinguishable inside the daemon so it
can be audited correctly. The later authentication coordinator must map unknown
users and wrong passwords to the same external FTAP error and must perform a
bounded dummy Argon2id verification for unknown users to avoid a trivial timing
oracle.

### Real PostgreSQL lookup integration test

The normal and sanitizer suites mock libpq so they remain deterministic and do
not modify a developer database. A separate target verifies the same lookup
against the local PostgreSQL service and peer-authenticated runtime role:

```sh
make database-login-integration-test
```

The test installs a uniquely named fixture with a fixed UUID, runs the lookup
binary as `fortytwo_authd`, verifies the full returned snapshot and the
not-found path, and removes the fixture through an EXIT trap. It refuses to
replace an unrelated account that happens to use the fixture login name.

## B3.4 bounded Argon2id worker pool

The fourth B3 step moves expensive password verification behind a fixed,
bounded pthread pool without connecting it to FTAP yet:

- `include/authd_worker_pool.h`
- `src/authd_worker_pool.c`
- `tests/authd_worker_pool_test.c`
- `tests/authd_worker_pool_password_integration_test.c`

Pre-alpha defaults are exposed through daemon configuration:

- `--password-workers 2`
- `--password-queue-capacity 16`

The capacity covers the complete lifecycle of a job: waiting, running, or
completed but not yet consumed by the event loop. This prevents completed jobs
from becoming an unbounded second queue when the event loop is busy.

Each submission copies the bounded password into pool-owned memory and wipes
the caller's complete declared buffer on both acceptance and rejection. Worker
threads call `authd_password_verify()` without holding the queue mutex. After
verification, only a result structure is returned; no worker retains a pointer
to a socket client or FTAP connection object.

A completion carries:

- a pool-generated nonzero job ID
- event-loop-owned connection ID
- connection generation
- FTAP request ID
- password result and `needs_rehash`

The connection generation lets the later FTAP integration discard a result if
the corresponding client slot was closed and reused while Argon2id was still
running. The pool exposes a nonblocking semaphore-style `eventfd`, so the main
`poll()` loop can receive exactly one readiness token per completion.

Shutdown is deliberately fail closed. New work is rejected, queued passwords
are wiped without verification, already-running Argon2id calls are joined, and
unclaimed completions are discarded. Running Argon2id calls are never cancelled
inside libsodium.

Test coverage includes bounded capacity, two-way parallelism, completion
notification, generation-token preservation, rejected-password wiping,
shutdown with pending jobs, a real libsodium verification through the pool,
ASan/UBSan, leak checks, and a dedicated ThreadSanitizer target:

```sh
make thread-sanitize-test
```

B3.7 instantiates the worker pool during daemon startup, adds its completion
descriptor to the existing `poll()` loop, and joins or wipes all remaining work
during controlled shutdown.

## B3.5 persistent failure window, temporary throttle, and audit

The fifth B3 step adds persistent user-level protection without yet wiring the
full FTAP authentication coordinator:

- `include/authd_throttle.h`
- `src/authd_throttle.c`
- `tests/authd_throttle_test.c`
- `authd_database_record_password_failure()`
- `authd_database_audit_login_rejection()`

Pre-alpha defaults are configurable through the daemon parser:

- `--password-failure-threshold 5`
- `--password-failure-window-seconds 900`
- `--password-throttle-seconds 900`

A wrong password for a known user is recorded by one data-modifying PostgreSQL
statement. It updates `failed_count` and `last_failed_at`, sets or preserves
`throttled_until` when the threshold is reached, inserts the detailed audit
event, and returns the new count and retry delay. PostgreSQL statement
atomicity means an audit failure also rolls back the counter and throttle
updates.

Failures older than the configured window reset the counter to one. Concurrent
failures serialize on the credential row, and the integer counter saturates
instead of overflowing. Administrative `account_state = 'locked'` remains
completely separate from the temporary `throttled_until` value.

Audit-only denials cover unknown users, account-state rejection, an already
active throttle, worker overload, and internal failure. The audit JSON contains
machine-readable reason, canonical login name where needed, protocol, count,
and throttle state. No API accepts or stores a plaintext password. Wrong
password audit must use the atomic counter function rather than the audit-only
function.

IPv4 and IPv6 text is validated before PostgreSQL casts it to `inet`, and only
FTAP 1.1 protocol names (`telnet`, `ssh`, and `local`) are accepted. The
in-memory per-IP short-window limiter remains a later integration component;
this step implements the persistent per-user half of the documented hybrid
model.

The successful-login reset is intentionally deferred to B3.6, where it must be
committed in the same transaction as terminal-session creation and the success
audit. A standalone reset here could otherwise leave partially authenticated
state after a later session-insert failure.

### Real PostgreSQL throttle integration test

The separate integration target creates an isolated fixture whose four old
failures are outside the 15-minute window. It verifies reset-to-one, five new
atomic failure updates, the stored temporary throttle, five audit events, an
unknown-user audit with no subject UUID, and complete cleanup:

```sh
make database-throttle-integration-test
```

## B3.6 atomic successful login and terminal session

The sixth B3 step persists the successful side of password authentication while
leaving FTAP socket-state binding for B3.7:

- migration `0006_authorization_revision.sql`
- `authd_database_create_password_session()`
- `authd_terminal_session_result_t`
- `tests/authd_database_session_integration_test.c`

Migration 0006 adds `bbs_users.authz_revision`, a positive monotonic revision
for the user's effective roles and capabilities. The value is returned with the
session context and will later let the daemon push authorization changes to
already connected clients without confusing them with `auth_epoch`, which is
reserved for security-state revocation.

After Argon2id succeeds, one data-modifying PostgreSQL statement locks and
rechecks the user snapshot. The current row must still have the same `user_id`,
canonical login name, `auth_epoch`, and `authz_revision`; remain active and
undeleted; have no active `throttled_until`; and retain the same password hash
without `must_change`.

Only then does the statement chain three writes through `RETURNING` rows:

1. reset `failed_count` and `last_failed_at`
2. insert the open `bbs_terminal_sessions` row
3. append the `auth.login_succeeded` audit event

PostgreSQL statement atomicity makes the operation all-or-nothing. A failure in
session creation or audit cannot leave cleared counters or a partial session.
A zero-row result is reported as `stale_state`, so an account lock, password
change, authorization revision, or throttle that occurs during Argon2id never
produces an authenticated session from an obsolete snapshot.

The returned result contains the binary `USER_ID`, generated `SESSION_ID`,
`AUTH_EPOCH`, and `AUTHZ_REVISION` needed for `AUTH_PASSWORD_RESULT`. Source IP,
protocol, TTY, node ID, and canonical login name remain libpq parameters and are
also captured in the success audit without exposing a password.

### Real PostgreSQL session integration test

The separate integration target starts with four stored failures, creates one
SSH/password session through the peer-authenticated runtime role, verifies the
counter reset, open session, and matching audit, then retries with a deliberately
stale epoch and confirms that no second session is created:

```sh
make database-session-integration-test
```


## B3.7 FTAP login coordinator and connection binding

The seventh B3 step connects the previously isolated components in the real
`fortytwo-authd` event loop:

- canonical FTAP login-name parsing;
- parameterized PostgreSQL snapshot lookup;
- account-state and temporary-throttle classification;
- asynchronous Argon2id submission;
- `eventfd` completion handling;
- snapshot revalidation and atomic session creation;
- FTAP success or deliberately uniform credential failure;
- database session closure when the bound socket ends.

Each client slot owns a stable nonzero connection ID and a generation that is
incremented every time the slot is reused. A running login additionally stores
the FTAP request ID and worker-generated job ID. A completion is accepted only
when all four values still match the live client:

```text
connection ID
connection generation
request ID
worker job ID
```

Workers never receive a pointer to a client structure. A result from a closed
connection, a reused slot, or a superseded request is discarded without a
response or database session. Socket close/error events are processed before
ready worker completions from the same `poll()` iteration.

### Dummy verification and external failures

At daemon startup, 32 random bytes are generated with the operating-system
random source and hashed with the same bounded Argon2id policy as normal
credentials. The resulting process-local dummy hash contains no user identity.
Unknown, pending, disabled, locked, deleted, password-change-required, and
otherwise unavailable accounts run through that dummy verification before the
client receives the same external result as a wrong password:

```text
FTAP_ERR_INVALID_CREDENTIALS
authentication failed
```

Exact reasons remain in the internal audit log. The deterministic daemon test
records the selected hash class and proves that unknown, locked, and disabled
fixtures reached the dummy worker path.

Temporary protection through `throttled_until` is intentionally visible in
FTAP 1.1 as `FTAP_ERR_RATE_LIMITED` with a bounded `RETRY_AFTER_MS`. This avoids
encouraging a client to retry expensive authentication immediately. Technical
database or worker failures remain separate from credential failures.

### Password and connection lifetime

The mutable password copy is wiped by worker submission on every acceptance or
rejection path. After a complete password frame is parsed, the corresponding
bytes are also wiped from the client's FTAP input buffer before pipelined data
is compacted. A connection reset overwrites the complete allocated input
buffer, pending login snapshot, response buffer, and stored session context.

The PostgreSQL terminal session is bound to exactly one authenticated FTAP
socket. `authd_database_close_terminal_session()` atomically closes an open
session and inserts `auth.terminal_session_closed`; a second cleanup attempt is
harmless and returns `not_found`. The daemon records distinct lifecycle reasons
such as:

```text
normal_logout
peer_disconnected
auth_response_failed
protocol_error
authd_shutdown
authd_failure
```

`SESSION_CLOSE` has no response in FTAP 1.1. The daemon first stores the
optional machine-readable `ENDED_REASON` (default `normal_logout`) and then
closes the socket. If PostgreSQL session creation succeeds but the FTAP success
frame cannot be queued or sent, the new session is immediately closed as
`auth_response_failed`; no open ghost session is left behind.

### Integration coverage

The test-only daemon uses deterministic database and password modules but the
production server state machine. End-to-end coverage includes:

- successful password login and ordered `SESSION_CLOSE`;
- wrong password;
- unknown user through the dummy hash;
- locked and disabled accounts through the dummy hash;
- active throttle and `RETRY_AFTER_MS`;
- stale login snapshot after password verification;
- invalid stored hash and session-creation failure;
- disconnect during a running password job;
- reuse of the same client slot with a new generation;
- a second login request while one is already running;
- full worker capacity;
- shutdown with a running job;
- forced failure while sending a successful authentication result;
- no second response or session from a late worker completion.

The production libpq wrapper test separately verifies the exact parameterized
SQL and lifecycle return values for terminal-session closure. The real
PostgreSQL session integration test now closes the created fixture session,
verifies the close audit, and verifies idempotent repeated cleanup.

No migration is added by B3.7. Migration 0002 already grants the runtime role
the required `SELECT`/`UPDATE` rights on `bbs_terminal_sessions` and
`SELECT`/`INSERT` rights on `bbs_audit_events`. Applied migration files remain
unchanged.
