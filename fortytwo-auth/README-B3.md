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

The password module is not called from the socket event loop yet. B3.4 now
provides the bounded worker pool; the remaining integration step will submit
FTAP login jobs and consume their results in the event loop.

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

The worker pool is linked into the production binary but is not instantiated by
the socket server yet. B3 integration will create it at startup and add its
completion descriptor to the existing event loop.
