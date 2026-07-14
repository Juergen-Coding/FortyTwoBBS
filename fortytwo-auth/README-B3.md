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

The password module is not yet called from the socket event loop. A later B3
step will place verification jobs in a bounded worker pool and return results
to the event loop without performing Argon2 work there.

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
