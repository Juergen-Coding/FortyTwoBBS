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
