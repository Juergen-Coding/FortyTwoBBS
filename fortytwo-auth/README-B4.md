# fortytwo-auth Phase B4

Phase B4 connects terminal transports to the internal FortyTwo identity without
turning BBS users into Linux accounts. It is split deliberately: B4.1 creates
and proves the secure access boundary, while the following step will adapt the
legacy MBSE session bootstrap to consume that identity.

## B4.1 access adapter and descriptor-bound identity

This step identifies the daemon build as `fortytwo-authd 0.2.2`; the new
terminal adapter starts at `fortytwo-login 0.1.0`. FTAP remains version 1.1.

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
