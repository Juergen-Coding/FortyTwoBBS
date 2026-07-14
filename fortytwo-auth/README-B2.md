# fortytwo-authd Phase B2

Phase B2 binds the B1 Unix-socket daemon to the local PostgreSQL identity
store. It still does not implement password authentication.

## Startup order

`fortytwo-authd` now performs these steps before creating `auth.sock`:

1. connect to PostgreSQL through a local Unix socket;
2. require the database role `fortytwo_authd`;
3. reject password-authenticated database connections;
4. require PostgreSQL 17 or newer and a read-write connection;
5. select UTF-8 and defensive session timeouts;
6. verify every registered migration name and SHA-256 checksum;
7. only then create the FTAP Unix socket and accept clients.

If any step fails, no FTAP socket is created.

## Database migration 0004

`0004_authd_schema_history_read.sql` grants `fortytwo_authd` read-only access
to `fortytwo_schema_migrations`. The daemon needs this metadata to verify that
the running binary and database schema match exactly.

The role receives no INSERT, UPDATE, DELETE, TRUNCATE or ownership privilege
on the migration history.

The migration must be applied and registered before the production daemon can
start successfully.

Later migrations add the canonical ASCII login-name policy, the monotonic
authorization revision and the explicit UUID-to-MBSE record binding. Current
binaries therefore require migrations 0001 through 0007 with their exact
registered SHA-256 checksums.

## Connection policy

The daemon accepts only an absolute PostgreSQL Unix-socket directory. TCP host
names and IP addresses are rejected by configuration parsing.

The database role is compiled as:

```text
fortytwo_authd
```

There is deliberately no command-line password option. The current deployment
uses local PostgreSQL peer authentication. If libpq reports that a password
was used, startup fails.

Defaults:

```text
db_host=/var/run/postgresql
db_port=5432
db_name=fortytwo
db_connect_timeout_seconds=5
db_health_interval_ms=5000
```

## Runtime failure policy

A periodic `SELECT 1` checks the established database connection. If it fails,
the daemon exits, closes every FTAP connection and removes only the Unix socket
inode it created itself.

Phase B2 deliberately performs no automatic database reconnect. The service
manager may restart the daemon. This avoids accepting authentication work with
an uncertain database state.

## Manual checks

Configuration only:

```sh
build/normal/fortytwo-authd --check-config
```

Database and schema, without opening the FTAP socket:

```sh
build/normal/fortytwo-authd --check-database
```

## Build requirements

In addition to the B1 compiler requirements:

```text
pkg-config
libpq development headers and library (Ubuntu package: libpq-dev)
```

## Tests

`make test` covers:

- all FTAP B1 tests;
- database configuration boundaries;
- role, database, server-version and read-only validation;
- exact migration name/checksum matching;
- the production libpq path through linker-wrapped responses;
- failure against a nonexistent PostgreSQL socket;
- no FTAP socket when database startup fails;
- daemon shutdown and client closure after a health-check failure.

`make sanitize-test` runs the same relevant paths with ASan and UBSan.

The integration test daemon links a test-only database stub. The production
`fortytwo-authd` always links libpq and has no runtime switch that bypasses the
database checks.
