#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s TEST_BINARY\n' "$0" >&2
    exit 2
fi

TEST_BINARY=$1
DB_NAME=${FT_DB_NAME:-fortytwo}
DB_ADMIN_USER=${FT_DB_ADMIN_USER:-postgres}
DB_RUNTIME_USER=${FT_DB_RUNTIME_USER:-fortytwo_authd}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SETUP_SQL=$SCRIPT_DIR/0005_throttle_fixture_setup.sql
VERIFY_SQL=$SCRIPT_DIR/0005_throttle_fixture_verify.sql
CLEANUP_SQL=$SCRIPT_DIR/0005_throttle_fixture_cleanup.sql
TEMP_BINARY=/tmp/fortytwo-authd-throttle-integration-test.$$
fixture_created=0

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    rm -f "$TEMP_BINARY"
    if [ "$fixture_created" -eq 1 ]; then
        if ! sudo -u "$DB_ADMIN_USER" \
            psql --no-psqlrc --set=ON_ERROR_STOP=1 \
            --dbname="$DB_NAME" < "$CLEANUP_SQL"
        then
            printf 'WARNING: could not remove PostgreSQL throttle fixture\n' >&2
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup EXIT HUP INT TERM

if [ ! -x "$TEST_BINARY" ]; then
    printf 'Test binary is missing or not executable: %s\n' "$TEST_BINARY" >&2
    exit 1
fi

install -m 0755 "$TEST_BINARY" "$TEMP_BINARY"

sudo -u "$DB_ADMIN_USER" \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --dbname="$DB_NAME" < "$SETUP_SQL"
fixture_created=1

sudo -u "$DB_RUNTIME_USER" "$TEMP_BINARY"

sudo -u "$DB_ADMIN_USER" \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --dbname="$DB_NAME" < "$VERIFY_SQL"
