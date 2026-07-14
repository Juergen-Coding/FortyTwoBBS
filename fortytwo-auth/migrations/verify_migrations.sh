#!/bin/sh

set -eu

DB_NAME="${FT_DB_NAME:-fortytwo}"
DB_ADMIN_USER="${FT_DB_ADMIN_USER:-postgres}"
MIGRATION_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

history_file=$(mktemp)
trap 'rm -f "$history_file"' EXIT HUP INT TERM

sudo -u "$DB_ADMIN_USER" \
    psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --field-separator='|' \
    --dbname="$DB_NAME" \
    --command="
        SELECT
            migration_version,
            migration_name,
            checksum_sha256
        FROM fortytwo_schema_migrations
        ORDER BY migration_version;
    " > "$history_file"

status=0
registered_count=0
local_count=0

while IFS='|' read -r version name expected_checksum
do
    [ -n "$version" ] || continue

    registered_count=$((registered_count + 1))
    migration_path="$MIGRATION_DIR/$name"

    if [ ! -f "$migration_path" ]; then
        printf 'FEHLT: Version %s ist registriert, aber die Datei fehlt: %s\n' \
            "$version" "$name"
        status=1
        continue
    fi

    actual_checksum=$(sha256sum "$migration_path" | awk '{print $1}')

    if [ "$actual_checksum" != "$expected_checksum" ]; then
        printf 'VERÄNDERT: %s\n' "$name"
        printf '  Datenbank: %s\n' "$expected_checksum"
        printf '  Datei:     %s\n' "$actual_checksum"
        status=1
    else
        printf 'OK: %s\n' "$name"
    fi
done < "$history_file"

for migration_path in "$MIGRATION_DIR"/[0-9][0-9][0-9][0-9]_*.sql
do
    [ -e "$migration_path" ] || continue

    local_count=$((local_count + 1))
    name=$(basename -- "$migration_path")

    if ! awk -F '|' -v migration_name="$name" '
        $2 == migration_name { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$history_file"
    then
        printf 'NEU, NOCH NICHT AUSGEFÜHRT: %s\n' "$name"
    fi
done

if [ "$status" -ne 0 ]; then
    printf '\nFEHLER: Die Migrationshistorie stimmt nicht mit den Dateien überein.\n' >&2
    exit 1
fi

printf '\nMigrationen geprüft: %s registriert, %s lokale SQL-Dateien.\n' \
    "$registered_count" "$local_count"
